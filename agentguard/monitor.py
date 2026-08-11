from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import socket
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import psutil

from .attribution import SessionAttributor
from .deep import FileAccessTracker, ReverseDnsResolver, TcpTrafficSampler, endpoint_host
from .extended import (
    ActivityCorrelator,
    ClipboardMetadataTracker,
    DnsEtwTracker,
    RegistryEtwTracker,
    ResourceTracker,
    SystemChangeTracker,
    WindowsAuditTracker,
    windows_process_security,
)
from .file_etw import EtwFileReadTracker
from .risk import RiskAssessor, is_operation_event


EXCLUDED_DIRS = {
    ".agentguard",
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
    "target",
    "dist",
    "build",
}
TEXT_LIMIT = 256 * 1024
DIFF_LIMIT = 16_000
FAST_FILE_STATE_LIMIT = 10_000
DEFAULT_MAX_SNAPSHOT_FILES = 5_000
TOKEN_PATTERN = re.compile(r"(?i)(?:sk-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9]{12,})")
INLINE_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|password|secret)=([^\s]+)"
)
SENSITIVE_FLAGS = {
    "--api-key",
    "--apikey",
    "--password",
    "--secret",
    "--token",
    "-password",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def redact_argv(argv: Iterable[str]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for raw in argv:
        arg = str(raw)
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        lowered = arg.lower()
        if lowered in SENSITIVE_FLAGS:
            result.append(arg)
            redact_next = True
            continue
        if any(lowered.startswith(flag + "=") for flag in SENSITIVE_FLAGS):
            result.append(arg.split("=", 1)[0] + "=[REDACTED]")
            continue
        arg = INLINE_SECRET_PATTERN.sub(lambda m: m.group(1) + "=[REDACTED]", arg)
        result.append(TOKEN_PATTERN.sub("[REDACTED]", arg))
    return result


def safe_processes(*, detailed: bool = False) -> dict[int, dict[str, Any]]:
    attrs = ["pid", "ppid", "name", "create_time"]
    if detailed:
        attrs.extend(["exe", "cwd", "cmdline"])
    result: dict[int, dict[str, Any]] = {}
    for process in psutil.process_iter(attrs=attrs, ad_value=None):
        info = dict(process.info)
        if info.get("pid") is not None:
            result[int(info["pid"])] = info
    return result


def find_agent_processes(target_names: Iterable[str]) -> list[dict[str, Any]]:
    targets = {name.lower() for name in target_names}
    return sorted(
        (
            info
        for info in safe_processes(detailed=True).values()
            if str(info.get("name") or "").lower() in targets
        ),
        key=lambda item: int(item["pid"]),
    )


class EventSink:
    def __init__(
        self,
        output: Path,
        metadata: dict[str, Any],
        on_event: Callable[[dict[str, Any]], None] | None = None,
        risk_assessor: RiskAssessor | None = None,
        correlator: ActivityCorrelator | None = None,
    ) -> None:
        self.output = output
        self.output.mkdir(parents=True, exist_ok=True)
        self._handle = (output / "events.jsonl").open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        self.sequence = 0
        self.counts: Counter[str] = Counter()
        self.process_names: Counter[str] = Counter()
        self.file_paths: Counter[str] = Counter()
        self.file_activity_by_pid: dict[int, deque[dict[str, Any]]] = defaultdict(deque)
        self.remote_endpoints: Counter[str] = Counter()
        self.metadata = metadata
        self.on_event = on_event
        self.risk_assessor = risk_assessor
        self.correlator = correlator
        self.risk_counts: Counter[str] = Counter()
        self.attention_events: list[dict[str, Any]] = []

    def emit(self, event_type: str, **data: Any) -> None:
        if event_type in {"file.read", "file.modified"} and data.get("pid") is not None:
            try:
                pid = int(data["pid"])
                activity = self.file_activity_by_pid[pid]
                activity.append(
                    {
                        "timestamp": time.monotonic(),
                        "path": data.get("path"),
                        "type": event_type,
                        "bytes_read": int(data.get("bytes_read") or 0),
                        "bytes_written": int(data.get("bytes_written") or 0),
                    }
                )
                cutoff = time.monotonic() - 10.0
                while activity and float(activity[0]["timestamp"]) < cutoff:
                    activity.popleft()
            except (TypeError, ValueError):
                pass
        if event_type == "resource.anomaly" and data.get("pid") is not None:
            try:
                activity = self.file_activity_by_pid.get(int(data["pid"]), ())
                paths = list(dict.fromkeys(str(item["path"]) for item in activity if item.get("path")))
                if paths:
                    data.setdefault("related_file_paths", paths[:20])
                    data.setdefault("related_file_operations", len(activity))
                    data.setdefault("related_file_read_bytes", sum(int(item.get("bytes_read") or 0) for item in activity))
                    data.setdefault("related_file_write_bytes", sum(int(item.get("bytes_written") or 0) for item in activity))
                    data.setdefault("related_file_window_seconds", 10)
            except (TypeError, ValueError):
                pass
        with self._lock:
            self.sequence += 1
            event = {
                "sequence": self.sequence,
                "timestamp": utc_now(),
                "type": event_type,
                **data,
            }
            if self.risk_assessor is not None:
                event["risk"] = self.risk_assessor.assess(event_type, data).as_dict()
            self._handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            self.counts[event_type] += 1
            if event_type.startswith("process.") and data.get("name"):
                self.process_names[str(data["name"])] += 1
            if event_type.startswith("file.") and data.get("path"):
                self.file_paths[str(data["path"])] += 1
            if event_type.startswith("network.") and data.get("remote"):
                self.remote_endpoints[str(data["remote"])] += 1
            if is_operation_event(event_type) and event.get("risk"):
                level = str(event["risk"]["level"])
                self.risk_counts[level] += 1
                if level == "review" and len(self.attention_events) < 100:
                    self.attention_events.append(
                        {
                            "sequence": event["sequence"],
                            "timestamp": event["timestamp"],
                            "type": event_type,
                            "path": data.get("path"),
                            "name": data.get("name"),
                            "remote": data.get("remote"),
                            "risk": event["risk"],
                        }
                    )
        if self.on_event is not None:
            self.on_event(event)
        if self.correlator is not None:
            for derived_type, derived_data in self.correlator.observe(event):
                self.emit(derived_type, **derived_data)

    def close(self) -> None:
        self._handle.close()
        summary = {
            "metadata": self.metadata,
            "finished_at": utc_now(),
            "event_counts": dict(self.counts),
            "processes": dict(self.process_names.most_common()),
            "changed_files": dict(self.file_paths.most_common()),
            "remote_endpoints": dict(self.remote_endpoints.most_common()),
            "screening_counts": dict(self.risk_counts),
            "attention_events": self.attention_events,
        }
        (self.output / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        lines = [
            "# AgentGuard observation summary",
            "",
            f"- Workspace: `{self.metadata['root']}`",
            f"- Started: `{self.metadata['started_at']}`",
            f"- Finished: `{summary['finished_at']}`",
            f"- Target roots: `{', '.join(map(str, self.metadata.get('root_pids', []))) or 'auto'}`",
            "",
            "## Event counts",
            "",
        ]
        if self.counts:
            lines.extend(f"- {name}: {count}" for name, count in self.counts.most_common())
        else:
            lines.append("- No events")
        if self.risk_counts:
            lines.extend(["", "## Automatic screening", ""])
            lines.append(f"- Clearly safe: {self.risk_counts.get('safe', 0)}")
            lines.append(f"- Needs attention: {self.risk_counts.get('review', 0)}")
        if self.file_paths:
            lines.extend(["", "## Changed files", ""])
            lines.extend(f"- `{path}`" for path, _ in self.file_paths.most_common(50))
        if self.remote_endpoints:
            lines.extend(["", "## Remote endpoints", ""])
            lines.extend(f"- `{remote}`" for remote, _ in self.remote_endpoints.most_common(50))
        (self.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class FileState:
    size: int
    mtime_ns: int
    inode: int
    digest: str | None
    text: str | None
    mode: int


class FileTracker:
    def __init__(
        self,
        root: Path,
        sink: EventSink,
        current_thread_id: str | None = None,
        lazy: bool = False,
        max_files: int | None = None,
    ) -> None:
        self.root = root
        self.sink = sink
        self.directory_mtimes: dict[str, int] = {}
        self.files_by_dir: dict[str, dict[str, FileState]] = {}
        self.max_files = max_files
        self.disabled = False
        self.snapshot: dict[str, FileState] | None = None
        if not lazy:
            self.snapshot = self._take_snapshot()
        self.attribution = {
            "session_id": f"workspace:{os.path.normcase(str(root.resolve()))}",
            "thread_id": None,
            "attribution": "current_workspace",
            "attribution_label": "当前工作区·写入会话未确认",
            "attribution_confidence": "low",
            "workspace_path": str(root.resolve()),
        }

    def initialize(self, cancel_event: threading.Event | None = None) -> bool:
        if os.environ.get("AGENTGUARD_DISABLE_WORKSPACE_SCAN") == "1":
            self.disabled = True
            return True
        if self.snapshot is None:
            # Inventory a large workspace without opening every small file.  A
            # second content pass is only worthwhile for small roots where it
            # enables useful first-change diffs.
            snapshot = self._take_snapshot(cancel_event=cancel_event, capture_content=False)
            if snapshot is None:
                self.disabled = True
                return True
            if len(snapshot) <= FAST_FILE_STATE_LIMIT and not (cancel_event and cancel_event.is_set()):
                snapshot = self._take_snapshot(snapshot, cancel_event=cancel_event, capture_content=True)
                if snapshot is None:
                    self.disabled = True
                    return True
            if cancel_event is not None and cancel_event.is_set():
                return False
            self.snapshot = snapshot
        return True

    def _paths(self, cancel_event: threading.Event | None = None) -> Iterable[Path]:
        for current, dirs, files in os.walk(self.root):
            if cancel_event is not None and cancel_event.is_set():
                return
            dirs[:] = [
                name
                for name in dirs
                if name not in EXCLUDED_DIRS
                and not (Path(current) / name).is_symlink()
            ]
            for name in files:
                path = Path(current) / name
                if not path.is_symlink():
                    yield path

    def _state(
        self,
        path: Path,
        previous: FileState | None = None,
        *,
        capture_content: bool = True,
    ) -> FileState | None:
        try:
            stat = path.stat()
            if (
                previous is not None
                and previous.size == stat.st_size
                and previous.mtime_ns == stat.st_mtime_ns
                and previous.inode == stat.st_ino
                and previous.mode == stat.st_mode
                and (not capture_content or previous.digest is not None)
            ):
                return previous
            text: str | None = None
            digest: str | None = None
            if capture_content and stat.st_size <= TEXT_LIMIT:
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if b"\x00" not in raw:
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        text = None
            return FileState(stat.st_size, stat.st_mtime_ns, stat.st_ino, digest, text, stat.st_mode)
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def _take_snapshot(
        self,
        previous: dict[str, FileState] | None = None,
        cancel_event: threading.Event | None = None,
        capture_content: bool = True,
    ) -> dict[str, FileState] | None:
        previous = previous or {}
        result: dict[str, FileState] = {}
        next_directory_mtimes: dict[str, int] = {}
        next_files_by_dir: dict[str, dict[str, FileState]] = {}
        stack = [self.root]
        while stack:
            if cancel_event is not None and cancel_event.is_set():
                break
            current = stack.pop()
            try:
                relative_dir = current.relative_to(self.root).as_posix() or "."
                directory_mtime = current.stat().st_mtime_ns
                entries = list(os.scandir(current))
            except (FileNotFoundError, PermissionError, OSError):
                continue
            next_directory_mtimes[relative_dir] = directory_mtime
            unchanged = (
                self.snapshot is not None
                and self.directory_mtimes.get(relative_dir) == directory_mtime
                and relative_dir in self.files_by_dir
            )
            # Small workspaces can cheaply refresh file mtimes on every pass;
            # large roots rely on ETW writes and only rescan changed directories.
            if unchanged and self.snapshot is not None and len(self.snapshot) <= FAST_FILE_STATE_LIMIT:
                unchanged = False
            if unchanged:
                direct_files = dict(self.files_by_dir[relative_dir])
                next_files_by_dir[relative_dir] = direct_files
                for name, state in direct_files.items():
                    relative = name if relative_dir == "." else f"{relative_dir}/{name}"
                    result[relative] = state
            else:
                direct_files: dict[str, FileState] = {}
                for entry in entries:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            path = Path(entry.path)
                            name = entry.name
                            relative = name if relative_dir == "." else f"{relative_dir}/{name}"
                            state = self._state(
                                path,
                                previous.get(relative),
                                capture_content=capture_content,
                            )
                            if state is not None:
                                direct_files[name] = state
                                result[relative] = state
                                if self.max_files is not None and len(result) > self.max_files:
                                    self.directory_mtimes = {}
                                    self.files_by_dir = {}
                                    return None
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
                next_files_by_dir[relative_dir] = direct_files
            for entry in entries:
                if cancel_event is not None and cancel_event.is_set():
                    break
                try:
                    if not entry.is_dir(follow_symlinks=False) or entry.name in EXCLUDED_DIRS:
                        continue
                    stack.append(Path(entry.path))
                except (FileNotFoundError, PermissionError, OSError):
                    continue
        self.directory_mtimes = next_directory_mtimes
        self.files_by_dir = next_files_by_dir
        return result

    @staticmethod
    def _diff(path: str, before: str | None, after: str | None) -> str | None:
        if before is None or after is None:
            return None
        text = "\n".join(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="",
            )
        )
        if len(text) > DIFF_LIMIT:
            return text[:DIFF_LIMIT] + "\n... [diff truncated]"
        return text or None

    def poll(self) -> None:
        if self.disabled:
            return
        if self.snapshot is None:
            self.initialize()
            return
        current = self._take_snapshot(self.snapshot)
        old_paths = set(self.snapshot)
        new_paths = set(current)

        deleted = old_paths - new_paths
        created = new_paths - old_paths
        old_inode = {self.snapshot[path].inode: path for path in deleted}
        new_inode = {current[path].inode: path for path in created}
        for inode in old_inode.keys() & new_inode.keys():
            old_path = old_inode[inode]
            new_path = new_inode[inode]
            self.sink.emit(
                "file.renamed",
                path=new_path,
                old_path=old_path,
                scope="workspace",
                **self.attribution,
            )
            deleted.discard(old_path)
            created.discard(new_path)

        for path in sorted(created):
            state = current[path]
            self.sink.emit(
                "file.created",
                path=path,
                size=state.size,
                sha256=state.digest,
                scope="workspace",
                **self.attribution,
            )
        for path in sorted(deleted):
            state = self.snapshot[path]
            self.sink.emit(
                "file.deleted",
                path=path,
                previous_size=state.size,
                previous_sha256=state.digest,
                scope="workspace",
                **self.attribution,
            )
        for path in sorted(old_paths & new_paths):
            before = self.snapshot[path]
            after = current[path]
            if before.mode != after.mode:
                self.sink.emit(
                    "file.permissions_changed",
                    path=path,
                    mode_before=oct(before.mode & 0o7777),
                    mode_after=oct(after.mode & 0o7777),
                    observation="filesystem_metadata",
                    scope="workspace",
                    **self.attribution,
                )
            if (
                before.size != after.size
                or before.mtime_ns != after.mtime_ns
                or before.digest != after.digest
            ):
                self.sink.emit(
                    "file.modified",
                    path=path,
                    size=after.size,
                    sha256=after.digest,
                    diff=self._diff(path, before.text, after.text),
                    scope="workspace",
                    **self.attribution,
                )
        self.snapshot = current


class ProcessTracker:
    def __init__(
        self,
        sink: EventSink,
        target_names: Iterable[str],
        explicit_pids: set[int],
        capture_command_lines: bool,
        workspace_root: Path,
        current_thread_id: str | None,
    ) -> None:
        self.sink = sink
        self.targets = {name.lower() for name in target_names}
        self.explicit_pids = explicit_pids
        self.capture_command_lines = capture_command_lines
        self.seen: dict[int, dict[str, Any]] = {}
        self.root_pids: set[int] = set()
        self.workspace_root = workspace_root
        self.attributor = SessionAttributor(workspace_root, current_thread_id)

    def _roots(self, processes: dict[int, dict[str, Any]]) -> set[int]:
        if self.explicit_pids:
            return {pid for pid in self.explicit_pids if pid in processes}
        candidates = {
            pid
            for pid, info in processes.items()
            if str(info.get("name") or "").lower() in self.targets
        }
        roots: set[int] = set()
        for pid in candidates:
            parent = processes[pid].get("ppid")
            has_target_ancestor = False
            visited: set[int] = set()
            while parent in processes and parent not in visited:
                visited.add(int(parent))
                if parent in candidates:
                    has_target_ancestor = True
                    break
                parent = processes[int(parent)].get("ppid")
            if not has_target_ancestor:
                roots.add(pid)
        # When several Codex installations are running, prefer the root whose
        # process tree contains the selected workspace. This avoids attributing
        # another VS Code/Desktop Codex instance to the current monitor.
        workspace = self.workspace_root.resolve()
        workspace_roots: set[int] = set()
        for pid, info in processes.items():
            if self._session_for(pid, roots, processes) is None:
                continue
            cwd = info.get("cwd")
            if cwd is None:
                try:
                    cwd = psutil.Process(pid).cwd()
                    info["cwd"] = cwd
                except (psutil.Error, OSError):
                    cwd = None
            if not cwd:
                continue
            try:
                Path(str(cwd)).resolve(strict=False).relative_to(workspace)
            except (ValueError, OSError, RuntimeError):
                continue
            root = self._session_for(pid, roots, processes)
            if root is not None:
                workspace_roots.add(root)
        if workspace_roots:
            roots = workspace_roots
        return roots

    @staticmethod
    def _session_for(
        pid: int, roots: set[int], processes: dict[int, dict[str, Any]]
    ) -> int | None:
        current = pid
        visited: set[int] = set()
        while current in processes and current not in visited:
            if current in roots:
                return current
            visited.add(current)
            parent = processes[current].get("ppid")
            if not isinstance(parent, int):
                break
            current = parent
        return None

    def poll(
        self, initial: bool = False
    ) -> tuple[set[int], dict[int, int], dict[int, dict[str, Any]]]:
        processes = safe_processes()
        roots = self._roots(processes)
        self.root_pids |= roots
        monitor_pids = {os.getpid()}
        changed = True
        while changed:
            changed = False
            for pid, info in processes.items():
                if pid not in monitor_pids and info.get("ppid") in monitor_pids:
                    monitor_pids.add(pid)
                    changed = True
        relevant: dict[int, tuple[dict[str, Any], int]] = {}
        for pid, info in processes.items():
            session = self._session_for(pid, roots, processes)
            if session is not None and pid not in monitor_pids:
                relevant[pid] = (info, session)
        attributions = self.attributor.build(relevant, roots)

        for pid, (info, session) in relevant.items():
            # Fetch expensive process fields only for the agent tree, and only
            # when they are not already cached in this poller's seen record.
            cached = self.seen.get(pid) or {}
            for field in ("cwd", "exe", "cmdline"):
                if not info.get(field) and cached.get(field):
                    info[field] = cached[field]
            if pid not in self.seen or not cached.get("cwd"):
                try:
                    process = psutil.Process(pid)
                    info["cwd"] = info.get("cwd") or process.cwd()
                    info["exe"] = info.get("exe") or process.exe()
                    info["cmdline"] = info.get("cmdline") or process.cmdline()
                except (psutil.Error, OSError):
                    pass
            if pid not in self.seen:
                payload: dict[str, Any] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "session_pid": session,
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "cwd": info.get("cwd"),
                    "create_time": info.get("create_time"),
                }
                if self.capture_command_lines:
                    payload["argv"] = redact_argv(info.get("cmdline") or [])
                payload.update(windows_process_security(pid))
                payload.update(attributions.get(pid, {}))
                self.sink.emit("process.discovered" if initial else "process.started", **payload)
            self.seen[pid] = {
                **info,
                "session_pid": session,
                **attributions.get(pid, {}),
            }

        for pid in set(self.seen) - set(relevant):
            info = self.seen.pop(pid)
            self.sink.emit(
                "process.ended",
                pid=pid,
                ppid=info.get("ppid"),
                session_pid=info.get("session_pid"),
                name=info.get("name"),
                create_time=info.get("create_time"),
                session_id=info.get("session_id"),
                thread_id=info.get("thread_id"),
                attribution=info.get("attribution"),
                attribution_label=info.get("attribution_label"),
                attribution_confidence=info.get("attribution_confidence"),
                workspace_path=info.get("workspace_path"),
            )
        return (
            set(relevant),
            {pid: session for pid, (_, session) in relevant.items()},
            attributions,
        )


def _address(value: Any) -> str | None:
    if not value:
        return None
    host = getattr(value, "ip", None) or value[0]
    port = getattr(value, "port", None) or value[1]
    if ":" in str(host):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class NetworkTracker:
    def __init__(self, sink: EventSink) -> None:
        self.sink = sink
        self.connections: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.warned = False
        self.resolver = ReverseDnsResolver()
        self.traffic = TcpTrafficSampler()
        self.resolved: set[tuple[tuple[Any, ...], str]] = set()
        self.traffic_emitted: dict[tuple[Any, ...], tuple[int, int, float]] = {}
        self.connection_started: dict[tuple[Any, ...], float] = {}

    def poll(
        self,
        pids: set[int],
        sessions: dict[int, int],
        attributions: dict[int, dict[str, Any]],
    ) -> None:
        current: dict[tuple[Any, ...], dict[str, Any]] = {}
        now = time.monotonic()
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            if not self.warned:
                self.sink.emit("monitor.warning", component="network", message=str(exc))
                self.warned = True
            return
        for conn in connections:
            if conn.pid not in pids:
                continue
            local = _address(conn.laddr)
            remote = _address(conn.raddr)
            if remote is None:
                continue
            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            key = (conn.pid, protocol, local, remote)
            started = self.connection_started.setdefault(key, now)
            duration = max(now - started, 0.1)
            current[key] = {
                "pid": conn.pid,
                "session_pid": sessions.get(conn.pid),
                "protocol": protocol,
                "local": local,
                "remote": remote,
                "status": conn.status,
                "observed_duration_seconds": round(duration, 3),
                **attributions.get(conn.pid, {}),
            }
            host = endpoint_host(remote)
            if host:
                hostname = self.resolver.request(host)
                if hostname:
                    current[key]["hostname"] = hostname
                    resolved_key = (key, hostname)
                    if resolved_key not in self.resolved:
                        self.resolved.add(resolved_key)
                        self.sink.emit(
                            "network.resolved",
                            **current[key],
                            hostname_source="reverse_dns",
                        )
            counters = self.traffic.sample(conn)
            if counters is not None:
                current[key]["bytes_sent"] = counters[0]
                current[key]["bytes_received"] = counters[1]
                current[key]["traffic_precision"] = "exact_tcp_payload"
                current[key]["average_send_rate_bps"] = round(counters[0] / duration, 2)
                current[key]["average_receive_rate_bps"] = round(counters[1] / duration, 2)
                current[key]["upload_download_ratio"] = round(
                    counters[0] / max(counters[1], 1), 3
                )
            else:
                current[key]["traffic_precision"] = (
                    "requires_elevation"
                    if self.traffic.requires_elevation
                    else "unavailable"
                )
        for key in current.keys() - self.connections.keys():
            self.sink.emit("network.opened", **current[key])
            self.traffic_emitted[key] = (
                int(current[key].get("bytes_sent") or 0),
                int(current[key].get("bytes_received") or 0),
                now,
            )
        for key in current.keys() & self.connections.keys():
            before = self.connections[key]
            after = current[key]
            if before["status"] != after["status"]:
                self.sink.emit(
                    "network.state_changed",
                    **after,
                    previous_status=before["status"],
                )
            if after.get("traffic_precision") == "exact_tcp_payload":
                sent = int(after.get("bytes_sent") or 0)
                received = int(after.get("bytes_received") or 0)
                previous_sent, previous_received, previous_time = self.traffic_emitted.get(
                    key, (0, 0, self.connection_started.get(key, now))
                )
                if sent - previous_sent >= 1024 * 1024 or received - previous_received >= 1024 * 1024:
                    interval = max(now - previous_time, 0.1)
                    after["recent_send_rate_bps"] = round(
                        max(sent - previous_sent, 0) / interval, 2
                    )
                    after["recent_receive_rate_bps"] = round(
                        max(received - previous_received, 0) / interval, 2
                    )
                    self.sink.emit("network.traffic", **after)
                    self.traffic_emitted[key] = (sent, received, now)
        for key in self.connections.keys() - current.keys():
            previous = self.connections[key]
            if previous.get("traffic_precision") == "exact_tcp_payload":
                sent = int(previous.get("bytes_sent") or 0)
                received = int(previous.get("bytes_received") or 0)
                emitted_sent, emitted_received, emitted_time = self.traffic_emitted.get(
                    key, (0, 0, self.connection_started.get(key, now))
                )
                if (sent, received) != (emitted_sent, emitted_received) and (sent or received):
                    interval = max(now - emitted_time, 0.1)
                    previous["recent_send_rate_bps"] = round(
                        max(sent - emitted_sent, 0) / interval, 2
                    )
                    previous["recent_receive_rate_bps"] = round(
                        max(received - emitted_received, 0) / interval, 2
                    )
                    self.sink.emit("network.traffic", **previous)
            self.sink.emit("network.closed", **previous)
            self.traffic_emitted.pop(key, None)
            self.connection_started.pop(key, None)
        self.connections = current

    def close(self) -> None:
        self.resolver.close()


class AgentMonitor:
    def __init__(
        self,
        root: Path,
        target_names: Iterable[str],
        explicit_pids: set[int],
        interval: float,
        file_interval: float,
        output: Path | None,
        capture_command_lines: bool,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.root = root
        self.target_names = list(target_names)
        self.explicit_pids = explicit_pids
        self.interval = interval
        self.file_interval = file_interval
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output = (output or root / ".agentguard" / "runs" / stamp).resolve()
        metadata = {
            "version": "0.1.0",
            "root": str(root),
            "started_at": utc_now(),
            "targets": self.target_names,
            "requested_pids": sorted(explicit_pids),
            "root_pids": [],
            "capture_command_lines": capture_command_lines,
            "mode": "observation-only",
            "current_thread_id": os.environ.get("CODEX_THREAD_ID"),
        }
        self.sink = EventSink(
            self.output,
            metadata,
            on_event=event_callback,
            risk_assessor=RiskAssessor(root),
            correlator=ActivityCorrelator(),
        )
        self.processes = ProcessTracker(
            self.sink,
            self.target_names,
            explicit_pids,
            capture_command_lines,
            root,
            os.environ.get("CODEX_THREAD_ID"),
        )
        self.files = FileTracker(
            root,
            self.sink,
            os.environ.get("CODEX_THREAD_ID"),
            lazy=True,
            max_files=DEFAULT_MAX_SNAPSHOT_FILES,
        )
        self.file_access = FileAccessTracker(root, self.sink)
        self.file_reads = EtwFileReadTracker(root, self.sink, track_workspace_reads=False)
        self.network = NetworkTracker(self.sink)
        self.registry_etw = RegistryEtwTracker(SystemChangeTracker.REGISTRY_TARGETS)
        self.system_changes = SystemChangeTracker(self.sink, registry_activity=self.registry_etw)
        self.resources = ResourceTracker(self.sink)
        self.clipboard = ClipboardMetadataTracker(self.sink)
        self.dns = DnsEtwTracker(self.sink)
        self.audit = WindowsAuditTracker(self.sink)

    def run(self, duration: float = 0, stop_event: threading.Event | None = None) -> int:
        started = time.monotonic()
        last_file_poll = started
        # ETW delivers file and registry events asynchronously.  The remaining
        # samplers do not need to run at the same rate as the UI; spreading them
        # out avoids repeatedly walking the process table, handles, and sockets.
        next_process_poll = started + max(self.interval, 1.5)
        next_network_poll = started + min(max(self.interval, 0.5), 1.0)
        # open_files() is the expensive fallback path; ETW remains the fast
        # path for reads/writes, so handle enumeration can be occasional.
        next_file_access_poll = started + 5.0
        next_system_poll = started + 2.0
        next_resource_poll = started + 2.0
        next_clipboard_poll = started + 2.0
        next_audit_poll = started + 2.0
        profile_enabled = os.environ.get("AGENTGUARD_PROFILE") == "1"
        profile_totals: Counter[str] = Counter()
        profile_counts: Counter[str] = Counter()
        last_profile = started

        def timed(label: str, callback: Callable[[], Any]) -> Any:
            if not profile_enabled:
                return callback()
            begin = time.perf_counter()
            value = callback()
            profile_totals[label] += time.perf_counter() - begin
            profile_counts[label] += 1
            return value
        effective_stop = stop_event or threading.Event()
        file_ready = threading.Event()
        relevant, sessions, attributions = self.processes.poll(initial=True)
        self.registry_etw.update_targets(relevant, attributions)
        self.file_reads.update_targets(
            relevant,
            sessions,
            attributions,
            {pid: str(info.get("name") or "") for pid, info in self.processes.seen.items()},
        )
        self.dns.update_targets(relevant, sessions, attributions)
        self.audit.update_targets(relevant, sessions, attributions)
        registry_events = self.registry_etw.start()
        self.system_changes.poll(force=True)
        self.audit.poll(force=True)
        self.sink.metadata["root_pids"] = sorted(self.processes.root_pids)
        self.sink.emit(
            "monitor.started",
            root=str(self.root),
            output=str(self.output),
            root_pids=sorted(self.processes.root_pids),
        )
        exact_file_io = self.file_reads.start()
        self.sink.emit(
            "monitor.capability",
            component="file_io",
            status=self.file_reads.status,
            exact=exact_file_io,
        )
        dns_events = self.dns.start()
        self.sink.emit(
            "monitor.capability",
            component="dns_targets",
            status=self.dns.status,
            exact=dns_events,
        )
        for component, status in (
            ("system_changes", "registry_services_tasks_metadata"),
            ("registry_writes", self.registry_etw.status),
            ("credential_access", "file_etw_sensitive_locations"),
            ("privilege_injection", "token_metadata_and_command_signals"),
            ("privacy_access", "command_signals_and_clipboard_sequence_only"),
            ("resource_anomalies", "process_resource_counters"),
            ("supply_chain", "process_and_lockfile_metadata"),
            ("process_memory_access", self.audit.status),
        ):
            self.sink.emit(
                "monitor.capability",
                component=component,
                status=status,
                exact=registry_events if component == "registry_writes" else False,
            )
        print(f"AgentGuard is observing: {self.root}")
        print(f"Agent roots: {sorted(self.processes.root_pids) or 'none detected yet'}")
        print(f"Events: {self.output / 'events.jsonl'}")
        print("Press Ctrl+C to stop.")

        def initialize_files() -> None:
            if self.files.initialize(effective_stop):
                file_ready.set()
                if self.files.disabled:
                    self.sink.emit(
                        "monitor.warning",
                        component="workspace_files",
                        message=f"工作区文件数超过 {self.files.max_files}，已切换为 Agent ETW 文件事件模式；未读取工作区文件内容",
                    )

        file_init_thread = threading.Thread(
            target=initialize_files,
            name="agentguard-file-baseline",
            daemon=True,
        )
        file_init_thread.start()
        try:
            while (
                (duration <= 0 or time.monotonic() - started < duration)
                and not effective_stop.is_set()
            ):
                now = time.monotonic()
                if now >= next_process_poll:
                    relevant, sessions, attributions = timed("process", self.processes.poll)
                    self.registry_etw.update_targets(relevant, attributions)
                    self.file_reads.update_targets(
                        relevant,
                        sessions,
                        attributions,
                        {pid: str(info.get("name") or "") for pid, info in self.processes.seen.items()},
                    )
                    self.dns.update_targets(relevant, sessions, attributions)
                    self.audit.update_targets(relevant, sessions, attributions)
                    next_process_poll = now + max(self.interval, 1.5)
                timed("file_etw_flush", self.file_reads.flush)
                if now >= next_file_access_poll:
                    timed("file_access", lambda: self.file_access.poll(relevant, sessions, attributions))
                    next_file_access_poll = now + 5.0
                if now >= next_network_poll:
                    timed("network", lambda: self.network.poll(relevant, sessions, attributions))
                    next_network_poll = now + min(max(self.interval, 0.5), 1.0)
                if now >= next_system_poll:
                    timed("system", self.system_changes.poll)
                    next_system_poll = now + 2.0
                if now >= next_resource_poll:
                    timed("resources", lambda: self.resources.poll(relevant, sessions, attributions))
                    next_resource_poll = now + 2.0
                if now >= next_clipboard_poll:
                    timed("clipboard", lambda: self.clipboard.poll(bool(relevant)))
                    next_clipboard_poll = now + 2.0
                if now >= next_audit_poll:
                    timed("audit", self.audit.poll)
                    next_audit_poll = now + 2.0
                if file_ready.is_set() and now - last_file_poll >= self.file_interval:
                    timed("workspace_scan", self.files.poll)
                    last_file_poll = now
                if profile_enabled and now - last_profile >= 10:
                    self.sink.emit(
                        "monitor.performance",
                        elapsed_seconds=round(now - last_profile, 3),
                        timings={key: round(value, 4) for key, value in profile_totals.items()},
                        calls=dict(profile_counts),
                    )
                    profile_totals.clear()
                    profile_counts.clear()
                    last_profile = now
                effective_stop.wait(min(max(self.interval, 0.1), 0.25))
        except KeyboardInterrupt:
            pass
        finally:
            effective_stop.set()
            if file_ready.is_set():
                self.files.poll()
            file_init_thread.join(timeout=1)
            self.file_reads.close()
            self.dns.close()
            self.network.close()
            self.registry_etw.close()
            self.sink.emit("monitor.stopped", elapsed_seconds=round(time.monotonic() - started, 3))
            self.sink.metadata["root_pids"] = sorted(self.processes.root_pids)
            self.sink.close()
            print(f"Observation complete: {self.output}")
        return 0
