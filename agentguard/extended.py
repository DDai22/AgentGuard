from __future__ import annotations

import ctypes
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import psutil


PACKAGE_PATTERN = re.compile(
    r"(?i)\b(?P<manager>npm|pnpm|yarn|bun|pip|pip3|uv|cargo|go|dotnet|gem|composer)"
    r"(?:\.exe)?\s+(?P<action>install|add|remove|uninstall|update|publish|get|require)\b"
)
PRIVILEGE_PATTERN = re.compile(
    r"(?i)\b(?:runas|psexec|schtasks\s+/create|sc(?:\.exe)?\s+create|"
    r"new-service|start-process\b[^\n]*-verb\s+runas|set-executionpolicy)\b"
)
INJECTION_PATTERN = re.compile(
    r"(?i)\b(?:mimikatz|procdump(?:\.exe)?\b[^\n]*\s-ma\b|"
    r"rundll32(?:\.exe)?\b[^\n]*comsvcs[^\n]*minidump|"
    r"create(?:remote)?thread|writeprocessmemory|virtualallocex|ntmapviewofsection)\b"
)
PRIVACY_PATTERN = re.compile(
    r"(?i)\b(?:get-clipboard|set-clipboard|clip(?:\.exe)?|snippingtool|"
    r"copyfromscreen|printwindow|windows\.graphics\.capture|"
    r"ffmpeg(?:\.exe)?\b[^\n]*(?:gdigrab|dshow)|"
    r"getusermedia|mediacapture|audiocapture)\b"
)
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
LOCKFILES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
    "uv.lock", "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum",
    "composer.lock", "gemfile.lock",
}
CLOUD_PATTERN = re.compile(
    r"(?i)(?:\b(?:aws|az|gcloud|kubectl|helm|terraform|pulumi|aliyun|oci)"
    r"(?:\.exe)?\s+(?P<action>apply|create|delete|destroy|update|patch|push|put|upload|deploy|run|exec|sync)\b|"
    r"\baws(?:\.exe)?\s+(?:s3|ec2|iam|lambda|cloudformation|sts)\s+"
    r"(?P<aws_action>cp|sync|put-object|create|delete|run|update)\b)"
)


def windows_process_security(pid: int) -> dict[str, Any]:
    """Return token metadata only; no token contents or privileges are retained."""

    if os.name != "nt":
        return {}
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(ctypes.c_ulong)
    process = kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        return {}
    token = ctypes.c_void_p()
    result: dict[str, Any] = {}
    try:
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            return {}
        elevation = ctypes.c_ulong()
        returned = ctypes.c_ulong()
        if advapi32.GetTokenInformation(
            token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(returned)
        ):
            result["elevated"] = bool(elevation.value)

        needed = ctypes.c_ulong()
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(needed))
        if needed.value:
            buffer = ctypes.create_string_buffer(needed.value)
            if advapi32.GetTokenInformation(
                token, 25, buffer, needed.value, ctypes.byref(needed)
            ):
                sid_ptr = ctypes.c_void_p.from_buffer(buffer).value
                count_ptr = advapi32.GetSidSubAuthorityCount(sid_ptr)
                if count_ptr:
                    count = count_ptr.contents.value
                    rid_ptr = advapi32.GetSidSubAuthority(sid_ptr, count - 1)
                    if rid_ptr:
                        rid = rid_ptr.contents.value
                        result["integrity_level"] = (
                            "system" if rid >= 0x4000 else "high" if rid >= 0x3000 else
                            "medium" if rid >= 0x2000 else "low"
                        )
    except (OSError, ValueError):
        return result
    finally:
        if token.value:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)
    try:
        result["username"] = psutil.Process(pid).username()
    except (psutil.Error, OSError):
        pass
    return result


class ActivityCorrelator:
    """Create low-volume derived events from existing metadata-only observations."""

    def __init__(self) -> None:
        self.file_events: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.process_starts: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.process_ends: dict[str, deque[tuple[float, str, float]]] = defaultdict(deque)
        self.last_alert: dict[tuple[str, str], float] = {}

    def _allow(self, session: str, rule: str, seconds: float = 60) -> bool:
        now = time.monotonic()
        key = (session, rule)
        if now - self.last_alert.get(key, -10_000) < seconds:
            return False
        self.last_alert[key] = now
        return True

    @staticmethod
    def _base(event: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "pid", "session_pid", "session_id", "thread_id", "agent_name", "attribution",
            "attribution_label", "attribution_confidence", "workspace_path",
        )
        return {key: event.get(key) for key in keys if event.get(key) is not None}

    def observe(self, event: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        kind = str(event.get("type") or "")
        if kind in {
            "behavior.detected", "supply_chain.operation", "privacy.access",
            "security.privilege", "resource.anomaly", "system.changed",
        }:
            return []
        derived: list[tuple[str, dict[str, Any]]] = []
        session = str(event.get("session_id") or event.get("session_pid") or "unknown")
        base = self._base(event)
        now = time.monotonic()

        if kind == "process.started":
            command = " ".join(str(item) for item in event.get("argv") or [])
            name = str(event.get("name") or "")
            text = f"{name} {command}".strip()
            starts = self.process_starts[session]
            starts.append((now, name.lower()))
            while starts and now - starts[0][0] > 10:
                starts.popleft()
            if len(starts) >= 20 and self._allow(session, "process_burst"):
                derived.append(("resource.anomaly", {
                    **base, "anomaly": "process_burst", "count": len(starts),
                    "needs_review": True, "risk_score": 72,
                    "reasons": ["同一会话 10 秒内启动了大量子进程"],
                }))
            package = PACKAGE_PATTERN.search(text)
            if package:
                custom_source = bool(re.search(r"(?i)--(?:registry|index-url|extra-index-url)\b|git\+https?://", text))
                publish = package.group("action").lower() == "publish"
                derived.append(("supply_chain.operation", {
                    **base, "manager": package.group("manager"), "action": package.group("action"),
                    "name": name, "command_summary": text[:400],
                    "needs_review": publish or custom_source,
                    "risk_score": 72 if publish or custom_source else 12,
                    "reasons": [
                        "向软件仓库发布或使用自定义依赖源" if publish or custom_source
                        else "软件依赖发生变化；未发现自定义来源或发布操作"
                    ],
                }))
            cloud = CLOUD_PATTERN.search(text)
            if cloud:
                cloud_action = cloud.group("action") or cloud.group("aws_action") or "operation"
                derived.append(("supply_chain.operation", {
                    **base, "manager": "cloud_control_plane", "action": cloud_action,
                    "name": name, "command_summary": text[:400], "needs_review": True,
                    "risk_score": 78,
                    "reasons": ["命令可能修改云端、集群或基础设施状态"],
                }))
            if PRIVILEGE_PATTERN.search(text) or event.get("elevated"):
                inherited_high = event.get("elevated") and event.get("integrity_level") in {"high", "system"}
                derived.append(("security.privilege", {
                    **base, "name": name, "integrity_level": event.get("integrity_level"),
                    "elevated": event.get("elevated"), "command_summary": text[:400],
                    "needs_review": bool(PRIVILEGE_PATTERN.search(text)),
                    "risk_score": 76 if PRIVILEGE_PATTERN.search(text) else 18,
                    "reasons": [
                        "命令包含提权、服务或计划任务创建线索" if PRIVILEGE_PATTERN.search(text)
                        else "进程使用高完整性令牌启动"
                    ],
                }))
            if INJECTION_PATTERN.search(text):
                derived.append(("security.privilege", {
                    **base, "name": name, "command_summary": text[:400],
                    "operation": "process_memory_or_injection", "needs_review": True,
                    "risk_score": 94,
                    "reasons": ["发现进程内存读取、转储或代码注入工具特征"],
                }))
            privacy = PRIVACY_PATTERN.search(text)
            if privacy:
                derived.append(("privacy.access", {
                    **base, "name": name, "signal": privacy.group(0),
                    "command_summary": text[:400], "needs_review": True,
                    "risk_score": 78,
                    "reasons": ["命令包含剪贴板、屏幕、摄像头或麦克风访问线索"],
                }))

        if kind == "process.ended":
            name = str(event.get("name") or "").lower()
            created = float(event.get("create_time") or 0)
            runtime = max(time.time() - created, 0) if created else 0
            endings = self.process_ends[session]
            endings.append((now, name, runtime))
            while endings and now - endings[0][0] > 60:
                endings.popleft()
            rapid_same = [item for item in endings if item[1] == name and 0 < item[2] < 30]
            if len(rapid_same) >= 10 and self._allow(session, f"rapid_restart:{name}"):
                derived.append(("resource.anomaly", {
                    **base, "anomaly": "rapid_process_restarts", "name": name,
                    "count": len(rapid_same), "window_seconds": 60,
                    "needs_review": True, "risk_score": 64,
                    "reasons": ["同一短生命周期进程在一分钟内反复启动和结束"],
                }))

        if kind.startswith("file.") and kind not in {"file.accessed", "file.read"}:
            action = kind.removeprefix("file.")
            path = str(event.get("path") or "")
            queue = self.file_events[session]
            queue.append((now, action, path))
            while queue and now - queue[0][0] > 30:
                queue.popleft()
            counts = Counter(item[1] for item in queue)
            deleted = counts["deleted"]
            renamed = counts["renamed"]
            modified = counts["modified"]
            created = counts["created"]
            destructive = deleted >= 5 or renamed >= 5
            bulk = len(queue) >= 5 or modified >= 5 or created >= 5
            if destructive and self._allow(session, "destructive_files"):
                derived.append(("behavior.detected", {
                    **base, "behavior": "destructive_files", "category": "文件行为",
                    "count": len(queue), "deleted": deleted, "renamed": renamed,
                    "window_seconds": 30, "needs_review": True, "risk_score": 93,
                    "reasons": [f"30 秒内删除 {deleted} 个文件、重命名 {renamed} 个文件，可能造成数据破坏"],
                }))
            elif bulk and self._allow(session, "bulk_files"):
                derived.append(("behavior.detected", {
                    **base, "behavior": "bulk_files", "category": "文件行为",
                    "count": len(queue), "modified": modified, "created": created,
                    "window_seconds": 30, "needs_review": True, "risk_score": 78,
                    "reasons": [f"30 秒内新增 {created} 个、修改 {modified} 个文件，属于批量文件行为"],
                }))
            if Path(path).suffix.lower() in ARCHIVE_SUFFIXES and self._allow(session, f"archive:{path}", 10):
                derived.append(("behavior.detected", {
                    **base, "behavior": "archive_created", "category": "文件行为",
                    "path": path, "needs_review": False, "risk_score": 15,
                    "reasons": ["创建或修改了压缩归档文件；将与后续公网发送关联分析"],
                }))
            if Path(path).name.lower() in LOCKFILES and action in {"created", "modified"}:
                derived.append(("supply_chain.operation", {
                    **base, "manager": "lockfile", "action": action, "path": path,
                    "needs_review": False, "risk_score": 8,
                    "reasons": ["依赖锁文件发生变化"],
                }))
        return derived


class RegistryEtwTracker:
    """Attribute writes to monitored registry keys without collecting values."""

    PROVIDER_GUID = "{70eb4f03-c1de-4f73-a051-33d13d5413bd}"
    # Kernel-Registry event ids for mutating operations. Query/open events are
    # deliberately excluded so a read of the certificate store is not a write.
    WRITE_EVENT_IDS = {1, 3, 6, 7, 9, 10, 15}

    def __init__(self, targets: tuple[tuple[str, str, str, int], ...]) -> None:
        self.targets = targets
        self.lock = threading.Lock()
        self.session: Any = None
        self.status = "not_started"
        self.agent_pids: set[int] = set()
        self.attributions: dict[int, dict[str, Any]] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=256)

    def update_targets(self, pids: set[int], attributions: dict[int, dict[str, Any]]) -> None:
        with self.lock:
            self.agent_pids = set(pids)
            self.attributions = {pid: dict(value) for pid, value in attributions.items()}

    @staticmethod
    def _field(data: dict[str, Any], *names: str) -> str:
        lowered = {str(key).lower(): value for key, value in data.items()}
        for name in names:
            value = lowered.get(name.lower())
            if value not in (None, ""):
                return str(value)
        return ""

    @classmethod
    def _registry_path(cls, data: dict[str, Any]) -> str:
        value = cls._field(data, "KeyName", "ObjectName", "RegistryPath", "Path", "Key")
        return value.replace("/", "\\").strip().upper()

    @classmethod
    def _target_for_path(cls, path: str, targets: tuple[tuple[str, str, str, int], ...]) -> str | None:
        if not path:
            return None
        for root, key, _, _ in targets:
            if path.startswith("\\REGISTRY\\MACHINE\\") and root != "HKLM":
                continue
            if path.startswith("\\REGISTRY\\USER\\") and root != "HKCU":
                continue
            if path.startswith("HKLM\\") and root != "HKLM":
                continue
            if path.startswith("HKCU\\") and root != "HKCU":
                continue
            target = f"{root}\\{key}".upper()
            suffix = f"\\{key}".upper()
            if path == target or path.endswith(suffix):
                return target
        return None

    @classmethod
    def _is_write(cls, event_id: int, data: dict[str, Any]) -> bool:
        operation = cls._field(data, "EventName", "Operation", "OpcodeName", "Action", "TaskName").lower()
        if operation:
            return any(token in operation for token in ("setvalue", "deletevalue", "createkey", "deletekey", "renamekey", "setinformation", "flushkey", "virtualize"))
        return event_id in cls.WRITE_EVENT_IDS

    def start(self) -> bool:
        if os.name != "nt":
            self.status = "windows_only"
            return False
        try:
            import etw
            provider = etw.ProviderInfo(
                "Microsoft-Windows-Kernel-Registry",
                etw.GUID(self.PROVIDER_GUID),
                level=5,
            )
            self.session = etw.ETW(providers=[provider], event_callback=self._on_event)
            self.session.start()
            self.status = "registry_write_etw"
            return True
        except Exception as exc:
            self.session = None
            self.status = f"unavailable:{type(exc).__name__}"
            return False

    def _on_event(self, item: tuple[int, dict[str, Any]]) -> None:
        event_id, data = item
        if not self._is_write(int(event_id), data):
            return
        path = self._registry_path(data)
        with self.lock:
            targets = self.targets
        target = self._target_for_path(path, targets)
        if target is None:
            return
        header = data.get("EventHeader") or {}
        try:
            pid = int(header.get("ProcessId"))
        except (TypeError, ValueError):
            return
        with self.lock:
            attribution = dict(self.attributions.get(pid) or {})
            agent_pid = pid in self.agent_pids
        if not agent_pid:
            attribution = {
                "attribution": "external_process",
                "attribution_label": f"其他进程·PID {pid}",
                "attribution_confidence": "high",
            }
        self.recent.append({
            "monotonic": time.monotonic(),
            "target": target,
            "pid": pid,
            "operation": self._field(data, "EventName", "Operation", "OpcodeName", "Action", "TaskName") or f"event_{event_id}",
            "attribution": attribution,
        })

    def match(self, key: str, max_age: float = 8.0) -> dict[str, Any] | None:
        target = str(key or "").replace("/", "\\").upper()
        now = time.monotonic()
        for record in reversed(self.recent):
            if now - float(record["monotonic"]) > max_age:
                break
            if record["target"] == target:
                return dict(record)
        return None

    def close(self) -> None:
        session, self.session = self.session, None
        if session is None:
            return
        try:
            if session.consumer is not None:
                session.consumer.stop()
            if session.provider is not None:
                session.provider.stop()
            session.running = False
        except Exception:
            pass


class SystemChangeTracker:
    """Poll high-value Windows configuration metadata without retaining values."""

    REGISTRY_TARGETS = (
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "启动项", 82),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "启动项", 82),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "启动项", 86),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "启动项", 86),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "系统代理", 72),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy", "防火墙", 78),
        ("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Exclusions", "安全排除项", 92),
        ("HKCU", r"Software\Microsoft\SystemCertificates", "用户证书", 74),
        ("HKLM", r"SOFTWARE\Microsoft\SystemCertificates", "系统证书", 82),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore", "隐私权限", 72),
    )

    def __init__(self, sink: Any, interval: float = 5.0, registry_activity: RegistryEtwTracker | None = None) -> None:
        self.sink = sink
        self.interval = interval
        self.registry_activity = registry_activity
        self.last_poll = 0.0
        self.registry: dict[str, tuple[int, tuple[str, ...], tuple[tuple[str, int], ...]]] = {}
        self.files: dict[str, tuple[int, int]] = {}
        self.tasks: dict[str, tuple[int, int]] = {}
        self.services: dict[str, tuple[Any, ...]] = {}
        self.initialized = False

    @staticmethod
    def _registry_snapshot() -> dict[str, tuple[int, tuple[str, ...], tuple[tuple[str, int], ...]]]:
        if os.name != "nt":
            return {}
        import winreg

        roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        result = {}
        for root_name, path, _, _ in SystemChangeTracker.REGISTRY_TARGETS:
            key_name = f"{root_name}\\{path}"
            try:
                with winreg.OpenKey(roots[root_name], path, 0, winreg.KEY_READ) as key:
                    sub_count, value_count, last_write = winreg.QueryInfoKey(key)
                    subkeys = []
                    for index in range(min(sub_count, 500)):
                        try:
                            child_name = winreg.EnumKey(key, index)
                            child_stamp = 0
                            grandchildren: list[str] = []
                            try:
                                with winreg.OpenKey(key, child_name, 0, winreg.KEY_READ) as child:
                                    child_count, _, child_stamp = winreg.QueryInfoKey(child)
                                    for child_index in range(min(child_count, 200)):
                                        try:
                                            grand_name = winreg.EnumKey(child, child_index)
                                            grand_stamp = 0
                                            try:
                                                with winreg.OpenKey(child, grand_name, 0, winreg.KEY_READ) as grand:
                                                    _, _, grand_stamp = winreg.QueryInfoKey(grand)
                                            except OSError:
                                                pass
                                            grandchildren.append(f"{grand_name}@{grand_stamp}")
                                        except OSError:
                                            break
                            except OSError:
                                pass
                            subkeys.append(f"{child_name}@{child_stamp}[{'|'.join(grandchildren)}]")
                        except OSError:
                            break
                    # Value data and names can themselves contain secrets. Keep only the count.
                    values = [("value_count", int(value_count))]
                    result[key_name] = (int(last_write), tuple(sorted(subkeys)), tuple(sorted(values)))
            except OSError:
                result[key_name] = (0, (), ())
        return result

    @staticmethod
    def _file_snapshot() -> dict[str, tuple[int, int]]:
        paths = [Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"]
        result = {}
        for path in paths:
            try:
                stat = path.stat()
                result[str(path)] = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                result[str(path)] = (0, 0)
        return result

    @staticmethod
    def _task_snapshot() -> dict[str, tuple[int, int]]:
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        result = {}
        try:
            for current, _, files in os.walk(root):
                for name in files:
                    path = Path(current) / name
                    try:
                        stat = path.stat()
                        result[str(path.relative_to(root))] = (stat.st_mtime_ns, stat.st_size)
                    except OSError:
                        continue
        except OSError:
            pass
        return result

    @staticmethod
    def _service_snapshot() -> dict[str, tuple[Any, ...]]:
        if os.name != "nt":
            return {}
        result = {}
        try:
            for service in psutil.win_service_iter():
                try:
                    data = service.as_dict()
                    result[str(data.get("name"))] = (
                        data.get("status"), data.get("start_type"), data.get("binpath"), data.get("username")
                    )
                except (psutil.Error, OSError):
                    continue
        except (AttributeError, psutil.Error, OSError):
            pass
        return result

    def _emit(self, **data: Any) -> None:
        if data.get("action") == "registry_metadata_changed":
            original_score = int(data.get("risk_score") or 0)
            original_reasons = list(data.get("reasons") or [])
            context = self.registry_activity.match(str(data.get("path") or "")) if self.registry_activity else None
            attribution = "system"
            label = "系统范围·进程未确认"
            confidence = "low"
            needs_review = False
            score = 0
            if context:
                context_attribution = context.get("attribution") or {}
                relation = context_attribution.get("attribution")
                attribution = relation or "external_process"
                label = str(context_attribution.get("attribution_label") or label)
                confidence = str(context_attribution.get("attribution_confidence") or "low")
                if relation in {"current_thread", "current_workspace", "shared"}:
                    needs_review = True
                    score = original_score
                    data["pid"] = context.get("pid")
                    data["registry_write_operation"] = context.get("operation")
                    original_reasons.append(
                        f"ETW 已确认进程 PID {context.get('pid')} 写入该注册表范围"
                    )
                elif relation == "other_thread":
                    data["pid"] = context.get("pid")
                    data["registry_write_operation"] = context.get("operation")
                    original_reasons.append("写入来自其他 Agent 会话，不计入当前会话风险")
                elif relation == "other_workspace":
                    data["pid"] = context.get("pid")
                    data["registry_write_operation"] = context.get("operation")
                    original_reasons.append("写入来自其他工作区进程，不计入当前会话风险")
                else:
                    data["pid"] = context.get("pid")
                    data["registry_write_operation"] = context.get("operation")
                    original_reasons.append("写入来自非 Agent 进程，仅记录不升级风险")
            else:
                original_reasons.append("未捕获到可归属的注册表写入事件，仅记录不升级风险")
            data.update(
                attribution=attribution,
                attribution_label=label,
                attribution_confidence=confidence,
                needs_review=needs_review,
                risk_score=score,
                reasons=list(dict.fromkeys(original_reasons)),
            )
        else:
            data.setdefault("attribution", "system")
            data.setdefault("attribution_label", "系统范围·进程未确认")
            data.setdefault("attribution_confidence", "low")
            data.setdefault("needs_review", True)
        self.sink.emit(
            "system.changed", **data,
        )

    def poll(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_poll < self.interval:
            return
        self.last_poll = now
        registry = self._registry_snapshot()
        files = self._file_snapshot()
        tasks = self._task_snapshot()
        services = self._service_snapshot()
        if not self.initialized:
            self.registry, self.files, self.tasks, self.services = registry, files, tasks, services
            self.initialized = True
            return
        target_meta = {f"{root}\\{path}": (component, score) for root, path, component, score in self.REGISTRY_TARGETS}
        for key in set(registry) | set(self.registry):
            if registry.get(key) != self.registry.get(key):
                component, score = target_meta.get(key, ("注册表", 75))
                self._emit(component=component, action="registry_metadata_changed", path=key,
                           risk_score=score, reasons=[f"{component}注册表元数据发生变化；未读取或保存配置值"])
        for path in set(files) | set(self.files):
            if files.get(path) != self.files.get(path):
                self._emit(component="hosts", action="file_metadata_changed", path=path,
                           risk_score=84, reasons=["系统 hosts 文件发生变化"])
        for name in set(tasks) | set(self.tasks):
            if tasks.get(name) != self.tasks.get(name):
                action = "created" if name not in self.tasks else "deleted" if name not in tasks else "modified"
                self._emit(component="计划任务", action=action, path=name, risk_score=82,
                           reasons=[f"计划任务被{ {'created':'创建','deleted':'删除','modified':'修改'}[action] }"])
        for name in set(services) | set(self.services):
            if services.get(name) != self.services.get(name):
                action = "created" if name not in self.services else "deleted" if name not in services else "configuration_changed"
                before, after = self.services.get(name), services.get(name)
                status_only = before and after and before[1:] == after[1:]
                self.sink.emit(
                    "system.changed", component="服务", action=action, name=name,
                    before_status=before[0] if before else None, after_status=after[0] if after else None,
                    attribution="system", attribution_label="系统范围·进程未确认", attribution_confidence="low",
                    needs_review=not status_only, risk_score=76 if not status_only else 18,
                    reasons=["Windows 服务配置发生变化" if not status_only else "Windows 服务运行状态发生变化"],
                )
        self.registry, self.files, self.tasks, self.services = registry, files, tasks, services


class ResourceTracker:
    def __init__(self, sink: Any) -> None:
        self.sink = sink
        self.previous: dict[int, tuple[float, int, int, int]] = {}
        self.cpu_since: dict[int, float] = {}
        self.cooldown: dict[tuple[int, str], float] = {}

    def _emit(self, pid: int, kind: str, score: int, reason: str, data: dict[str, Any]) -> None:
        now = time.monotonic()
        key = (pid, kind)
        if now - self.cooldown.get(key, -10_000) < 60:
            return
        self.cooldown[key] = now
        self.sink.emit("resource.anomaly", pid=pid, anomaly=kind, needs_review=True,
                       risk_score=score, reasons=[reason], **data)

    def poll(self, pids: set[int], sessions: dict[int, int], attributions: dict[int, dict[str, Any]]) -> None:
        now = time.monotonic()
        for pid in pids:
            try:
                process = psutil.Process(pid)
                cpu = process.cpu_percent(None)
                memory = process.memory_info().rss
                io = process.io_counters()
            except (psutil.Error, OSError):
                continue
            base = {"session_pid": sessions.get(pid), **attributions.get(pid, {})}
            previous = self.previous.get(pid)
            if cpu >= 85:
                self.cpu_since.setdefault(pid, now)
                if now - self.cpu_since[pid] >= 20:
                    self._emit(pid, "sustained_cpu", 58, "进程持续高 CPU 使用", {**base, "cpu_percent": round(cpu, 1)})
            else:
                self.cpu_since.pop(pid, None)
            if memory >= 2 * 1024**3:
                self._emit(pid, "high_memory", 62, "进程内存占用超过 2 GB", {**base, "memory_bytes": memory})
            if previous:
                elapsed = max(now - previous[0], 0.1)
                read_rate = max(int(io.read_bytes) - previous[2], 0) / elapsed
                write_rate = max(int(io.write_bytes) - previous[3], 0) / elapsed
                if max(read_rate, write_rate) >= 200 * 1024**2:
                    self._emit(pid, "disk_io_burst", 66, "进程出现异常高速磁盘读写",
                               {
                                   **base,
                                   "disk_read_bytes": int(io.read_bytes),
                                   "disk_write_bytes": int(io.write_bytes),
                                   "disk_read_rate_bps": round(read_rate),
                                   "disk_write_rate_bps": round(write_rate),
                                   "disk_observed_seconds": round(elapsed, 2),
                                   "disk_io_observation": "Windows 进程 IO 计数器；进程级汇总，不读取内容",
                               })
                if memory - previous[1] >= 1024**3 and elapsed <= 60:
                    self._emit(pid, "memory_growth", 68, "进程内存短时间增长超过 1 GB",
                               {**base, "memory_bytes": memory, "memory_growth_bytes": memory - previous[1]})
            self.previous[pid] = (now, memory, int(io.read_bytes), int(io.write_bytes))
        for pid in set(self.previous) - pids:
            self.previous.pop(pid, None)
            self.cpu_since.pop(pid, None)


class ClipboardMetadataTracker:
    """Observe clipboard sequence changes only; never opens the clipboard."""

    def __init__(self, sink: Any) -> None:
        self.sink = sink
        self.sequence = None

    def poll(self, agent_active: bool) -> None:
        if os.name != "nt":
            return
        try:
            value = int(ctypes.windll.user32.GetClipboardSequenceNumber())
        except (AttributeError, OSError):
            return
        if self.sequence is None:
            self.sequence = value
            return
        if value != self.sequence:
            self.sequence = value
            self.sink.emit(
                "privacy.clipboard_changed", sequence_number=value,
                agent_active=agent_active, attribution="unknown",
                attribution_label="无法归因到具体进程", attribution_confidence="low",
            )


class WindowsAuditTracker:
    """Consume optional Sysmon process-access events; retain no call stacks or payloads."""

    CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(self, sink: Any, interval: float = 3.0) -> None:
        self.sink = sink
        self.interval = interval
        self.last_poll = 0.0
        self.last_record = 0
        self.status = "not_started"
        self.targets: set[int] = set()
        self.sessions: dict[int, int] = {}
        self.attributions: dict[int, dict[str, Any]] = {}

    def update_targets(self, pids: set[int], sessions: dict[int, int], attributions: dict[int, dict[str, Any]]) -> None:
        self.targets, self.sessions = set(pids), dict(sessions)
        self.attributions = {pid: dict(value) for pid, value in attributions.items()}

    @staticmethod
    def _parse(xml: str) -> tuple[int, int, dict[str, str]]:
        root = ET.fromstring(xml)
        namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        event_id = int(root.findtext("e:System/e:EventID", default="0", namespaces=namespace))
        record_id = int(root.findtext("e:System/e:EventRecordID", default="0", namespaces=namespace))
        fields = {}
        for node in root.findall("e:EventData/e:Data", namespace):
            name = node.attrib.get("Name")
            if name:
                fields[name] = node.text or ""
        return event_id, record_id, fields

    def _read(self) -> list[tuple[int, int, dict[str, str]]]:
        try:
            import pywintypes
            import win32evtlog
        except ImportError:
            self.status = "pywin32_unavailable"
            return []
        query = "*[System[(EventID=8 or EventID=10)]]"
        handle = None
        events = []
        try:
            handle = win32evtlog.EvtQuery(
                self.CHANNEL,
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                query,
            )
            raw_events = win32evtlog.EvtNext(handle, 128, 0, 0)
            for raw in raw_events:
                try:
                    parsed = self._parse(win32evtlog.EvtRender(raw, win32evtlog.EvtRenderEventXml))
                    if parsed[1] > self.last_record:
                        events.append(parsed)
                finally:
                    win32evtlog.EvtClose(raw)
            self.status = "sysmon_process_access" if raw_events is not None else "sysmon_no_events"
        except pywintypes.error as exc:
            self.status = "sysmon_not_installed" if getattr(exc, "winerror", 0) in {2, 3, 15007} else f"sysmon_unavailable:{getattr(exc, 'winerror', 'error')}"
        finally:
            if handle is not None:
                try:
                    win32evtlog.EvtClose(handle)
                except Exception:
                    pass
        return sorted(events, key=lambda item: item[1])

    @staticmethod
    def _pid(value: str | None) -> int | None:
        try:
            return int(str(value or "0"), 0)
        except ValueError:
            return None

    def poll(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_poll < self.interval:
            return
        self.last_poll = now
        events = self._read()
        if not events:
            return
        if self.last_record == 0:
            self.last_record = max(record for _, record, _ in events)
            return
        for event_id, record_id, fields in events:
            self.last_record = max(self.last_record, record_id)
            source_pid = self._pid(fields.get("SourceProcessId"))
            if source_pid not in self.targets:
                continue
            target_pid = self._pid(fields.get("TargetProcessId"))
            remote_thread = event_id == 8
            self.sink.emit(
                "security.process_access", pid=source_pid, target_pid=target_pid,
                operation="create_remote_thread" if remote_thread else "open_process",
                granted_access=fields.get("GrantedAccess"), record_id=record_id,
                session_pid=self.sessions.get(source_pid), **self.attributions.get(source_pid, {}),
            )


class DnsEtwTracker:
    PROVIDER_GUID = "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"
    SCHANNEL_GUID = "{1f678132-5938-4686-9fdc-c8ff68f15c85}"

    def __init__(self, sink: Any) -> None:
        self.sink = sink
        self.session: Any = None
        self.status = "not_started"
        self.lock = threading.Lock()
        self.targets: set[int] = set()
        self.sessions: dict[int, int] = {}
        self.attributions: dict[int, dict[str, Any]] = {}
        self.recent: dict[tuple[int, str], float] = {}

    def update_targets(self, pids: set[int], sessions: dict[int, int], attributions: dict[int, dict[str, Any]]) -> None:
        with self.lock:
            self.targets, self.sessions = set(pids), dict(sessions)
            self.attributions = {pid: dict(value) for pid, value in attributions.items()}

    def start(self) -> bool:
        if os.name != "nt":
            self.status = "windows_only"
            return False
        try:
            import etw
            providers = [
                etw.ProviderInfo("Microsoft-Windows-DNS-Client", etw.GUID(self.PROVIDER_GUID), level=5),
                etw.ProviderInfo("Microsoft-Windows-Schannel", etw.GUID(self.SCHANNEL_GUID), level=5),
            ]
            self.session = etw.ETW(providers=providers, event_callback=self._on_event)
            self.session.start()
            self.status = "dns_and_schannel_etw"
            return True
        except Exception as exc:
            self.session = None
            self.status = f"unavailable:{type(exc).__name__}"
            return False

    def _on_event(self, item: tuple[int, dict[str, Any]]) -> None:
        event_id, data = item
        header = data.get("EventHeader") or {}
        try:
            pid = int(header.get("ProcessId"))
        except (TypeError, ValueError):
            return
        provider_id = str(header.get("ProviderId") or "").lower()
        is_schannel = self.SCHANNEL_GUID.strip("{}").lower() in provider_id
        fields = ("TargetName", "ServerName", "SniName", "HostName") if is_schannel else ("QueryName", "Name", "HostName")
        target = next((str(data.get(key)) for key in fields if data.get(key)), "")
        if not target or len(target) > 512:
            return
        now = time.monotonic()
        with self.lock:
            if pid not in self.targets:
                return
            key = (pid, ("tls:" if is_schannel else "dns:") + target.lower())
            if now - self.recent.get(key, -10_000) < 5:
                return
            self.recent[key] = now
            attribution = self.attributions.get(pid, {})
            session_pid = self.sessions.get(pid)
        if is_schannel:
            self.sink.emit(
                "network.tls", pid=pid, session_pid=session_pid, target_name=target,
                protocol=data.get("Protocol") or data.get("ProtocolName"),
                cipher=data.get("CipherSuite") or data.get("CipherAlgorithm"),
                certificate_subject=data.get("SubjectName") or data.get("CertificateSubject"),
                certificate_thumbprint=data.get("Thumbprint"), event_id=event_id,
                hostname_source="schannel_etw", **attribution,
            )
        else:
            self.sink.emit(
                "network.dns", pid=pid, session_pid=session_pid, query_name=target,
                query_type=data.get("QueryType"), status=data.get("Status"),
                event_id=event_id, hostname_source="dns_client_etw", **attribution,
            )

    def close(self) -> None:
        session, self.session = self.session, None
        if session is None:
            return
        try:
            if session.consumer is not None:
                session.consumer.stop()
            if session.provider is not None:
                session.provider.stop()
            session.running = False
        except Exception:
            pass
