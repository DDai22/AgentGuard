from __future__ import annotations

import concurrent.futures
import ctypes
import os
import socket
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import psutil


SENSITIVE_EXTERNAL_PARTS = {
    ".ssh",
    ".aws",
    ".azure",
    ".kube",
    "gcloud",
    "credentials",
    "secrets",
    "vault",
    "protect",
}
SENSITIVE_EXTERNAL_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service_account.json",
    ".git-credentials",
    "login data",
    "cookies",
    "web data",
    "local state",
    "key4.db",
    "logins.json",
    "signons.sqlite",
    "wallet.dat",
}
SENSITIVE_EXTERNAL_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}


def classify_observed_file(
    root: Path,
    raw_path: str,
    attribution: dict[str, Any] | None = None,
    *,
    include_external: bool = False,
) -> tuple[str, str, bool] | None:
    """Classify a path without opening it or inspecting its contents."""

    root = root.resolve()
    try:
        path = Path(raw_path).resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    try:
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".agentguard":
            return None
        return relative.as_posix(), "workspace", False
    except ValueError:
        lowered_parts = {part.lower() for part in path.parts}
        name = path.name.lower()
        sensitive = (
            bool(lowered_parts & SENSITIVE_EXTERNAL_PARTS)
            or name in SENSITIVE_EXTERNAL_NAMES
            or path.suffix.lower() in SENSITIVE_EXTERNAL_SUFFIXES
            or name.startswith(".env.")
        )
        workspace_path = (attribution or {}).get("workspace_path")
        relation = str((attribution or {}).get("attribution") or "")
        if workspace_path and relation in {"other_thread", "other_workspace"}:
            try:
                path.relative_to(Path(str(workspace_path)).resolve(strict=False))
                return str(path), "other_session", sensitive
            except (ValueError, OSError, RuntimeError):
                pass
        if not sensitive and not include_external:
            return None
        return str(path), "external", sensitive


class FileAccessTracker:
    """Best-effort open-handle observation without reading file contents."""

    def __init__(self, root: Path, sink: Any) -> None:
        self.root = root.resolve()
        self.sink = sink
        self.open_handles: set[tuple[int, str]] = set()

    def _classify(
        self, raw_path: str, attribution: dict[str, Any] | None = None
    ) -> tuple[str, str, bool] | None:
        return classify_observed_file(self.root, raw_path, attribution)

    def poll(
        self,
        pids: set[int],
        sessions: dict[int, int],
        attributions: dict[int, dict[str, Any]],
    ) -> None:
        current: set[tuple[int, str]] = set()
        details: dict[tuple[int, str], dict[str, Any]] = {}
        for pid in pids:
            try:
                process = psutil.Process(pid)
                name = process.name()
                files = process.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            for opened in files:
                attribution = attributions.get(pid, {})
                classified = self._classify(opened.path, attribution)
                if classified is None:
                    continue
                display_path, scope, sensitive = classified
                key = (pid, os.path.normcase(str(Path(opened.path))))
                current.add(key)
                if key not in self.open_handles:
                    try:
                        size = Path(opened.path).stat().st_size
                    except (OSError, ValueError):
                        size = None
                    details[key] = {
                        "pid": pid,
                        "session_pid": sessions.get(pid),
                        "name": name,
                        "path": display_path,
                        "scope": scope,
                        "sensitive": sensitive,
                        "size": size,
                        "observation": "open_handle",
                        **attribution,
                    }
        for key in current - self.open_handles:
            if key in details:
                self.sink.emit("file.accessed", **details[key])
        self.open_handles = current


class ReverseDnsResolver:
    """Asynchronous PTR lookup; this is a hostname clue, not the requested URL."""

    def __init__(self) -> None:
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="agentguard-rdns"
        )
        self.futures: dict[str, concurrent.futures.Future[str | None]] = {}
        self.cache: dict[str, str | None] = {}

    @staticmethod
    def _resolve(host: str) -> str | None:
        try:
            value = socket.gethostbyaddr(host)[0].rstrip(".")
            return value if value and value != host else None
        except (OSError, socket.herror, socket.gaierror):
            return None

    def request(self, host: str) -> str | None:
        if host in self.cache:
            return self.cache[host]
        future = self.futures.get(host)
        if future is None:
            self.futures[host] = self.executor.submit(self._resolve, host)
            return None
        if future.done():
            try:
                self.cache[host] = future.result()
            except Exception:
                self.cache[host] = None
            self.futures.pop(host, None)
            return self.cache[host]
        return None

    def close(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)


class _MibTcpRow(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("local_address", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_address", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
    ]


class _TcpEstatsData(ctypes.Structure):
    _fields_ = [
        ("data_bytes_out", ctypes.c_ulonglong),
        ("data_segs_out", ctypes.c_ulonglong),
        ("data_bytes_in", ctypes.c_ulonglong),
        ("data_segs_in", ctypes.c_ulonglong),
        ("segs_out", ctypes.c_ulonglong),
        ("segs_in", ctypes.c_ulonglong),
        ("soft_errors", wintypes.DWORD),
        ("soft_error_reason", wintypes.DWORD),
        ("snd_una", wintypes.DWORD),
        ("snd_nxt", wintypes.DWORD),
        ("snd_max", wintypes.DWORD),
        ("thru_bytes_acked", ctypes.c_ulonglong),
        ("rcv_nxt", wintypes.DWORD),
        ("thru_bytes_received", ctypes.c_ulonglong),
    ]


TCP_STATES = {
    "CLOSED": 1,
    "SYN_SENT": 3,
    "SYN_RECV": 4,
    "ESTABLISHED": 5,
    "FIN_WAIT1": 6,
    "FIN_WAIT2": 7,
    "CLOSE_WAIT": 8,
    "CLOSING": 9,
    "LAST_ACK": 10,
    "TIME_WAIT": 11,
}


class TcpTrafficSampler:
    """Exact IPv4 TCP payload counters when Windows EStats can be enabled."""

    def __init__(self) -> None:
        self.supported = os.name == "nt"
        self.requires_elevation = False
        self._dll = ctypes.WinDLL("iphlpapi") if self.supported else None
        self._enabled: set[tuple[Any, ...]] = set()

    @staticmethod
    def _row(connection: Any) -> _MibTcpRow | None:
        if (
            not connection.laddr
            or not connection.raddr
            or ":" in connection.laddr.ip
            or connection.status not in TCP_STATES
        ):
            return None
        return _MibTcpRow(
            TCP_STATES[connection.status],
            int.from_bytes(socket.inet_aton(connection.laddr.ip), "little"),
            socket.htons(connection.laddr.port),
            int.from_bytes(socket.inet_aton(connection.raddr.ip), "little"),
            socket.htons(connection.raddr.port),
        )

    @staticmethod
    def _key(connection: Any) -> tuple[Any, ...]:
        return (
            connection.laddr.ip,
            connection.laddr.port,
            connection.raddr.ip,
            connection.raddr.port,
        )

    def sample(self, connection: Any) -> tuple[int, int] | None:
        if not self.supported or self.requires_elevation or connection.type != socket.SOCK_STREAM:
            return None
        row = self._row(connection)
        if row is None:
            return None
        key = self._key(connection)
        rw = ctypes.c_ubyte(0)
        data = _TcpEstatsData()
        if key not in self._enabled:
            result = self._dll.SetPerTcpConnectionEStats(
                ctypes.byref(row), 1, ctypes.byref(ctypes.c_ubyte(1)), 0, 1, 0
            )
            if result == 5:
                self.requires_elevation = True
                return None
            if result != 0:
                return None
            self._enabled.add(key)
        result = self._dll.GetPerTcpConnectionEStats(
            ctypes.byref(row),
            1,
            ctypes.byref(rw),
            0,
            1,
            None,
            0,
            0,
            ctypes.byref(data),
            0,
            ctypes.sizeof(data),
        )
        if result != 0 or rw.value != 1:
            return None
        return int(data.data_bytes_out), int(data.data_bytes_in)


def endpoint_host(endpoint: str | None) -> str | None:
    value = str(endpoint or "")
    if value.startswith("[") and "]:" in value:
        return value[1:].split("]:", 1)[0]
    if ":" in value:
        return value.rsplit(":", 1)[0]
    return value or None


def human_bytes(value: int | None) -> str:
    if value is None:
        return "unavailable"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"
