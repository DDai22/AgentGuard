from __future__ import annotations

import ctypes
import os
import string
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any


FILE_IO_CREATE_OPCODE = 64
FILE_IO_CLEANUP_OPCODE = 65
FILE_IO_CLOSE_OPCODE = 66
FILE_IO_READ_OPCODE = 67
FILE_IO_WRITE_OPCODE = 68
FILE_IO_SET_INFORMATION_OPCODE = 69
FILE_IO_DELETE_OPCODE = 70
FILE_IO_RENAME_OPCODE = 71
FILE_IO_NAME_CREATE_OPCODE = 32
FILE_IO_NAME_DELETE_OPCODE = 35
FILE_INFORMATION_CLASS_DISPOSITION = 13
MAX_PATH_CACHE = 50_000
MAX_CLASS_CACHE = 20_000


class EtwFileReadTracker:
    """Aggregate Windows kernel FileIo metadata without reading file contents."""

    def __init__(self, root: Path, sink: Any, *, track_workspace_reads: bool = True) -> None:
        self.root = root.resolve()
        self.sink = sink
        self.available = False
        self.status = "not_started"
        self._session: Any = None
        self._lock = threading.RLock()
        self._targets: set[int] = set()
        self._sessions: dict[int, int] = {}
        self._attributions: dict[int, dict[str, Any]] = {}
        self._process_names: dict[int, str] = {}
        self._object_paths: OrderedDict[str, str] = OrderedDict()
        self._object_classes: OrderedDict[str, tuple[str, str, bool] | None] = OrderedDict()
        self._class_cache: OrderedDict[tuple[str, str, str, bool], tuple[str, str, bool] | None] = OrderedDict()
        self.track_workspace_reads = track_workspace_reads
        self._buckets: dict[tuple[int, str], dict[str, Any]] = {}
        self._write_buckets: dict[tuple[int, str], dict[str, Any]] = {}
        self._device_roots = self._query_device_roots()

    @staticmethod
    def _query_device_roots() -> list[tuple[str, str]]:
        if os.name != "nt":
            return []
        kernel32 = ctypes.windll.kernel32
        mappings: list[tuple[str, str]] = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:"
            buffer = ctypes.create_unicode_buffer(2048)
            if kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):
                device = buffer.value.rstrip("\\")
                if device:
                    mappings.append((device.lower(), drive))
        return sorted(mappings, key=lambda item: len(item[0]), reverse=True)

    def _dos_path(self, raw_path: str | None) -> str | None:
        value = str(raw_path or "")
        if not value:
            return None
        if value.startswith("\\??\\"):
            value = value[4:]
        if value.lower().startswith("\\device\\mup\\"):
            return "\\\\" + value[len("\\Device\\Mup\\") :]
        lowered = value.lower()
        for device, drive in self._device_roots:
            if lowered == device or lowered.startswith(device + "\\"):
                return drive + value[len(device) :]
        return value if len(value) >= 2 and value[1] == ":" else None

    @staticmethod
    def _remember(cache: OrderedDict[str, str], key: str | None, path: str) -> None:
        if not key:
            return
        cache[str(key)] = path
        cache.move_to_end(str(key))
        while len(cache) > MAX_PATH_CACHE:
            cache.popitem(last=False)

    def update_targets(
        self,
        pids: set[int],
        sessions: dict[int, int],
        attributions: dict[int, dict[str, Any]],
        process_names: dict[int, str] | None = None,
    ) -> None:
        with self._lock:
            self._targets = set(pids)
            self._sessions = dict(sessions)
            self._attributions = {pid: dict(value) for pid, value in attributions.items()}
            if process_names is not None:
                self._process_names = dict(process_names)

    def start(self) -> bool:
        if os.environ.get("AGENTGUARD_DISABLE_FILE_ETW") == "1":
            self.status = "disabled_by_config"
            return False
        if os.name != "nt":
            self.status = "windows_only"
            return False
        try:
            import etw
            from etw import evntrace

            flags = (
                evntrace.EVENT_TRACE_FLAG_FILE_IO
                | evntrace.EVENT_TRACE_FLAG_FILE_IO_INIT
            )
            provider = etw.ProviderInfo(
                "SystemTraceControlGuid",
                etw.GUID("{9e814aad-3204-11d2-9a82-006008a86939}"),
                any_keywords=flags,
            )
            self._session = etw.ETW(
                session_name=evntrace.KERNEL_LOGGER_NAME,
                providers=[provider],
                event_callback=self._on_event,
                ignore_exists_error=False,
            )
            self._session.start()
        except PermissionError:
            self.status = "requires_elevation"
            self._session = None
            return False
        except Exception as exc:
            self.status = f"unavailable:{type(exc).__name__}"
            self._session = None
            return False
        self.available = True
        self.status = "exact_windows_etw"
        return True

    @staticmethod
    def _opcode(data: dict[str, Any]) -> int:
        try:
            return int(data["EventHeader"]["EventDescriptor"]["Opcode"])
        except (KeyError, TypeError, ValueError):
            return -1

    @staticmethod
    def _pid(data: dict[str, Any]) -> int:
        try:
            return int(data["EventHeader"]["ProcessId"])
        except (KeyError, TypeError, ValueError):
            return -1

    def _on_event(self, item: tuple[int, dict[str, Any]]) -> None:
        _, data = item
        if str(data.get("Task Name") or "").upper() != "FILEIO":
            return
        opcode = self._opcode(data)
        pid = self._pid(data)
        with self._lock:
            if pid not in self._targets:
                return
            if opcode in {FILE_IO_NAME_CREATE_OPCODE, FILE_IO_NAME_DELETE_OPCODE}:
                path = self._dos_path(data.get("FileName") or data.get("OpenPath"))
                if path:
                    self._remember(self._object_paths, data.get("FileObject"), path)
                    event_type = "file.created" if opcode == FILE_IO_NAME_CREATE_OPCODE else "file.deleted"
                    self._emit_external_metadata(event_type, pid, path, data, None)
                return
            if opcode == FILE_IO_CREATE_OPCODE:
                path = self._dos_path(data.get("OpenPath"))
                if path:
                    object_key = str(data.get("FileObject") or "")
                    self._remember(self._object_paths, object_key, path)
                    classified = self._classify(path, self._attributions.get(pid, {}), include_external=True)
                    if object_key:
                        self._object_classes[object_key] = classified
                        self._object_classes.move_to_end(object_key)
                        while len(self._object_classes) > MAX_PATH_CACHE:
                            self._object_classes.popitem(last=False)
                    # Create events are emitted for opens as well as new files.  Only
                    # trust an explicit disposition/new-file marker when available.
                    if self._is_new_file(data):
                        self._emit_external_metadata("file.created", pid, path, data, attribution=None)
                return
            if opcode in {FILE_IO_CLEANUP_OPCODE, FILE_IO_CLOSE_OPCODE}:
                if opcode == FILE_IO_CLOSE_OPCODE:
                    object_key = str(data.get("FileObject") or "")
                    self._object_paths.pop(object_key, None)
                    self._object_classes.pop(object_key, None)
                return
            if opcode in {FILE_IO_DELETE_OPCODE, FILE_IO_SET_INFORMATION_OPCODE}:
                self._maybe_delete(pid, data)
                return
            if opcode == FILE_IO_RENAME_OPCODE:
                self._maybe_rename(pid, data)
                return
            if opcode == FILE_IO_WRITE_OPCODE:
                self._record_write(pid, data)
                return
            if opcode != FILE_IO_READ_OPCODE:
                return
            path = self._object_paths.get(str(data.get("FileObject") or ""))
            if path is None:
                return
            try:
                io_size = int(data.get("IoSize") or 0)
            except (TypeError, ValueError):
                return
            if io_size <= 0:
                return
            attribution = self._attributions.get(pid, {})
            object_key = str(data.get("FileObject") or "")
            classified = self._object_classes.get(object_key)
            if classified is None and object_key not in self._object_classes:
                classified = self._classify(path, attribution, include_external=True)
            if not self.track_workspace_reads and (classified is None or classified[1] == "workspace"):
                return
            if classified is not None and classified[1] == "external" and not classified[2]:
                return
            if classified is None:
                return
            display_path, scope, sensitive = classified
            now = time.monotonic()
            key = (pid, os.path.normcase(path))
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = {
                    "pid": pid,
                    "session_pid": self._sessions.get(pid),
                    "name": self._process_names.get(pid),
                    "path": display_path,
                    "scope": scope,
                    "sensitive": sensitive,
                    "bytes_read": 0,
                    "read_operations": 0,
                    "observation": "windows_etw",
                    "traffic_precision": "exact_file_io_bytes",
                    "first_observed_monotonic": now,
                    "last_observed_monotonic": now,
                    **attribution,
                }
                self._buckets[key] = bucket
            bucket["bytes_read"] += io_size
            bucket["read_operations"] += 1
            bucket["last_observed_monotonic"] = now

    @staticmethod
    def _is_new_file(data: dict[str, Any]) -> bool:
        value = data.get("CreateDisposition", data.get("Disposition"))
        try:
            return int(value) in {2, 5}
        except (TypeError, ValueError):
            return bool(data.get("Created") is True or data.get("NewFile") is True)

    def _classify(
        self, path: str, attribution: dict[str, Any], *, include_external: bool = False
    ) -> tuple[str, str, bool] | None:
        from .deep import classify_observed_file

        key = (
            os.path.normcase(path),
            str(attribution.get("attribution") or ""),
            str(attribution.get("workspace_path") or ""),
            include_external,
        )
        if key in self._class_cache:
            value = self._class_cache[key]
            self._class_cache.move_to_end(key)
            return value
        value = classify_observed_file(
            self.root, path, attribution, include_external=include_external
        )
        self._class_cache[key] = value
        self._class_cache.move_to_end(key)
        while len(self._class_cache) > MAX_CLASS_CACHE:
            self._class_cache.popitem(last=False)
        return value

    def _emit_external_metadata(
        self,
        event_type: str,
        pid: int,
        path: str,
        data: dict[str, Any],
        attribution: dict[str, Any] | None,
        **extra: Any,
    ) -> None:
        attribution = dict(attribution or self._attributions.get(pid, {}))
        classified = self._classify(path, attribution, include_external=True)
        if classified is None:
            return
        display_path, scope, sensitive = classified
        if scope != "external":
            return
        payload = {
            "pid": pid,
            "session_pid": self._sessions.get(pid),
            "name": self._process_names.get(pid),
            "path": display_path,
            "scope": scope,
            "sensitive": sensitive,
            "observation": "windows_etw",
            **attribution,
            **extra,
        }
        self.sink.emit(event_type, **payload)

    def _record_write(self, pid: int, data: dict[str, Any]) -> None:
        path = self._object_paths.get(str(data.get("FileObject") or ""))
        if path is None:
            path = self._dos_path(data.get("OpenPath"))
        if path is None:
            return
        try:
            io_size = int(data.get("IoSize") or data.get("TransferSize") or 0)
        except (TypeError, ValueError):
            return
        if io_size <= 0:
            return
        attribution = self._attributions.get(pid, {})
        object_key = str(data.get("FileObject") or "")
        classified = self._object_classes.get(object_key)
        if classified is None and object_key not in self._object_classes:
            classified = self._classify(path, attribution, include_external=True)
        if classified is None:
            return
        display_path, scope, sensitive = classified
        now = time.monotonic()
        key = (pid, os.path.normcase(path))
        bucket = self._write_buckets.get(key)
        if bucket is None:
            bucket = {
                "pid": pid,
                "session_pid": self._sessions.get(pid),
                "name": self._process_names.get(pid),
                "path": display_path,
                "scope": scope,
                "sensitive": sensitive,
                "bytes_written": 0,
                "write_operations": 0,
                "observation": "windows_etw",
                "traffic_precision": "exact_file_io_bytes",
                "first_observed_monotonic": now,
                "last_observed_monotonic": now,
                **attribution,
            }
            self._write_buckets[key] = bucket
        bucket["bytes_written"] += io_size
        bucket["write_operations"] += 1
        bucket["last_observed_monotonic"] = now

    def _maybe_delete(self, pid: int, data: dict[str, Any]) -> None:
        delete = data.get("DeletePending", data.get("Delete"))
        info_class = data.get("FileInformationClass", data.get("InfoClass"))
        is_delete = bool(delete is True or str(delete).lower() in {"1", "true"})
        try:
            is_delete = is_delete or int(info_class) == FILE_INFORMATION_CLASS_DISPOSITION
        except (TypeError, ValueError):
            pass
        if not is_delete and data.get("EventHeader", {}).get("EventDescriptor", {}).get("Opcode") != FILE_IO_DELETE_OPCODE:
            return
        path = self._object_paths.get(str(data.get("FileObject") or ""))
        if path:
            self._emit_external_metadata("file.deleted", pid, path, data, None)

    def _maybe_rename(self, pid: int, data: dict[str, Any]) -> None:
        path = self._object_paths.get(str(data.get("FileObject") or ""))
        new_path = self._dos_path(data.get("NewName") or data.get("NewPath"))
        if path and new_path and path != new_path:
            attribution = self._attributions.get(pid, {})
            classified = self._classify(path, attribution, include_external=True)
            if classified and classified[1] == "external":
                self._emit_external_metadata(
                    "file.renamed", pid, new_path, data, attribution, old_path=path
                )

    def flush(self, force: bool = False) -> int:
        now = time.monotonic()
        ready: list[tuple[str, dict[str, Any]]] = []
        with self._lock:
            for key, bucket in list(self._buckets.items()):
                if force or now - float(bucket["last_observed_monotonic"]) >= 0.75:
                    ready.append(("file.read", self._buckets.pop(key)))
            for key, bucket in list(self._write_buckets.items()):
                if force or now - float(bucket["last_observed_monotonic"]) >= 0.75:
                    write_bucket = self._write_buckets.pop(key)
                    ready.append(("file.modified", write_bucket))
        for event_type, bucket in ready:
            first = float(bucket.pop("first_observed_monotonic"))
            last = float(bucket.pop("last_observed_monotonic"))
            bucket["observed_duration_seconds"] = round(max(last - first, 0.0), 3)
            self.sink.emit(event_type, **bucket)
        return len(ready)

    def close(self) -> None:
        self.flush(force=True)
        session = self._session
        self._session = None
        self.available = False
        if session is None:
            return
        try:
            # Closing the consumer first prevents a large kernel backlog from delaying shutdown.
            if session.consumer is not None:
                session.consumer.stop()
            if session.provider is not None:
                session.provider.stop()
            session.running = False
        except Exception:
            pass
