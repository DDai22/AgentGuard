from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psutil


GENERIC_CWD_PARTS = {
    "windows",
    "program files",
    "program files (x86)",
    "windowsapps",
    "appdata",
    "temp",
}


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


class SessionAttributor:
    """Metadata-only Codex thread/workspace attribution with explicit confidence."""

    def __init__(self, root: Path, current_thread_id: str | None = None) -> None:
        self.root = root.resolve()
        self.current_thread_id = current_thread_id or os.environ.get("CODEX_THREAD_ID")
        self.thread_cache: dict[tuple[int, float | None], str | None] = {}

    def _thread_id(self, pid: int, create_time: float | None) -> str | None:
        key = (pid, create_time)
        if key in self.thread_cache:
            return self.thread_cache[key]
        try:
            value = psutil.Process(pid).environ().get("CODEX_THREAD_ID") or None
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            value = None
        self.thread_cache[key] = value
        return value

    @staticmethod
    def _useful_workspace(cwd: Any) -> Path | None:
        if not cwd:
            return None
        try:
            path = Path(str(cwd)).resolve(strict=False)
        except (OSError, RuntimeError):
            return None
        lowered = {part.lower() for part in path.parts}
        if lowered & GENERIC_CWD_PARTS:
            return None
        return path

    def build(
        self,
        relevant: dict[int, tuple[dict[str, Any], int]],
        roots: set[int],
    ) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        pending = set(relevant)
        while pending:
            progressed = False
            for pid in list(pending):
                info, root_pid = relevant[pid]
                parent_pid = info.get("ppid")
                parent = result.get(parent_pid) if isinstance(parent_pid, int) else None
                if parent_pid in pending and parent is None:
                    continue
                thread_id = self._thread_id(pid, info.get("create_time"))
                workspace = self._useful_workspace(info.get("cwd"))
                if thread_id:
                    current = bool(self.current_thread_id and thread_id == self.current_thread_id)
                    relation = "current_thread" if current else "other_thread"
                    label = "当前会话" if current else "其他会话"
                    confidence = "high"
                    session_id = f"thread:{thread_id}"
                elif parent and parent.get("thread_id"):
                    relation = str(parent["attribution"])
                    label = str(parent["attribution_label"])
                    confidence = "high"
                    session_id = str(parent["session_id"])
                    thread_id = str(parent["thread_id"])
                    if workspace is None and parent.get("workspace_path"):
                        workspace = Path(str(parent["workspace_path"]))
                elif workspace and _within(workspace, self.root):
                    relation = "current_workspace"
                    label = "当前工作区·会话未确认"
                    confidence = "medium"
                    session_id = f"workspace:{os.path.normcase(str(self.root))}"
                elif parent and parent.get("attribution") not in {"shared", "unknown"}:
                    relation = str(parent["attribution"])
                    label = str(parent["attribution_label"])
                    confidence = "medium"
                    session_id = str(parent["session_id"])
                    if workspace is None and parent.get("workspace_path"):
                        workspace = Path(str(parent["workspace_path"]))
                elif parent and parent.get("attribution") == "shared" and workspace is None:
                    relation = "shared"
                    label = "共享 Codex"
                    confidence = "medium"
                    session_id = str(parent["session_id"])
                elif pid in roots:
                    relation = "shared"
                    label = "共享 Codex"
                    confidence = "high"
                    session_id = f"shared:{root_pid}"
                elif workspace:
                    relation = "other_workspace"
                    label = "其他工作区·会话未确认"
                    confidence = "medium"
                    session_id = f"workspace:{os.path.normcase(str(workspace))}"
                else:
                    relation = "unknown"
                    label = "归属不确定"
                    confidence = "low"
                    session_id = f"unknown:{root_pid}:{pid}"
                result[pid] = {
                    "session_id": session_id,
                    "thread_id": thread_id,
                    "attribution": relation,
                    "attribution_label": label,
                    "attribution_confidence": confidence,
                    "workspace_path": str(workspace) if workspace else None,
                }
                pending.remove(pid)
                progressed = True
            if not progressed:
                pid = pending.pop()
                info, root_pid = relevant[pid]
                result[pid] = {
                    "session_id": f"unknown:{root_pid}:{pid}",
                    "thread_id": None,
                    "attribution": "unknown",
                    "attribution_label": "归属不确定",
                    "attribution_confidence": "low",
                    "workspace_path": str(info.get("cwd") or "") or None,
                }
        return result
