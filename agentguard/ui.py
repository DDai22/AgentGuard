from __future__ import annotations

import copy
import ctypes
import ipaddress
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .deep import human_bytes
from .monitor import AgentMonitor
from .risk import is_operation_event


CONFIG_PATH = Path(os.environ.get("LOCALAPPDATA", Path.cwd())) / "AgentGuard" / "config.json"


def _load_workspace() -> Path | None:
    try:
        value = json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("workspace")
        path = Path(str(value)).resolve()
        return path if path.is_dir() else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _save_workspace(path: Path) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        json.dumps({"workspace": str(path.resolve())}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def format_event(event: dict[str, Any]) -> tuple[str, str]:
    kind = str(event.get("type") or "")
    if kind == "process.started":
        return "工具", f"启动 {event.get('name') or '进程'}"
    if kind == "file.created":
        prefix = "工作区外创建" if event.get("scope") == "external" else "创建"
        return "文件", f"{prefix} {event.get('path')}"
    if kind == "file.modified":
        prefix = "工作区外修改" if event.get("scope") == "external" else "修改"
        suffix = f" · ↑{human_bytes(event.get('bytes_written'))}" if event.get("bytes_written") is not None else ""
        return "文件", f"{prefix} {event.get('path')}{suffix}"
    if kind == "file.deleted":
        prefix = "工作区外删除" if event.get("scope") == "external" else "删除"
        return "文件", f"{prefix} {event.get('path')}"
    if kind == "file.renamed":
        prefix = "工作区外重命名" if event.get("scope") == "external" else "重命名"
        return "文件", f"{prefix} {event.get('old_path')} → {event.get('path')}"
    if kind == "file.accessed":
        prefix = "外部敏感文件" if event.get("scope") == "external" else "打开文件"
        return "文件", f"{prefix} {event.get('path')}"
    if kind == "file.read":
        prefix = "读取外部敏感文件" if event.get("scope") == "external" else "读取"
        return "文件", f"{prefix} {event.get('path')} · {human_bytes(event.get('bytes_read'))}"
    if kind == "file.permissions_changed":
        return "文件", f"权限变化 {event.get('path')}"
    if kind == "network.opened":
        category = "公网" if _is_public_endpoint(str(event.get("remote") or "")) else "本地网络"
        return category, f"连接 {event.get('remote')}"
    if kind == "network.resolved":
        category = "公网" if _is_public_endpoint(str(event.get("remote") or "")) else "本地网络"
        return category, f"域名线索 {event.get('hostname')}"
    if kind == "network.traffic":
        category = "公网" if _is_public_endpoint(str(event.get("remote") or "")) else "本地网络"
        return category, f"传输 ↑{human_bytes(event.get('bytes_sent'))} ↓{human_bytes(event.get('bytes_received'))}"
    if kind == "network.dns":
        return "网络", f"查询域名 {event.get('query_name')}"
    if kind == "network.tls":
        return "公网", f"TLS 握手 {event.get('target_name')}"
    if kind == "system.changed":
        target = event.get("path") or event.get("name") or "系统配置"
        return "系统", f"{event.get('component') or '配置'} · {event.get('action')} · {target}"
    if kind == "behavior.detected":
        return "文件", f"{event.get('category') or '行为检测'} · {event.get('behavior')}"
    if kind == "supply_chain.operation":
        return "供应链", f"{event.get('manager')} {event.get('action')}"
    if kind == "privacy.access":
        return "隐私", f"访问线索 · {event.get('signal')}"
    if kind == "privacy.clipboard_changed":
        return "隐私", "剪贴板发生变化（进程未确认）"
    if kind == "security.privilege":
        return "系统", f"{event.get('operation') or '权限行为'} · {event.get('name') or '进程'}"
    if kind == "security.process_access":
        return "系统", f"进程访问 · PID {event.get('pid')} → {event.get('target_pid')}"
    if kind == "resource.anomaly":
        return "资源", f"资源异常 · {event.get('anomaly')}"
    return "状态", kind


def _local_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%H:%M")
    except (TypeError, ValueError):
        return "刚刚"


def _is_public_endpoint(remote: str) -> bool:
    host = remote
    if remote.startswith("[") and "]:" in remote:
        host = remote[1:].split("]:", 1)[0]
    elif ":" in remote:
        host = remote.rsplit(":", 1)[0]
    try:
        address = ipaddress.ip_address(host)
        return not (address.is_loopback or address.is_private or address.is_link_local)
    except ValueError:
        return bool(host)


def _text(value: Any) -> str:
    return "—" if value in (None, "", []) else str(value)


def _metadata(event: dict[str, Any]) -> list[dict[str, str]]:
    kind = str(event.get("type") or "")
    rows: list[tuple[str, Any]] = []
    if kind == "process.started":
        argv = " ".join(str(value) for value in event.get("argv") or [])
        rows = [
            ("程序", event.get("name")),
            ("PID", event.get("pid")),
            ("父进程", event.get("ppid")),
            ("工作目录", event.get("cwd")),
            ("可执行文件", event.get("exe")),
            ("命令参数", argv[:500] if argv else None),
        ]
    elif kind.startswith("file."):
        scope = {
            "external": "工作区外",
            "workspace": "当前工作区",
            "other_session": "其他会话工作区",
        }.get(str(event.get("scope") or ""))
        observation = {
            "open_handle": "检测到打开句柄（近似）",
            "windows_etw": "Windows ETW 内核文件事件（仅元数据）",
        }.get(str(event.get("observation") or ""))
        rows = [
            ("操作类型", kind.removeprefix("file.")),
            ("文件路径", event.get("path")),
            ("访问范围", scope),
            ("观测方式", observation),
            ("读取数据量", human_bytes(event.get("bytes_read")) if event.get("bytes_read") is not None else None),
            ("写入数据量", human_bytes(event.get("bytes_written")) if event.get("bytes_written") is not None else None),
            ("底层读取次数", event.get("read_operations")),
            ("底层写入次数", event.get("write_operations")),
            ("读取观察时长", f"{float(event.get('observed_duration_seconds')):.3f} 秒" if event.get("observed_duration_seconds") is not None else None),
            ("进程 PID", event.get("pid")),
            ("程序", event.get("name")),
            ("Agent 根进程 PID", event.get("session_pid")),
            ("原路径", event.get("old_path")),
            ("文件大小", f"{event.get('size')} bytes" if event.get("size") is not None else None),
            ("SHA-256", event.get("sha256")),
            ("权限变更前", event.get("mode_before")),
            ("权限变更后", event.get("mode_after")),
        ]
    elif kind.startswith("network."):
        precision = {
            "exact_tcp_payload": "精确 TCP 载荷字节",
            "requires_elevation": "需要管理员权限启用精确统计",
            "unavailable": "当前连接不支持精确统计",
        }.get(str(event.get("traffic_precision") or ""))
        rows = [
            ("目标地址", event.get("remote")),
            ("域名线索", event.get("hostname")),
            ("域名来源", "反向 DNS；不代表完整 URL" if event.get("hostname_source") == "reverse_dns" or event.get("hostname") else None),
            ("本地地址", event.get("local")),
            ("协议", str(event.get("protocol") or "").upper()),
            ("连接状态", event.get("status")),
            ("已发送", human_bytes(event.get("bytes_sent")) if event.get("bytes_sent") is not None else None),
            ("已接收", human_bytes(event.get("bytes_received")) if event.get("bytes_received") is not None else None),
            ("已观察时长", f"{float(event.get('observed_duration_seconds')):.1f} 秒" if event.get("observed_duration_seconds") is not None else None),
            ("平均上传速率", f"{human_bytes(int(event.get('average_send_rate_bps') or 0))}/s" if event.get("average_send_rate_bps") is not None else None),
            ("近期上传速率", f"{human_bytes(int(event.get('recent_send_rate_bps') or 0))}/s" if event.get("recent_send_rate_bps") is not None else None),
            ("上下行比例", f"{float(event.get('upload_download_ratio')):.2f} : 1" if event.get("upload_download_ratio") is not None else None),
            ("流量统计", precision),
            ("进程 PID", event.get("pid")),
            ("Agent PID", event.get("session_pid")),
        ]
        if kind == "network.dns":
            rows = [
                ("查询域名", event.get("query_name")),
                ("查询类型", event.get("query_type")),
                ("查询状态", event.get("status")),
                ("观测方式", "Windows DNS Client ETW；不读取请求内容"),
                ("进程 PID", event.get("pid")),
                ("Agent PID", event.get("session_pid")),
            ]
        elif kind == "network.tls":
            rows = [
                ("TLS 目标", event.get("target_name")),
                ("TLS 协议", event.get("protocol")),
                ("密码套件", event.get("cipher")),
                ("证书主题", event.get("certificate_subject")),
                ("证书指纹", event.get("certificate_thumbprint")),
                ("观测方式", "Windows Schannel ETW；未抓取或解密载荷"),
                ("进程 PID", event.get("pid")),
                ("Agent PID", event.get("session_pid")),
            ]
    elif kind in {"system.changed", "behavior.detected", "supply_chain.operation", "privacy.access", "privacy.clipboard_changed", "security.privilege", "security.process_access", "resource.anomaly"}:
        rows = [
            ("事件类型", kind),
            ("系统组件", event.get("component")),
            ("行为", event.get("behavior") or event.get("operation") or event.get("anomaly") or event.get("action")),
            ("注册表写入操作", event.get("registry_write_operation")),
            ("目标", event.get("path") or event.get("name") or event.get("signal")),
            ("包管理器", event.get("manager")),
            ("操作数量", event.get("count")),
            ("观察窗口", f"{event.get('window_seconds')} 秒" if event.get("window_seconds") is not None else None),
            ("CPU", f"{event.get('cpu_percent')}%" if event.get("cpu_percent") is not None else None),
            ("内存", human_bytes(event.get("memory_bytes")) if event.get("memory_bytes") is not None else None),
            ("完整性级别", event.get("integrity_level")),
            ("管理员令牌", "是" if event.get("elevated") else "否" if event.get("elevated") is not None else None),
            ("命令摘要", event.get("command_summary")),
            ("进程 PID", event.get("pid")),
            ("目标进程 PID", event.get("target_pid")),
            ("请求权限", event.get("granted_access")),
        ]
        if kind == "resource.anomaly" and event.get("anomaly") == "disk_io_burst":
            related_paths = event.get("related_file_paths") or []
            rows.extend(
                [
                    ("磁盘读取总量", human_bytes(event.get("disk_read_bytes")) if event.get("disk_read_bytes") is not None else None),
                    ("磁盘写入总量", human_bytes(event.get("disk_write_bytes")) if event.get("disk_write_bytes") is not None else None),
                    ("读取速度", f"{human_bytes(int(event.get('disk_read_rate_bps') or 0))}/s" if event.get("disk_read_rate_bps") is not None else None),
                    ("写入速度", f"{human_bytes(int(event.get('disk_write_rate_bps') or 0))}/s" if event.get("disk_write_rate_bps") is not None else None),
                    ("磁盘观测窗口", f"{event.get('disk_observed_seconds')} 秒" if event.get("disk_observed_seconds") is not None else None),
                    ("磁盘观测方式", event.get("disk_io_observation")),
                    ("关联文件（近 10 秒）", "\n".join(str(path) for path in related_paths) if related_paths else "未捕获到对应文件路径；请查看同一 PID 的文件操作记录"),
                    ("关联文件读写量", f"读 {human_bytes(event.get('related_file_read_bytes') or 0)} · 写 {human_bytes(event.get('related_file_write_bytes') or 0)}" if related_paths else None),
                    ("关联文件操作数", event.get("related_file_operations")),
                ]
            )
    if event.get("attribution_label"):
        rows.extend(
            [
                ("会话归属", event.get("attribution_label")),
                ("Agent 类型", event.get("agent_name")),
                ("归属置信度", {"high": "高", "medium": "中", "low": "低"}.get(str(event.get("attribution_confidence") or ""))),
                ("对话 ID", event.get("thread_id")),
                ("归属工作区", event.get("workspace_path")),
            ]
        )
    risk = event.get("risk") or {}
    if risk.get("level") == "review":
        rows.extend(
            [
                ("风险等级", "高" if risk.get("severity") == "high" else "中"),
                ("规则评分", f"{int(risk.get('score') or 0)}/100（启发式评分，不是发生概率）"),
            ]
        )
    rows.append(("发生时间", _local_time(str(event.get("timestamp") or ""))))
    return [{"label": label, "value": _text(value)} for label, value in rows if value not in (None, "")]


class ScreeningState:
    """Thread-safe, deduplicated presentation model for the floating panel."""

    def __init__(self, workspace: Path, current_thread_id: str | None = None) -> None:
        self.workspace = workspace
        self.current_thread_id = current_thread_id or os.environ.get("CODEX_THREAD_ID")
        self.lock = threading.Lock()
        self.revision = 0
        self.agent_pids: set[int] = set()
        self.agent_names: set[str] = set()
        self.seen_operations: set[str] = set()
        self.counts = {"safe": 0, "review": 0, "total": 0}
        self.kind_counts = {"tools": 0, "files": 0, "network": 0, "system": 0}
        self.attention: dict[str, dict[str, Any]] = {}
        self.reviewed: dict[str, dict[str, Any]] = {}
        self.recent_safe: dict[str, dict[str, Any]] = {}
        self.recent_safe_by_category: dict[str, dict[str, dict[str, Any]]] = {}
        self.confirmed_thread_ids: set[str] = set()
        self.confirmed_workspaces: set[str] = set()

    @staticmethod
    def _fingerprint(event: dict[str, Any], level: str, reason: str) -> str:
        kind = str(event.get("type") or "")
        if kind == "network.opened":
            if level == "review":
                return f"network-review:{event.get('session_id') or event.get('session_pid')}:{reason}"
            return f"network:{event.get('pid')}:{event.get('remote')}"
        if kind == "network.traffic" and level == "review":
            return f"network-traffic:{event.get('pid')}:{event.get('remote')}:{reason}"
        if kind == "network.traffic":
            return f"network-traffic:{event.get('session_id')}:{event.get('pid')}:{event.get('remote')}"
        if kind == "process.started":
            return f"process:{event.get('pid')}:{event.get('create_time')}"
        if kind == "file.read":
            return f"file.read:{event.get('session_id')}:{event.get('pid')}:{event.get('path')}"
        if kind.startswith("file."):
            if level == "review":
                return f"{kind}:{event.get('session_id')}:{event.get('path')}"
            return f"{kind}:{event.get('path')}:{event.get('sha256') or event.get('sequence')}"
        if kind == "privacy.clipboard_changed":
            return "privacy:clipboard_changed"
        if kind in {"system.changed", "behavior.detected", "supply_chain.operation", "privacy.access", "security.privilege", "security.process_access", "resource.anomaly"}:
            return f"{kind}:{event.get('session_id')}:{event.get('component') or event.get('behavior') or event.get('operation') or event.get('anomaly') or event.get('signal')}:{event.get('path') or event.get('name') or ''}"
        return f"{kind}:{event.get('sequence')}"

    @staticmethod
    def _kind_key(event: dict[str, Any]) -> str | None:
        event_type = str(event.get("type") or "")
        if event_type == "process.started":
            return "tools"
        if event_type.startswith("file."):
            return "files"
        if event_type == "network.opened" and _is_public_endpoint(str(event.get("remote") or "")):
            return "network"
        if event_type in {"network.dns", "network.tls"}:
            return "network"
        if event_type == "behavior.detected":
            return "files"
        if event_type in {"system.changed", "supply_chain.operation", "privacy.access", "privacy.clipboard_changed", "security.privilege", "security.process_access", "resource.anomaly"}:
            return "system"
        return None

    @staticmethod
    def _category_key(event: dict[str, Any]) -> str:
        event_type = str(event.get("type") or "")
        if event_type == "process.started":
            return "tool"
        if event_type.startswith("file."):
            return "file"
        if event_type == "behavior.detected":
            return "file"
        if event_type in {"network.dns", "network.tls"}:
            return "network"
        if event_type in {"system.changed", "supply_chain.operation", "privacy.access", "privacy.clipboard_changed", "security.privilege", "security.process_access", "resource.anomaly"}:
            return "system"
        return "network" if _is_public_endpoint(str(event.get("remote") or "")) else "local"

    @staticmethod
    def _workspace_key(value: Any) -> str | None:
        if not value:
            return None
        try:
            return os.path.normcase(str(Path(str(value)).resolve(strict=False)))
        except (OSError, RuntimeError, TypeError):
            return None

    def _confirmed_context(self, event: dict[str, Any]) -> tuple[str, str] | None:
        thread_id = str(event.get("thread_id") or "")
        if thread_id and thread_id in self.confirmed_thread_ids:
            return "current_thread", "当前会话·用户确认"
        workspace = self._workspace_key(event.get("workspace_path"))
        if workspace and workspace in self.confirmed_workspaces:
            return "current_workspace", "当前工作区·会话已确认"
        return None

    def consume(self, event: dict[str, Any]) -> None:
        kind = str(event.get("type") or "")
        with self.lock:
            if kind == "monitor.started":
                self.agent_pids.update(int(pid) for pid in event.get("root_pids") or [])
                self.agent_names.update(str(name) for name in event.get("agent_names") or [] if name)
                self.revision += 1
                return
            if kind in {"process.discovered", "process.started"} and event.get("session_pid"):
                self.agent_pids.add(int(event["session_pid"]))
                if event.get("agent_name"):
                    self.agent_names.add(str(event["agent_name"]))
            if not is_operation_event(kind):
                return

            risk = event.get("risk") or {"level": "safe", "score": 0, "reasons": []}
            level = "review" if risk.get("level") == "review" else "safe"
            category, description = format_event(event)
            reasons = list(risk.get("reasons") or [])
            reason = "；".join(reasons) if reasons else "未发现明显风险特征"
            fingerprint = self._fingerprint(event, level, reason)
            confirmed = self._confirmed_context(event)
            attribution = event.get("attribution") or "unknown"
            attribution_label = event.get("attribution_label") or "归属不确定"
            attribution_confidence = event.get("attribution_confidence") or "low"
            if confirmed:
                attribution, attribution_label = confirmed
                attribution_confidence = "high"
            item = {
                "id": fingerprint,
                "time": _local_time(str(event.get("timestamp") or "")),
                "category": category,
                "category_key": self._category_key(event),
                "event_type": kind,
                "level": level,
                "title": "子工具访问公网" if kind == "network.opened" and level == "review" else description,
                "description": description,
                "reason": reason,
                "score": int(risk.get("score") or 0),
                "severity": str(risk.get("severity") or "low"),
                "occurrences": 1,
                "targets": [str(event.get("remote"))] if event.get("remote") else [],
                "pids": [int(event["pid"])] if event.get("pid") is not None else [],
                "metadata": _metadata(event),
                "bytes_read": int(event.get("bytes_read") or 0),
                "bytes_written": (int(event.get("bytes_written")) if event.get("bytes_written") is not None else None),
                "write_operations": (int(event.get("write_operations")) if event.get("write_operations") is not None else None),
                "scope": event.get("scope") or ("workspace" if kind.startswith("file.") and event.get("workspace_path") else None),
                "session_pid": event.get("session_pid"),
                "session_id": event.get("session_id"),
                "thread_id": event.get("thread_id"),
                "workspace_path": event.get("workspace_path"),
                "attribution": attribution,
                "attribution_label": attribution_label,
                "attribution_confidence": attribution_confidence,
                "session_confirmed": bool(confirmed),
            }

            collection = self.attention if level == "review" else self.recent_safe
            if fingerprint in collection:
                existing = collection[fingerprint]
                existing["occurrences"] += 1
                existing["time"] = item["time"]
                if kind == "network.traffic":
                    existing.update(
                        title=item["title"],
                        description=item["description"],
                        reason=item["reason"],
                        score=item["score"],
                        severity=item["severity"],
                        metadata=item["metadata"],
                    )
                elif kind == "file.read":
                    existing["bytes_read"] = int(existing.get("bytes_read") or 0) + item["bytes_read"]
                    existing["title"] = (
                        f"读取 {event.get('path')} · {human_bytes(existing['bytes_read'])}"
                    )
                    existing["description"] = existing["title"]
                    for row in existing["metadata"]:
                        if row["label"] == "读取数据量":
                            row["value"] = human_bytes(existing["bytes_read"])
                elif kind == "file.modified" and item.get("bytes_written") is not None:
                    existing["bytes_written"] = int(existing.get("bytes_written") or 0) + item["bytes_written"]
                    existing["title"] = (
                        f"工作区外修改 {event.get('path')} · ↑{human_bytes(existing['bytes_written'])}"
                        if event.get("scope") == "external"
                        else f"修改 {event.get('path')} · ↑{human_bytes(existing['bytes_written'])}"
                    )
                    existing["description"] = existing["title"]
                    for row in existing["metadata"]:
                        if row["label"] == "写入数据量":
                            row["value"] = human_bytes(existing["bytes_written"])
                existing["targets"] = list(dict.fromkeys(existing["targets"] + item["targets"]))
                existing["pids"] = list(dict.fromkeys(existing["pids"] + item["pids"]))
                for row in existing["metadata"]:
                    if row["label"] == "目标地址":
                        targets = existing["targets"]
                        row["value"] = ", ".join(targets[:3]) + (
                            f"，另有 {len(targets) - 3} 个" if len(targets) > 3 else ""
                        )
                    elif row["label"] == "进程 PID":
                        row["value"] = ", ".join(str(pid) for pid in existing["pids"])
                self.revision += 1
                return

            collection[fingerprint] = item
            if fingerprint not in self.seen_operations:
                self.seen_operations.add(fingerprint)
                self.counts[level] += 1
                self.counts["total"] += 1
                kind_key = self._kind_key(event)
                if kind_key is not None:
                    self.kind_counts[kind_key] += 1
                    if level == "safe":
                        category_key = {"tools": "tool", "files": "file"}.get(kind_key, kind_key)
                        bucket = self.recent_safe_by_category.setdefault(category_key, {})
                        bucket[fingerprint] = item
                        if len(bucket) > 50:
                            bucket.pop(next(iter(bucket)))
            if len(self.recent_safe) > 50:
                self.recent_safe.pop(next(iter(self.recent_safe)))
            self.revision += 1

    def dismiss(self, item_id: str) -> None:
        with self.lock:
            item = self.attention.pop(item_id, None)
            if item is not None:
                item = copy.deepcopy(item)
                item["reviewed"] = True
                self.reviewed[item_id] = item
            self.revision += 1

    def confirm_session(self, item_id: str) -> bool:
        with self.lock:
            item = next(
                (
                    value
                    for collection in (self.attention, self.reviewed, self.recent_safe)
                    for value in collection.values()
                    if value.get("id") == item_id
                ),
                None,
            )
            if item is None:
                return False
            thread_id = str(item.get("thread_id") or "")
            workspace = self._workspace_key(item.get("workspace_path"))
            if thread_id:
                self.confirmed_thread_ids.add(thread_id)
                relation, label = "current_thread", "当前会话·用户确认"
            elif workspace:
                self.confirmed_workspaces.add(workspace)
                relation, label = "current_workspace", "当前工作区·会话已确认"
            else:
                return False
            for collection in (self.attention, self.reviewed, self.recent_safe):
                for value in collection.values():
                    same_thread = thread_id and value.get("thread_id") == thread_id
                    same_workspace = workspace and self._workspace_key(value.get("workspace_path")) == workspace
                    if same_thread or (not thread_id and same_workspace):
                        value["attribution"] = relation
                        value["attribution_label"] = label
                        value["attribution_confidence"] = "high"
                        value["session_confirmed"] = True
                        for row in value.get("metadata") or []:
                            if row.get("label") == "会话归属":
                                row["value"] = label
                            elif row.get("label") == "归属置信度":
                                row["value"] = "高"
            self.revision += 1
            return True

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            attention = list(reversed(self.attention.values()))
            reviewed = list(reversed(self.reviewed.values()))
            all_recent = list(reversed(self.recent_safe.values()))
            recent = all_recent[:50]
            if attention:
                max_score = max(item["score"] for item in attention)
                posture = {
                    "level": "danger" if max_score >= 80 else "review",
                    "title": f"{len(attention)} 项操作需要关注",
                    "subtitle": f"{attention[0]['attribution_label']} · {attention[0]['category']} · {attention[0]['title']}",
                    "score": max_score,
                    "primary_id": attention[0]["id"],
                }
            else:
                posture = {
                    "level": "safe",
                    "title": "当前操作看起来正常",
                    "subtitle": "未发现明显的高风险行为",
                    "score": 0,
                    "primary_id": None,
                }
            return copy.deepcopy(
                {
                    "revision": self.revision,
                    "workspace": self.workspace.name,
                    "workspace_path": str(self.workspace.resolve()),
                    "current_thread_id": self.current_thread_id,
                    "active": bool(self.agent_pids),
                    "pids": sorted(self.agent_pids),
                    "agent_names": sorted(self.agent_names),
                    "posture": posture,
                    "counts": self.counts,
                    "kind_counts": self.kind_counts,
                    "attention": attention[:50],
                    "reviewed": reviewed[:50],
                    "recent": recent,
                    "recent_by_category": {
                        category: list(reversed(items.values()))[:50]
                        for category, items in self.recent_safe_by_category.items()
                    },
                }
            )


class UiApi:
    def __init__(
        self,
        state: ScreeningState,
        stop_event: threading.Event,
        monitor_thread: threading.Thread,
        target_names: Iterable[str],
        explicit_pids: set[int],
        capture_command_lines: bool,
        frame_extra: int = 0,
        dpi_scale: float = 1.0,
    ) -> None:
        self._state = state
        self._stop_event = stop_event
        self._monitor_thread = monitor_thread
        self._target_names = list(target_names)
        self._explicit_pids = set(explicit_pids)
        self._capture_command_lines = capture_command_lines
        self._lifecycle_lock = threading.RLock()
        self._window: Any = None
        self._frame_extra = frame_extra
        self._dpi_scale = dpi_scale

    def get_state(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            state = self._state
        return state.snapshot()

    def set_expanded(self, expanded: bool) -> bool:
        if self._window is not None:
            width = round(372 * self._dpi_scale)
            height = round(((560 if expanded else 236) + self._frame_extra) * self._dpi_scale)
            self._window.resize(width, height)
        return expanded

    def set_minimal(self, minimal: bool) -> bool:
        """Resize the always-on-top window to its compact status strip."""
        if self._window is not None:
            if minimal:
                width = round(300 * self._dpi_scale)
                height = round((52 + self._frame_extra) * self._dpi_scale)
            else:
                width = round(372 * self._dpi_scale)
                height = round((236 + self._frame_extra) * self._dpi_scale)
            self._window.resize(width, height)
        return minimal

    def dismiss(self, item_id: str) -> bool:
        with self._lifecycle_lock:
            state = self._state
        state.dismiss(item_id)
        return True

    def confirm_session(self, item_id: str) -> bool:
        with self._lifecycle_lock:
            state = self._state
        return state.confirm_session(item_id)

    def minimize(self) -> bool:
        if self._window is not None:
            self._window.minimize()
        return True

    def choose_workspace(self) -> bool:
        if self._window is None:
            return False
        selected = self._window.create_file_dialog(
            20,
            directory=str(self._state.workspace),
            allow_multiple=False,
        )
        if not selected:
            return False
        path = Path(selected[0]).resolve()
        if not path.is_dir():
            return False
        _save_workspace(path)
        if path == self._state.workspace.resolve():
            return True
        with self._lifecycle_lock:
            current_thread_id = self._state.current_thread_id
        new_state = ScreeningState(path, current_thread_id=current_thread_id)
        new_stop_event = threading.Event()

        def receive(event: dict[str, Any]) -> None:
            new_state.consume(event)

        monitor = AgentMonitor(
            root=path,
            target_names=self._target_names,
            explicit_pids=self._explicit_pids,
            interval=0.5,
            file_interval=2.0,
            output=None,
            capture_command_lines=self._capture_command_lines,
            event_callback=receive,
        )
        new_thread = threading.Thread(
            target=monitor.run,
            kwargs={"stop_event": new_stop_event},
            name="agentguard-monitor",
            daemon=True,
        )
        with self._lifecycle_lock:
            old_stop_event = self._stop_event
            old_thread = self._monitor_thread
            self._state = new_state
            self._stop_event = new_stop_event
            self._monitor_thread = new_thread
        new_thread.start()
        old_stop_event.set()
        threading.Thread(
            target=lambda: old_thread.join(timeout=3),
            name="agentguard-workspace-switch",
            daemon=True,
        ).start()
        return True

    def stop_monitor(self) -> None:
        with self._lifecycle_lock:
            stop_event = self._stop_event
            monitor_thread = self._monitor_thread
        stop_event.set()
        monitor_thread.join(timeout=3)

    def close(self) -> bool:
        def finish() -> None:
            self.stop_monitor()
            if self._window is not None:
                self._window.destroy()

        threading.Thread(target=finish, name="agentguard-ui-close", daemon=True).start()
        return True


def run_ui(
    root: Path | None,
    target_names: Iterable[str],
    explicit_pids: set[int],
    output: Path | None,
    capture_command_lines: bool,
    language: str = "zh",
) -> int:
    try:
        import webview
    except ImportError as exc:
        raise SystemExit("UI dependency missing. Run: pip install pywebview>=5.4,<6") from exc

    root = (root or _load_workspace() or Path.cwd()).resolve()
    if not root.is_dir():
        raise SystemExit(f"Workspace does not exist: {root}")
    _save_workspace(root)

    state = ScreeningState(root, current_thread_id=os.environ.get("CODEX_THREAD_ID"))
    stop_event = threading.Event()

    def receive(event: dict[str, Any]) -> None:
        state.consume(event)

    monitor = AgentMonitor(
        root=root,
        target_names=target_names,
        explicit_pids=explicit_pids,
        interval=0.5,
        file_interval=2.0,
        output=output,
        capture_command_lines=capture_command_lines,
        event_callback=receive,
    )
    monitor_thread = threading.Thread(
        target=monitor.run,
        kwargs={"stop_event": stop_event},
        name="agentguard-monitor",
        daemon=True,
    )
    framed = os.environ.get("AGENTGUARD_UI_FRAME") == "1"
    dpi_scale = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100
    api = UiApi(
        state,
        stop_event,
        monitor_thread,
        target_names,
        explicit_pids,
        capture_command_lines,
        frame_extra=30 if framed else 0,
        dpi_scale=dpi_scale,
    )
    html = (Path(__file__).parent / "assets" / "floating.html").read_text(encoding="utf-8")
    html = html.replace("__AGENTGUARD_LANGUAGE__", "en" if language == "en" else "zh")
    screen_width = ctypes.windll.user32.GetSystemMetrics(0)
    window = webview.create_window(
        "AgentGuard",
        html=html,
        js_api=api,
        width=372,
        height=236 + (30 if framed else 0),
        x=max(16, screen_width - 396),
        y=44,
        resizable=False,
        frameless=not framed,
        easy_drag=False,
        shadow=True,
        on_top=True,
        background_color="#090D14",
        transparent=False,
        text_select=False,
    )
    api._window = window

    def on_closed() -> None:
        threading.Thread(target=api.stop_monitor, daemon=True).start()

    window.events.closed += on_closed
    monitor_thread.start()
    try:
        webview.start(gui="edgechromium", private_mode=True)
    finally:
        api.stop_monitor()
    return 0
