from __future__ import annotations

import ipaddress
import re
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


OPERATION_EVENTS = {
    "process.started",
    "file.created",
    "file.modified",
    "file.deleted",
    "file.renamed",
    "file.accessed",
    "file.read",
    "file.permissions_changed",
    "network.opened",
    "network.resolved",
    "network.dns",
    "network.tls",
    "network.traffic",
    "system.changed",
    "behavior.detected",
    "supply_chain.operation",
    "privacy.access",
    "privacy.clipboard_changed",
    "security.privilege",
    "security.process_access",
    "resource.anomaly",
}


def is_operation_event(event_type: str) -> bool:
    return event_type in OPERATION_EVENTS


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    score: int
    severity: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


PROCESS_RULES = [
    (
        re.compile(
            r"(?i)(?:^|\s)(?:format(?:\.com)?|diskpart(?:\.exe)?|"
            r"mkfs(?:\.[a-z0-9]+)?|shred)(?:\s|$)"
        ),
        95,
        "可能破坏磁盘或大量数据",
    ),
    (
        re.compile(
            r"(?i)(?:\bremove-item\b.*\b-recurse\b|\brm\b.*(?:\s-rf?\b|--recursive)|"
            r"\brmdir\b.*\s/s\b|\bdel\b.*\s/s\b)"
        ),
        85,
        "递归删除操作",
    ),
    (
        re.compile(r"(?i)\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f|push\b[^\n]*--force)"),
        82,
        "可能丢失或强制覆盖 Git 数据",
    ),
    (
        re.compile(
            r"(?i)(?:\binvoke-expression\b|(?:^|\s)iex(?:\s|$)|"
            r"(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(?:sh|bash|iex))"
        ),
        80,
        "下载内容后直接执行",
    ),
    (
        re.compile(r"(?i)\b(set-executionpolicy|sudo|runas)\b"),
        72,
        "涉及提权或执行策略变更",
    ),
    (
        re.compile(
            r"(?i)\b(?:npm\s+publish|docker\s+push|git\s+push|"
            r"kubectl\s+(?:apply|delete)|terraform\s+(?:apply|destroy))\b"
        ),
        65,
        "可能修改外部或生产系统",
    ),
    (
        re.compile(r"(?i)(?:\.ssh[\\/]|\.aws[\\/]credentials|\.env(?:\s|$)|id_rsa|credentials?)"),
        70,
        "命令可能接触凭据或密钥",
    ),
]

SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.kube|gcloud)(?:[/\\])|"
    r"(?:^|[/\\])(?:\.env(?:\..*)?|credentials?(?:\..*)?|secrets?(?:\..*)?|"
    r"id_rsa|id_ed25519|\.npmrc|\.pypirc|\.git-credentials|login data|cookies|"
    r"web data|local state|key4\.db|logins\.json|signons\.sqlite|wallet\.dat)$|"
    r"\.(?:pem|p12|pfx|key)$"
)
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".sys", ".reg", ".msi"}
SCRIPT_SUFFIXES = {".ps1", ".bat", ".cmd", ".vbs", ".sh"}
ARCHIVE_PATTERN = re.compile(
    r"(?i)(?:^|[\\/\s])(?:7z|7za|rar|winrar|zip|gzip|tar)(?:\.exe)?(?:\s|$)|"
    r"\bcompress-archive\b|\bpython(?:\.exe)?\b.*\s-m\s+zipfile\b|"
    r"\b(?:make_archive|shutil\.make_archive)\b"
)


class RiskAssessor:
    """Explainable two-bucket heuristic screening; it never blocks an action."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.recent_sensitive_access: dict[str, float] = {}
        self.recent_reads: dict[str, deque[tuple[float, int, str]]] = {}
        self.recent_archives: dict[str, tuple[float, str]] = {}
        self.public_destinations: dict[str, dict[str, float]] = {}

    @staticmethod
    def _safe(reason: str, score: int = 5) -> RiskAssessment:
        return RiskAssessment("safe", score, "low", (reason,))

    @staticmethod
    def _review(score: int, *reasons: str) -> RiskAssessment:
        severity = "high" if score >= 80 else "medium"
        return RiskAssessment("review", score, severity, tuple(dict.fromkeys(reasons)))

    def assess(self, event_type: str, data: dict[str, Any]) -> RiskAssessment:
        if event_type in {
            "system.changed", "behavior.detected", "supply_chain.operation",
            "privacy.access", "security.privilege", "resource.anomaly",
        }:
            reasons = tuple(str(value) for value in data.get("reasons") or ["检测到需要解释的系统行为"])
            score = int(data.get("risk_score") or 0)
            return self._review(score, *reasons) if data.get("needs_review") else self._safe(reasons[0], score=score)
        if event_type == "security.process_access":
            if data.get("operation") == "create_remote_thread":
                return self._review(96, "Agent 进程在其他进程中创建远程线程")
            return self._review(82, "Agent 进程请求访问其他进程内存或句柄")
        if event_type == "privacy.clipboard_changed":
            return self._safe("剪贴板序号发生变化，但无法被动归因到具体进程；未读取内容", score=1)
        if event_type == "process.started":
            return self._process(data)
        if event_type.startswith("file."):
            return self._file(event_type, data)
        if event_type == "network.opened":
            return self._network(data)
        if event_type == "network.traffic":
            return self._network_traffic(data)
        if event_type in {"network.resolved", "network.dns", "network.tls"}:
            return self._safe("域名线索仅用于解释已有连接", score=2)
        return self._safe("状态或结束事件，不代表新的操作", score=0)

    def _process(self, data: dict[str, Any]) -> RiskAssessment:
        correlation_key = str(data.get("session_id") or "")
        command = " ".join(str(part) for part in data.get("argv") or [])
        archive_text = f"{data.get('name') or ''} {command}".strip()
        if correlation_key and ARCHIVE_PATTERN.search(archive_text):
            self.recent_archives[correlation_key] = (time.monotonic(), archive_text[:300])
        if data.get("attribution") in {"other_thread", "other_workspace"}:
            return self._safe("其他 Agent 会话的工具操作，不计入当前会话风险", score=2)
        matches = [(score, reason) for pattern, score, reason in PROCESS_RULES if pattern.search(command)]
        if matches:
            return self._review(max(score for score, _ in matches), *(reason for _, reason in matches))
        return self._safe("未发现危险命令特征")

    def _file(self, event_type: str, data: dict[str, Any]) -> RiskAssessment:
        path = str(data.get("path") or "")
        suffix = Path(path).suffix.lower()
        sensitive = bool(SENSITIVE_PATH.search(path))
        correlation_key = str(data.get("session_id") or "")
        now = time.monotonic()
        if event_type in {"file.accessed", "file.read"} and sensitive and correlation_key:
            self.recent_sensitive_access[correlation_key] = time.monotonic()
        if event_type == "file.read" and correlation_key:
            reads = self.recent_reads.setdefault(correlation_key, deque())
            reads.append((now, int(data.get("bytes_read") or 0), path))
            while reads and now - reads[0][0] > 120:
                reads.popleft()
        reasons: list[str] = []
        score = 0
        external = data.get("scope") == "external"
        attribution = str(data.get("attribution") or "")
        actor = "Agent" if attribution in {"current_thread", "shared"} else "未确认归属的进程"
        if event_type in {"file.accessed", "file.read"} and external:
            score = max(score, 86)
            reasons.append(f"{actor}打开或读取了当前工作区外的文件")
        if event_type in {"file.created", "file.modified"} and external:
            score = max(score, 88)
            reasons.append(f"{actor}在当前工作区外创建或修改了文件")
        if event_type == "file.deleted" and external:
            score = max(score, 92)
            reasons.append(f"{actor}删除了当前工作区外的文件")
        if event_type == "file.renamed" and external:
            score = max(score, 88)
            reasons.append(f"{actor}重命名了当前工作区外的文件")
        if sensitive:
            score = max(score, 88)
            reasons.append("涉及凭据、密钥或敏感配置文件")
        if event_type.startswith("file.") and data.get("scope") == "external" and sensitive:
            score = max(score, 96)
            operation = {
                "file.accessed": "读取或打开",
                "file.read": "读取",
                "file.created": "创建或覆盖",
                "file.modified": "修改",
                "file.deleted": "删除",
                "file.renamed": "重命名",
            }.get(event_type, "操作")
            reasons.append(f"{actor}{operation}了工作区外的敏感文件")
        if event_type == "file.deleted":
            score = max(score, 58)
            reasons.append("删除文件可能造成数据损失")
        if event_type == "file.permissions_changed":
            score = max(score, 68)
            reasons.append("文件权限元数据发生变化")
        if event_type in {"file.created", "file.modified"} and suffix in EXECUTABLE_SUFFIXES:
            score = max(score, 75)
            reasons.append("创建或修改可执行/系统文件")
        elif event_type in {"file.created", "file.modified"} and suffix in SCRIPT_SUFFIXES:
            score = max(score, 52)
            reasons.append("创建或修改可直接执行的脚本")
        if reasons:
            return self._review(score, *reasons)
        if event_type == "file.accessed":
            return self._safe("Agent 打开了工作区内文件；未读取或保存文件内容")
        if event_type == "file.read":
            return self._safe("ETW 已记录读取路径和字节数；没有检查文件内容", score=3)
        return self._safe("工作区内的普通文件变更")

    def _network_traffic(self, data: dict[str, Any]) -> RiskAssessment:
        if data.get("attribution") in {"other_thread", "other_workspace"}:
            return self._safe("其他 Agent 会话的网络流量，不计入当前会话风险", score=2)
        if data.get("traffic_precision") != "exact_tcp_payload":
            return self._safe("流量大小不可精确归因，未据此判定风险", score=0)
        remote = str(data.get("remote") or "")
        host = remote[1:].split("]:", 1)[0] if remote.startswith("[") and "]:" in remote else remote.rsplit(":", 1)[0]
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback or address.is_private or address.is_link_local:
                return self._safe("本机或内网流量不按数据外传判定", score=2)
        except ValueError:
            pass
        sent = int(data.get("bytes_sent") or 0)
        received = int(data.get("bytes_received") or 0)
        duration = float(data.get("observed_duration_seconds") or 0)
        average_rate = float(data.get("average_send_rate_bps") or 0)
        recent_rate = float(data.get("recent_send_rate_bps") or average_rate)
        ratio = float(data.get("upload_download_ratio") or (sent / max(received, 1)))
        correlation_key = str(data.get("session_id") or "")
        now = time.monotonic()
        sensitive_recently = bool(
            correlation_key
            and now - self.recent_sensitive_access.get(correlation_key, -10_000) <= 600
        )
        reads = self.recent_reads.get(correlation_key, deque())
        while reads and now - reads[0][0] > 120:
            reads.popleft()
        read_bytes = sum(item[1] for item in reads)
        read_files = len({item[2] for item in reads if item[2]})
        mass_read = read_bytes >= 100 * 1024 * 1024 or read_files >= 100
        archive = self.recent_archives.get(correlation_key)
        archive_recently = bool(archive and now - archive[0] <= 300)
        destinations = self.public_destinations.setdefault(correlation_key, {}) if correlation_key else {}
        first_seen = destinations.setdefault(remote, now) if destinations is not None else now
        new_destination = now - first_seen <= 600
        if (
            mass_read
            and archive_recently
            and sent >= 5 * 1024 * 1024
            and recent_rate >= 128 * 1024
            and ratio >= 1.5
        ):
            return self._review(
                96,
                f"同一会话 2 分钟内读取了 {read_files} 个文件 / {read_bytes // (1024 * 1024)} MB",
                "随后启动压缩或归档工具，并向公网持续发送数据",
            )
        if sensitive_recently and sent >= 5 * 1024 * 1024 and recent_rate >= 64 * 1024:
            return self._review(
                92,
                "同一会话近期访问过敏感文件",
                "随后出现持续公网发送行为",
            )
        if (
            mass_read
            and new_destination
            and sent >= 10 * 1024 * 1024
            and recent_rate >= 256 * 1024
            and ratio >= 2
        ):
            return self._review(
                91,
                f"同一会话短时间批量读取 {read_files} 个文件 / {read_bytes // (1024 * 1024)} MB",
                "随后向新出现的公网目标进行明显偏上行传输",
            )
        if sent >= 50 * 1024 * 1024 and recent_rate >= 2 * 1024 * 1024 and ratio >= 3:
            return self._review(86, "短时间高速上传，且上传量明显高于下载量")
        if (
            duration >= 60
            and sent >= 100 * 1024 * 1024
            and average_rate >= 512 * 1024
            and ratio >= 3
        ):
            return self._review(76, "持续较高上传速率，且上下行明显不对称")
        if duration < 10:
            return self._safe("观察时间过短，暂不根据累计流量判定风险", score=5)
        if sent >= 100 * 1024 * 1024 and average_rate < 128 * 1024:
            return self._safe("累计流量较大，但连接持续较久且平均速率平稳", score=8)
        return self._safe("未形成高速、不对称或敏感访问关联等组合证据", score=6)

    def _network(self, data: dict[str, Any]) -> RiskAssessment:
        remote = str(data.get("remote") or "")
        if data.get("attribution") in {"other_thread", "other_workspace"}:
            return self._safe("其他 Agent 会话的连接，不计入当前会话风险", score=2)
        if data.get("attribution") == "unknown":
            return self._safe("连接归属不确定，未强行计入当前会话风险", score=10)
        if data.get("pid") == data.get("session_pid"):
            return self._safe("Agent 主进程自身的服务连接")
        host = remote
        if remote.startswith("[") and "]:" in remote:
            host = remote[1:].split("]:", 1)[0]
        elif ":" in remote:
            host = remote.rsplit(":", 1)[0]
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback or address.is_private or address.is_link_local:
                return self._safe("仅访问本机或内网地址")
        except ValueError:
            pass
        correlation_key = str(data.get("session_id") or "")
        if correlation_key:
            self.public_destinations.setdefault(correlation_key, {}).setdefault(
                remote, time.monotonic()
            )
        return self._safe(
            "仅观察到公网连接；尚无敏感读取、批量读取或异常上传等组合证据",
            score=8,
        )
