from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from agentguard.attribution import SessionAttributor
from agentguard.deep import FileAccessTracker, classify_observed_file, human_bytes
from agentguard.file_etw import EtwFileReadTracker
from agentguard.extended import ActivityCorrelator, DnsEtwTracker, RegistryEtwTracker, SystemChangeTracker, windows_process_security
from agentguard.monitor import EventSink, FileTracker, ProcessTracker, redact_argv
from agentguard.ui import ScreeningState, format_event
from agentguard.risk import RiskAssessor


class RedactionTests(unittest.TestCase):
    def test_redacts_flags_and_token_shapes(self) -> None:
        argv = [
            "tool",
            "--api-key",
            "secret-value",
            "--token=another-secret",
            "sk-abcdefghijklmnopqrstuvwxyz",
            "ghp_abcdefghijklmnopqrstuvwxyz",
        ]
        redacted = redact_argv(argv)
        self.assertNotIn("secret-value", redacted)
        self.assertEqual(redacted[2], "[REDACTED]")
        self.assertEqual(redacted[3], "--token=[REDACTED]")
        self.assertEqual(redacted[4], "[REDACTED]")
        self.assertEqual(redacted[5], "[REDACTED]")


class SessionAttributionTests(unittest.TestCase):
    def test_thread_id_separates_parallel_codex_conversations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "current"
            root.mkdir()
            other = Path(directory) / "other"
            other.mkdir()
            attributor = SessionAttributor(root, current_thread_id="thread-current")
            thread_ids = {10: None, 11: "thread-current", 12: "thread-other"}
            attributor._thread_id = lambda pid, _created: thread_ids[pid]
            result = attributor.build(
                {
                    10: ({"pid": 10, "ppid": 1, "cwd": None, "create_time": 1.0}, 10),
                    11: ({"pid": 11, "ppid": 10, "cwd": str(root), "create_time": 2.0}, 10),
                    12: ({"pid": 12, "ppid": 10, "cwd": str(other), "create_time": 3.0}, 10),
                },
                {10},
            )
            self.assertEqual(result[10]["attribution"], "shared")
            self.assertEqual(result[11]["attribution"], "current_thread")
            self.assertEqual(result[12]["attribution"], "other_thread")
            self.assertEqual(result[11]["attribution_confidence"], "high")

    def test_process_roots_follow_selected_workspace(self) -> None:
        tracker = ProcessTracker(
            object(), {"codex.exe"}, set(), False, Path(r"D:\WorkPlace"), None
        )
        processes = {
            26168: {"pid": 26168, "ppid": 1, "name": "codex.exe", "cwd": r"D:\Microsoft VS Code"},
            33016: {"pid": 33016, "ppid": 1, "name": "codex.exe", "cwd": r"C:\Program Files\Codex"},
            16476: {"pid": 16476, "ppid": 33016, "name": "NVIDIA Overlay.exe", "cwd": r"D:\WorkPlace\Defuze\Desktop-Application\app\engine"},
        }
        self.assertEqual(tracker._roots(processes), {33016})


class RegistryAttributionTests(unittest.TestCase):
    TARGETS = (("HKLM", r"SOFTWARE\Microsoft\SystemCertificates", "系统证书", 82),)

    def test_registry_write_is_attributed_to_current_agent(self) -> None:
        tracker = RegistryEtwTracker(self.TARGETS)
        tracker.update_targets(
            {42},
            {42: {"attribution": "current_thread", "attribution_label": "当前会话", "attribution_confidence": "high"}},
        )
        tracker._on_event((6, {
            "EventHeader": {"ProcessId": 42},
            "KeyName": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates",
            "EventName": "RegSetValue",
        }))
        record = tracker.match(r"HKLM\SOFTWARE\Microsoft\SystemCertificates")
        self.assertIsNotNone(record)
        self.assertEqual(record["pid"], 42)
        self.assertEqual(record["attribution"]["attribution"], "current_thread")

    def test_registry_write_from_unknown_process_is_not_agent_attributed(self) -> None:
        tracker = RegistryEtwTracker(self.TARGETS)
        tracker.update_targets(set(), {})
        tracker._on_event((6, {
            "EventHeader": {"ProcessId": 99},
            "KeyName": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates",
            "EventName": "RegSetValue",
        }))
        record = tracker.match(r"HKLM\SOFTWARE\Microsoft\SystemCertificates")
        self.assertIsNotNone(record)
        self.assertEqual(record["attribution"]["attribution"], "external_process")

    def test_only_current_agent_write_keeps_registry_change_reviewable(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events = []

            def emit(self, event_type, **data) -> None:
                self.events.append((event_type, data))

        sink = Sink()
        activity = RegistryEtwTracker(self.TARGETS)
        activity.update_targets(
            {42},
            {42: {"attribution": "current_thread", "attribution_label": "当前会话", "attribution_confidence": "high"}},
        )
        activity._on_event((6, {
            "EventHeader": {"ProcessId": 42},
            "KeyName": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\SystemCertificates",
            "EventName": "RegSetValue",
        }))
        tracker = SystemChangeTracker(sink, registry_activity=activity)
        tracker._emit(
            component="系统证书", action="registry_metadata_changed",
            path=r"HKLM\SOFTWARE\Microsoft\SystemCertificates", risk_score=82,
            reasons=["系统证书注册表元数据发生变化"],
        )
        self.assertTrue(sink.events[0][1]["needs_review"])
        self.assertEqual(sink.events[0][1]["pid"], 42)

        sink.events.clear()
        tracker = SystemChangeTracker(sink, registry_activity=RegistryEtwTracker(self.TARGETS))
        tracker._emit(
            component="系统证书", action="registry_metadata_changed",
            path=r"HKLM\SOFTWARE\Microsoft\SystemCertificates", risk_score=82,
            reasons=["系统证书注册表元数据发生变化"],
        )
        self.assertFalse(sink.events[0][1]["needs_review"])


class FileTrackerTests(unittest.TestCase):
    def test_create_modify_delete_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root.parent / (root.name + "-events")
            sink = EventSink(output, {"root": str(root), "started_at": "test", "root_pids": []})
            tracker = FileTracker(root, sink)
            target = root / "sample.txt"

            target.write_text("one\n", encoding="utf-8")
            tracker.poll()
            time.sleep(0.002)
            target.write_text("two\n", encoding="utf-8")
            tracker.poll()
            target.unlink()
            tracker.poll()
            sink.close()

            events = [
                json.loads(line)
                for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            types = [event["type"] for event in events]
            self.assertEqual(types, ["file.created", "file.modified", "file.deleted"])
            self.assertTrue(all(event["scope"] == "workspace" for event in events))
            self.assertIn("-one", events[1]["diff"])
            self.assertIn("+two", events[1]["diff"])

    def test_external_sensitive_open_is_classified_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            tracker = FileAccessTracker(root, object())
            classified = tracker._classify(str(Path(directory) / ".ssh" / "id_ed25519"))
            self.assertIsNotNone(classified)
            self.assertEqual(classified[1:], ("external", True))

    def test_external_non_sensitive_path_can_be_classified_for_write_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            classified = classify_observed_file(
                root,
                str(Path(directory) / "outside.txt"),
                include_external=True,
            )
            self.assertIsNotNone(classified)
            self.assertEqual(classified[1:], ("external", False))

    def test_etw_read_events_are_aggregated_without_file_content(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events = []

            def emit(self, event_type, **data) -> None:
                self.events.append({"type": event_type, **data})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.txt"
            target.write_text("private content", encoding="utf-8")
            sink = Sink()
            tracker = EtwFileReadTracker(root, sink)
            attribution = {
                "session_id": "thread:test",
                "attribution": "current_thread",
                "attribution_label": "当前会话",
            }
            tracker.update_targets({123}, {123: 100}, {123: attribution}, {123: "tool.exe"})
            header = lambda opcode: {
                "ProcessId": 123,
                "EventDescriptor": {"Opcode": opcode},
            }
            tracker._on_event(
                (0, {"Task Name": "FILEIO", "EventHeader": header(64), "FileObject": "obj", "OpenPath": str(target)})
            )
            tracker._on_event(
                (0, {"Task Name": "FILEIO", "EventHeader": header(67), "FileObject": "obj", "IoSize": "7"})
            )
            tracker._on_event(
                (0, {"Task Name": "FILEIO", "EventHeader": header(67), "FileObject": "obj", "IoSize": "5"})
            )
            tracker.flush(force=True)
            self.assertEqual(len(sink.events), 1)
            self.assertEqual(sink.events[0]["type"], "file.read")
            self.assertEqual(sink.events[0]["path"], "sample.txt")
            self.assertEqual(sink.events[0]["bytes_read"], 12)
            self.assertEqual(sink.events[0]["read_operations"], 2)
            self.assertNotIn("private content", json.dumps(sink.events))

    def test_etw_external_write_create_delete_are_metadata_only(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events = []

            def emit(self, event_type, **data) -> None:
                self.events.append({"type": event_type, **data})

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            target = base / "outside.txt"
            sink = Sink()
            tracker = EtwFileReadTracker(root, sink)
            attribution = {"session_id": "thread:external", "attribution": "current_thread"}
            tracker.update_targets({123}, {123: 100}, {123: attribution}, {123: "tool.exe"})
            header = lambda opcode: {
                "ProcessId": 123,
                "EventDescriptor": {"Opcode": opcode},
            }
            tracker._on_event((0, {"Task Name": "FILEIO", "EventHeader": header(64), "FileObject": "obj", "OpenPath": str(target), "CreateDisposition": 2}))
            tracker._on_event((0, {"Task Name": "FILEIO", "EventHeader": header(68), "FileObject": "obj", "IoSize": 11}))
            tracker.flush(force=True)
            tracker._on_event((0, {"Task Name": "FILEIO", "EventHeader": header(70), "FileObject": "obj"}))
            types = [event["type"] for event in sink.events]
            self.assertEqual(types, ["file.created", "file.modified", "file.deleted"])
            self.assertEqual(sink.events[1]["bytes_written"], 11)
            self.assertEqual(sink.events[1]["scope"], "external")
            self.assertNotIn("content", json.dumps(sink.events))


class UiFormattingTests(unittest.TestCase):
    def test_formats_core_event_types(self) -> None:
        self.assertEqual(
            format_event({"type": "file.modified", "path": "app.py"}),
            ("文件", "修改 app.py"),
        )
        self.assertEqual(
            format_event({"type": "network.opened", "remote": "1.2.3.4:443"}),
            ("公网", "连接 1.2.3.4:443"),
        )
        self.assertEqual(
            format_event({"type": "file.accessed", "path": ".ssh/id_ed25519", "scope": "external"}),
            ("文件", "外部敏感文件 .ssh/id_ed25519"),
        )
        self.assertEqual(human_bytes(5 * 1024 * 1024), "5.0 MB")
        self.assertEqual(
            format_event({"type": "file.read", "path": "src/app.py", "bytes_read": 4096}),
            ("文件", "读取 src/app.py · 4.0 KB"),
        )
        self.assertEqual(
            format_event({"type": "system.changed", "component": "启动项", "action": "modified", "path": "HKCU\\Run"}),
            ("系统", "启动项 · modified · HKCU\\Run"),
        )

    def test_repeated_public_network_risk_is_grouped(self) -> None:
        state = ScreeningState(Path("."))
        for sequence, remote in enumerate(("1.1.1.1:443", "8.8.8.8:443"), start=1):
            state.consume(
                {
                    "sequence": sequence,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "type": "network.opened",
                    "pid": 20 + sequence,
                    "session_pid": 10,
                    "remote": remote,
                    "risk": {
                        "level": "review",
                        "score": 55,
                        "severity": "medium",
                        "reasons": ["Agent 子工具正在访问公网地址"],
                    },
                }
            )
        snapshot = state.snapshot()
        self.assertEqual(snapshot["counts"]["review"], 1)
        self.assertEqual(snapshot["attention"][0]["occurrences"], 2)
        self.assertEqual(snapshot["attention"][0]["category_key"], "network")
        self.assertEqual(len(snapshot["attention"][0]["targets"]), 2)
        self.assertEqual(snapshot["kind_counts"]["network"], 1)

    def test_marking_attention_reviewed_keeps_it_in_history(self) -> None:
        state = ScreeningState(Path("."))
        state.consume(
            {
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "type": "system.changed",
                "component": "系统证书",
                "action": "registry_metadata_changed",
                "path": "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates",
                "risk": {"level": "review", "score": 82, "severity": "high", "reasons": ["测试"]},
            }
        )
        item_id = state.snapshot()["attention"][0]["id"]
        state.dismiss(item_id)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["attention"], [])
        self.assertEqual(len(snapshot["reviewed"]), 1)
        self.assertTrue(snapshot["reviewed"][0]["reviewed"])

    def test_category_history_is_not_evicted_by_other_categories(self) -> None:
        state = ScreeningState(Path("."))
        for sequence in range(60):
            state.consume(
                {
                    "sequence": sequence,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "type": "network.opened",
                    "pid": sequence + 1,
                    "remote": f"8.8.8.{(sequence % 200) + 1}:443",
                    "risk": {"level": "safe", "score": 1, "severity": "low", "reasons": ["test"]},
                }
            )
        state.consume(
            {
                "sequence": 61,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "type": "file.read",
                "pid": 99,
                "path": "src/app.py",
                "bytes_read": 10,
                "risk": {"level": "safe", "score": 1, "severity": "low", "reasons": ["test"]},
            }
        )
        snapshot = state.snapshot()
        self.assertEqual(len(snapshot["recent_by_category"]["file"]), 1)

    def test_user_can_confirm_workspace_session_for_future_operations(self) -> None:
        state = ScreeningState(Path("."))
        event = {
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "type": "file.modified",
            "path": "src/app.py",
            "workspace_path": str(Path(".").resolve()),
            "attribution": "current_workspace",
            "attribution_label": "当前工作区·会话未确认",
            "attribution_confidence": "low",
            "risk": {"level": "safe", "score": 1, "severity": "low", "reasons": ["test"]},
        }
        state.consume(event)
        item_id = state.snapshot()["recent"][0]["id"]
        self.assertTrue(state.confirm_session(item_id))
        confirmed = state.snapshot()["recent"][0]
        self.assertEqual(confirmed["attribution_label"], "当前工作区·会话已确认")
        self.assertTrue(confirmed["session_confirmed"])

        event["sequence"] = 2
        event["path"] = "src/other.py"
        state.consume(event)
        self.assertTrue(state.snapshot()["recent"][0]["session_confirmed"])


class RiskAssessorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assessor = RiskAssessor(Path("."))

    def test_normal_workspace_edit_is_safe(self) -> None:
        result = self.assessor.assess("file.modified", {"path": "src/app.py"})
        self.assertEqual(result.level, "safe")

    def test_delete_and_sensitive_file_need_attention(self) -> None:
        deleted = self.assessor.assess("file.deleted", {"path": "src/app.py"})
        secret = self.assessor.assess("file.modified", {"path": ".env"})
        self.assertEqual(deleted.level, "review")
        self.assertEqual(secret.level, "review")
        self.assertGreaterEqual(secret.score, 80)

    def test_dangerous_command_needs_attention(self) -> None:
        result = self.assessor.assess(
            "process.started",
            {"argv": ["git", "reset", "--hard"]},
        )
        self.assertEqual(result.level, "review")
        self.assertGreaterEqual(result.score, 80)

    def test_powershell_format_table_is_not_disk_format(self) -> None:
        result = self.assessor.assess(
            "process.started",
            {"argv": ["powershell", "Get-Process", "|", "Format-Table"]},
        )
        self.assertEqual(result.level, "safe")

    def test_public_connection_alone_is_safe_for_agent_and_child(self) -> None:
        agent = self.assessor.assess(
            "network.opened",
            {"pid": 10, "session_pid": 10, "remote": "8.8.8.8:443"},
        )
        child = self.assessor.assess(
            "network.opened",
            {"pid": 11, "session_pid": 10, "remote": "8.8.8.8:443"},
        )
        self.assertEqual(agent.level, "safe")
        self.assertEqual(child.level, "safe")

    def test_other_thread_network_is_not_charged_to_current_thread(self) -> None:
        result = self.assessor.assess(
            "network.opened",
            {
                "pid": 11,
                "session_pid": 10,
                "remote": "8.8.8.8:443",
                "attribution": "other_thread",
            },
        )
        self.assertEqual(result.level, "safe")

    def test_external_sensitive_read_and_large_upload_need_attention(self) -> None:
        opened = self.assessor.assess(
            "file.accessed",
            {
                "path": r"C:\\Users\\me\\.ssh\\id_ed25519",
                "scope": "external",
                "session_id": "thread:test-sensitive",
            },
        )
        upload = self.assessor.assess(
            "network.traffic",
            {
                "traffic_precision": "exact_tcp_payload",
                "bytes_sent": 8 * 1024 * 1024,
                "bytes_received": 512 * 1024,
                "observed_duration_seconds": 30,
                "average_send_rate_bps": 300 * 1024,
                "recent_send_rate_bps": 512 * 1024,
                "upload_download_ratio": 16,
                "remote": "1.2.3.4:443",
                "session_id": "thread:test-sensitive",
            },
        )
        self.assertEqual(opened.level, "review")
        self.assertGreaterEqual(opened.score, 90)
        self.assertEqual(upload.level, "review")
        self.assertGreaterEqual(upload.score, 90)

    def test_any_external_file_read_is_high_risk(self) -> None:
        result = self.assessor.assess(
            "file.read",
            {"path": r"C:\\Users\\me\\Documents\\notes.txt", "scope": "external"},
        )
        self.assertEqual(result.level, "review")
        self.assertGreaterEqual(result.score, 80)

    def test_external_create_modify_delete_are_attention(self) -> None:
        for event_type in ("file.created", "file.modified", "file.deleted"):
            result = self.assessor.assess(
                event_type,
                {"path": r"C:\\Users\\me\\Documents\\outside.txt", "scope": "external"},
            )
            self.assertEqual(result.level, "review")
            self.assertGreaterEqual(result.score, 80)

    def test_large_but_slow_long_lived_transfer_is_safe(self) -> None:
        result = self.assessor.assess(
            "network.traffic",
            {
                "traffic_precision": "exact_tcp_payload",
                "bytes_sent": 500 * 1024 * 1024,
                "bytes_received": 100 * 1024 * 1024,
                "observed_duration_seconds": 4 * 60 * 60,
                "average_send_rate_bps": 37 * 1024,
                "recent_send_rate_bps": 40 * 1024,
                "upload_download_ratio": 5,
                "remote": "1.2.3.4:443",
                "session_id": "thread:slow-normal",
            },
        )
        self.assertEqual(result.level, "safe")

    def test_fast_asymmetric_upload_needs_attention(self) -> None:
        result = self.assessor.assess(
            "network.traffic",
            {
                "traffic_precision": "exact_tcp_payload",
                "bytes_sent": 80 * 1024 * 1024,
                "bytes_received": 10 * 1024 * 1024,
                "observed_duration_seconds": 25,
                "average_send_rate_bps": 3 * 1024 * 1024,
                "recent_send_rate_bps": 4 * 1024 * 1024,
                "upload_download_ratio": 8,
                "remote": "1.2.3.4:443",
                "session_id": "thread:burst",
            },
        )
        self.assertEqual(result.level, "review")
        self.assertGreaterEqual(result.score, 80)

    def test_mass_read_archive_then_upload_forms_high_risk_chain(self) -> None:
        for index in range(100):
            self.assessor.assess(
                "file.read",
                {
                    "path": f"dataset/file-{index}.bin",
                    "bytes_read": 1024,
                    "session_id": "thread:chain",
                },
            )
        self.assessor.assess(
            "process.started",
            {
                "name": "7z.exe",
                "argv": ["7z", "a", "bundle.7z", "dataset"],
                "session_id": "thread:chain",
            },
        )
        result = self.assessor.assess(
            "network.traffic",
            {
                "traffic_precision": "exact_tcp_payload",
                "bytes_sent": 12 * 1024 * 1024,
                "bytes_received": 512 * 1024,
                "observed_duration_seconds": 30,
                "average_send_rate_bps": 400 * 1024,
                "recent_send_rate_bps": 512 * 1024,
                "upload_download_ratio": 24,
                "remote": "9.9.9.9:443",
                "session_id": "thread:chain",
            },
        )
        self.assertEqual(result.level, "review")
        self.assertGreaterEqual(result.score, 95)
        self.assertTrue(any("压缩" in reason for reason in result.reasons))

    def test_declared_system_behavior_uses_explainable_score(self) -> None:
        result = self.assessor.assess(
            "system.changed",
            {"needs_review": True, "risk_score": 84, "reasons": ["hosts 文件发生变化"]},
        )
        self.assertEqual(result.level, "review")
        self.assertEqual(result.score, 84)


class ExtendedMonitoringTests(unittest.TestCase):
    def test_supply_privacy_and_destructive_sequences_create_derived_events(self) -> None:
        correlator = ActivityCorrelator()
        supply = correlator.observe(
            {
                "type": "process.started",
                "name": "npm.cmd",
                "argv": ["npm", "install", "left-pad"],
                "session_id": "thread:x",
            }
        )
        self.assertTrue(any(kind == "supply_chain.operation" for kind, _ in supply))
        cloud = correlator.observe(
            {
                "type": "process.started",
                "name": "kubectl.exe",
                "argv": ["kubectl", "apply", "-f", "deployment.yaml"],
                "session_id": "thread:cloud",
            }
        )
        self.assertTrue(any(kind == "supply_chain.operation" for kind, _ in cloud))
        privacy = correlator.observe(
            {
                "type": "process.started",
                "name": "powershell.exe",
                "argv": ["powershell", "Get-Clipboard"],
                "session_id": "thread:privacy",
            }
        )
        self.assertTrue(any(kind == "privacy.access" for kind, _ in privacy))
        derived = []
        for index in range(5):
            derived.extend(
                correlator.observe(
                    {
                        "type": "file.deleted",
                        "path": f"src/{index}.txt",
                        "session_id": "thread:delete",
                    }
                )
            )
        alert = next(data for kind, data in derived if kind == "behavior.detected")
        self.assertGreaterEqual(alert["risk_score"], 90)

        modified = []
        for index in range(5):
            modified.extend(
                correlator.observe(
                    {
                        "type": "file.modified",
                        "path": f"src/changed-{index}.txt",
                        "session_id": "thread:bulk-modify",
                    }
                )
            )
        bulk_alert = next(data for kind, data in modified if kind == "behavior.detected")
        self.assertEqual(bulk_alert["behavior"], "bulk_files")
        self.assertGreaterEqual(bulk_alert["risk_score"], 70)

    def test_permission_metadata_is_screened_without_reading_contents(self) -> None:
        result = RiskAssessor(Path(".")).assess(
            "file.permissions_changed",
            {"path": "scripts/run.ps1", "mode_before": "0o644", "mode_after": "0o755"},
        )
        self.assertEqual(result.level, "review")
        self.assertIn("权限", result.reasons[0])

    def test_dns_and_tls_etw_metadata_are_filtered_by_agent_pid(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events = []

            def emit(self, event_type, **data) -> None:
                self.events.append({"type": event_type, **data})

        sink = Sink()
        tracker = DnsEtwTracker(sink)
        tracker.update_targets({123}, {123: 100}, {123: {"session_id": "thread:dns"}})
        tracker._on_event(
            (3006, {"EventHeader": {"ProcessId": 123, "ProviderId": tracker.PROVIDER_GUID}, "QueryName": "example.com"})
        )
        tracker._on_event(
            (36874, {"EventHeader": {"ProcessId": 123, "ProviderId": tracker.SCHANNEL_GUID}, "TargetName": "api.example.com", "Protocol": "TLS 1.3"})
        )
        self.assertEqual([event["type"] for event in sink.events], ["network.dns", "network.tls"])

    @unittest.skipUnless(os.name == "nt", "Windows token metadata")
    def test_process_security_returns_metadata_without_token_contents(self) -> None:
        result = windows_process_security(os.getpid())
        self.assertIn(result.get("integrity_level"), {"low", "medium", "high", "system"})
        self.assertIn("elevated", result)


if __name__ == "__main__":
    unittest.main()
