import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from app import build_service
from src.domain import Actor, Conflict, ErasureInterrupted, PermissionDenied


ADMIN = Actor("admin-1", "administrator")
ADMIN2 = Actor("admin-2", "administrator")
GUARDIAN_DATA = {
    'student_id': 'S-200', 'disability': 'autism', 'service_minutes': 300,
    'delivered_minutes': 0, 'review_due_days': 0, 'goals_count': 2, 'consent': False,
    'guardian_name': '张家长', 'guardian_contact': '13800000000',
}


def close_plan(service, ref, data=GUARDIAN_DATA):
    record = service.create(Actor("creator", "case_manager"), ref, data)
    record = service.act(Actor("p", "parent_rep"), record["id"], record["version"], "consent",
                         {'guardian_confirmed': True, 'consent_scope': '个别化服务'})
    record = service.act(Actor("cm", "case_manager"), record["id"], record["version"], "activate", {})
    record = service.act(Actor("sp", "specialist"), record["id"], record["version"], "log_service",
                         {'session_minutes': 300, 'provider': 'SP-9'})
    record = service.act(Actor("adm", "administrator"), record["id"], record["version"], "close",
                         {'review_complete': True})
    return record


def erasure_body(**overrides):
    body = {
        'request_key': 'REQ-1', 'guardian_request_ref': 'GR-1',
        'authorization_scope': '到期清退身份信息', 'guardian_authorized': True,
        'retention_expired': True,
    }
    body.update(overrides)
    return body


class ErasureHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = build_service(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_expired_plan_erases_identity_but_keeps_service_and_audit(self):
        record = close_plan(self.service, "IEP-30001")
        result = self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result.get("duplicate"))
        self.assertEqual(set(result["erased_fields"]), {"student_id", "guardian_name", "guardian_contact"})

        record = self.service.repository.get(record["id"])
        self.assertEqual(record["state"], "anonymized")
        self.assertEqual(record["retention_state"], "retained_anonymized")
        self.assertEqual(record["disposition_state"], "erased")
        for field in ("student_id", "guardian_name", "guardian_contact"):
            self.assertIsNone(record["payload"][field])
        # 服务与同意事实保留
        self.assertEqual(record["payload"]["delivered_minutes"], 300)
        self.assertTrue(record["payload"]["consent"])
        self.assertEqual(record["payload"]["consent_scope"], "个别化服务")

        timeline = self.service.timeline(ADMIN, record["id"])
        actions = [event["action"] for event in timeline]
        self.assertIn("erasure_requested", actions)
        self.assertEqual(actions[-1], "erasure_completed")
        # 成功审计的上一条是逐字段进度，且任何时刻不存在“未擦完却成功”
        completed = [e for e in timeline if e["action"] == "erasure_completed"][0]
        self.assertEqual(set(completed["details"]["erased_fields"]),
                         {"student_id", "guardian_name", "guardian_contact"})
        # 审计从未被清退连带删除
        self.assertGreaterEqual(len(actions), 8)

    def test_detail_reports_which_fields_erased_and_retained(self):
        record = close_plan(self.service, "IEP-30002")
        self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        detail = self.service.get_record(ADMIN, record["id"])
        by_field = {item["field"]: item for item in detail["identity_fields"]}
        for field in ("student_id", "guardian_name", "guardian_contact"):
            self.assertEqual(by_field[field]["status"], "erased")
            self.assertIn("已擦除", by_field[field]["basis"])
        retained = {item["field"] for item in detail["retained_fields"]}
        self.assertIn("delivered_minutes", retained)
        self.assertIn("consent", retained)
        self.assertIn("consent_scope", retained)

    def test_export_contains_anonymous_service_events_and_audit_summary(self):
        record = close_plan(self.service, "IEP-30003")
        self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        export = self.service.export_record(ADMIN, record["id"])
        self.assertEqual(export["retention"]["state"], "retained_anonymized")
        self.assertEqual(export["service_events"]["delivered_minutes"], 300)
        self.assertEqual(len(export["service_events"]["sessions"]), 1)
        session = export["service_events"]["sessions"][0]
        self.assertNotIn("provider", session)  # 摘要不回传身份相关明细
        self.assertEqual(export["audit_summary"]["count"], len(self.service.timeline(ADMIN, record["id"])))
        for event in export["audit_summary"]["events"]:
            self.assertNotIn("input", event)

    def test_rejected_before_retention_expiry(self):
        record = close_plan(self.service, "IEP-30004")
        with self.assertRaises(Conflict):
            self.service.submit_erasure(ADMIN, record["id"], erasure_body(retention_expired=False))

    def test_anonymized_record_is_read_only(self):
        record = close_plan(self.service, "IEP-30006")
        self.service.submit_erasure(ADMIN, record["id"], erasure_body(request_key="K-6", guardian_request_ref="G-6"))
        with self.assertRaises(Conflict):
            self.service.act(Actor("adm", "administrator"), record["id"], record["version"],
                             "review", {"progress_note": "不应允许"})

    def test_requires_guardian_authorization(self):
        from src.domain import ValidationError
        record = close_plan(self.service, "IEP-30005")
        with self.assertRaises(ValidationError):
            self.service.submit_erasure(ADMIN, record["id"], erasure_body(guardian_authorized=False))


class FreezeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = build_service(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    def _under_review_plan(self, ref):
        record = self.service.create(Actor("creator", "case_manager"), ref, GUARDIAN_DATA)
        record = self.service.act(Actor("p", "parent_rep"), record["id"], record["version"], "consent",
                                  {'guardian_confirmed': True, 'consent_scope': '个别化服务'})
        record = self.service.act(Actor("cm", "case_manager"), record["id"], record["version"], "activate", {})
        record = self.service.act(Actor("adm", "administrator"), record["id"], record["version"], "review",
                                  {'progress_note': '复查中'})
        return record

    def test_erasure_freezes_under_review_and_resumes_on_close(self):
        record = self._under_review_plan("IEP-31001")
        result = self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        self.assertEqual(result["status"], "frozen")
        self.assertIsNone(result.get("result"))

        frozen = self.service.repository.get(record["id"])
        self.assertEqual(frozen["retention_state"], "legal_hold")
        self.assertEqual(frozen["hold_reason"], "open_review")
        # 冻结期间身份信息仍在、详情标注暂缓擦除
        self.assertEqual(frozen["payload"]["student_id"], "S-200")
        detail = self.service.get_record(ADMIN, record["id"])
        self.assertTrue(all(item["status"] == "frozen_pending_erasure" for item in detail["identity_fields"]))

        # 复查走完关闭计划 -> 自动解冻并续做擦除
        record = self.service.act(Actor("adm", "administrator"), record["id"], record["version"], "close",
                                  {'review_complete': True})
        self.assertEqual(record["state"], "anonymized")
        self.assertIsNone(record["payload"]["student_id"])
        request = self.service.repository.latest_erasure_request(record["id"])
        self.assertEqual(request["status"], "completed")

    def test_dispute_plan_freezes_and_resumes_after_resolution(self):
        data = dict(GUARDIAN_DATA, dispute_open=True)
        record = close_plan(self.service, "IEP-31002", data)
        result = self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        self.assertEqual(result["status"], "frozen")
        record = self.service.repository.get(record["id"])
        self.assertEqual(record["hold_reason"], "dispute_open")

        # 普通变更在冻结下被拒
        with self.assertRaises(Conflict):
            self.service.act(Actor("cm", "case_manager"), record["id"], record["version"],
                             "log_service", {'session_minutes': 1, 'provider': 'X'})

        refreshed = self.service.repository.get(record["id"])
        updated = self.service.resolve_dispute(ADMIN, refreshed["id"], refreshed["version"],
                                               {'resolution': '争议核实无误，同意清退'})
        self.assertEqual(updated["state"], "anonymized")
        self.assertIsNone(updated["payload"]["guardian_contact"])
        self.assertFalse(updated["payload"]["dispute_open"])

    def test_export_of_frozen_plan_explains_legal_hold(self):
        record = self._under_review_plan("IEP-31003")
        self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        export = self.service.export_record(ADMIN, record["id"])
        self.assertEqual(export["retention"]["state"], "legal_hold")
        self.assertEqual(export["retention"]["hold_reason"], "open_review")
        statuses = {item["field"]: item["status"] for item in export["identity_fields"]}
        self.assertTrue(all(value == "frozen_pending_erasure" for value in statuses.values()))


class FailureRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = build_service(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_failure_restores_batch_and_resume_completes(self):
        record = close_plan(self.service, "IEP-32001")
        # 内部调用注入失败：在 guardian_name 字段中断
        with self.assertRaises(ErasureInterrupted):
            self._submit_with_failure(record["id"], "guardian_name")

        request = self.service.repository.latest_erasure_request(record["id"])
        self.assertEqual(request["status"], "failed")
        self.assertEqual(request["erased_fields"], ["student_id"])
        self.assertIsNotNone(request["snapshot"])  # 快照仍在，可恢复

        mid = self.service.repository.get(record["id"])
        self.assertIsNone(mid["payload"]["student_id"])              # 已完成字段保持擦除
        self.assertEqual(mid["payload"]["guardian_name"], "张家长")  # 未完成字段从完整批次恢复
        self.assertEqual(mid["payload"]["guardian_contact"], "13800000000")
        timeline = self.service.timeline(ADMIN, record["id"])
        self.assertNotIn("erasure_completed", [e["action"] for e in timeline])
        self.assertIn("erasure_failed", [e["action"] for e in timeline])

        # 续做：从快照重建，只擦未完成字段
        summary = self.service.resume_erasure(ADMIN, request["id"])
        self.assertEqual(summary["status"], "completed")
        final = self.service.repository.get(record["id"])
        for field in ("student_id", "guardian_name", "guardian_contact"):
            self.assertIsNone(final["payload"][field])
        self.assertEqual(final["payload"]["delivered_minutes"], 300)
        request = self.service.repository.get_erasure_request(request["id"])
        self.assertIsNone(request["snapshot"])  # 完成后销毁完整快照

    def test_resume_cannot_claim_success_while_field_remains(self):
        record = close_plan(self.service, "IEP-32002")
        with self.assertRaises(ErasureInterrupted):
            self._submit_with_failure(record["id"], "guardian_contact")
        request = self.service.repository.latest_erasure_request(record["id"])
        # 再次注入失败在最后字段 -> 仍是 failed，绝不出 completed
        summary = self.service.resume_erasure(ADMIN, request["id"], fail_at_field="guardian_contact")
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(self.service.repository.get(record["id"])["payload"]["guardian_contact"], "13800000000")
        summary = self.service.resume_erasure(ADMIN, request["id"])
        self.assertEqual(summary["status"], "completed")

    def test_resume_refreezes_when_dispute_opened_after_failure(self):
        import json as _json
        import sqlite3
        record = close_plan(self.service, "IEP-32003")
        with self.assertRaises(ErasureInterrupted):
            self._submit_with_failure(record["id"], "guardian_name")
        request = self.service.repository.latest_erasure_request(record["id"])
        self.assertEqual(request["status"], "failed")

        # 模拟批次失败后家长新开争议（绕过状态机直接改 payload）
        with sqlite3.connect(self.service.repository.db_path) as conn:
            row = conn.execute("SELECT payload FROM records WHERE id=?", (record["id"],)).fetchone()
            payload = _json.loads(row[0])
            payload["dispute_open"] = True
            conn.execute("UPDATE records SET payload=? WHERE id=?",
                         (_json.dumps(payload, ensure_ascii=False), record["id"]))

        summary = self.service.resume_erasure(ADMIN, request["id"])
        self.assertEqual(summary["status"], "frozen")
        record = self.service.repository.get(record["id"])
        self.assertEqual(record["retention_state"], "legal_hold")
        self.assertEqual(record["hold_reason"], "dispute_open")
        self.assertEqual(record["payload"]["guardian_name"], "张家长")  # 未续擦

    def _submit_with_failure(self, record_id, fail_at):
        actor = ADMIN
        body = erasure_body()
        record = self.service.repository.get(record_id)
        from src import disposition
        snapshot = disposition.snapshot_from_payload(record["payload"])
        _, request = self.service.repository.submit_erasure_request(
            record_id=record_id, request_key=body["request_key"],
            guardian_request_ref=body["guardian_request_ref"], guardian_authorized=True,
            authorization_scope=body["authorization_scope"], retention_expired=True,
            initial_status="processing", snapshot=snapshot,
            identity_fields=disposition.target_identity_fields(snapshot),
            actor_id=actor.user_id, hold_reason=None,
        )
        self.service._run_erasure_batch(request["id"], actor, fail_at_field=fail_at)


class IdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = build_service(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_duplicate_submission_returns_same_result(self):
        record = close_plan(self.service, "IEP-33001")
        first = self.service.submit_erasure(ADMIN, record["id"], erasure_body())
        second = self.service.submit_erasure(ADMIN2, record["id"], erasure_body(request_key="REQ-1"))
        third = self.service.submit_erasure(ADMIN2, record["id"],
                                            erasure_body(request_key="REQ-OTHER", guardian_request_ref="GR-1"))
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["id"], third["id"])
        self.assertTrue(second["duplicate"])
        self.assertTrue(third["duplicate"])
        rows = self.service.repository.list_erasure_requests()
        self.assertEqual(len(rows), 1)

    def test_concurrent_submissions_single_writer(self):
        record = close_plan(self.service, "IEP-33002")
        outcomes = []

        def submit(admin, key):
            # 两个管理员各自使用不同 request_key 但同一家长申请编号
            result = self.service.submit_erasure(admin, record["id"], erasure_body(request_key=key))
            outcomes.append(result)

        t1 = threading.Thread(target=submit, args=(ADMIN, "C-1"))
        t2 = threading.Thread(target=submit, args=(ADMIN2, "C-2"))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes[0]["id"], outcomes[1]["id"])
        self.assertEqual(len(self.service.repository.list_erasure_requests()), 1)
        self.assertEqual(sum(1 for item in outcomes if item.get("duplicate")), 1)
        self.assertTrue(all(item["status"] == "completed" for item in outcomes))

    def test_non_admin_cannot_submit(self):
        record = close_plan(self.service, "IEP-33003")
        with self.assertRaises(PermissionDenied):
            self.service.submit_erasure(Actor("sp", "specialist"), record["id"], erasure_body())


class BackfillTest(unittest.TestCase):
    def test_legacy_db_without_retention_state_is_backfilled(self):
        temp = tempfile.TemporaryDirectory()
        db_path = str(Path(temp.name) / "legacy.db")
        connection = sqlite3.connect(db_path)
        connection.executescript(
            """
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, payload TEXT NOT NULL,
                created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                action TEXT NOT NULL, actor_id TEXT NOT NULL, version INTEGER NOT NULL,
                details TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO records(reference,state,version,payload,created_by,updated_by,created_at,updated_at) "
            "VALUES('OLD-1','closed',1,?,?,?,?,?)",
            (json.dumps({"student_id": "S-OLD"}), "u", "u", "2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00+00:00"),
        )
        connection.commit()
        connection.close()

        service = build_service(db_path)
        record = service.repository.get(1)
        self.assertEqual(record["retention_state"], "retained_until_expiry")
        self.assertTrue(record["retention_backfilled"])
        self.assertEqual(record["disposition_state"], "active")
        timeline = service.timeline(ADMIN, 1)
        self.assertEqual(timeline[0]["action"], "retention_backfilled")

        # 审计表已脱离 CASCADE：清退后审计依旧在
        result = service.submit_erasure(ADMIN, 1, {
            'request_key': 'REQ-OLD', 'guardian_request_ref': 'GR-OLD',
            'authorization_scope': '清退', 'guardian_authorized': True, 'retention_expired': True,
        })
        self.assertEqual(result["status"], "completed")
        timeline = service.timeline(ADMIN, 1)
        self.assertIn("retention_backfilled", [e["action"] for e in timeline])
        self.assertIn("erasure_completed", [e["action"] for e in timeline])

        # 详情/导出说明回填来源
        export = service.export_record(ADMIN, 1)
        self.assertTrue(export["retention"]["backfilled"])
        self.assertIn("回填", export["legal_notice"])
        temp.cleanup()


if __name__ == "__main__":
    unittest.main()
