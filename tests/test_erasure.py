import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from app import build_service
from src.domain import Actor, Conflict, ErasureBlocked, FrozenPlan, PermissionDenied
from src.erasure import ErasureStepError, anonymized_token


CREATE_DATA = {
    'student_id': 'S-100', 'disability': 'hearing', 'service_minutes': 600,
    'delivered_minutes': 120, 'review_due_days': 15, 'goals_count': 4, 'consent': False,
    'guardian_name': '张三家长', 'guardian_contact': '13800000000',
}
FLOW = [
    ('consent', 'parent_rep', {'guardian_confirmed': True, 'consent_scope': '个别化服务'}, 'consented'),
    ('activate', 'case_manager', {}, 'active'),
    ('log_service', 'specialist', {'session_minutes': 60, 'provider': 'SP-3'}, 'active'),
    ('review', 'administrator', {'progress_note': '阶段复盘'}, 'under_review'),
    ('amend', 'case_manager', {'amendment_reason': '调整目标', 'updated_goals': ['目标A', '目标B']}, 'active'),
    ('close', 'administrator', {'review_complete': True}, 'closed'),
]
ADMIN = Actor("admin-1", "admin")
ERASURE_BODY = {
    'request_reference': 'ER-2026-0001',
    'guardian_authorization': {
        'reference': 'AUTH-77', 'scope': '身份信息擦除',
        'guardian_confirmed': True, 'confirmed_at': '2026-09-30T10:00:00+00:00',
    },
}


def closed_plan(service, guardian=True, data=None):
    create_data = dict(data if data is not None else CREATE_DATA)
    if not guardian:
        create_data.pop('guardian_name', None)
        create_data.pop('guardian_contact', None)
    record = service.create(Actor("creator", "case_manager"), "IEP-28001", create_data)
    for action, role, payload, _ in FLOW:
        record = service.act(Actor("operator", role), record["id"], record["version"], action, payload)
    return record


class ErasureChainTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp.name) / "test.db")
        self.service = build_service(self.db_path)

    def tearDown(self):
        self.temp.cleanup()

    def test_erasure_keeps_service_and_audit_but_wipes_identity(self):
        record = closed_plan(self.service)
        # 历史审计明细中出现过学生身份值
        self.service.repository.add_audit(
            record["id"], "case_manager", "note",
            {"summary": "学生S-100家长张三家长到场确认", "ref": "S-100"},
        )
        result = self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["completed_fields"], ["student_id", "guardian_name", "guardian_contact"])

        detail = self.service.get_record(ADMIN, record["id"])
        payload = detail["payload"]
        self.assertEqual(payload["student_id"], anonymized_token(record["id"]))
        self.assertIsNone(payload["guardian_name"])
        self.assertIsNone(payload["guardian_contact"])
        # 匿名服务事件与同意事实保留
        self.assertEqual(payload["delivered_minutes"], 180)
        self.assertTrue(payload["consent"])
        self.assertEqual(payload["consent_scope"], "个别化服务")
        self.assertEqual(payload["plan_status"], "closed")
        self.assertEqual(payload["last_provider"], "SP-3")

        disposition = {item["field"]: item for item in detail["erasure"]["field_disposition"]}
        self.assertEqual(disposition["student_id"]["status"], "erased")
        self.assertEqual(disposition["guardian_contact"]["status"], "erased")
        self.assertEqual(disposition["service_minutes"]["status"], "retained")
        self.assertIn("basis", disposition["delivered_minutes"])
        self.assertGreaterEqual(detail["erasure"]["redacted_audit_rows"], 1)
        self.assertEqual(detail["erasure"]["request_reference"], "ER-2026-0001")
        self.assertEqual(detail["erasure"]["guardian_authorization"]["reference"], "AUTH-77")

        timeline = self.service.timeline(ADMIN, record["id"])
        actions = [event["action"] for event in timeline]
        self.assertIn("erasure_requested", actions)
        self.assertIn("erasure_completed", actions)
        self.assertIn("audit_redacted", actions)
        self.assertNotIn("erasure_failed", actions)
        # 审计时间线仍可证明服务发生过
        self.assertIn("log_service", actions)
        # 历史审计不再含身份值，摘要结构保留
        raw_timeline = json.dumps(timeline, ensure_ascii=False)
        self.assertNotIn("S-100", raw_timeline)
        self.assertNotIn("张三家长", raw_timeline)
        self.assertIn("ANON-%06d" % record["id"], raw_timeline)
        self.assertTrue(any(
            event["action"] == "note" and "到场确认" in json.dumps(event["details"], ensure_ascii=False)
            for event in timeline
        ))

        export = self.service.export_record(ADMIN, record["id"])
        self.assertEqual(export["anonymous_service_events"]["delivered_minutes"], 180)
        self.assertTrue(export["guardian_consent_retained"]["consent"])
        self.assertTrue(any(event["action"] == "erasure_completed" for event in export["audit_summary"]))
        self.assertTrue(any(item["field"] == "student_id" and item["status"] == "erased"
                            for item in export["field_disposition"]))
        self.assertTrue(any(item["field"] == "progress_note" and item["status"] == "retained"
                            for item in export["field_disposition"]))

    def test_under_review_is_frozen_then_resumes(self):
        record = self.service.create(Actor("creator", "case_manager"), "IEP-28001", CREATE_DATA)
        for action, role, payload, expected in FLOW[:4]:
            record = self.service.act(Actor("operator", role), record["id"], record["version"], action, payload)
        self.assertEqual(record["state"], "under_review")

        result = self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        self.assertEqual(result["status"], "frozen")
        self.assertIn("复查", result["frozen_reason"])

        # 未解除前恢复仍被拒
        with self.assertRaises(FrozenPlan):
            self.service.resume_erasure(ADMIN, result["id"])

        # 完成复查路径：amend -> close 后恢复清退
        record = self.service.act(Actor("operator", "case_manager"), record["id"], record["version"],
                                  "amend", {"amendment_reason": "调整目标", "updated_goals": ["目标A"]})
        record = self.service.act(Actor("operator", "administrator"), record["id"], record["version"],
                                  "close", {"review_complete": True})
        result = self.service.resume_erasure(ADMIN, result["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.service.get_record(ADMIN, record["id"])["payload"]["student_id"],
                         anonymized_token(record["id"]))

    def test_legal_hold_freezes_record_and_request(self):
        record = closed_plan(self.service)
        self.service.set_legal_hold(Actor("admin-2", "administrator"), record["id"], True, "家长投诉争议调查中")

        held = self.service.get_record(ADMIN, record["id"])
        self.assertEqual(held["retention_state"], "legal_hold")
        # 冻结期间业务动作被拒绝
        with self.assertRaises(Conflict):
            self.service.act(Actor("creator", "case_manager"), record["id"], 1, "amend",
                             {"amendment_reason": "x", "updated_goals": ["g"]})

        result = self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        self.assertEqual(result["status"], "frozen")
        self.assertIn("争议", result["frozen_reason"])

        # 解除法律保留后续做
        self.service.set_legal_hold(ADMIN, record["id"], False, "")
        result = self.service.resume_erasure(ADMIN, result["id"])
        self.assertEqual(result["status"], "completed")

    def test_unclosed_plan_is_blocked(self):
        record = self.service.create(Actor("creator", "case_manager"), "IEP-28001", CREATE_DATA)
        record = self.service.act(Actor("p", "parent_rep"), record["id"], record["version"],
                                  "consent", {"guardian_confirmed": True, "consent_scope": "x"})
        with self.assertRaises(ErasureBlocked):
            self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)

    def test_duplicate_submission_returns_same_result(self):
        record = closed_plan(self.service)
        first = self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        second = self.service.submit_erasure(Actor("admin-9", "administrator"), record["id"], ERASURE_BODY)
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(second["status"], "completed")
        requests = self.service.list_erasure_requests(ADMIN, record_id=record["id"])
        self.assertEqual(len(requests), 1)

    def test_open_request_blocks_second_distinct_request(self):
        record = self.service.create(Actor("creator", "case_manager"), "IEP-28001", CREATE_DATA)
        for action, role, payload, _ in FLOW[:4]:
            record = self.service.act(Actor("operator", role), record["id"], record["version"], action, payload)
        frozen = self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        self.assertEqual(frozen["status"], "frozen")
        other = {
            'request_reference': 'ER-2026-0002',
            'guardian_authorization': dict(ERASURE_BODY['guardian_authorization'], reference='AUTH-88'),
        }
        with self.assertRaises(Conflict):
            self.service.submit_erasure(ADMIN, record["id"], other)

    def test_concurrent_submissions_single_write(self):
        record = closed_plan(self.service)
        results = []
        errors = []

        def submit(actor):
            try:
                results.append(self.service.submit_erasure(actor, record["id"], ERASURE_BODY))
            except Exception as exc:  # pragma: no cover - 失败即暴露并发缺陷
                errors.append(exc)

        threads = [threading.Thread(target=submit, args=(Actor("admin-%d" % i, "admin"),)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        self.assertEqual({item["id"] for item in results}, {results[0]["id"]})
        self.assertEqual(sum(1 for item in results if not item["idempotent_replay"]), 1)
        requests = self.service.list_erasure_requests(ADMIN)
        self.assertEqual(len(requests), 1)

    def test_crash_after_partial_step_resumes_from_progress(self):
        record = closed_plan(self.service)
        # 第一个字段提交后模拟进程崩溃
        self.service.crash_after_step = 1
        with self.assertRaises(ErasureStepError):
            self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)

        request = self.service.list_erasure_requests(ADMIN, record_id=record["id"])[0]
        # 第一个字段已落库（student_id 已匿名），请求停在 processing，绝无成功审计
        payload = self.service.repository.get(record["id"])["payload"]
        self.assertEqual(payload["student_id"], anonymized_token(record["id"]))
        self.assertEqual(request["status"], "processing")
        self.assertEqual(request["completed_fields"], ["student_id"])
        actions = [e["action"] for e in self.service.timeline(ADMIN, record["id"])]
        self.assertNotIn("erasure_completed", actions)
        self.assertNotIn("erasure_failed", actions)

        # 新进程：续做未完成字段，得到相同最终结果
        service2 = build_service(self.db_path)
        result = service2.resume_erasure(ADMIN, request["id"])
        self.assertEqual(result["status"], "completed")
        payload = service2.repository.get(record["id"])["payload"]
        self.assertIsNone(payload["guardian_name"])
        self.assertIsNone(payload["guardian_contact"])
        timeline = service2.timeline(ADMIN, record["id"])
        self.assertEqual([e["action"] for e in timeline].count("erasure_completed"), 1)

    def test_step_failure_marked_failed_and_no_false_success(self):
        record = closed_plan(self.service)
        with mock.patch.object(
            self.service.repository, "apply_erasure_step",
            side_effect=sqlite3.OperationalError("disk I/O error"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)

        request = self.service.list_erasure_requests(ADMIN, record_id=record["id"])[0]
        self.assertEqual(request["status"], "failed")
        self.assertIn("disk I/O", request["error"])
        actions = [e["action"] for e in self.service.timeline(ADMIN, record["id"])]
        self.assertIn("erasure_failed", actions)
        self.assertNotIn("erasure_completed", actions)
        # 身份字段未被擦（失败前事务回滚）
        payload = self.service.repository.get(record["id"])["payload"]
        self.assertEqual(payload["student_id"], "S-100")

        # 续做：恢复后从头完成
        result = self.service.resume_erasure(ADMIN, request["id"])
        self.assertEqual(result["status"], "completed")

    def test_drift_is_restored_from_full_batch_before_continue(self):
        record = closed_plan(self.service)
        self.service.crash_after_step = 1
        with self.assertRaises(ErasureStepError):
            self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        request = self.service.list_erasure_requests(ADMIN, record_id=record["id"])[0]

        # 运维误操作直接改了载荷，与批次进度不一致
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT payload FROM records WHERE id=?", (record["id"],)).fetchone()
            payload = json.loads(row[0])
            payload["student_id"] = "S-TAMPERED"
            conn.execute("UPDATE records SET payload=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), record["id"]))
            conn.commit()

        service2 = build_service(self.db_path)
        result = service2.resume_erasure(ADMIN, request["id"])
        self.assertEqual(result["status"], "completed")
        final = service2.repository.get(record["id"])["payload"]
        self.assertEqual(final["student_id"], anonymized_token(record["id"]))
        self.assertIsNone(final["guardian_name"])
        actions = [e["action"] for e in service2.timeline(ADMIN, record["id"])]
        self.assertIn("erasure_restored", actions)
        self.assertEqual(actions.count("erasure_completed"), 1)
        # 保留字段未被恢复动作破坏
        self.assertEqual(final["delivered_minutes"], 180)

    def test_verify_failure_restores_and_reports_failed(self):
        record = closed_plan(self.service)
        self.service.crash_after_step = 1
        with self.assertRaises(ErasureStepError):
            self.service.submit_erasure(ADMIN, record["id"], ERASURE_BODY)
        request = self.service.list_erasure_requests(ADMIN, record_id=record["id"])[0]

        with mock.patch("src.service.verify_completion", side_effect=ErasureStepError("核对不一致")):
            with self.assertRaises(ErasureStepError):
                self.service.resume_erasure(ADMIN, request["id"])

        failed = self.service.get_erasure_request(ADMIN, request["id"])
        self.assertEqual(failed["status"], "failed")
        actions = [e["action"] for e in self.service.timeline(ADMIN, record["id"])]
        self.assertIn("erasure_restored", actions)
        self.assertIn("erasure_failed", actions)
        self.assertNotIn("erasure_completed", actions)
        # 恢复后身份字段回到批次原状（完整身份，无半擦状态）
        payload = self.service.repository.get(record["id"])["payload"]
        self.assertEqual(payload["student_id"], "S-100")
        self.assertEqual(payload["guardian_name"], "张三家长")

    def test_authorization_required(self):
        record = closed_plan(self.service)
        body = {"request_reference": "ER-X"}
        from src.domain import ValidationError
        with self.assertRaises(ValidationError):
            self.service.submit_erasure(ADMIN, record["id"], body)
        body = dict(ERASURE_BODY)
        body = {"request_reference": "ER-X",
                "guardian_authorization": dict(ERASURE_BODY["guardian_authorization"], guardian_confirmed=False)}
        with self.assertRaises(ValidationError):
            self.service.submit_erasure(ADMIN, record["id"], body)

    def test_permission_denied_for_non_admin(self):
        record = closed_plan(self.service)
        with self.assertRaises(PermissionDenied):
            self.service.submit_erasure(Actor("cm", "case_manager"), record["id"], ERASURE_BODY)
        with self.assertRaises(PermissionDenied):
            self.service.export_record(Actor("cm", "case_manager"), record["id"])
        with self.assertRaises(PermissionDenied):
            self.service.set_legal_hold(Actor("cm", "case_manager"), record["id"], True, "争议")


class MigrationBackfillTest(unittest.TestCase):
    def test_legacy_data_retention_state_backfilled_and_audited(self):
        temp = tempfile.TemporaryDirectory()
        db_path = str(Path(temp.name) / "legacy.db")
        now = "2026-01-01T00:00:00+00:00"
        with sqlite3.connect(db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, payload TEXT NOT NULL,
                    created_by TEXT NOT NULL, updated_by TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL,
                    version INTEGER NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO records(reference,state,version,payload,created_by,updated_by,created_at,updated_at)"
                " VALUES('IEP-OLD','closed',1,?,?,?,?,?)",
                ('{"plan_status":"closed","student_id":"S-OLD"}', "u", "u", now, now),
            )
            conn.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at)"
                " VALUES(1,'created','u',1,'{}',?)",
                (now,),
            )
            conn.commit()

        service = build_service(db_path)
        record = service.repository.get(1)
        self.assertEqual(record["retention_state"], "normal")
        self.assertEqual(record["frozen"], 0)
        timeline = service.timeline(Actor("a", "admin"), 1)
        self.assertTrue(any(event["action"] == "retention_backfilled" for event in timeline))
        # 回填幂等：重启不重复回填
        build_service(db_path)
        service3 = build_service(db_path)
        timeline3 = service3.timeline(Actor("a", "admin"), 1)
        self.assertEqual([e["action"] for e in timeline3].count("retention_backfilled"), 1)

        # 详情对旧数据同样逐字段说明
        detail = service3.get_record(Actor("a", "admin"), 1)
        disposition = {item["field"]: item for item in detail["erasure"]["field_disposition"]}
        self.assertEqual(disposition["student_id"]["status"], "present")
        self.assertEqual(disposition["plan_status"]["status"], "present")
        self.assertIn("basis", disposition["plan_status"])
        temp.cleanup()


if __name__ == "__main__":
    unittest.main()
