import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib import request as urlrequest

from app import build_service
from src.domain import Actor
from src.http_api import create_server


CREATE_DATA = {
    'student_id': 'S-200', 'disability': 'vision', 'service_minutes': 300,
    'delivered_minutes': 0, 'review_due_days': 30, 'goals_count': 2, 'consent': False,
    'guardian_name': '李四家长', 'guardian_contact': '13911112222',
}
FLOW = [
    ('consent', 'parent_rep', {'guardian_confirmed': True, 'consent_scope': '语言训练'}),
    ('activate', 'case_manager', {}),
    ('log_service', 'specialist', {'session_minutes': 90, 'provider': 'SP-9'}),
    ('close', 'administrator', {'review_complete': True}),
]
ERASURE_BODY = json.dumps({
    'data': {
        'request_reference': 'ER-HTTP-1',
        'guardian_authorization': {
            'reference': 'AUTH-HTTP', 'scope': '身份擦除',
            'guardian_confirmed': True, 'confirmed_at': '2026-09-30T10:00:00Z',
        },
    }
})


class HttpApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp.name) / "http.db")
        service = build_service(db_path)
        record = service.create(Actor('cm', 'case_manager'), 'IEP-HTTP', CREATE_DATA)
        for action, role, data in FLOW:
            record = service.act(Actor('op', role), record['id'], record['version'], action, data)
        self.record_id = record['id']
        self.server = create_server("127.0.0.1", 0, service, Path(__file__).resolve().parent.parent / "static")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def _call(self, method, path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urlrequest.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            response = urlrequest.urlopen(req)
            return response.status, json.loads(response.read().decode())
        except Exception as exc:
            payload = json.loads(exc.read().decode())
            return exc.code, payload

    def ADMIN(self):
        return {"X-User-Id": "a1", "X-Role": "admin"}

    def test_erasure_http_idempotency_and_export(self):
        status, body = self._call("POST", "/api/records/%d/erasure" % self.record_id,
                                  json.loads(ERASURE_BODY), self.ADMIN())
        self.assertEqual(status, 201)
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(body["status"], "completed")
        request_id = body["id"]

        status2, body2 = self._call("POST", "/api/records/%d/erasure" % self.record_id,
                                    json.loads(ERASURE_BODY), {"X-User-Id": "a2", "X-Role": "administrator"})
        self.assertEqual(status2, 200)
        self.assertTrue(body2["idempotent_replay"])
        self.assertEqual(body2["id"], request_id)

        # 显式幂等键重复提交同样返回同一结果
        status3, body3 = self._call(
            "POST", "/api/records/%d/erasure" % self.record_id, json.loads(ERASURE_BODY),
            {**self.ADMIN(), "Idempotency-Key": "client-key-1"},
        )
        self.assertEqual(status3, 200)
        self.assertTrue(body3["idempotent_replay"])
        self.assertEqual(body3["id"], request_id)

        status, detail = self._call("GET", "/api/records/%d" % self.record_id, headers=self.ADMIN())
        self.assertEqual(status, 200)
        self.assertEqual(detail["erasure"]["state"], "erased")

        status, export = self._call("GET", "/api/records/%d/export" % self.record_id, headers=self.ADMIN())
        self.assertEqual(status, 200)
        self.assertEqual(export["anonymous_service_events"]["delivered_minutes"], 90)
        erased = {item["field"]: item for item in export["field_disposition"]}
        self.assertEqual(erased["student_id"]["status"], "erased")
        self.assertEqual(erased["disability"]["status"], "retained")

        status, items = self._call("GET", "/api/erasure-requests", headers=self.ADMIN())
        self.assertEqual(status, 200)
        self.assertEqual(len(items["items"]), 1)

    def test_permission_and_legal_hold_http(self):
        status, body = self._call("POST", "/api/records/%d/erasure" % self.record_id,
                                  json.loads(ERASURE_BODY), {"X-User-Id": "cm", "X-Role": "case_manager"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "permission_denied")

        status, body = self._call("POST", "/api/records/%d/legal-hold" % self.record_id,
                                  {"held": True, "reason": "争议调查"}, self.ADMIN())
        self.assertEqual(status, 200)
        self.assertEqual(body["retention_state"], "legal_hold")

        status, body = self._call("POST", "/api/records/%d/erasure" % self.record_id,
                                  json.loads(ERASURE_BODY), self.ADMIN())
        self.assertEqual(status, 409)
        self.assertEqual(body["status"], "frozen")
        self.assertIn("争议", body["frozen_reason"])

        status, body = self._call("GET", "/api/records/%d/export" % self.record_id,
                                  headers={"X-User-Id": "cm", "X-Role": "specialist"})
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
