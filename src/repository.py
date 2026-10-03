"""SQLite 表结构与事务访问。"""
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .domain import Conflict, NotFound


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    # ---------------------------------------------------------------- schema

    def _init_schema(self) -> None:
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='records'"
            ).fetchone()
            if not exists:
                self._create_fresh(connection)
            else:
                self._migrate_legacy(connection)

    @staticmethod
    def _create_fresh(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                payload TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                retention_state TEXT NOT NULL DEFAULT 'retained_until_expiry',
                hold_reason TEXT,
                disposition_state TEXT NOT NULL DEFAULT 'active',
                erased_fields TEXT NOT NULL DEFAULT '[]',
                retention_backfilled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL REFERENCES records(id),
                action TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE erasure_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL REFERENCES records(id),
                request_key TEXT NOT NULL UNIQUE,
                guardian_request_ref TEXT NOT NULL,
                guardian_authorized INTEGER NOT NULL,
                authorization_scope TEXT NOT NULL DEFAULT '',
                retention_expired INTEGER NOT NULL,
                status TEXT NOT NULL,
                identity_fields TEXT NOT NULL,
                erased_fields TEXT NOT NULL DEFAULT '[]',
                snapshot TEXT,
                result TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                UNIQUE(record_id, guardian_request_ref)
            );
            CREATE INDEX IF NOT EXISTS idx_records_state ON records(state);
            CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_events(record_id, id);
            CREATE INDEX IF NOT EXISTS idx_erasure_record ON erasure_requests(record_id, id);
            """
        )

    def _migrate_legacy(self, connection: sqlite3.Connection) -> None:
        """旧库：补齐法定保留列并回填；审计表改为无 ON DELETE CASCADE（清退不连带删审计）。"""
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(records)")}
        added: List[str] = []
        if "retention_state" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN retention_state TEXT")
            added.append("retention_state")
        if "hold_reason" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN hold_reason TEXT")
        if "disposition_state" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN disposition_state TEXT")
            added.append("disposition_state")
        if "erased_fields" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN erased_fields TEXT")
            added.append("erased_fields")
        if "retention_backfilled" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN retention_backfilled INTEGER NOT NULL DEFAULT 0")
            added.append("retention_backfilled")

        if added:
            # 旧数据缺少法律保留状态：先回填，再补审计依据
            now = _now()
            rows = connection.execute("SELECT id FROM records").fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE records SET retention_state='retained_until_expiry', "
                    "disposition_state='active', erased_fields='[]', retention_backfilled=1 WHERE id=?",
                    (row["id"],),
                )
                connection.execute(
                    "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (row["id"], "retention_backfilled", "system", 0,
                     json.dumps({"summary": "旧数据缺少法律保留状态，已回填为法定保留期内",
                                 "retention_state": "retained_until_expiry"},
                                ensure_ascii=False, sort_keys=True), now),
                )

        # 审计表若带 ON DELETE CASCADE 则重建，保证清退永远不会连带清掉审计
        ddl = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'"
        ).fetchone()
        if ddl and "ON DELETE CASCADE" in (ddl["sql"] or "").upper():
            connection.executescript(
                """
                CREATE TABLE audit_events_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL REFERENCES records(id),
                    action TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO audit_events_new(id,record_id,action,actor_id,version,details,created_at)
                SELECT id,record_id,action,actor_id,version,details,created_at FROM audit_events;
                DROP TABLE audit_events;
                ALTER TABLE audit_events_new RENAME TO audit_events;
                CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_events(record_id, id);
                """
            )

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS erasure_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL REFERENCES records(id),
                request_key TEXT NOT NULL UNIQUE,
                guardian_request_ref TEXT NOT NULL,
                guardian_authorized INTEGER NOT NULL,
                authorization_scope TEXT NOT NULL DEFAULT '',
                retention_expired INTEGER NOT NULL,
                status TEXT NOT NULL,
                identity_fields TEXT NOT NULL,
                erased_fields TEXT NOT NULL DEFAULT '[]',
                snapshot TEXT,
                result TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                UNIQUE(record_id, guardian_request_ref)
            );
            CREATE INDEX IF NOT EXISTS idx_records_state ON records(state);
            CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_events(record_id, id);
            CREATE INDEX IF NOT EXISTS idx_erasure_record ON erasure_requests(record_id, id);
            """
        )

    # ------------------------------------------------------------- (de)serialize

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        item["erased_fields"] = json.loads(item.get("erased_fields") or "[]")
        item["retention_backfilled"] = bool(item.get("retention_backfilled"))
        return item

    @staticmethod
    def _erasure_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["guardian_authorized"] = bool(item["guardian_authorized"])
        item["retention_expired"] = bool(item["retention_expired"])
        item["identity_fields"] = json.loads(item["identity_fields"])
        item["erased_fields"] = json.loads(item["erased_fields"] or "[]")
        item["snapshot"] = json.loads(item["snapshot"]) if item.get("snapshot") else None
        item["result"] = json.loads(item["result"]) if item.get("result") else None
        return item

    # ----------------------------------------------------------------- records

    def create(self, reference: str, state: str, payload: Dict[str, Any], actor_id: str) -> Dict[str, Any]:
        now = _now()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO records(reference,state,version,payload,created_by,updated_by,"
                    "created_at,updated_at,retention_state,hold_reason,disposition_state,"
                    "erased_fields,retention_backfilled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)",
                    (reference, state, 1, json.dumps(payload, ensure_ascii=False, sort_keys=True),
                     actor_id, actor_id, now, now, "retained_until_expiry", None, "active", "[]"),
                )
                record_id = int(cursor.lastrowid)
                connection.execute(
                    "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                    (record_id, "created", actor_id, 1, json.dumps({"state": state}, ensure_ascii=False, sort_keys=True), now),
                )
                row = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        except sqlite3.IntegrityError as exc:
            raise Conflict("reference已存在") from exc
        return self._row(row)

    def get(self, record_id: int) -> Dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise NotFound("记录不存在")
        return self._row(row)

    def list_records(self, state: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as connection:
            if state:
                rows = connection.execute("SELECT * FROM records WHERE state=? ORDER BY id DESC LIMIT ?", (state, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM records ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(row) for row in rows]

    def mutate(self, record_id: int, expected_version: int, state: str, payload: Dict[str, Any], actor_id: str, action: str, details: Dict[str, Any], allow_frozen: bool = False) -> Dict[str, Any]:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT version, disposition_state FROM records WHERE id=?", (record_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise NotFound("记录不存在")
            if int(row["version"]) != int(expected_version):
                connection.rollback()
                raise Conflict("版本冲突，请刷新后重试")
            if row["disposition_state"] == "frozen" and not allow_frozen:
                connection.rollback()
                raise Conflict("计划处于法律冻结状态，复查/争议解除前不得变更")
            if row["disposition_state"] == "erased":
                connection.rollback()
                raise Conflict("计划已完成清退匿名化，只保留匿名只读资料，不得变更")
            version = int(expected_version) + 1
            connection.execute(
                "UPDATE records SET state=?,version=?,payload=?,updated_by=?,updated_at=? WHERE id=?",
                (state, version, json.dumps(payload, ensure_ascii=False, sort_keys=True), actor_id, now, record_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, action, actor_id, version, json.dumps(details, ensure_ascii=False, sort_keys=True), now),
            )
            result = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            connection.commit()
        return self._row(result)

    def resolve_dispute(self, record_id: int, expected_version: int, actor_id: str, resolution: str) -> Dict[str, Any]:
        """管理员解除争议：只改争议标记，版本递增并审计；冻结记录经由此路径解冻。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT version, state, payload FROM records WHERE id=?", (record_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise NotFound("记录不存在")
            if int(row["version"]) != int(expected_version):
                connection.rollback()
                raise Conflict("版本冲突，请刷新后重试")
            payload = json.loads(row["payload"])
            if not payload.get("dispute_open"):
                connection.rollback()
                raise Conflict("该计划没有待解决的争议")
            payload["dispute_open"] = False
            payload["dispute_resolution"] = resolution
            version = int(row["version"]) + 1
            connection.execute(
                "UPDATE records SET version=?,payload=?,updated_by=?,updated_at=? WHERE id=?",
                (version, json.dumps(payload, ensure_ascii=False, sort_keys=True), actor_id, now, record_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, "dispute_resolved", actor_id, version,
                 json.dumps({"summary": "争议已解除，清退冻结可继续", "resolution": resolution}, ensure_ascii=False, sort_keys=True), now),
            )
            result = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            connection.commit()
        return self._row(result)

    # ------------------------------------------------------------------ audit

    def add_audit(self, record_id: int, actor_id: str, action: str, details: Dict[str, Any], version: int = None) -> None:
        with self._connect() as connection:
            if version is None:
                row = connection.execute("SELECT version FROM records WHERE id=?", (record_id,)).fetchone()
                if row is None:
                    raise NotFound("记录不存在")
                version = int(row["version"])
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, action, actor_id, version, json.dumps(details, ensure_ascii=False, sort_keys=True), _now()),
            )

    def audit_timeline(self, record_id: int) -> List[Dict[str, Any]]:
        self.get(record_id)
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events WHERE record_id=? ORDER BY id", (record_id,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item["details"])
            result.append(item)
        return result

    def stats(self) -> Dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute("SELECT state, COUNT(*) AS total FROM records GROUP BY state").fetchall()
        return {str(row["state"]): int(row["total"]) for row in rows}

    def health(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # -------------------------------------------------------- erasure requests

    def find_erasure_request(self, record_id: int, request_key: Optional[str], guardian_request_ref: Optional[str]) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = None
            if request_key:
                row = connection.execute("SELECT * FROM erasure_requests WHERE request_key=?", (request_key,)).fetchone()
            if row is None and guardian_request_ref:
                row = connection.execute(
                    "SELECT * FROM erasure_requests WHERE record_id=? AND guardian_request_ref=?",
                    (record_id, guardian_request_ref),
                ).fetchone()
        return self._erasure_row(row) if row else None

    def get_erasure_request(self, request_id: int) -> Dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise NotFound("清退请求不存在")
        return self._erasure_row(row)

    def list_erasure_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM erasure_requests ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._erasure_row(row) for row in rows]

    def latest_erasure_request(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM erasure_requests WHERE record_id=? ORDER BY id DESC LIMIT 1",
                (record_id,),
            ).fetchone()
        return self._erasure_row(row) if row else None

    def submit_erasure_request(self, record_id: int, request_key: str, guardian_request_ref: str,
                               guardian_authorized: bool, authorization_scope: str, retention_expired: bool,
                               initial_status: str, snapshot: Dict[str, Any], identity_fields: List[str],
                               actor_id: str, hold_reason: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        """原子受理：锁记录、查重（request_key 与 家长申请编号双重幂等）、写请求与审计。

        返回 ("created", request) 或 ("duplicate", existing)。
        """
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            record = connection.execute("SELECT id, version FROM records WHERE id=?", (record_id,)).fetchone()
            if record is None:
                connection.rollback()
                raise NotFound("记录不存在")
            existing = connection.execute(
                "SELECT * FROM erasure_requests WHERE request_key=? OR "
                "(record_id=? AND guardian_request_ref=?)",
                (request_key, record_id, guardian_request_ref),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return "duplicate", self._erasure_row(existing)

            if initial_status == "frozen":
                connection.execute(
                    "UPDATE records SET retention_state='legal_hold', hold_reason=?, "
                    "disposition_state='frozen', updated_by=?, updated_at=? WHERE id=?",
                    (hold_reason, actor_id, now, record_id),
                )
            try:
                cursor = connection.execute(
                    "INSERT INTO erasure_requests(record_id,request_key,guardian_request_ref,guardian_authorized,"
                    "authorization_scope,retention_expired,status,identity_fields,erased_fields,snapshot,result,"
                    "created_by,created_at,updated_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record_id, request_key, guardian_request_ref, 1 if guardian_authorized else 0,
                     authorization_scope, 1 if retention_expired else 0, initial_status,
                     json.dumps(identity_fields, ensure_ascii=False), "[]",
                     json.dumps(snapshot, ensure_ascii=False, sort_keys=True), None,
                     actor_id, now, now, None),
                )
            except sqlite3.IntegrityError:
                # 并发下另一个管理员已写入：转为幂等返回同一请求
                connection.rollback()
                with self._connect() as other:
                    existing = other.execute(
                        "SELECT * FROM erasure_requests WHERE request_key=? OR "
                        "(record_id=? AND guardian_request_ref=?)",
                        (request_key, record_id, guardian_request_ref),
                    ).fetchone()
                return "duplicate", self._erasure_row(existing)
            request_id = int(cursor.lastrowid)
            frozen_summary = "清退请求已受理：未结复查/争议，计划冻结，擦除暂缓" if initial_status == "frozen" \
                else "家长清退申请与授权已受理，进入处置链"
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, "erasure_frozen" if initial_status == "frozen" else "erasure_requested",
                 actor_id, int(record["version"]),
                 json.dumps({"summary": frozen_summary, "erasure_request_id": request_id,
                             "guardian_request_ref": guardian_request_ref,
                             "guardian_authorized": guardian_authorized,
                             "authorization_scope": authorization_scope,
                             "hold_reason": hold_reason}, ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return "created", self._erasure_row(row)

    def apply_erasure_field(self, request_id: int, field: str, actor_id: str) -> Dict[str, Any]:
        """逐字段擦除（一个字段一个事务，失败不污染已完成字段）。

        以请求检查点为准：仅当字段尚未擦除时，把记录 payload 中该字段置空，
        并把字段追加进请求 erased_fields，同时写进度审计。
        """
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            if request is None:
                connection.rollback()
                raise NotFound("清退请求不存在")
            erased_fields = json.loads(request["erased_fields"] or "[]")
            record = connection.execute("SELECT version, payload FROM records WHERE id=?", (request["record_id"],)).fetchone()
            if record is None:
                connection.rollback()
                raise NotFound("记录不存在")
            if field in erased_fields:
                connection.rollback()
                return self._erasure_row(request)
            payload = json.loads(record["payload"])
            payload[field] = None
            erased_fields.append(field)
            connection.execute(
                "UPDATE records SET payload=?, updated_by=?, updated_at=? WHERE id=?",
                (json.dumps(payload, ensure_ascii=False, sort_keys=True), actor_id, now, request["record_id"]),
            )
            pending = [f for f in json.loads(request["identity_fields"]) if f not in erased_fields]
            connection.execute(
                "UPDATE erasure_requests SET erased_fields=?, status='processing', updated_at=? WHERE id=?",
                (json.dumps(erased_fields, ensure_ascii=False), now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (request["record_id"], "erasure_progress", actor_id, int(record["version"]),
                 json.dumps({"summary": "清退批次进度：身份字段%s已擦除" % field, "field": field,
                             "erased_fields": erased_fields, "pending_fields": pending},
                            ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._erasure_row(row)

    def fail_erasure(self, request_id: int, failed_field: str, actor_id: str, message: str) -> Dict[str, Any]:
        """批次中断：以「完整快照 + 已完成检查点」重建一致基线，审计声明失败而非成功。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            if request is None:
                connection.rollback()
                raise NotFound("清退请求不存在")
            snapshot = json.loads(request["snapshot"])
            erased_fields = json.loads(request["erased_fields"] or "[]")
            # 已完成字段保持擦除，其余字段从完整批次恢复 -> 不会出现半擦且审计说成功
            baseline = dict(snapshot)
            for field in erased_fields:
                baseline[field] = None
            record = connection.execute("SELECT version FROM records WHERE id=?", (request["record_id"],)).fetchone()
            connection.execute(
                "UPDATE records SET payload=?, updated_by=?, updated_at=? WHERE id=?",
                (json.dumps(baseline, ensure_ascii=False, sort_keys=True), actor_id, now, request["record_id"]),
            )
            pending = [f for f in json.loads(request["identity_fields"]) if f not in erased_fields]
            result = {"outcome": "failed", "failed_at_field": failed_field, "message": message,
                      "erased_fields": erased_fields, "pending_fields": pending,
                      "note": "批次中断，可从完整批次快照续做未完成字段；审计未声明成功"}
            connection.execute(
                "UPDATE erasure_requests SET status='failed', result=?, updated_at=? WHERE id=?",
                (json.dumps(result, ensure_ascii=False, sort_keys=True), now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (request["record_id"], "erasure_failed", actor_id, int(record["version"]),
                 json.dumps({"summary": "清退批次在字段%s处中断，等待续做" % failed_field,
                             "failed_at_field": failed_field, "erased_fields": erased_fields,
                             "pending_fields": pending}, ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._erasure_row(row)

    def complete_erasure(self, request_id: int, actor_id: str) -> Dict[str, Any]:
        """整批完成：最终核对全部身份字段已擦除后，单事务提交匿名态与成功审计。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            if request is None:
                connection.rollback()
                raise NotFound("清退请求不存在")
            identity_fields = json.loads(request["identity_fields"])
            erased_fields = json.loads(request["erased_fields"] or "[]")
            not_done = [f for f in identity_fields if f not in erased_fields]
            if not_done:
                connection.rollback()
                raise Conflict("仍有身份字段未擦除，不能声明完成：%s" % ",".join(not_done))

            record = connection.execute("SELECT version, payload FROM records WHERE id=?", (request["record_id"],)).fetchone()
            if record is None:
                connection.rollback()
                raise NotFound("记录不存在")
            current_payload = json.loads(record["payload"])
            # 保留字段以记录最新值为准（冻结期间的复查/修订不得被提交时旧快照覆盖）；
            # 完整快照只负责失败恢复与身份字段范围认定。
            final_payload = dict(current_payload)
            for field in identity_fields:
                final_payload[field] = None
            # 最终一致性闸门：任何身份字段未空都不得成功，杜绝“字段已擦而审计说成功”的反例
            leak = [f for f in identity_fields if final_payload.get(f) is not None]
            if leak:
                connection.rollback()
                raise Conflict("身份字段尚未擦除，禁止完成擦除：%s" % ",".join(leak))

            version = int(record["version"]) + 1
            connection.execute(
                "UPDATE records SET state='anonymized', version=?, payload=?, updated_by=?, updated_at=?, "
                "retention_state='retained_anonymized', hold_reason=NULL, disposition_state='erased', "
                "erased_fields=? WHERE id=?",
                (version, json.dumps(final_payload, ensure_ascii=False, sort_keys=True), actor_id, now,
                 json.dumps(identity_fields, ensure_ascii=False), request["record_id"]),
            )
            result = {"outcome": "completed", "erased_fields": identity_fields,
                      "retained": "匿名服务事件、家长授权事实与审计摘要依法保留",
                      "note": "完整批次快照已销毁，身份信息不可恢复"}
            connection.execute(
                "UPDATE erasure_requests SET status='completed', result=?, snapshot=NULL, "
                "updated_at=?, completed_at=? WHERE id=?",
                (json.dumps(result, ensure_ascii=False, sort_keys=True), now, now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (request["record_id"], "erasure_completed", actor_id, version,
                 json.dumps({"summary": "清退处置完成：身份信息已擦除，匿名服务事件与审计摘要保留",
                             "erased_fields": identity_fields,
                             "retention_state": "retained_anonymized"}, ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._erasure_row(row)

    def freeze_for_hold(self, request_id: int, actor_id: str, hold_reason: str) -> Dict[str, Any]:
        """复查中/争议出现：把已受理的请求与计划一并冻结。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            if request is None:
                connection.rollback()
                raise NotFound("清退请求不存在")
            record = connection.execute("SELECT version FROM records WHERE id=?", (request["record_id"],)).fetchone()
            connection.execute(
                "UPDATE records SET retention_state='legal_hold', hold_reason=?, disposition_state='frozen', "
                "updated_by=?, updated_at=? WHERE id=?",
                (hold_reason, actor_id, now, request["record_id"]),
            )
            connection.execute("UPDATE erasure_requests SET status='frozen', updated_at=? WHERE id=?", (now, request_id))
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (request["record_id"], "erasure_frozen", actor_id, int(record["version"]),
                 json.dumps({"summary": "出现未结复查/争议，清退请求冻结", "hold_reason": hold_reason},
                            ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._erasure_row(row)

    def release_hold(self, request_id: int, actor_id: str, resolution_note: str) -> Dict[str, Any]:
        """解除冻结：记录恢复法定保留基线，请求进入可续做状态。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            if request is None:
                connection.rollback()
                raise NotFound("清退请求不存在")
            record = connection.execute(
                "SELECT version, state, payload FROM records WHERE id=?", (request["record_id"],)
            ).fetchone()
            connection.execute(
                "UPDATE records SET retention_state='retained_until_expiry', hold_reason=NULL, "
                "disposition_state='active', updated_by=?, updated_at=? WHERE id=?",
                (actor_id, now, request["record_id"]),
            )
            new_status = "resumable" if request["status"] in {"frozen", "failed"} else request["status"]
            connection.execute("UPDATE erasure_requests SET status=?, updated_at=? WHERE id=?", (new_status, now, request_id))
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (request["record_id"], "hold_released", actor_id, int(record["version"]),
                 json.dumps({"summary": "复查/争议已解除，清退冻结释放，可续做擦除",
                             "note": resolution_note}, ensure_ascii=False, sort_keys=True), now),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._erasure_row(row)
