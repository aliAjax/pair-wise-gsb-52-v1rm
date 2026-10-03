"""SQLite 表结构与事务访问。"""
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .domain import Conflict, NotFound
from .erasure import STATUS_FROZEN, redact_obj


SCHEMA_VERSION = 2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class Repository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reference TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                    action TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS erasure_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id INTEGER NOT NULL,
                    request_key TEXT NOT NULL UNIQUE,
                    request_reference TEXT NOT NULL,
                    authorization TEXT NOT NULL,
                    status TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    identity_fields TEXT NOT NULL,
                    progress TEXT NOT NULL,
                    manifest TEXT,
                    error TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    processed_at TEXT,
                    frozen_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_records_state ON records(state);
                CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_events(record_id, id);
                CREATE INDEX IF NOT EXISTS idx_erasure_record ON erasure_requests(record_id);
                CREATE INDEX IF NOT EXISTS idx_erasure_status ON erasure_requests(status);
                """
            )
            self._migrate(connection)

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """schema 升级与旧数据回填。v2：补法律保留状态字段，缺省一律回填 normal。"""
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(records)")}
        if "retention_state" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN retention_state TEXT NOT NULL DEFAULT 'normal'")
        if "frozen" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN frozen INTEGER NOT NULL DEFAULT 0")
        if "freeze_reason" not in columns:
            connection.execute("ALTER TABLE records ADD COLUMN freeze_reason TEXT")
        applied = {int(row["version"]) for row in connection.execute("SELECT version FROM schema_migrations")}
        if SCHEMA_VERSION not in applied:
            now = _now()
            backfilled = connection.execute(
                "UPDATE records SET retention_state='normal' WHERE retention_state IS NULL OR retention_state=''"
            ).rowcount
            for record_id, in connection.execute("SELECT id FROM records ORDER BY id"):
                connection.execute(
                    "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        record_id,
                        "retention_backfilled",
                        "system-migration",
                        1,
                        _dumps({"summary": "旧数据法律保留状态已回填为normal", "backfilled_batch": backfilled}),
                        now,
                    ),
                )
            connection.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", (SCHEMA_VERSION, now)
            )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        return item

    @staticmethod
    def _request_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        for key in ("authorization", "snapshot", "identity_fields", "progress", "manifest"):
            value = item.get(key)
            item[key] = json.loads(value) if value else ([] if key in ("identity_fields", "progress") else None)
        return item

    def create(self, reference: str, state: str, payload: Dict[str, Any], actor_id: str) -> Dict[str, Any]:
        now = _now()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO records(reference,state,version,payload,created_by,updated_by,created_at,updated_at,retention_state,frozen,freeze_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (reference, state, 1, _dumps(payload), actor_id, actor_id, now, now, "normal", 0, None),
                )
                record_id = int(cursor.lastrowid)
                connection.execute(
                    "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                    (record_id, "created", actor_id, 1, _dumps({"state": state}), now),
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

    def mutate(self, record_id: int, expected_version: int, state: str, payload: Dict[str, Any], actor_id: str, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT version,frozen FROM records WHERE id=?", (record_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise NotFound("记录不存在")
            if int(row["frozen"]):
                connection.rollback()
                raise Conflict("计划已冻结（清退挂起），业务动作暂停")
            if int(row["version"]) != int(expected_version):
                connection.rollback()
                raise Conflict("版本冲突，请刷新后重试")
            version = int(expected_version) + 1
            connection.execute(
                "UPDATE records SET state=?,version=?,payload=?,updated_by=?,updated_at=? WHERE id=?",
                (state, version, _dumps(payload), actor_id, now, record_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, action, actor_id, version, _dumps(details), now),
            )
            result = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            connection.commit()
        return self._row(result)

    def add_audit(self, record_id: int, actor_id: str, action: str, details: Dict[str, Any]) -> None:
        with self._connect() as connection:
            row = connection.execute("SELECT version FROM records WHERE id=?", (record_id,)).fetchone()
            if row is None:
                raise NotFound("记录不存在")
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (record_id, action, actor_id, int(row["version"]), _dumps(details), _now()),
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

    # ---- 法律保留 / 冻结 ----
    def set_legal_hold(self, record_id: int, held: bool, reason: str, actor_id: str) -> Dict[str, Any]:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise NotFound("记录不存在")
            state_value = "legal_hold" if held else "normal"
            frozen_value = 1 if held else 0
            freeze_reason = reason if held else None
            connection.execute(
                "UPDATE records SET retention_state=?,frozen=?,freeze_reason=?,updated_by=?,updated_at=? WHERE id=?",
                (state_value, frozen_value, freeze_reason, actor_id, now, record_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "legal_hold" if held else "legal_hold_released",
                    actor_id,
                    int(row["version"]),
                    _dumps({"summary": ("已设置法律保留/争议冻结：%s" % reason) if held else "法律保留解除，计划恢复可处置"}),
                    now,
                ),
            )
            result = connection.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            connection.commit()
        return self._row(result)

    # ---- 清退处置链 ----
    def create_erasure_request(
        self,
        record_id: int,
        request_key: str,
        request_reference: str,
        authorization: Dict[str, Any],
        snapshot: Dict[str, Any],
        identity_fields: List[str],
        actor_id: str,
        status: str,
        frozen_reason: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        """插入清退请求。命中唯一键时返回已存在请求与 False（重复提交）。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM erasure_requests WHERE request_key=?", (request_key,)
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return self._request_row(existing), False
            try:
                cursor = connection.execute(
                    """INSERT INTO erasure_requests(
                           record_id,request_key,request_reference,authorization,status,snapshot,
                           identity_fields,progress,manifest,error,created_by,created_at,updated_at,
                           processed_at,frozen_reason
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        record_id,
                        request_key,
                        request_reference,
                        _dumps(authorization),
                        status,
                        _dumps(snapshot),
                        _dumps(identity_fields),
                        _dumps([]),
                        None,
                        None,
                        actor_id,
                        now,
                        now,
                        None,
                        frozen_reason,
                    ),
                )
            except sqlite3.IntegrityError:
                # 跨进程并发：另一个管理员已抢先写入，重复提交返回同一结果
                connection.rollback()
                with self._connect() as second:
                    row = second.execute(
                        "SELECT * FROM erasure_requests WHERE request_key=?", (request_key,)
                    ).fetchone()
                return self._request_row(row), False
            row = connection.execute(
                "SELECT * FROM erasure_requests WHERE id=?", (int(cursor.lastrowid),)
            ).fetchone()
            if status == "frozen":
                record_row = connection.execute(
                    "SELECT retention_state FROM records WHERE id=?", (record_id,)
                ).fetchone()
                # 法律保留/争议冻结记录本身；未结复查仅冻结处置链，复查业务动作照常
                if record_row is not None and record_row["retention_state"] == "legal_hold":
                    connection.execute(
                        "UPDATE records SET frozen=1,freeze_reason=? WHERE id=?",
                        (frozen_reason, record_id),
                    )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "erasure_frozen" if status == STATUS_FROZEN else "erasure_requested",
                    actor_id,
                    self._record_version(connection, record_id),
                    _dumps(
                        {
                            "summary": "清退请求已登记，计划冻结等待未结事项" if status == STATUS_FROZEN else "家长清退申请与监护人授权已登记",
                            "request_reference": request_reference,
                            "identity_fields": identity_fields,
                            "frozen_reason": frozen_reason,
                        }
                    ),
                    now,
                ),
            )
            connection.commit()
        return self._request_row(row), True

    @staticmethod
    def _record_version(connection: sqlite3.Connection, record_id: int) -> int:
        row = connection.execute("SELECT version FROM records WHERE id=?", (record_id,)).fetchone()
        return int(row["version"]) if row else 0

    def get_erasure_request(self, request_id: int) -> Dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise NotFound("清退请求不存在")
        return self._request_row(row)

    def get_open_erasure_request(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM erasure_requests WHERE record_id=? AND status IN (?,?,?,?) ORDER BY id DESC LIMIT 1",
                (record_id, "pending", "processing", "frozen", "failed"),
            ).fetchone()
        return self._request_row(row) if row else None

    def find_latest_by_reference(self, record_id: int, request_reference: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM erasure_requests WHERE record_id=? AND request_reference=? ORDER BY id DESC LIMIT 1",
                (record_id, request_reference),
            ).fetchone()
        return self._request_row(row) if row else None

    def find_erasure_request_by_key(self, request_key: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM erasure_requests WHERE request_key=?", (request_key,)
            ).fetchone()
        return self._request_row(row) if row else None

    def list_erasure_requests(self, record_id: Optional[int] = None, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        sql = "SELECT * FROM erasure_requests"
        clauses = []
        params: List[Any] = []
        if record_id is not None:
            clauses.append("record_id=?")
            params.append(record_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._request_row(row) for row in rows]

    def begin_processing(
        self,
        request_id: int,
        snapshot: Dict[str, Any],
        identity_fields: List[str],
        actor_id: str,
    ) -> None:
        """冻结恢复后以当前载荷重建批次快照，进度清零，进入处理中。"""
        now = _now()
        with self._connect() as connection:
            request_row = connection.execute(
                "SELECT record_id FROM erasure_requests WHERE id=?", (request_id,)
            ).fetchone()
            if request_row is None:
                raise NotFound("清退请求不存在")
            record_id = int(request_row["record_id"])
            connection.execute(
                "UPDATE erasure_requests SET status='processing',snapshot=?,identity_fields=?,progress='[]',frozen_reason=NULL,error=NULL,updated_at=? WHERE id=?",
                (_dumps(snapshot), _dumps(identity_fields), now, request_id),
            )
            connection.execute(
                "UPDATE records SET frozen=0,freeze_reason=NULL WHERE id=?",
                (record_id,),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "erasure_resumed",
                    actor_id,
                    self._record_version(connection, record_id),
                    _dumps({"summary": "未结事项解除，清退恢复处理"}),
                    now,
                ),
            )
            connection.commit()

    def apply_erasure_step(
        self,
        record_id: int,
        request_id: int,
        field: str,
        new_payload: Dict[str, Any],
        progress: List[str],
        actor_id: str,
    ) -> None:
        """单字段擦除落库 + 请求进度推进，同一事务，杜绝半途不一致。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE records SET payload=?,updated_by=?,updated_at=? WHERE id=?",
                (_dumps(new_payload), actor_id, now, record_id),
            )
            connection.execute(
                "UPDATE erasure_requests SET progress=?,updated_at=? WHERE id=?",
                (_dumps(progress), now, request_id),
            )
            connection.commit()

    def restore_from_snapshot(self, request_id: int, record_id: int, snapshot: Dict[str, Any], actor_id: str) -> None:
        """从完整批次快照恢复记录载荷，请求进度清零以续做未完成字段。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE records SET payload=?,updated_by=?,updated_at=? WHERE id=?",
                (_dumps(snapshot), actor_id, now, record_id),
            )
            connection.execute(
                "UPDATE erasure_requests SET progress='[]',updated_at=? WHERE id=?",
                (now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "erasure_restored",
                    actor_id,
                    self._record_version(connection, record_id),
                    _dumps({"summary": "擦除失败后已从完整批次快照恢复，将续做未完成字段"}),
                    now,
                ),
            )
            connection.commit()

    def redact_audit_details(self, record_id: int, needles: List[Tuple[str, str]], request_id: int, actor_id: str) -> int:
        """替换审计明细中的身份字符串，审计摘要与时间线结构保留。返回受影响行数。"""
        if not needles:
            return 0
        now = _now()
        touched = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT id,details FROM audit_events WHERE record_id=? ORDER BY id", (record_id,)).fetchall()
            for row in rows:
                details = json.loads(row["details"])
                redacted = redact_obj(details, needles)
                if _dumps(redacted) != _dumps(details):
                    connection.execute("UPDATE audit_events SET details=? WHERE id=?", (_dumps(redacted), row["id"]))
                    touched += 1
            if touched:
                connection.execute(
                    "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        record_id,
                        "audit_redacted",
                        actor_id,
                        self._record_version(connection, record_id),
                        _dumps({"summary": "历史审计中的身份信息已随清退匿名化，审计摘要完整保留", "request_id": request_id, "rows": touched}),
                        now,
                    ),
                )
            connection.commit()
        return touched

    def complete_erasure_request(
        self,
        request_id: int,
        record_id: int,
        final_payload: Dict[str, Any],
        manifest: Dict[str, Any],
        actor_id: str,
    ) -> None:
        """终态提交：载荷写清退清单、请求置完成、写成功审计，同一事务。

        只有调用方完成逐字段一致性校验后才能调用，保证字段状态与审计结论一致。
        """
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE records SET payload=?,updated_by=?,updated_at=? WHERE id=?",
                (_dumps(final_payload), actor_id, now, record_id),
            )
            connection.execute(
                "UPDATE erasure_requests SET status=?,manifest=?,error=NULL,updated_at=?,processed_at=? WHERE id=?",
                ("completed", _dumps(manifest), now, now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "erasure_completed",
                    actor_id,
                    self._record_version(connection, record_id),
                    _dumps(
                        {
                            "summary": "清退完成：身份字段已擦除，匿名服务事件与审计摘要依法保留",
                            "request_reference": manifest["request_reference"],
                            "erased_fields": [item["field"] for item in manifest["erased_fields"]],
                            "retained_fields": [item["field"] for item in manifest["retained_fields"]],
                            "redacted_audit_rows": manifest["redacted_audit_rows"],
                        }
                    ),
                    now,
                ),
            )
            connection.commit()

    def fail_erasure_request(self, request_id: int, record_id: int, error: str, actor_id: str, restored: bool) -> None:
        """失败落账：请求置 failed 并审计；成功审计在任何失败路径上都不写。"""
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE erasure_requests SET status=?,error=?,updated_at=? WHERE id=?",
                ("failed", error[:500], now, request_id),
            )
            connection.execute(
                "INSERT INTO audit_events(record_id,action,actor_id,version,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    record_id,
                    "erasure_failed",
                    actor_id,
                    self._record_version(connection, record_id),
                    _dumps(
                        {
                            "summary": "清退失败，未写入成功结论；已从完整批次快照恢复" if restored else "清退失败，未写入成功结论，可续做未完成字段",
                            "error": error[:500],
                        }
                    ),
                    now,
                ),
            )
            connection.commit()

    def freeze_request(self, request_id: int, reason: str, actor_id: str) -> Dict[str, Any]:
        now = _now()
        with self._connect() as connection:
            connection.execute(
                "UPDATE erasure_requests SET status=?,frozen_reason=?,updated_at=? WHERE id=?",
                (STATUS_FROZEN, reason, now, request_id),
            )
            connection.execute(
                "UPDATE records SET frozen=1,freeze_reason=? WHERE id=(SELECT record_id FROM erasure_requests WHERE id=?)",
                (reason, request_id),
            )
            row = connection.execute("SELECT * FROM erasure_requests WHERE id=?", (request_id,)).fetchone()
            connection.commit()
        return self._request_row(row)
