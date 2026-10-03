"""业务用例编排、权限检查、乐观并发与审计。"""
import hashlib
import threading
from typing import Any, Dict, List, Optional

from .audit import AuditRecorder
from .domain import Actor, Conflict, FrozenPlan, PermissionDenied, ValidationError, text
from .erasure import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_FROZEN,
    STATUS_PROCESSING,
    ErasureStepError,
    build_manifest,
    disposition_from_manifest,
    disposition_from_payload,
    erase_field_value,
    evaluate_record,
    expected_payload,
    identity_needles,
    payloads_consistent,
    present_identity_fields,
    validate_request_payload,
    verify_completion,
)
from .repository import Repository, _now
from .rules import DomainRules


ERASURE_ROLES = {'admin', 'administrator'}
HOLD_ROLES = {'admin', 'administrator'}
EXPORT_ROLES = {'admin', 'administrator'}
# 服务事件：可匿名化后依法保留的非身份字段
SERVICE_EVENT_FIELDS = (
    "disability", "service_minutes", "delivered_minutes", "missing_minutes", "compliance_rate",
    "goals_count", "updated_goals", "progress_note", "amendment_reason",
    "review_overdue", "plan_status", "last_provider",
)
# 授权与同意事实：证明服务经监护人同意开展，依法保留
CONSENT_FIELDS = ("consent", "consent_scope")


class Service:
    def __init__(self, repository: Repository, rules: DomainRules, audit: AuditRecorder = None) -> None:
        self.repository = repository
        self.rules = rules
        self.audit = audit or AuditRecorder(repository)
        self._request_locks_guard = threading.Lock()
        self._request_locks: Dict[str, threading.Lock] = {}
        # 故障注入：单字段步骤提交后模拟进程崩溃，用于验证批次恢复（仅测试使用）
        self.crash_after_step: int = -1

    def _key_lock(self, key: str) -> threading.Lock:
        with self._request_locks_guard:
            lock = self._request_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._request_locks[key] = lock
            return lock

    @staticmethod
    def _actor(actor: Actor) -> Actor:
        if actor is None or not actor.user_id.strip() or not actor.role.strip():
            raise PermissionDenied("缺少调用身份")
        return actor

    def _ensure_known_role(self, actor: Actor) -> None:
        if not self.rules.known_role(actor.role):
            raise PermissionDenied("角色无权访问该服务")

    def create(self, actor: Actor, reference: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if not self.rules.role_can_create(actor.role):
            raise PermissionDenied("角色无权创建记录")
        reference = text({"reference": reference}, "reference")
        prepared = self.rules.prepare_create(payload or {})
        self.rules.check_create_conflicts(prepared, self.repository.list_records(limit=500))
        return self.repository.create(reference, self.rules.INITIAL_STATE, prepared, actor.user_id)

    def _enrich(self, record: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(record)
        payload = record["payload"]
        manifest = payload.get("_erasure")
        record["payload"] = {key: value for key, value in payload.items() if not key.startswith("_")}
        if manifest:
            record["erasure"] = {
                "state": "erased",
                "request_reference": manifest.get("request_reference"),
                "guardian_authorization": manifest.get("guardian_authorization"),
                "completed_at": manifest.get("completed_at"),
                "redacted_audit_rows": manifest.get("redacted_audit_rows"),
                "field_disposition": disposition_from_manifest(manifest),
                "legal_note": manifest.get("legal_note"),
            }
        else:
            record["erasure"] = {
                "state": "active",
                "retention_state": record.get("retention_state", "normal"),
                "field_disposition": disposition_from_payload(record["payload"]),
                "legal_note": "清退申请获批并到期后，仅擦除身份字段，服务事件与审计摘要依法保留。",
            }
        return record

    def list_records(self, actor: Actor, state: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return [self._enrich(item) for item in self.repository.list_records(state=state, limit=limit)]

    def get_record(self, actor: Actor, record_id: int) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self._enrich(self.repository.get(record_id))

    def act(self, actor: Actor, record_id: int, expected_version: int, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        action = text({"action": action}, "action")
        if not self.rules.role_can_action(actor.role, action):
            raise PermissionDenied("角色无权执行该操作")
        record = self.repository.get(record_id)
        self.rules.require_transition(record, action)
        new_state, new_payload, summary = self.rules.apply_action(record, action, data or {})
        return self._enrich(
            self.repository.mutate(
                record_id=record_id,
                expected_version=int(expected_version),
                state=new_state,
                payload=new_payload,
                actor_id=actor.user_id,
                action=action,
                details={"summary": summary, "input": data or {}, "from": record["state"], "to": new_state},
            )
        )

    def timeline(self, actor: Actor, record_id: int) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self.audit.timeline(record_id)

    def stats(self, actor: Actor) -> Dict[str, int]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self.repository.stats()

    # ---- 法律保留 / 争议冻结 ----
    def set_legal_hold(self, actor: Actor, record_id: int, held: bool, reason: str) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if actor.role not in HOLD_ROLES:
            raise PermissionDenied("角色无权设置法律保留")
        if held:
            reason = text({"reason": reason}, "reason")
        return self._enrich(self.repository.set_legal_hold(record_id, held, reason if held else "", actor.user_id))

    # ---- 清退处置链 ----
    @staticmethod
    def _request_key(record_id: int, request_reference: str, authorization_reference: str) -> str:
        digest = hashlib.sha256(
            ("%s|%s|%s" % (record_id, request_reference, authorization_reference)).encode("utf-8")
        ).hexdigest()
        return "erasure-%s-%s" % (record_id, digest[:16])

    def submit_erasure(
        self,
        actor: Actor,
        record_id: int,
        data: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """家长申请清退：登记请求+家长授权，接通服务记录与审计，按资格处置或冻结。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if actor.role not in ERASURE_ROLES:
            raise PermissionDenied("角色无权提交清退请求")
        validated = validate_request_payload(data or {})
        record = self.repository.get(record_id)  # 不存在抛 NotFound
        request_reference = validated["request_reference"]
        authorization = validated["authorization"]
        if idempotency_key:
            key = text({"idempotency_key": idempotency_key}, "idempotency_key")
        else:
            key = self._request_key(record_id, request_reference, authorization["reference"])

        lock = self._key_lock(key)
        with lock:
            # 重复提交（两个管理员同时提交同一请求）：只允许一个写入，返回同一结果
            existing = self.repository.find_erasure_request_by_key(key)
            if existing is None:
                # 客户端自带幂等键或同申请编号的再次提交，一律回到同一处置结果
                existing = self.repository.find_latest_by_reference(record_id, request_reference)
            if existing is not None:
                return self._request_view(existing, record_id, idempotent_replay=True)

            # 同一记录已有未结请求（冻结/失败/处理中）时，不允许并行开立第二条处置链
            open_request = self.repository.get_open_erasure_request(record_id)
            if open_request is not None:
                raise Conflict("该记录存在未结清退请求#%s，请先处理或续做" % open_request["id"])

            snapshot = dict(record["payload"])
            identity_fields = present_identity_fields(snapshot)
            if not identity_fields:
                raise ValidationError("记录不含可擦除的身份字段")
            # 未结复查或争议（法律保留）计划先冻结；未到期拒绝
            try:
                evaluate_record(record)
            except FrozenPlan as exc:
                request, _ = self.repository.create_erasure_request(
                    record_id, key, request_reference, authorization, snapshot, identity_fields,
                    actor.user_id, STATUS_FROZEN, frozen_reason=str(exc),
                )
                return self._request_view(request, record_id)
            request, _ = self.repository.create_erasure_request(
                record_id, key, request_reference, authorization, snapshot, identity_fields,
                actor.user_id, STATUS_PROCESSING,
            )
            return self._run_erasure(request)

    def resume_erasure(self, actor: Actor, request_id: int) -> Dict[str, Any]:
        """冻结解除后续做，或失败/中断后从完整批次恢复并续做未完成字段。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if actor.role not in ERASURE_ROLES:
            raise PermissionDenied("角色无权处理清退请求")
        request = self.repository.get_erasure_request(request_id)
        record_id = int(request["record_id"])
        lock = self._key_lock(request["request_key"])
        with lock:
            if request["status"] == STATUS_COMPLETED:
                return self._request_view(request, record_id, idempotent_replay=True)
            # 冻结请求：未结事项必须先解除
            if request["status"] == STATUS_FROZEN:
                record = self.repository.get(record_id)
                try:
                    evaluate_record(record)
                except FrozenPlan as exc:
                    raise FrozenPlan(str(exc)) from exc
                snapshot = dict(record["payload"])
                identity_fields = present_identity_fields(snapshot)
                if not identity_fields:
                    raise ValidationError("记录不含可擦除的身份字段")
                self.repository.begin_processing(request_id, snapshot, identity_fields, actor.user_id)
                request = self.repository.get_erasure_request(request_id)
            return self._run_erasure(request)

    def _run_erasure(self, request: Dict[str, Any]) -> Dict[str, Any]:
        request_id = int(request["id"])
        record_id = int(request["record_id"])
        actor_id = request["created_by"]
        snapshot = request["snapshot"]
        identity_fields = list(request["identity_fields"])
        progress = list(request["progress"])

        record = self.repository.get(record_id)
        actual = {key: value for key, value in record["payload"].items() if not key.startswith("_")}
        # 任何续做入口都先核对当前载荷是否等于“快照+已完成字段”，不符则从完整批次恢复
        expected_now = expected_payload(snapshot, progress, record_id)
        if not payloads_consistent(actual, expected_now):
            self.repository.restore_from_snapshot(request_id, record_id, snapshot, actor_id)
            progress = []

        payload = dict(snapshot)
        for field in progress:
            payload = erase_field_value(payload, field, record_id)

        for field in identity_fields:
            if field in progress:
                continue
            payload = erase_field_value(payload, field, record_id)
            try:
                self.repository.apply_erasure_step(
                    record_id, request_id, field, payload, progress + [field], actor_id
                )
            except Exception as exc:  # 步骤落库失败：落 failed 审计（成功审计绝不写），可续做
                self.repository.fail_erasure_request(request_id, record_id, str(exc), actor_id, restored=False)
                raise
            progress.append(field)
            if len(progress) == int(self.crash_after_step):
                raise ErasureStepError("simulated-crash")  # 模拟进程崩溃：进度已持久化

        # 终局核对：身份字段确已擦除、保留字段与快照逐字段一致
        try:
            verify_completion(payload, snapshot, identity_fields, record_id)
        except ErasureStepError as exc:
            self.repository.restore_from_snapshot(request_id, record_id, snapshot, actor_id)
            self.repository.fail_erasure_request(request_id, record_id, str(exc), actor_id, restored=True)
            raise

        needles = identity_needles(snapshot, identity_fields, record_id)
        redacted_rows = self.repository.redact_audit_details(record_id, needles, request_id, actor_id)
        manifest = build_manifest(
            request_id=request_id,
            request_reference=request["request_reference"],
            authorization=request["authorization"],
            snapshot=snapshot,
            identity_fields=identity_fields,
            record_id=record_id,
            redacted_audit_rows=redacted_rows,
            completed_at=_now(),
        )
        final_payload = dict(payload)
        final_payload["_erasure"] = manifest
        self.repository.complete_erasure_request(request_id, record_id, final_payload, manifest, actor_id)
        return self._request_view(self.repository.get_erasure_request(request_id), record_id)

    def get_erasure_request(self, actor: Actor, request_id: int) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        request = self.repository.get_erasure_request(request_id)
        return self._request_view(request, int(request["record_id"]))

    def list_erasure_requests(
        self, actor: Actor, record_id: Optional[int] = None, status: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return [
            self._request_view(item, int(item["record_id"]))
            for item in self.repository.list_erasure_requests(record_id=record_id, status=status, limit=limit)
        ]

    def _request_view(self, request: Dict[str, Any], record_id: int, idempotent_replay: bool = False) -> Dict[str, Any]:
        view = {
            "id": request["id"],
            "record_id": record_id,
            "request_key": request["request_key"],
            "request_reference": request["request_reference"],
            "guardian_authorization": request["authorization"],
            "status": request["status"],
            "identity_fields": request["identity_fields"],
            "completed_fields": request["progress"],
            "remaining_fields": list(request["identity_fields"])[len(request["progress"]):],
            "error": request.get("error"),
            "frozen_reason": request.get("frozen_reason"),
            "created_by": request["created_by"],
            "created_at": request["created_at"],
            "processed_at": request.get("processed_at"),
            "idempotent_replay": idempotent_replay,
        }
        if request.get("manifest"):
            view["manifest"] = request["manifest"]
        if request["status"] == STATUS_FAILED:
            view["recovery"] = "可调用处理接口续做；系统会先从完整批次快照核对/恢复，再擦除未完成字段"
        return view

    def export_record(self, actor: Actor, record_id: int) -> Dict[str, Any]:
        """导出：说明哪些字段已擦除、哪些依法保留；含匿名服务事件与审计摘要。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if actor.role not in EXPORT_ROLES:
            raise PermissionDenied("角色无权导出处置包")
        record = self._enrich(self.repository.get(record_id))
        payload = record["payload"]
        erased = record["erasure"]
        service_events = {
            field: payload[field] for field in SERVICE_EVENT_FIELDS if field in payload
        }
        consent = {field: payload[field] for field in CONSENT_FIELDS if field in payload}
        timeline = self.audit.timeline(record_id)
        audit_summary = [
            {
                "action": event["action"],
                "actor_id": event["actor_id"],
                "summary": event["details"].get("summary") if isinstance(event["details"], dict) else None,
                "created_at": event["created_at"],
            }
            for event in timeline
        ]
        return {
            "record_id": record_id,
            "reference": record["reference"],
            "state": record["state"],
            "retention_state": record.get("retention_state", "normal"),
            "guardian_consent_retained": consent,
            "anonymous_service_events": service_events,
            "audit_summary": audit_summary,
            "field_disposition": erased["field_disposition"],
            "erasure_request_reference": erased.get("request_reference"),
            "guardian_authorization": erased.get("guardian_authorization"),
            "redacted_audit_rows": erased.get("redacted_audit_rows"),
            "legal_note": erased.get("legal_note"),
        }
