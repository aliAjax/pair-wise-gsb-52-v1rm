"""业务用例编排、权限检查、清退处置链与审计。"""
import time
from typing import Any, Dict, List, Optional

from . import disposition
from .audit import AuditRecorder
from .domain import Actor, Conflict, ErasureInterrupted, PermissionDenied, ValidationError, boolean, text
from .repository import Repository
from .rules import DomainRules


TERMINAL_STATUSES = {"frozen", "failed", "completed"}
ERASURE_ROLES = {"administrator", "admin"}
# 冻结期间允许继续走完的复查动作（它们是解冻依据）
FROZEN_ALLOWED_ACTIONS = {"review", "amend", "close"}


class Service:
    def __init__(self, repository: Repository, rules: DomainRules, audit: AuditRecorder = None) -> None:
        self.repository = repository
        self.rules = rules
        self.audit = audit or AuditRecorder(repository)

    @staticmethod
    def _actor(actor: Actor) -> Actor:
        if actor is None or not actor.user_id.strip() or not actor.role.strip():
            raise PermissionDenied("缺少调用身份")
        return actor

    def _ensure_known_role(self, actor: Actor) -> None:
        if not self.rules.known_role(actor.role):
            raise PermissionDenied("角色无权访问该服务")

    def _require_admin(self, actor: Actor, action_desc: str) -> None:
        if actor.role not in ERASURE_ROLES:
            raise PermissionDenied("仅管理员可%s" % action_desc)

    def create(self, actor: Actor, reference: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        if not self.rules.role_can_create(actor.role):
            raise PermissionDenied("角色无权创建记录")
        reference = text({"reference": reference}, "reference")
        prepared = self.rules.prepare_create(payload or {})
        self.rules.check_create_conflicts(prepared, self.repository.list_records(limit=500))
        return self.repository.create(reference, self.rules.INITIAL_STATE, prepared, actor.user_id)

    def list_records(self, actor: Actor, state: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self.repository.list_records(state=state, limit=limit)

    def get_record(self, actor: Actor, record_id: int) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        record = self.repository.get(record_id)
        return self._enrich(record)

    def _enrich(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """详情附带法律保留状态、逐字段处置说明和关联清退请求摘要。"""
        request = self.repository.latest_erasure_request(record["id"])
        record["retention"] = {
            "state": record.get("retention_state") or disposition.RETENTION_ACTIVE,
            "state_label": disposition.retention_label(record.get("retention_state") or disposition.RETENTION_ACTIVE),
            "hold_reason": record.get("hold_reason"),
            "hold_reason_label": disposition.hold_reason_label(record.get("hold_reason")),
            "backfilled": record.get("retention_backfilled", False),
            "disposition_state": record.get("disposition_state") or "active",
            "disposition_label": disposition.DISPOSITION_LABELS.get(record.get("disposition_state") or "active", ""),
        }
        reports = disposition.field_reports(record, request)
        record["identity_fields"] = reports["identity_fields"]
        record["retained_fields"] = reports["retained_fields"]
        record["erasure_request"] = disposition.request_summary(request)
        return record

    def act(self, actor: Actor, record_id: int, expected_version: int, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        action = text({"action": action}, "action")
        if not self.rules.role_can_action(actor.role, action):
            raise PermissionDenied("角色无权执行该操作")
        record = self.repository.get(record_id)
        self.rules.require_transition(record, action)
        new_state, new_payload, summary = self.rules.apply_action(record, action, data or {})

        # 冻结只拦截普通变更；复查推进/结束允许继续（解冻依据）
        frozen = record.get("disposition_state") == "frozen"
        allow_frozen = frozen and action in FROZEN_ALLOWED_ACTIONS
        updated = self.repository.mutate(
            record_id=record_id,
            expected_version=int(expected_version),
            state=new_state,
            payload=new_payload,
            actor_id=actor.user_id,
            action=action,
            details={"summary": summary, "input": data or {}, "from": record["state"], "to": new_state},
            allow_frozen=allow_frozen,
        )

        # 复查走完（计划结束）且记录上有冻结清退请求：解除冻结并续做擦除
        if frozen and action == "close":
            self._resume_after_unfreeze(record_id, actor, "复查结束，计划关闭，续做清退")
            updated = self.repository.get(record_id)
        return self._enrich(updated)

    def _resume_after_unfreeze(self, record_id: int, actor: Actor, note: str) -> None:
        request = self.repository.latest_erasure_request(record_id)
        if request is None or request["status"] != "frozen":
            return
        self.repository.release_hold(request["id"], actor.user_id, note)
        # 自动续做若再次中断，保留 failed 状态供 POST /resume 续做，不把解冻调用变成500
        try:
            self._run_erasure_batch(request["id"], actor, record_id=record_id)
        except ErasureInterrupted:
            pass

    def resolve_dispute(self, actor: Actor, record_id: int, expected_version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """管理员解除争议；若因此解冻清退请求，自动续做擦除。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        self._require_admin(actor, "解除争议")
        resolution = text(data or {}, "resolution")
        record = self.repository.resolve_dispute(record_id, int(expected_version), actor.user_id, resolution)
        self._resume_after_unfreeze(record_id, actor, "争议已解除：%s" % resolution)
        return self._enrich(self.repository.get(record_id))

    def timeline(self, actor: Actor, record_id: int) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self.audit.timeline(record_id)

    def stats(self, actor: Actor) -> Dict[str, int]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return self.repository.stats()

    # ------------------------------------------------------------ erasure chain

    @staticmethod
    def _wait_settle(repository: Repository, request_id: int, timeout: float = 10.0) -> Dict[str, Any]:
        """并发重复提交：另一个管理员的写入进行中时，等待其到达可稳定返回的状态。"""
        deadline = time.monotonic() + timeout
        request = repository.get_erasure_request(request_id)
        while request["status"] not in TERMINAL_STATUSES and time.monotonic() < deadline:
            time.sleep(0.02)
            request = repository.get_erasure_request(request_id)
        return request

    def submit_erasure(self, actor: Actor, record_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """受理家长清退申请 + 授权，串起申请、记录、服务事件与审计。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        self._require_admin(actor, "受理清退请求")

        request_key = text(data or {}, "request_key")
        guardian_request_ref = text(data or {}, "guardian_request_ref")
        authorization_scope = text(data or {}, "authorization_scope")
        if not boolean(data or {}, "guardian_authorized"):
            raise ValidationError("缺少家长授权确认，清退请求不能受理")
        retention_expired = boolean(data or {}, "retention_expired")

        # 幂等：同一 request_key 或同一记录上同一家长申请编号 -> 返回同一结果
        existing = self.repository.find_erasure_request(record_id, request_key, guardian_request_ref)
        if existing is not None:
            if existing["record_id"] != record_id:
                existing = self.repository.find_erasure_request(record_id, None, guardian_request_ref)
            if existing is not None:
                existing = self._wait_settle(self.repository, existing["id"])
                summary = disposition.request_summary(existing)
                summary["duplicate"] = True
                return summary

        record = self.repository.get(record_id)
        if record.get("disposition_state") == "erased":
            request = self.repository.latest_erasure_request(record_id)
            summary = disposition.request_summary(request)
            summary["duplicate"] = True
            return summary

        decision, reason = disposition.decide(record, retention_expired)
        if decision == "rejected":
            raise Conflict("法定保留期尚未届满，不能清退；应先保持法律保留")

        snapshot = disposition.snapshot_from_payload(record["payload"])
        identity_fields = disposition.target_identity_fields(snapshot)
        initial_status = "frozen" if decision == "frozen" else "processing"
        outcome, request = self.repository.submit_erasure_request(
            record_id=record_id,
            request_key=request_key,
            guardian_request_ref=guardian_request_ref,
            guardian_authorized=True,
            authorization_scope=authorization_scope,
            retention_expired=retention_expired,
            initial_status=initial_status,
            snapshot=snapshot,
            identity_fields=identity_fields,
            actor_id=actor.user_id,
            hold_reason=reason,
        )
        if outcome == "duplicate":
            request = self._wait_settle(self.repository, request["id"])
            summary = disposition.request_summary(request)
            summary["duplicate"] = True
            return summary

        if initial_status == "frozen":
            return disposition.request_summary(request)

        # 到期可擦：立即跑完整批次
        try:
            return self._run_erasure_batch(request["id"], actor, record_id=record_id)
        except ErasureInterrupted as exc:
            failed = getattr(exc.__cause__, "request", None)
            return disposition.request_summary(failed) if failed else disposition.request_summary(
                self.repository.get_erasure_request(request["id"]))

    def _run_erasure_batch(self, request_id: int, actor: Actor, record_id: int = None,
                           fail_at_field: Optional[str] = None) -> Dict[str, Any]:
        """逐字段擦除批次。fail_at_field 注入失败：中断字段不得被声明为已擦除。"""
        request = self.repository.get_erasure_request(request_id)
        record_id = record_id or request["record_id"]
        if request["status"] in {"frozen", "completed"}:
            raise Conflict("清退请求当前状态为%s，不可执行擦除" % request["status"])

        for field in request["identity_fields"]:
            if field in request["erased_fields"]:
                continue  # 续做：已完成字段跳过，只做未完成字段
            if fail_at_field == field:
                failed = self.repository.fail_erasure(
                    request_id, field, actor.user_id, "擦除失败（注入），等待从完整批次续做"
                )
                raise ErasureInterrupted(
                    "清退批次在字段%s处中断：已从完整批次恢复，未完成字段待续做" % field
                ) from _BatchFailure(failed)
            request = self.repository.apply_erasure_field(request_id, field, actor.user_id)

        completed = self.repository.complete_erasure(request_id, actor.user_id)
        return disposition.request_summary(completed)

    def get_erasure(self, actor: Actor, request_id: int) -> Dict[str, Any]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return disposition.request_summary(self.repository.get_erasure_request(request_id))

    def list_erasure(self, actor: Actor, limit: int = 100) -> List[Dict[str, Any]]:
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        return [disposition.request_summary(item) for item in self.repository.list_erasure_requests(limit=limit)]

    def resume_erasure(self, actor: Actor, request_id: int, fail_at_field: Optional[str] = None) -> Dict[str, Any]:
        """失败/冻结释放后续做：从完整批次快照恢复基线，只续擦未完成字段。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        self._require_admin(actor, "续做清退")
        request = self.repository.get_erasure_request(request_id)
        if request["status"] == "frozen":
            raise Conflict("未结复查/争议仍冻结，需先解除冻结")
        if request["status"] == "completed":
            return disposition.request_summary(request)
        if request["status"] not in {"failed", "resumable", "processing"}:
            raise Conflict("清退请求当前状态为%s，不能续做" % request["status"])
        if not request["snapshot"]:
            raise Conflict("缺少完整批次快照，无法恢复续做")

        # 续做前重新判定：批次失败后若已进入未结复查或新开争议，先冻结而非继续擦
        record = self.repository.get(request["record_id"])
        decision, reason = disposition.decide(record, bool(request["retention_expired"]))
        if decision == "frozen":
            frozen_request = self.repository.freeze_for_hold(request_id, actor.user_id, reason)
            return disposition.request_summary(frozen_request)

        try:
            return self._run_erasure_batch(request_id, actor, fail_at_field=fail_at_field)
        except ErasureInterrupted as exc:
            # 中断后返回失败态摘要（HTTP 202），审计只记录 erasure_failed
            failed = getattr(exc.__cause__, "request", None)
            return disposition.request_summary(failed) if failed else disposition.request_summary(
                self.repository.get_erasure_request(request_id))

    def export_record(self, actor: Actor, record_id: int) -> Dict[str, Any]:
        """合规导出：逐字段擦除/保留说明 + 匿名服务事件 + 去标识审计摘要。"""
        actor = self._actor(actor)
        self._ensure_known_role(actor)
        self._require_admin(actor, "导出合规资料")
        record = self.repository.get(record_id)
        timeline = self.audit.timeline(record_id)
        request = self.repository.latest_erasure_request(record_id)
        return disposition.build_export(record, timeline, request)


class _BatchFailure(Exception):
    """携带失败后的请求行，仅用于批次内部传递。"""
    def __init__(self, request: Dict[str, Any]) -> None:
        super().__init__("batch failure")
        self.request = request
