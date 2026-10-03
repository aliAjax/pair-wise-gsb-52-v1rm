"""清退处置策略：字段分级、冻结决策、擦除目标与导出说明。

处置链：家长清退申请 + 家长授权 -> 支持计划记录 -> 匿名服务事件 -> 审计摘要。
本模块只包含纯函数策略，不触碰数据库，便于单独测试。
"""
from typing import Any, Dict, List, Optional, Tuple


# 到期资料允许擦除的唯一字段类别：直接或间接识别学生/家长身份的字段
IDENTITY_FIELDS: List[str] = ["student_id", "guardian_name", "guardian_contact"]

# 法律保留状态
RETENTION_ACTIVE = "retained_until_expiry"      # 法定保留期内
RETENTION_HOLD = "legal_hold"                   # 未结复查/争议冻结
RETENTION_ANONYMIZED = "retained_anonymized"   # 到期擦身份后匿名保留

RETENTION_LABELS: Dict[str, str] = {
    RETENTION_ACTIVE: "法定保留期内，身份、服务与审计依据完整保留",
    RETENTION_HOLD: "未结复查或争议冻结，清退暂缓，全部资料依法保留",
    RETENTION_ANONYMIZED: "保留期届满且身份信息已擦除，匿名服务事件与审计摘要依法保留",
}

HOLD_REASONS: Dict[str, str] = {
    "open_review": "计划复查尚未结束",
    "dispute_open": "家长对清退/服务存在未解决争议",
}

DISPOSITION_LABELS: Dict[str, str] = {
    "active": "正常处置中",
    "frozen": "已冻结，等待复查结束或争议解除",
    "erased": "身份信息已擦除，仅保留匿名资料",
}

# 每类保留字段的法律/业务依据
RETAINED_BASIS: Dict[str, str] = {
    "consent": "监护人授权事实：证明服务曾经合法同意，依法保留",
    "consent_scope": "家长授权范围：服务合法性与清退边界依据，依法保留",
    "disability": "服务类别事实（去标识）：履约统计与审计依据，依法保留",
    "service_minutes": "匿名服务履约事实：法定服务证据，依法保留",
    "delivered_minutes": "匿名服务履约事实：法定服务证据，依法保留",
    "missing_minutes": "匿名服务履约事实：法定服务证据，依法保留",
    "compliance_rate": "匿名服务履约统计：法定服务证据，依法保留",
    "last_provider": "服务提供方代码（去标识）：履约证据，依法保留",
    "review_overdue": "复查期限事实：审计依据，依法保留",
    "goals_count": "计划目标数量（去标识）：履约证据，依法保留",
    "updated_goals": "计划修订内容（去标识）：版本与履约证据，依法保留",
    "amendment_reason": "计划修订原因：版本证据，依法保留",
    "progress_note": "复查结论：法定复查记录，依法保留",
    "plan_status": "计划状态事实：审计依据，依法保留",
    "dispute_open": "争议标记：冻结与解除依据，依法保留",
    "dispute_resolution": "争议处理结论：法律保留状态变更依据，依法保留",
}
DEFAULT_RETAINED_BASIS = "法定服务记录（去标识）：履约或审计依据，依法保留"

ERASED_BASIS = "保留期届满且家长授权清退，身份信息已擦除，不可恢复"
FROZEN_IDENTITY_BASIS = "清退请求已受理，但存在未结复查/争议，身份字段暂缓擦除并依法冻结保留"
PRESENT_IDENTITY_BASIS = "法定保留期内，身份信息随服务档案完整保留"
BACKFILLED_NOTE = "旧数据原本缺少法律保留状态，已按法定保留回填"


def decide(record: Dict[str, Any], retention_expired: bool) -> Tuple[str, Optional[str]]:
    """返回 (decision, reason)：eligible / frozen / rejected。"""
    if record.get("state") == "under_review":
        return "frozen", "open_review"
    if record.get("payload", {}).get("dispute_open"):
        return "frozen", "dispute_open"
    if not retention_expired:
        return "rejected", "retention_not_expired"
    return "eligible", None


def snapshot_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """提交时的完整批次快照：补齐身份字段，保证逐字段擦除范围稳定。"""
    snapshot = dict(payload)
    for field in IDENTITY_FIELDS:
        snapshot.setdefault(field, None)
    return snapshot


def target_identity_fields(snapshot: Dict[str, Any]) -> List[str]:
    """本批次需要擦除的身份字段（固定分类，与字段当前是否有值无关）。"""
    return list(IDENTITY_FIELDS)


def apply_erased_fields(snapshot: Dict[str, Any], erased_fields: List[str]) -> Dict[str, Any]:
    """以完整快照为基准，叠加已擦除检查点，得到当前一致的 payload。"""
    payload = dict(snapshot)
    for field in erased_fields:
        if field in IDENTITY_FIELDS:
            payload[field] = None
    return payload


def retained_fields(snapshot: Dict[str, Any], erased_fields: List[str]) -> List[str]:
    return [key for key in sorted(snapshot.keys()) if key not in erased_fields]


def retention_label(state: str) -> str:
    return RETENTION_LABELS.get(state, state)


def hold_reason_label(reason: Optional[str]) -> Optional[str]:
    if not reason:
        return None
    return HOLD_REASONS.get(reason, reason)


def field_reports(record: Dict[str, Any], request: Optional[Dict[str, Any]] = None) -> Dict[str, List[Dict[str, str]]]:
    """生成逐字段处置说明：哪些已擦除、哪些依法保留、依据是什么。"""
    erased = list(record.get("erased_fields") or [])
    retention_state = record.get("retention_state") or RETENTION_ACTIVE
    disposition_state = record.get("disposition_state") or "active"
    backfilled = bool(record.get("retention_backfilled"))

    identity: List[Dict[str, str]] = []
    for field in IDENTITY_FIELDS:
        if field in erased or disposition_state == "erased":
            identity.append({"field": field, "status": "erased", "basis": ERASED_BASIS})
        elif retention_state == RETENTION_HOLD:
            identity.append({"field": field, "status": "frozen_pending_erasure", "basis": FROZEN_IDENTITY_BASIS})
        elif record.get("payload", {}).get(field) is None:
            identity.append({"field": field, "status": "absent", "basis": "该身份字段从未采集，无需擦除"})
        else:
            basis = PRESENT_IDENTITY_BASIS
            if backfilled:
                basis += "；%s" % BACKFILLED_NOTE
            identity.append({"field": field, "status": "present", "basis": basis})

    retained: List[Dict[str, str]] = []
    for key in sorted(record.get("payload", {}).keys()):
        if key in IDENTITY_FIELDS:
            continue
        if retention_state == RETENTION_HOLD:
            basis = "冻结期间全部字段依法保留；%s" % RETAINED_BASIS.get(key, DEFAULT_RETAINED_BASIS)
        else:
            basis = RETAINED_BASIS.get(key, DEFAULT_RETAINED_BASIS)
        retained.append({"field": key, "status": "retained", "basis": basis})
    return {"identity_fields": identity, "retained_fields": retained}


def request_summary(request: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """对外的请求摘要：不含完整批次快照（快照仅用于失败恢复）。"""
    if not request:
        return None
    return {
        "id": request["id"],
        "request_key": request["request_key"],
        "guardian_request_ref": request["guardian_request_ref"],
        "guardian_authorized": bool(request["guardian_authorized"]),
        "authorization_scope": request.get("authorization_scope", ""),
        "retention_expired": bool(request["retention_expired"]),
        "status": request["status"],
        "identity_fields": list(request.get("identity_fields") or []),
        "erased_fields": list(request.get("erased_fields") or []),
        "result": request.get("result"),
        "created_at": request["created_at"],
        "updated_at": request["updated_at"],
        "completed_at": request.get("completed_at"),
    }


def service_events(record: Dict[str, Any], timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    """从记录与审计时间线聚合匿名服务事件（不含任何身份字段）。"""
    payload = record.get("payload", {})
    sessions = []
    for event in timeline:
        if event.get("action") != "log_service":
            continue
        user_input = event.get("details", {}).get("input", {}) or {}
        sessions.append({
            "version": event.get("version"),
            "created_at": event.get("created_at"),
            "session_minutes": user_input.get("session_minutes"),
        })
    return {
        "service_minutes": payload.get("service_minutes"),
        "delivered_minutes": payload.get("delivered_minutes"),
        "missing_minutes": payload.get("missing_minutes"),
        "compliance_rate": payload.get("compliance_rate"),
        "sessions": sessions,
    }


def audit_summary(timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    """去标识审计摘要：只保留动作、版本、时间与结论性摘要，剔除输入明细。"""
    events = []
    for event in timeline:
        details = event.get("details", {}) or {}
        events.append({
            "action": event.get("action"),
            "version": event.get("version"),
            "created_at": event.get("created_at"),
            "summary": details.get("summary", event.get("action")),
        })
    return {
        "count": len(events),
        "events": events,
        "note": "审计摘要已去标识，按法定审计要求保留；清退不删除审计。",
    }


def build_export(record: Dict[str, Any], timeline: List[Dict[str, Any]],
                 request: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """组装合规导出：明确每个字段的擦除/保留状态与依据。"""
    retention_state = record.get("retention_state") or RETENTION_ACTIVE
    reports = field_reports(record, request)
    legal_notice = retention_label(retention_state)
    if record.get("retention_backfilled"):
        legal_notice += "；%s" % BACKFILLED_NOTE

    result: Dict[str, Any] = {
        "record_id": record["id"],
        "reference": record["reference"],
        "business_state": record["state"],
        "legal_notice": legal_notice,
        "retention": {
            "state": retention_state,
            "state_label": retention_label(retention_state),
            "hold_reason": record.get("hold_reason"),
            "hold_reason_label": hold_reason_label(record.get("hold_reason")),
            "backfilled": bool(record.get("retention_backfilled")),
            "disposition_state": record.get("disposition_state") or "active",
            "disposition_label": DISPOSITION_LABELS.get(record.get("disposition_state") or "active", ""),
        },
        "identity_fields": reports["identity_fields"],
        "retained_fields": reports["retained_fields"],
        "service_events": service_events(record, timeline),
        "audit_summary": audit_summary(timeline),
        "erasure_request": request_summary(request),
    }
    return result
