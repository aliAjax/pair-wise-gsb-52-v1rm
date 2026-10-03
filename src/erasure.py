"""清退处置链领域规则：身份字段擦除、法定保留、冻结、批次校验。

处置链：清退请求 → 家长授权 → 服务记录 → 审计摘要。
到期资料只擦身份信息；匿名服务事件与审计摘要依法保留；未结复查或
争议（法律保留）计划先冻结。
"""
import json
from typing import Any, Dict, List, Tuple

from .domain import ErasureBlocked, FrozenPlan, ValidationError, text


# 身份字段：到期后必须擦除（student_id 以匿名令牌替代）
IDENTITY_FIELDS = ("student_id", "guardian_name", "guardian_contact")
GUARDIAN_FIELDS = ("guardian_name", "guardian_contact")

ERASURE_REASON = "身份信息，依家长清退申请与监护人授权擦除"

# 依法保留字段的法律依据
RETAIN_BASIS = {
    "consent": "监护人授权事实存证，证明服务经同意开展",
    "consent_scope": "监护人授权范围存证，证明服务具备合法基础",
    "disability": "法定教育服务类别记录，匿名化后保留",
    "service_minutes": "法定教育服务履行凭证，匿名化后保留",
    "delivered_minutes": "法定教育服务履行凭证，匿名化后保留",
    "missing_minutes": "法定教育服务履行凭证，匿名化后保留",
    "compliance_rate": "法定教育服务履行凭证，匿名化后保留",
    "last_provider": "服务提供方编号（非身份信息），履行凭证保留",
    "goals_count": "服务目标统计，匿名化后保留",
    "updated_goals": "服务目标内容，匿名化后保留",
    "progress_note": "复查/服务过程记录，匿名化后保留",
    "amendment_reason": "计划修订过程记录，匿名化后保留",
    "review_overdue": "复查期限状态，法定期限管理需要",
    "plan_status": "计划状态事实，审计与法定义务需要",
}
DEFAULT_BASIS = "服务过程信息，匿名化后依法保留"

# 清退请求状态
STATUS_PROCESSING = "processing"
STATUS_COMPLETED = "completed"
STATUS_FROZEN = "frozen"
STATUS_FAILED = "failed"


class ErasureStepError(RuntimeError):
    """单个字段擦除步骤失败（用于记录失败状态并支持批次恢复）。"""


def anonymized_token(record_id: int) -> str:
    return "ANON-%06d" % int(record_id)


def validate_request_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """校验家长清退申请与监护人授权，授权是处置链的法定起点。"""
    data = data or {}
    request_reference = text(data, "request_reference")
    auth = data.get("guardian_authorization")
    if not isinstance(auth, dict):
        raise ValidationError("缺少监护人授权guardian_authorization")
    authorization = {
        "reference": text(auth, "reference"),
        "scope": text(auth, "scope"),
        "guardian_confirmed": bool(auth.get("guardian_confirmed", False)),
        "confirmed_at": text(auth, "confirmed_at"),
    }
    if not authorization["guardian_confirmed"]:
        raise ValidationError("监护人尚未确认授权")
    return {"request_reference": request_reference, "authorization": authorization}


def evaluate_record(record: Dict[str, Any]) -> None:
    """判定清退资格：未结复查/争议冻结；未到期拒绝；到期可处置。"""
    if record.get("retention_state") == "legal_hold":
        raise FrozenPlan("计划处于法律保留/争议状态：%s" % (record.get("freeze_reason") or "待争议解决"))
    if record["state"] == "under_review":
        raise FrozenPlan("存在未结复查，复查结论作出前暂停清退")
    if record["state"] != "closed":
        raise ErasureBlocked("支持计划尚未到期结束，不能清退")


def present_identity_fields(payload: Dict[str, Any]) -> List[str]:
    """快照中实际含有的身份字段（旧数据可能没有监护人字段）。"""
    fields = []
    for field in IDENTITY_FIELDS:
        value = payload.get(field)
        if field == "student_id":
            if isinstance(value, str) and value.strip() and not value.startswith("ANON-"):
                fields.append(field)
        elif isinstance(value, str) and value.strip():
            fields.append(field)
    return fields


def retained_fields(payload: Dict[str, Any]) -> List[str]:
    return [key for key in payload.keys() if key not in IDENTITY_FIELDS and not key.startswith("_")]


def erase_field_value(payload: Dict[str, Any], field: str, record_id: int) -> Dict[str, Any]:
    """对单个身份字段做确定性擦除，重复执行得到相同结果（可安全续做）。"""
    result = dict(payload)
    if field == "student_id":
        result[field] = anonymized_token(record_id)
    elif field in GUARDIAN_FIELDS:
        result[field] = None
    else:  # pragma: no cover - 规划外字段不允许进入擦除批次
        raise ValidationError("未知身份字段：%s" % field)
    return result


def expected_payload(snapshot: Dict[str, Any], fields: List[str], record_id: int) -> Dict[str, Any]:
    """从完整批次快照应用给定字段擦除，得到期望载荷，用于一致性核对。"""
    payload = dict(snapshot)
    for field in fields:
        payload = erase_field_value(payload, field, record_id)
    return payload


def payloads_consistent(actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    return json.dumps(actual, ensure_ascii=False, sort_keys=True) == json.dumps(
        expected, ensure_ascii=False, sort_keys=True
    )


def verify_completion(
    final_payload: Dict[str, Any],
    snapshot: Dict[str, Any],
    identity_fields: List[str],
    record_id: int,
) -> None:
    """完成前强校验：身份字段确实已擦、保留字段与快照逐字段一致。

    校验不过绝不允许写成功审计，杜绝“字段已擦除而审计说成功”或其反向不一致。
    """
    for field in identity_fields:
        expected = erase_field_value(snapshot, field, record_id)[field]
        if final_payload.get(field) != expected:
            raise ErasureStepError("字段%s未按计划擦除" % field)
    if final_payload.get("student_id") == snapshot.get("student_id"):
        raise ErasureStepError("学生身份标识仍然存在")
    for field in retained_fields(snapshot):
        if final_payload.get(field) != snapshot.get(field):
            raise ErasureStepError("依法保留字段%s与批次快照不一致" % field)


def build_manifest(
    request_id: int,
    request_reference: str,
    authorization: Dict[str, Any],
    snapshot: Dict[str, Any],
    identity_fields: List[str],
    record_id: int,
    redacted_audit_rows: int,
    completed_at: str,
) -> Dict[str, Any]:
    erased = [
        {
            "field": field,
            "status": "erased",
            "reason": ERASURE_REASON,
            "anonymized_as": anonymized_token(record_id) if field == "student_id" else None,
            "erased_at": completed_at,
        }
        for field in identity_fields
    ]
    retained = [
        {"field": field, "status": "retained", "basis": RETAIN_BASIS.get(field, DEFAULT_BASIS)}
        for field in retained_fields(snapshot)
    ]
    return {
        "request_id": request_id,
        "request_reference": request_reference,
        "guardian_authorization": authorization,
        "completed_at": completed_at,
        "erased_fields": erased,
        "retained_fields": retained,
        "redacted_audit_rows": redacted_audit_rows,
        "legal_note": "身份字段已依家长清退申请擦除；服务事件与审计摘要依法定义务保留。",
    }


def disposition_from_manifest(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(manifest.get("erased_fields", [])) + list(manifest.get("retained_fields", []))


def disposition_from_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """未擦除记录的导出/详情也要逐字段说明状态与保留依据。"""
    result = []
    for field, value in payload.items():
        if field.startswith("_"):
            continue
        if field in IDENTITY_FIELDS:
            status = "present" if (field == "student_id" or value) else "absent"
            result.append({"field": field, "status": status, "basis": "身份信息，清退申请获批并到期后擦除"})
        else:
            result.append({"field": field, "status": "present", "basis": RETAIN_BASIS.get(field, DEFAULT_BASIS)})
    return result


def identity_needles(snapshot: Dict[str, Any], identity_fields: List[str], record_id: int) -> List[Tuple[str, str]]:
    """审计明细中需要替换的旧身份值（旧值 → 匿名/擦除标记）。"""
    needles = []
    for field in identity_fields:
        old_value = snapshot.get(field)
        if isinstance(old_value, str) and old_value.strip():
            replacement = anonymized_token(record_id) if field == "student_id" else "[身份信息已擦除]"
            needles.append((old_value, replacement))
    return needles


def redact_obj(obj: Any, needles: List[Tuple[str, str]]) -> Any:
    """递归替换审计 JSON 中的身份字符串，结构与摘要保持不变。"""
    if isinstance(obj, str):
        for old_value, replacement in needles:
            if old_value in obj:
                obj = obj.replace(old_value, replacement)
        return obj
    if isinstance(obj, dict):
        return {key: redact_obj(value, needles) for key, value in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(item, needles) for item in obj]
    return obj
