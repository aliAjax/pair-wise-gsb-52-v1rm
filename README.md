# 特殊教育支持计划合规

纯Python标准库实现的特殊教育支持计划合规原型，使用SQLite持久化，HTTP接口由`http.server`提供。

## 模块结构

- `app.py`：命令行参数、依赖组装和服务启动。
- `src/domain.py`：领域数据类型、错误和基础校验。
- `src/rules.py`：状态转换、同意、服务履约、复查期限和计划版本和冲突检查。
- `src/disposition.py`：清退处置策略（字段分级、冻结决策、失败恢复、导出说明），纯函数。
- `src/repository.py`：SQLite建表、旧库迁移回填、事务和查询。
- `src/service.py`：用例编排、权限检查、乐观并发、清退处置链和审计。
- `src/http_api.py`：HTTP路由与统一错误响应。
- `src/audit.py`：事件时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则计算、失败场景和清退处置链测试。

## 启动

```bash
python3 app.py --db ./data.db --port 8328
```

默认端口为`8328`，默认数据库位于项目目录。服务启动时自动建表；旧库缺少法律保留状态时会自动迁移回填并写入`retention_backfilled`审计。

## 清退处置链

家长申请清退支持计划资料后，系统把「清退申请 + 家长授权 + 服务记录 + 审计」串成处置链，而不是物理删除：

- **到期资料只擦身份信息**：`student_id`、`guardian_name`、`guardian_contact`三类身份字段置空；记录进入`anonymized`终态，法律保留状态变为`retained_anonymized`。
- **匿名服务事件与审计摘要保留**：服务分钟数、履约率、同意事实与授权范围等去标识保留；审计表不随清退删除（迁移时移除外键`ON DELETE CASCADE`），导出中提供匿名服务事件和去标识审计摘要。
- **未结复查/争议先冻结**：`under_review`或`dispute_open`计划受理后进入`legal_hold`，身份字段暂缓擦除；复查结束关闭计划、或管理员解除争议后自动续做。
- **两个管理员同一请求只允许一个写入**：`request_key`唯一，且同一记录上家长申请编号`guardian_request_ref`唯一；重复提交（含并发）返回同一结果并带`duplicate: true`。
- **擦除失败从完整批次恢复并续做**：受理时存完整快照，逐字段独立事务推进并记录检查点；某字段失败时以「快照+已完成检查点」恢复一致基线，审计只写`erasure_failed`；续做时只擦未完成字段；全部字段擦完的同一事务才写`erasure_completed`，并销毁快照。不会出现字段已擦除而审计说成功。
- **旧数据回填**：缺少法律保留状态的旧记录回填为`retained_until_expiry`并审计；详情与导出标明回填来源。
- **字段级说明**：记录详情与导出逐字段标注`erased`/`present`/`frozen_pending_erasure`/`absent`以及依法保留依据。

## 主要接口

- `GET /health`：健康检查。
- `GET /`：演示页面。
- `GET /api/records`：记录列表，可带`state`和`limit`参数。
- `GET /api/records/{id}`：记录详情（含法律保留状态、逐字段擦除/保留说明、关联清退请求）。
- `GET /api/records/{id}/audit`：审计时间线。
- `GET /api/records/{id}/export`：管理员合规导出（逐字段依据、匿名服务事件、去标识审计摘要）。
- `GET /api/stats`：状态统计。
- `POST /api/records`：创建记录，请求体为`{"reference":"...","data":{...}}`。
- `POST /api/records/{id}/actions/{action}`：执行业务动作，请求体为`{"expected_version":1,"data":{...}}`。
- `POST /api/records/{id}/dispute-resolution`：管理员解除争议（`expected_version`、`data.resolution`），解冻并自动续做清退。
- `POST /api/erasure-requests`：受理清退请求，请求体包含`record_id`、`request_key`、`guardian_request_ref`、`guardian_authorized`、`authorization_scope`、`retention_expired`；冻结返回`frozen`，完成返回`completed`，重复提交返回同一请求（HTTP 200且`duplicate:true`）。
- `POST /api/erasure-requests/{id}/resume`：失败后续做擦除。
- `GET /api/erasure-requests`：清退请求列表。

除`/health`和`/`外，请求需提供`X-User-Id`、`X-Role`，可选`X-Org`。清退受理、续做、争议解除与导出仅管理员（`administrator`/`admin`）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整流程、规则计算、重复引用、权限拒绝、版本冲突，以及清退处置链：到期匿名化、复查/争议冻结与自动续做、失败恢复续做、并发幂等单写入和旧库回填。
