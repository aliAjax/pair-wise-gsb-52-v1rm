# 特殊教育支持计划合规

纯Python标准库实现的特殊教育支持计划合规原型，使用SQLite持久化，HTTP接口由`http.server`提供。

## 模块结构

- `app.py`：命令行参数、依赖组装和服务启动。
- `src/domain.py`：领域数据类型、错误和基础校验。
- `src/rules.py`：状态转换、同意、服务履约、复查期限和计划版本和冲突检查。
- `src/repository.py`：SQLite建表、事务、查询、旧数据迁移回填和清退处置原语。
- `src/service.py`：用例编排、权限检查、乐观并发、审计和清退处置链。
- `src/erasure.py`：身份字段擦除、法定保留依据、冻结判定、批次快照校验。
- `src/http_api.py`：HTTP路由与统一错误响应。
- `src/audit.py`：事件时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则计算、失败场景、清退处置链和HTTP接口测试。

## 启动

```bash
python3 app.py --db ./data.db --port 8328
```

默认端口为`8328`，默认数据库位于项目目录。服务启动时自动建表。

## 主要接口

- `GET /health`：健康检查。
- `GET /`：演示页面。
- `GET /api/records`：记录列表，可带`state`和`limit`参数。
- `GET /api/records/{id}`：记录详情。
- `GET /api/records/{id}/audit`：审计时间线。
- `GET /api/stats`：状态统计。
- `POST /api/records`：创建记录，请求体为`{"reference":"...","data":{...}}`。
- `POST /api/records/{id}/actions/{action}`：执行业务动作，请求体为`{"expected_version":1,"data":{...}}`。

除`/health`和`/`外，请求需提供`X-User-Id`、`X-Role`，可选`X-Org`。

## 清退处置链

家长申请清退支持计划资料时，系统把**清退请求 → 家长授权 → 服务记录 → 审计摘要**接成一条可核验的处置链（仅`admin`/`administrator`可操作）：

- 到期（`closed`）资料：只擦身份字段（`student_id`替换为`ANON-000001`式匿名令牌，监护人姓名/联系方式置空）；匿名化的服务事件、监护人同意事实和审计摘要依法定义务保留，仍可证明服务发生过。
- 未结复查（`under_review`）或争议/法律保留（`legal_hold`）计划：请求登记为`frozen`先冻结，业务动作暂停；未结事项解除后调用处理接口续做。
- 两个管理员同时提交同一请求：按`记录+申请编号+授权编号`派生幂等键，进程内锁加数据库唯一约束只允许一个写入，重复提交（也支持`Idempotency-Key`头）返回同一结果并带`idempotent_replay:true`。
- 擦除按字段分批落库并持久化进度；续做前先用完整批次快照核对，发现字段状态与批次不符先整批恢复再续做未完成字段；终局逐字段校验通过后才写成功审计，失败只写`erasure_failed`，杜绝“字段已擦除而审计说成功”。
- 旧数据缺少法律保留状态时，启动迁移自动回填`retention_state=normal`并写`retention_backfilled`审计，迁移只执行一次。
- 详情与导出逐字段标注`erased/retained/present`和保留依据。

接口：

- `POST /api/records/{id}/legal-hold`：设置/解除法律保留，请求体`{"held":true,"reason":"争议调查中"}`。
- `POST /api/records/{id}/erasure`：提交清退请求，请求体`{"data":{"request_reference":"ER-1","guardian_authorization":{"reference":"AUTH-1","scope":"身份擦除","guardian_confirmed":true,"confirmed_at":"..."}}}`；冻结返回409，重复提交返回200，首次处理返回201。
- `POST /api/erasure-requests/{id}/process`：冻结解除或失败后恢复续做。
- `GET /api/erasure-requests`、`GET /api/erasure-requests/{id}`、`GET /api/records/{id}/erasure`：清退请求查询。
- `GET /api/records/{id}/export`：导出处置包（匿名服务事件、同意事实、审计摘要、逐字段处置说明）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整流程、规则计算、重复引用、权限拒绝、版本冲突、清退擦除与法定保留、未结复查/争议冻结、并发重复提交、崩溃/失败/串改后的批次恢复、旧数据回填和HTTP接口。
