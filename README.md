# 多时区应用日志小时桶重算

        面向一线复核人员的单服务数据工作台。样例数据随仓库提供，结论保留行号、原因码和原值。

        ## 业务模块

        - M1 日志采信：`/api/logs/import`
- M2 时间解析：`/api/time/normalize`
- M3 事件去重：`/api/events/dedupe`
- M4 小时分桶：`/api/buckets/rebuild`
- M5 迟到修订：`/api/watermark/advance`
- M6 批次对账：`/api/export/buckets.csv`（全量导出，需独立审计权限）
- M7 按服务交付：`/api/delivery/batches` / `/delivery`

        ## 按服务授权的批次交付（M7）

        - 导入实际日志批次：`POST /api/delivery/batches`，返回批次摘要、隔离原因码与物理行号。
- 签发授权：`POST /api/delivery/grants`，按 `batch_id + service` 限定；可设 `expires_at`。
- 制包：`POST /api/delivery/grants/{grant_id}/packages`；同一批次/服务/授权只建一个包，重试复用。
  分块提交进度，`interrupt_at` 模拟中断，`POST` 重试即从断点续跑。
- 领取：`POST /api/delivery/packages/{package_id}/claim` 返回下载凭据。
- 下载：`GET /api/delivery/downloads/{token}`，受限副本只含授权服务，附 `source_lines` 便于核对计数。
- 撤销：`POST /api/delivery/grants/{grant_id}/revoke`，旧凭据立即失效；撤销与下载并发以撤销为准。
- 原件：`GET /api/audit/batches/{batch_id}/original`，只接受独立审计密钥，保留原始字节。
- 回读：`GET /api/delivery/readback`，返回待生成、可领取、已撤销及按授权的交付范围。

        权限三分：管理密钥（`X-Admin-Key`）签发/撤销授权与制包；独立审计密钥（`X-Audit-Key`）读原件与全量导出；
        下载凭据（`Authorization: Bearer`）仅能取受限副本。默认值见 `.env.example`，生产必须覆盖。

        不扩展项：不按服务做时区更正（仍按 UTC 整点入桶）；不改动请求去重规则（交付层不去重）。

        ## 核心规则

        事件先归一到 UTC，DST 重叠时保留 fold；小时桶右端开，水位只能前进且迟到事件仍进入修订。

        ## 启动

        ```bash
        docker compose up --build
        ```

        浏览器访问 `http://localhost:18212`。运行测试：

        ```bash
        docker compose exec -T app pytest -q
        ```

        ## 样例流程

        依次运行六个模块；最后在批次页复核输入、有效、隔离与输出合计。同一输入摘要重复执行时复用原 `run_id`。
        需要交付时把实际日志导入 M7，按服务签发授权并制包，原件另行以审计权限核对。

        ## 已知不覆盖

        不处理加密文件与需要外部密钥的对象；不连接真实生产存储。
