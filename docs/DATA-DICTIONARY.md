# 数据字典

| 字段 | 类型 | 可空 | 定义 |
|---|---|---:|---|
| `run_id` | string | 否 | 输入摘要派生的稳定运行编号 |
| `source_line` | integer | 否 | 原文件物理行号 |
| `reason_code` | string | 是 | 隔离或冲突的稳定原因码 |
| `raw_value` | string | 是 | 未归一的原始证据 |
| `normalized_value` | string | 是 | 按项目规则得到的值 |
| `rule_version` | string | 否 | 计算规则版本 |

字符串编号逐字保留。金额与计量值用 `Decimal`。时间值带偏移并以 UTC 参与比较。区间统一采用左闭右开。

## 交付域（M7）

| 字段 | 类型 | 可空 | 定义 |
|---|---|---:|---|
| `batch_id` | string | 否 | 原始批次内容摘要派生的稳定编号 |
| `grant_id` | string | 否 | 一次按服务授权，绑定 `batch_id + service` |
| `package_id` | string | 否 | 由 `batch_id + service + grant_id` 派生的稳定包编号 |
| `state` | string | 否 | 包状态：`pending`（待生成）/`claimable`（可领取）/`revoked`（已撤销） |
| `grant_state` | string | 否 | 授权状态：`active`/`expired`/`revoked` |
| `counts_match` | boolean | 否 | 受限副本包含行数与授权服务有效行数一致且不含其他服务 |
| `source_lines` | integer | 否 | 该小时桶对应的有效原始行数，用于与原件核对 |
| `expires_at` | string | 是 | 授权或凭据到期时间，UTC |
| `revoked_at` | string | 是 | 撤销时间，UTC |

受限副本仅含授权服务；全量原件与全量导出只对独立审计权限开放。撤销后旧下载凭据不可再用。
