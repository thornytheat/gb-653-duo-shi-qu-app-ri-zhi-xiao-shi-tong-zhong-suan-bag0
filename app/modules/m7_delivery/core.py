"""实际日志批次解析、按服务分桶与受限副本生成。

约束：
- 不引入按服务的时区修正（沿用 UTC 归一后的整点键）。
- 不改变请求去重规则（本模块不做任何去重）。
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone

CSV_FIELDS = ["hour", "service", "count", "errors", "source_lines", "line_digest"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def hour_key(value) -> str:
    """UTC 整点键（左闭右开）：先把带偏移时间归一到 UTC，再截断到小时。"""
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("TIMEZONE_REQUIRED")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")


def _iter_documents(raw: str):
    """扫描连接在一起的 JSON 文档，返回 (逻辑行号, 文档或 None, 原文片段)。

    实际日志既可能是逐行 JSON，也可能把换行存成字面量 ``\\n``。
    字面量分隔符也计入逻辑行号，保证 source_line 可用于对账。
    """
    decoder = json.JSONDecoder()
    index, length, line = 0, len(raw), 1
    while index < length:
        char = raw[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in " \t\r":
            index += 1
            continue
        if raw.startswith("\\n", index):
            line += 1
            index += 2
            continue
        try:
            document, end = decoder.raw_decode(raw, index)
        except json.JSONDecodeError:
            stop = index
            while stop < length and raw[stop] != "\n" and not raw.startswith("\\n", stop):
                stop += 1
            yield line, None, raw[index:stop]
            index = stop
            continue
        yield line, document, raw[index:end]
        line += raw[index:end].count("\n")
        index = end


def parse_batch(raw: str) -> dict:
    """解析实际日志，保留物理/逻辑行号、原因码和原值。"""
    rows: list[dict] = []
    quarantine: list[dict] = []
    for line_no, document, fragment in _iter_documents(raw or ""):
        if document is None:
            quarantine.append({"source_line": line_no, "reason": "TRUNCATED",
                               "raw_value": fragment[:500]})
            continue
        if not isinstance(document, dict):
            quarantine.append({"source_line": line_no, "reason": "INVALID_VALUE",
                               "raw_value": fragment[:500]})
            continue
        service = document.get("service")
        timestamp = document.get("timestamp")
        if service in (None, ""):
            quarantine.append({"source_line": line_no, "reason": "EMPTY_VALUE",
                               "raw_value": fragment[:500]})
            continue
        if timestamp in (None, ""):
            quarantine.append({"source_line": line_no, "reason": "EMPTY_VALUE",
                               "raw_value": fragment[:500]})
            continue
        try:
            hour = hour_key(timestamp)
            status = int(document.get("status"))
        except (TypeError, ValueError):
            quarantine.append({"source_line": line_no, "reason": "INVALID_VALUE",
                               "raw_value": fragment[:500]})
            continue
        rows.append({
            "source_line": line_no,
            "request_id": str(document.get("request_id", "")),
            "service": str(service),
            "timestamp": str(timestamp),
            "status": status,
            "hour": hour,
        })
    return {
        "rows": rows,
        "quarantine": quarantine,
        "input_rows": len(rows) + len(quarantine),
        "valid_rows": len(rows),
        "quarantine_rows": len(quarantine),
    }


def services(rows: list[dict]) -> list[str]:
    return sorted({row["service"] for row in rows})


def bucket_rows(rows: list[dict], service: str) -> list[dict]:
    """仅保留授权服务，按 UTC 小时聚合。

    source_lines 与 line_digest 让审计可只凭原件核对每个桶：
    行数一致且授权服务原行摘要一致，即可确认副本未混入其他服务、也未漏行。
    """
    buckets: dict[str, dict] = {}
    lines: dict[str, list[int]] = {}
    for row in rows:
        if row["service"] != service:
            continue
        item = buckets.setdefault(row["hour"], {
            "hour": row["hour"], "service": service,
            "count": 0, "errors": 0, "source_lines": 0,
        })
        item["count"] += 1
        item["errors"] += int(row["status"] >= 500)
        item["source_lines"] += 1
        lines.setdefault(row["hour"], []).append(row["source_line"])
    out = []
    for hour in sorted(buckets):
        item = dict(buckets[hour])
        digest = hashlib.sha256(
            (service + "\x1f" + ",".join(str(n) for n in sorted(lines[hour]))).encode("utf-8")
        ).hexdigest()
        item["line_digest"] = digest[:16]
        out.append(item)
    return out


def artifact_digest(rows: list[dict]) -> str:
    canonical = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def csv_text(rows: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row[key] for key in CSV_FIELDS})
    return out.getvalue()


def totals(rows: list[dict]) -> dict:
    return {
        "bucket_count": len(rows),
        "included_rows": sum(row["count"] for row in rows),
        "error_count": sum(row["errors"] for row in rows),
        "source_line_count": sum(row["source_lines"] for row in rows),
        "artifact_digest": artifact_digest(rows),
    }
