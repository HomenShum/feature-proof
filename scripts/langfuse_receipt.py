"""Normalize a bounded Langfuse trace export without retaining raw inputs/outputs.

This module intentionally has no network client and no third-party dependency.
It creates diagnostic staging only; promotion performs its own authenticated
Langfuse retrieval and scans the complete raw payload before calling this
normalizer. Only timing, topology, closed metrics, and score values are kept;
prompt, document, user, and observation input/output fields are dropped.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import re
from typing import Any, Mapping, Sequence


def _first(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return default


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        moment = datetime.fromisoformat(text)
    else:
        raise ValueError("trace timestamp is missing or malformed")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    """Return the parsed UTC instant without changing its receipt spelling."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value if math.isfinite(float(value)) else None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _metric(metadata: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = metadata.get(name)
        if value is not None and isinstance(value, (str, int, float, bool)):
            return value
    return None


def _closed_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", text):
        raise ValueError(f"{label} must be a bounded closed identifier")
    return text


def _normalize_observation(row: Mapping[str, Any], default_trace_id: str) -> dict[str, Any]:
    level = row.get("level")
    if level != "DEFAULT":
        raise ValueError("observation level must be DEFAULT")
    status_message = _first(row, "statusMessage", "status_message", default=None)
    if status_message not in (None, ""):
        raise ValueError("observation statusMessage must be empty")
    metadata = _mapping(row.get("metadata"))
    usage = _mapping(_first(row, "usage_details", "usageDetails", "usage", default={}))
    cost = _mapping(_first(row, "cost_details", "costDetails", default={}))
    start_time = _iso(_first(row, "start_time", "startTime"))
    end_time = _iso(_first(row, "end_time", "endTime"))
    latency = _number(_first(row, "latency", default=None))
    if latency is None:
        start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
        latency = (end - start).total_seconds()
    metrics: dict[str, Any] = {}

    result_count = _metric(metadata, "result_count", "resultCount")
    if result_count is not None:
        metrics["result_count"] = result_count
    if latency is not None:
        metrics["latency_ms"] = round(float(latency) * 1000, 6)

    model = _closed_text(
        _first(
            row,
            "model",
            "provided_model_name",
            "providedModelName",
            default=_metric(metadata, "model"),
        ),
        "model",
    )
    prompt_version = _closed_text(
        _first(row, "prompt_version", "promptVersion", default=_metric(metadata, "prompt_version")),
        "prompt_version",
    )
    input_tokens = _number(
        _first(
            usage,
            "input",
            "input_tokens",
            "inputTokens",
            "prompt_tokens",
            default=_metric(metadata, "input_tokens"),
        )
    )
    output_tokens = _number(
        _first(
            usage,
            "output",
            "output_tokens",
            "outputTokens",
            "completion_tokens",
            default=_metric(metadata, "output_tokens"),
        )
    )
    total_tokens = _number(
        _first(
            usage,
            "total",
            "total_tokens",
            "totalTokens",
            default=_metric(metadata, "total_tokens"),
        )
    )
    total_cost = _number(
        _first(
            row,
            "calculated_total_cost",
            "calculatedTotalCost",
            "total_cost",
            "totalCost",
            default=_first(cost, "total", "total_cost", default=_metric(metadata, "cost_usd")),
        )
    )
    for key, value in (
        ("model", model),
        ("prompt_version", prompt_version),
        ("input_tokens", input_tokens),
        ("output_tokens", output_tokens),
        ("total_tokens", total_tokens),
        ("cost_usd", total_cost),
    ):
        if value is not None:
            metrics[key] = value

    for key in (
        "document_count",
        "result_count",
        "latency_ms",
        "admitted_pair_count",
        "candidate_count",
        "verified_fact_count",
        "rejected_citation_count",
        "action_count",
        "quarantined_count",
        "replay_bundle_sha256",
        "workflow_run_sha256",
        "checkpoint_sha256",
        "corpus_sha256",
        "proposal_sha256",
        "query_sha256",
        "review_receipt_sha256",
        "library_release_sha256",
        "route_sha256",
        "candidate_sha256",
        "persisted",
        "authenticated",
        "authorized",
        "receipt_persisted",
        "checkpointed",
        "resumed",
        "provisional",
        "graph_mutated",
        "idempotent",
        "resulting_version",
        "review_decision",
        "total_tokens",
        "model_attempted",
        "fallback_used",
        "model_disposition",
        "status",
    ):
        value = _metric(metadata, key)
        if value is not None:
            if isinstance(value, str):
                value = _closed_text(value, key)
            if value is not None:
                metrics[key] = value

    span_id = _closed_text(
        _first(row, "id", "observation_id", "observationId", default=None),
        "observation id",
    )
    if not span_id:
        raise ValueError("observation has no id")
    trace_id = _closed_text(
        _first(row, "trace_id", "traceId", default=default_trace_id),
        "trace id",
    )
    if trace_id != default_trace_id:
        raise ValueError("observation belongs to a different trace")
    parent = _first(row, "parent_observation_id", "parentObservationId", default=None)
    parent_id = _closed_text(parent, "parent observation id") if parent else None
    name = _closed_text(_first(row, "name", default=None), "observation name")
    kind = _closed_text(_first(row, "type", "kind", default="span"), "observation kind")
    if not name:
        raise ValueError("observation has no name")
    return {
        "span_id": span_id,
        "parent_span_id": parent_id,
        "name": name,
        "kind": str(kind).lower(),
        "start_time": start_time,
        "end_time": end_time,
        "status": "ok",
        "metrics": dict(sorted(metrics.items())),
    }


def normalize_langfuse_export(raw: Mapping[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    """Return the feature-proof trace receipt for one Langfuse trace export."""

    trace = raw.get("trace") if isinstance(raw.get("trace"), Mapping) else raw
    if not isinstance(trace, Mapping):
        raise ValueError("Langfuse export must contain one trace object")
    trace_id = _closed_text(
        _first(trace, "id", "trace_id", "traceId", default=None), "trace id"
    )
    if not trace_id:
        raise ValueError("Langfuse trace has no id")
    rows = _first(
        raw,
        "observations",
        "spans",
        default=_first(trace, "observations", "spans", default=[]),
    )
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        raise ValueError("Langfuse observations must be an array")
    if len(rows) > 256:
        raise ValueError("Langfuse export exceeds 256 observations")
    spans = [_normalize_observation(row, trace_id) for row in rows if isinstance(row, Mapping)]
    if len(spans) != len(rows):
        raise ValueError("every Langfuse observation must be an object")
    spans.sort(
        key=lambda span: (_instant(span["start_time"]), span["name"], span["span_id"])
    )

    scores_in = _first(raw, "scores", default=_first(trace, "scores", default=[]))
    if not isinstance(scores_in, Sequence) or isinstance(scores_in, (str, bytes, bytearray)):
        raise ValueError("Langfuse scores must be an array")
    if len(scores_in) > 256:
        raise ValueError("Langfuse export exceeds 256 scores")
    scores = []
    score_names: set[str] = set()
    for score in scores_in:
        if not isinstance(score, Mapping):
            raise ValueError("every Langfuse score must be an object")
        value = _first(score, "value", "string_value", "stringValue", default=None)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("score value must be finite numeric")
        score_name = _closed_text(_first(score, "name", default=None), "score name")
        if not score_name:
            raise ValueError("score has no name")
        if score_name in score_names:
            raise ValueError(f"duplicate score name: {score_name}")
        score_names.add(score_name)
        scores.append(
            {
                "name": score_name,
                "value": value,
            }
        )
    scores.sort(key=lambda score: (score["name"], json.dumps(score["value"], sort_keys=True)))

    root_metadata = _mapping(trace.get("metadata"))
    root_model_attempted = _metric(root_metadata, "model_attempted")
    if root_model_attempted is not None and not isinstance(root_model_attempted, bool):
        raise ValueError("root model_attempted must be boolean")
    model_attempted = root_model_attempted is True or any(
        span["metrics"].get("model_attempted") is True or "model" in span["metrics"]
        for span in spans
    )
    captured = _first(trace, "timestamp", "created_at", "createdAt", default=None)
    captured_at = (
        _iso(captured)
        if captured
        else max(
            (span["end_time"] for span in spans),
            key=_instant,
            default="1970-01-01T00:00:00Z",
        )
    )
    release = _closed_text(
        _first(trace, "release", "version", default=None), "trace release"
    )
    trace_name = _closed_text(_first(trace, "name", default=None), "trace name")
    if not release or not trace_name:
        raise ValueError("trace release and name are required")
    return {
        "schema_version": "feature-proof-trace-normalized/v1",
        "source": {"provider": "langfuse", "raw_sha256": sha256(raw_bytes).hexdigest()},
        "trace_id": trace_id,
        "release": release,
        "trace_name": trace_name,
        "captured_at": captured_at,
        "model_attempted": model_attempted,
        "spans": spans,
        "scores": scores,
    }
