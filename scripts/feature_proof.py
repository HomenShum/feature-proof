#!/usr/bin/env python3
"""Initialize, normalize, check, and finalize feature-proof packets.

The checker treats files as untrusted input.  It is intentionally stdlib-only,
bounded, deterministic in ordering, and refuses path escapes and symlinks.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from html import escape as html_escape
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
import unicodedata

from langfuse_receipt import normalize_langfuse_export


MAX_JSON_BYTES = 1_048_576
MAX_TEXT_BYTES = 2_097_152
MAX_PACKET_FILES = 512
MAX_PACKET_BYTES = 67_108_864
HARD_MAX_PACKET_BYTES = 268_435_456
MAX_GATE_STREAM_BYTES = 1_048_576
MAX_GATE_SECONDS = 3_600
MAX_LANGFUSE_CREDENTIAL_CHARS = 4_096
MAX_LANGFUSE_CREDENTIAL_SOURCE_CHARS = 8_192
MAX_LANGFUSE_FETCH_SECONDS = 30.0
MAX_LANGFUSE_REQUEST_SECONDS = 10.0
MAX_LANGFUSE_SHUTDOWN_SECONDS = 2.0
DEFAULT_LANGFUSE_ORIGIN = "https://cloud.langfuse.com"
LOCAL_LANGFUSE_ORIGIN = "http://127.0.0.1:3000"
LANGFUSE_HTTPS_ORIGIN = re.compile(
    r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?"
)
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
MAIN_PORTABLE_INTEGRITY_CONTRACT = "git-seal-main-portable/v1"
# This public checker can prove ancestry only to the checkout's current HEAD.
# A Graphite/GitHub host workflow must also run
# `git merge-base --is-ancestor $Source origin/main` before source freeze.
MAIN_PORTABLE_TEXT_SUFFIXES = frozenset(
    {".ffconcat", ".json", ".jsonl", ".md", ".svg", ".txt", ".vtt"}
)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
FORBIDDEN_KEYS = {
    "authorization",
    "access_token",
    "refresh_token",
    "api_key",
    "secret_key",
    "password",
    "cookie",
    "set_cookie",
    "document_text",
    "customer_document_text",
    "raw_document",
    "email",
}
RAW_TRACE_FORBIDDEN_KEYS = FORBIDDEN_KEYS | {
    "comments",
    "confidential",
    "confidential_input",
    "documents",
    "input",
    "output",
    "prompt",
    "prompt_text",
    "raw_input",
    "raw_output",
    "status_message",
    "user_id",
}
CLAIM_TYPES = {
    "idempotent",
    "versioned",
    "parallel",
    "fail_closed",
    "citation_grounded",
    "human_reviewed",
    "no_duplicate_job",
    "trace_contract",
    "gate",
}
REQUIRED_DECISION_FIELDS = {
    "id",
    "timestamp",
    "decision",
    "why",
    "rejected_alternative",
    "evidence",
    "trigger_to_revisit",
    "supersedes",
}
DEFAULT_PRODUCT_FORBIDDEN = {
    "api",
    "class",
    "endpoint",
    "function",
    "http",
    "json",
    "langfuse",
    "langgraph",
    "python",
    "typescript",
}
REQUIRED_SCENARIO_CATEGORIES = {
    "happy",
    "sad",
    "adversarial",
    "degraded",
    "burst",
    "sustained",
    "restore",
}
TRACE_CONTRACT_FIELDS = {
    "schema_version",
    "trace_name",
    "required_root",
    "required_spans",
    "optional_spans",
    "ordered_pairs",
    "parallel_groups",
    "metrics",
    "required_scores",
    "must_not_capture",
    "limits",
}
TRACE_RECEIPT_FIELDS = {
    "schema_version",
    "source",
    "claim_id",
    "claim_definition",
    "claim_definition_sha256",
    "trace_contract_sha256",
    "source_identity_sha256",
    "raw_langfuse_sha256",
    "trace_id",
    "release",
    "trace_name",
    "captured_at",
    "model_attempted",
    "spans",
    "scores",
}
TRACE_STAGING_FIELDS = {
    "schema_version",
    "source",
    "trace_id",
    "release",
    "trace_name",
    "captured_at",
    "model_attempted",
    "spans",
    "scores",
}
SPAN_FIELDS = {
    "span_id",
    "parent_span_id",
    "name",
    "kind",
    "start_time",
    "end_time",
    "status",
    "metrics",
}
ALLOWED_METRIC_KEYS = {
    "action_count",
    "admission_oracle_mismatch_count",
    "admitted_pair_count",
    "authenticated",
    "authorized",
    "case_count",
    "candidate_count",
    "candidate_sha256",
    "checkpoint_sha256",
    "checkpointed",
    "controlled_unsigned_fixture",
    "corpus_sha256",
    "cost_usd",
    "counterfactual_evaluation_depth",
    "dataset_sha256",
    "dimensions",
    "document_count",
    "duration_ms",
    "estimated_list_price_cost_usd",
    "exact_scan",
    "excluded_pair_count",
    "expected_admission_sha256",
    "fallback_used",
    "graph_mutated",
    "idempotent",
    "input_count",
    "input_format_version",
    "input_tokens",
    "lane_depth",
    "latency_ms",
    "leakage_count",
    "library_release_sha256",
    "list_price_basis",
    "locator_checks",
    "locator_failures",
    "max_admitted_candidates",
    "model",
    "model_attempted",
    "model_disposition",
    "model_version",
    "no_evidence_case_count",
    "output_tokens",
    "parallel_groups",
    "pass_scope",
    "persisted",
    "positive_case_count",
    "prefix_identity_checked",
    "prompt_version",
    "proposal_sha256",
    "provisional",
    "provider",
    "quarantined_count",
    "query_sha256",
    "ranking_backend",
    "recall_depth_saturated",
    "receipt_persisted",
    "rejected_citation_count",
    "replay_bundle_sha256",
    "request_count",
    "result_count",
    "resulting_version",
    "resumed",
    "review_decision",
    "review_receipt_sha256",
    "route_sha256",
    "rrf_k",
    "semantic_report_sha256",
    "selection_authority",
    "serving_depth",
    "serving_hydration_depth",
    "status",
    "strategy_count",
    "total_tokens",
    "variant_count",
    "verified_fact_count",
    "workflow_run_sha256",
}
NONNEGATIVE_NUMERIC_METRIC_KEYS = frozenset({
    "cost_usd",
    "duration_ms",
    "estimated_list_price_cost_usd",
    "latency_ms",
})
NONNEGATIVE_INTEGER_METRIC_KEYS = frozenset({
    "action_count",
    "admission_oracle_mismatch_count",
    "admitted_pair_count",
    "case_count",
    "candidate_count",
    "counterfactual_evaluation_depth",
    "dimensions",
    "document_count",
    "excluded_pair_count",
    "input_count",
    "input_tokens",
    "lane_depth",
    "leakage_count",
    "locator_checks",
    "locator_failures",
    "max_admitted_candidates",
    "no_evidence_case_count",
    "output_tokens",
    "parallel_groups",
    "positive_case_count",
    "quarantined_count",
    "rejected_citation_count",
    "request_count",
    "result_count",
    "resulting_version",
    "rrf_k",
    "serving_depth",
    "serving_hydration_depth",
    "strategy_count",
    "total_tokens",
    "variant_count",
    "verified_fact_count",
})
BOOLEAN_METRIC_KEYS = frozenset({
    "authenticated",
    "authorized",
    "checkpointed",
    "controlled_unsigned_fixture",
    "exact_scan",
    "fallback_used",
    "graph_mutated",
    "idempotent",
    "model_attempted",
    "persisted",
    "prefix_identity_checked",
    "provisional",
    "recall_depth_saturated",
    "receipt_persisted",
    "resumed",
})
SHA256_METRIC_KEYS = frozenset({
    "candidate_sha256",
    "checkpoint_sha256",
    "corpus_sha256",
    "dataset_sha256",
    "expected_admission_sha256",
    "library_release_sha256",
    "proposal_sha256",
    "query_sha256",
    "replay_bundle_sha256",
    "review_receipt_sha256",
    "route_sha256",
    "semantic_report_sha256",
    "workflow_run_sha256",
})
CLOSED_IDENTIFIER_METRIC_KEYS = frozenset({
    "input_format_version",
    "list_price_basis",
    "model",
    "model_disposition",
    "model_version",
    "pass_scope",
    "prompt_version",
    "provider",
    "ranking_backend",
    "review_decision",
    "selection_authority",
    "status",
})
_METRIC_TYPE_GROUPS = (
    NONNEGATIVE_NUMERIC_METRIC_KEYS,
    NONNEGATIVE_INTEGER_METRIC_KEYS,
    BOOLEAN_METRIC_KEYS,
    SHA256_METRIC_KEYS,
    CLOSED_IDENTIFIER_METRIC_KEYS,
)
_TYPED_METRIC_KEYS = frozenset().union(*_METRIC_TYPE_GROUPS)
if (
    sum(len(group) for group in _METRIC_TYPE_GROUPS) != len(_TYPED_METRIC_KEYS)
    or _TYPED_METRIC_KEYS != ALLOWED_METRIC_KEYS
):
    raise RuntimeError("feature-proof metric type guards must partition the closed schema")
SEMANTIC_REQUIRED_VALUES = {
    "authenticated",
    "authorized",
    "checkpointed",
    "controlled_unsigned_fixture",
    "dataset_sha256",
    "graph_mutated",
    "persisted",
    "ranking_backend",
    "receipt_persisted",
    "review_decision",
    "resumed",
    "selection_authority",
    "status",
}
GENERIC_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_type",
    "claim_id",
    "claim_definition",
    "claim_definition_sha256",
    "source_commit",
    "source_identity_sha256",
    "passed",
    "evidence",
    "derived_from",
}
CLAIM_FIELDS = {
    "id",
    "text",
    "receipt_type",
    "receipt_ref",
    "modes",
    "required",
    "status",
}
CLAIM_DEFINITION_FIELDS = {
    "schema_version",
    "claim_id",
    "outcome_text",
    "narration_authority",
    "receipt_rule",
    "required",
}
EVIDENCE_SCHEMA_TOKENS = {
    "boolean",
    "empty_array",
    "identifier",
    "integer",
    "nonnegative_integer",
    "number",
    "positive_integer",
    "sha256",
    "string",
    "string_array",
    "true",
    "false",
}
DERIVATION_FIELDS = {
    "scenario_output_ref",
    "scenario_output_sha256",
    "gate_receipt_ref",
    "gate_receipt_sha256",
}
GATE_RECEIPT_FIELDS = {
    "schema_version",
    "gate_id",
    "source_commit",
    "source_identity_sha256",
    "argv",
    "command_sha256",
    "exit_code",
    "passed",
    "expected_literal",
    "observed_literal",
    "stdout_bytes",
    "stdout_sha256",
    "stderr_bytes",
    "stderr_sha256",
    "output_sha256",
    "scenario_output_ref",
    "scenario_output_sha256",
    "captured_at",
}

_THREAD_MUTATION_LOCK = threading.Lock()


class ProofError(RuntimeError):
    """A safe, user-actionable feature-proof failure."""


@dataclass
class Report:
    feature_id: str = "unknown"
    errors: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    verified_claims: list[str] = field(default_factory=list)
    checked_files: int = 0

    def error(self, message: str) -> None:
        self.errors.append(message)

    def wait(self, message: str) -> None:
        self.pending.append(message)

    def as_dict(self) -> dict[str, Any]:
        status = "FAIL" if self.errors else "PENDING" if self.pending else "PASS"
        return {
            "schema_version": "feature-proof-check/v1",
            "status": status,
            "feature_id": self.feature_id,
            "checked_files": self.checked_files,
            "verified_claims": sorted(set(self.verified_claims)),
            "pending": sorted(set(self.pending)),
            "errors": sorted(set(self.errors)),
        }


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _source_identity_sha256(source: Mapping[str, Any]) -> str:
    """Bind receipts to the complete manifest source identity, not just a label."""

    return sha256(_canonical(source)).hexdigest()


def _claim_definition(claim: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable narration and receipt rule a claim may prove."""

    receipt_type = str(claim.get("receipt_type", ""))
    receipt_rule: dict[str, Any] = {
        "schema_version": "feature-proof-receipt-rule/v1",
        "receipt_type": receipt_type,
        "receipt_ref": claim.get("receipt_ref"),
    }
    if receipt_type == "trace_contract":
        receipt_rule["trace_contract_ref"] = claim.get("trace_contract_ref")
    else:
        receipt_rule["evidence_schema"] = claim.get("evidence_schema")
    return {
        "schema_version": "feature-proof-claim-definition/v1",
        "claim_id": claim.get("id"),
        "outcome_text": claim.get("text"),
        "narration_authority": {
            "text": claim.get("text"),
            "modes": claim.get("modes"),
        },
        "receipt_rule": receipt_rule,
        "required": claim.get("required"),
    }


def _claim_definition_sha256(claim: Mapping[str, Any]) -> str:
    return sha256(_canonical(_claim_definition(claim))).hexdigest()


def _validate_evidence_schema(
    schema: Any,
    report: Report,
    location: str,
    *,
    depth: int = 0,
    nodes: list[int] | None = None,
) -> None:
    """Validate the bounded closed-shape language used by typed claim evidence."""

    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > 256 or depth > 8:
        report.error(f"{location}: evidence schema exceeds its structural bound")
        return
    if isinstance(schema, str):
        if schema not in EVIDENCE_SCHEMA_TOKENS:
            report.error(f"{location}: unsupported evidence schema token {schema}")
        return
    if not isinstance(schema, Mapping):
        report.error(f"{location}: evidence schema node must be an object or token")
        return
    if set(schema) == {"$const"}:
        value = schema["$const"]
        if not isinstance(value, (str, int, float, bool)) or (
            isinstance(value, float) and not math.isfinite(value)
        ):
            report.error(f"{location}: $const must be a finite JSON scalar")
        elif isinstance(value, str) and not 1 <= len(value) <= 2_000:
            report.error(f"{location}: $const string is unbounded")
        return
    if set(schema) == {"$enum"}:
        values = schema["$enum"]
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 32
            or len({_canonical(value) for value in values}) != len(values)
        ):
            report.error(f"{location}: $enum must contain 1-32 unique scalars")
            return
        for index, value in enumerate(values):
            if not isinstance(value, (str, int, float, bool)) or (
                isinstance(value, float) and not math.isfinite(value)
            ):
                report.error(f"{location}.$enum[{index}]: value must be a finite scalar")
            elif isinstance(value, str) and not 1 <= len(value) <= 2_000:
                report.error(f"{location}.$enum[{index}]: string is unbounded")
        return
    if not schema:
        report.error(f"{location}: evidence object schema cannot be empty")
        return
    for key, nested in schema.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
            report.error(f"{location}: evidence schema key is malformed")
            continue
        _validate_evidence_schema(
            nested, report, f"{location}.{key}", depth=depth + 1, nodes=nodes,
        )


def _validate_evidence_value(
    value: Any,
    schema: Any,
    report: Report,
    location: str,
    *,
    depth: int = 0,
) -> None:
    if depth > 8:
        report.error(f"{location}: evidence exceeds its structural bound")
        return
    if isinstance(schema, Mapping):
        if set(schema) == {"$const"}:
            if _canonical(value) != _canonical(schema["$const"]):
                report.error(f"{location}: evidence does not equal its declared constant")
            return
        if set(schema) == {"$enum"}:
            if not any(_canonical(value) == _canonical(item) for item in schema["$enum"]):
                report.error(f"{location}: evidence is outside its declared enum")
            return
        if not isinstance(value, Mapping):
            report.error(f"{location}: evidence must be an object")
            return
        _exact_keys(value, set(schema), report, location)
        for key, nested in schema.items():
            if key in value:
                _validate_evidence_value(
                    value[key], nested, report, f"{location}.{key}", depth=depth + 1,
                )
        return
    if schema == "string":
        valid = isinstance(value, str) and 1 <= len(value) <= 2_000
    elif schema == "identifier":
        valid = isinstance(value, str) and re.fullmatch(
            r"[A-Za-z0-9._:/-]{1,256}", value,
        ) is not None
    elif schema == "sha256":
        valid = isinstance(value, str) and SHA_RE.fullmatch(value) is not None
    elif schema == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif schema == "nonnegative_integer":
        valid = isinstance(value, int) and not isinstance(value, bool) and value >= 0
    elif schema == "positive_integer":
        valid = isinstance(value, int) and not isinstance(value, bool) and value > 0
    elif schema == "number":
        valid = _finite_number(value)
    elif schema == "boolean":
        valid = isinstance(value, bool)
    elif schema == "true":
        valid = value is True
    elif schema == "false":
        valid = value is False
    elif schema == "empty_array":
        valid = isinstance(value, list) and not value
    elif schema == "string_array":
        valid = (
            isinstance(value, list)
            and len(value) <= 256
            and all(isinstance(item, str) and 1 <= len(item) <= 2_000 for item in value)
            and len(value) == len(set(value))
        )
    else:
        valid = False
    if not valid:
        report.error(f"{location}: evidence does not match schema token {schema}")


def _validate_claim_binding(
    receipt: Mapping[str, Any],
    claim: Mapping[str, Any],
    report: Report,
    location: str,
) -> bool:
    expected = _claim_definition(claim)
    definition = receipt.get("claim_definition")
    digest = receipt.get("claim_definition_sha256")
    valid = True
    if not isinstance(definition, Mapping):
        report.error(f"{location}: claim definition is missing")
        return False
    _exact_keys(definition, CLAIM_DEFINITION_FIELDS, report, f"{location}.claim_definition")
    narration = definition.get("narration_authority")
    if not isinstance(narration, Mapping) or set(narration) != {"text", "modes"}:
        report.error(f"{location}: claim narration authority schema is not closed")
        valid = False
    rule = definition.get("receipt_rule")
    expected_rule = expected["receipt_rule"]
    if not isinstance(rule, Mapping) or set(rule) != set(expected_rule):
        report.error(f"{location}: claim receipt rule schema is not closed")
        valid = False
    if _canonical(definition) != _canonical(expected):
        report.error(f"{location}: claim definition differs from the manifest")
        valid = False
    expected_digest = sha256(_canonical(expected)).hexdigest()
    if digest != expected_digest:
        report.error(f"{location}: claim definition digest differs from the manifest")
        valid = False
    return valid


def _command_output_sha256(stdout: bytes, stderr: bytes) -> str:
    streams = {
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256(stderr).hexdigest(),
    }
    return sha256(_canonical(streams)).hexdigest()


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ProofError(f"non-finite JSON number is forbidden: {value}")


def _exact_keys(
    value: Mapping[str, Any], expected: set[str], report: Report, location: str,
) -> bool:
    actual = set(value)
    if actual == expected:
        return True
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    details = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if extra:
        details.append("unexpected " + ", ".join(extra))
    report.error(f"{location}: schema is not closed ({'; '.join(details)})")
    return False


def _closed_key(value: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _read_bytes(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ProofError(f"{path.name} exceeds {limit} bytes")
    data = path.read_bytes()
    if len(data) != size:
        raise ProofError(f"{path.name} changed while it was read")
    return data


def _read_json(path: Path, limit: int = MAX_JSON_BYTES) -> Any:
    try:
        return json.loads(
            _read_bytes(path, limit).decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"{path.name} is not valid bounded UTF-8 JSON: {exc}") from exc


def _safe_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative.strip():
        raise ProofError("empty evidence path")
    normalized = relative.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("/"):
        raise ProofError(f"absolute evidence path is forbidden: {relative}")
    path = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ProofError(f"unsafe evidence path: {relative}")
    return path.parts


def _resolve_in(base: Path, relative: str, *, must_exist: bool = True) -> Path:
    parts = _safe_parts(relative)
    root = base.resolve(strict=True)
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.exists() and cursor.is_symlink():
            raise ProofError(f"symlink evidence path is forbidden: {relative}")
    candidate = root.joinpath(*parts)
    resolved = candidate.resolve(strict=must_exist)
    try:
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            raise ProofError(f"evidence path escapes packet: {relative}")
    except ValueError as exc:
        raise ProofError(f"evidence path escapes packet: {relative}") from exc
    if must_exist and not resolved.is_file():
        raise ProofError(f"evidence reference is not a file: {relative}")
    return resolved


def _scan_packet(packet: Path, byte_limit: int) -> list[Path]:
    if packet.is_symlink():
        raise ProofError("packet root may not be a symlink")
    files: list[Path] = []
    total = 0
    for path in sorted(packet.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ProofError(f"packet contains a symlink: {path.relative_to(packet).as_posix()}")
        if path.is_file():
            files.append(path)
            total += path.stat().st_size
            if path.name.startswith(".feature-proof-"):
                raise ProofError(f"packet contains an unpublished staging file: {path.name}")
    if len(files) > MAX_PACKET_FILES:
        raise ProofError(f"packet exceeds {MAX_PACKET_FILES} files")
    if total > min(byte_limit, HARD_MAX_PACKET_BYTES):
        raise ProofError(f"packet exceeds {min(byte_limit, HARD_MAX_PACKET_BYTES)} bytes")
    return files


def _reject_symlink_ancestors(path: Path) -> None:
    cursor = path
    while True:
        if cursor.exists() and cursor.is_symlink():
            raise ProofError(f"symlink path component is forbidden: {cursor}")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _privacy_scan(
    value: Any,
    report: Report,
    location: str,
    *,
    extra_keys: Iterable[str] = (),
    extra_patterns: Iterable[str] = (),
    allow_empty_forbidden: bool = False,
) -> None:
    forbidden = FORBIDDEN_KEYS | {str(key).lower() for key in extra_keys}
    compiled: list[re.Pattern[str]] = []
    for pattern in extra_patterns:
        if not isinstance(pattern, str) or len(pattern) > 256:
            report.error(f"{location}: invalid must-not-capture pattern")
            continue
        try:
            compiled.append(re.compile(pattern, re.I))
        except re.error as exc:
            report.error(f"{location}: invalid must-not-capture regex: {exc}")

    def walk(item: Any, trail: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                normalized = _closed_key(key)
                empty_placeholder = (
                    child is None
                    or (isinstance(child, str) and child == "")
                    or (isinstance(child, list) and not child)
                    or (isinstance(child, Mapping) and not child)
                )
                if normalized in forbidden and not (
                    allow_empty_forbidden and empty_placeholder
                ):
                    report.error(f"{location}: forbidden privacy key at {trail}.{key}")
                walk(child, f"{trail}.{key}")
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for index, child in enumerate(item):
                walk(child, f"{trail}[{index}]")
        elif isinstance(item, str):
            if EMAIL_RE.search(item):
                report.error(f"{location}: raw email-like identifier at {trail}")
            if any(pattern.search(item) for pattern in SECRET_VALUE_PATTERNS):
                report.error(f"{location}: credential-like value at {trail}")
            if any(pattern.search(item) for pattern in compiled):
                report.error(f"{location}: must-not-capture content at {trail}")

    walk(value, "$")


def _git_bytes(root: Path, argv: Sequence[str], *, label: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProofError(f"{label}: git verification could not run") from exc
    if completed.returncode != 0:
        raise ProofError(f"{label}: git verification failed")
    if len(completed.stdout) > MAX_TEXT_BYTES:
        raise ProofError(f"{label}: git verification output is unbounded")
    return completed.stdout


def _git_is_ancestor(
    root: Path,
    ancestor: str,
    descendant: str,
    *,
    label: str,
) -> bool:
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProofError(f"{label}: git ancestry verification could not run") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise ProofError(f"{label}: git ancestry verification failed")


def _verify_source_identity(
    root: Path,
    source: Mapping[str, Any],
    *,
    newline_portable_paths: set[str] | None = None,
) -> None:
    """Prove the declared commit owns the exact bytes being executed."""

    if source.get("repository") != ".":
        raise ProofError("source.repository must be '.' for a repo-root-bound receipt")
    commit = str(source.get("implementation_commit", ""))
    if not COMMIT_RE.fullmatch(commit):
        raise ProofError("source implementation commit is malformed")
    _git_bytes(root, ["cat-file", "-e", f"{commit}^{{commit}}"], label="implementation commit")
    integrity_contract = source.get("integrity_contract")
    if integrity_contract is not None:
        if integrity_contract != MAIN_PORTABLE_INTEGRITY_CONTRACT:
            raise ProofError("source.integrity_contract is unsupported")
        if not _git_is_ancestor(
            root,
            commit,
            "HEAD",
            label="source integrity",
        ):
            raise ProofError(
                "source implementation commit must be an ancestor of HEAD "
                f"under {MAIN_PORTABLE_INTEGRITY_CONTRACT}"
            )
    paths = source.get("implementation_paths")
    if not isinstance(paths, list) or not paths:
        raise ProofError("implementation paths must be a nonempty array")
    normalized: list[str] = []
    for value in paths:
        parts = _safe_parts(str(value))
        relative = PurePosixPath(*parts).as_posix()
        if relative in normalized:
            raise ProofError(f"implementation path is duplicated: {relative}")
        normalized.append(relative)
        try:
            local = _resolve_in(root, relative)
        except FileNotFoundError as exc:
            raise ProofError(
                f"implementation path is missing from the current checkout: {relative}"
            ) from exc
        object_type = _git_bytes(
            root, ["cat-file", "-t", f"{commit}:{relative}"],
            label=f"implementation path {relative}",
        ).strip()
        if object_type != b"blob":
            raise ProofError(f"implementation path is not a tracked file at the commit: {relative}")
        committed_oid = _git_bytes(
            root, ["rev-parse", f"{commit}:{relative}"],
            label=f"implementation path {relative}",
        ).strip()
        current_oid = _git_bytes(
            root, ["hash-object", f"--path={relative}", "--", str(local)],
            label=f"implementation path {relative}",
        ).strip()
        if committed_oid != current_oid:
            if relative in (newline_portable_paths or set()):
                committed = _git_bytes(
                    root, ["show", f"{commit}:{relative}"],
                    label=f"implementation path {relative}",
                )
                current = _read_bytes(local, MAX_JSON_BYTES)
                if _canonical_line_endings(current) == _canonical_line_endings(committed):
                    continue
            raise ProofError(
                f"implementation path differs from the declared commit: {relative}"
            )


def _git_nul_paths(root: Path, argv: Sequence[str], *, label: str) -> list[str]:
    """Read one bounded NUL-delimited Git path list without shell parsing."""

    encoded = _git_bytes(root, argv, label=label)
    if not encoded:
        return []
    if not encoded.endswith(b"\0"):
        raise ProofError(f"{label}: git path output is malformed")
    paths: list[str] = []
    for raw in encoded[:-1].split(b"\0"):
        relative = os.fsdecode(raw).replace("\\", "/")
        try:
            normalized = PurePosixPath(*_safe_parts(relative)).as_posix()
        except ProofError as exc:
            raise ProofError(f"{label}: git returned an unsafe path") from exc
        paths.append(normalized)
    return paths


def _path_key(relative: str) -> str:
    """Keep manifest/Git path spelling exact on every checkout platform."""

    return relative


def _committed_packet_bytes(
    root: Path,
    commit: str,
    packet_prefix: str,
    relative: str,
    *,
    label: str,
) -> bytes:
    """Read one bounded packet blob from the frozen source commit."""

    normalized = PurePosixPath(*_safe_parts(relative)).as_posix()
    repository_path = f"{packet_prefix}/{normalized}"
    object_type = _git_bytes(
        root, ["cat-file", "-t", f"{commit}:{repository_path}"], label=label,
    ).strip()
    if object_type != b"blob":
        raise ProofError(f"{label}: source commit path is not a tracked file")
    return _git_bytes(
        root, ["show", f"{commit}:{repository_path}"], label=label,
    )


def _bounded_json_bytes(data: bytes, *, label: str) -> Any:
    """Decode one bounded duplicate-safe JSON value already held in memory."""

    if len(data) > MAX_JSON_BYTES:
        raise ProofError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"{label} is not valid bounded UTF-8 JSON: {exc}") from exc


def _canonical_line_endings(data: bytes) -> bytes:
    """Normalize only CRLF and bare CR so Git-smudged text compares as LF."""

    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _source_bound_trace_contract_sha256(
    root: Path,
    packet: Path,
    commit: str,
    relative: str,
) -> str:
    """Hash the frozen Git blob after allowing only worktree newline smudging."""

    contract_ref = PurePosixPath(*_safe_parts(relative)).as_posix()
    if not COMMIT_RE.fullmatch(commit):
        return _sha_file(_resolve_in(packet, contract_ref))
    try:
        packet_relative = packet.relative_to(root)
    except ValueError as exc:
        raise ProofError("feature packet must be inside the Git worktree root") from exc
    if not packet_relative.parts:
        raise ProofError("feature packet cannot be the Git worktree root")
    packet_prefix = PurePosixPath(*packet_relative.parts).as_posix()
    committed = _committed_packet_bytes(
        root,
        commit,
        packet_prefix,
        contract_ref,
        label=f"source trace contract {contract_ref}",
    )
    current = _read_bytes(
        _resolve_in(packet, contract_ref), MAX_JSON_BYTES,
    )
    if _canonical_line_endings(current) != _canonical_line_endings(committed):
        raise ProofError(
            f"trace contract differs from the source commit beyond line endings: {contract_ref}"
        )
    return sha256(committed).hexdigest()


def _trace_contract_refs(manifest: Mapping[str, Any]) -> set[str]:
    """Return the closed set of contracts that may authorize trace receipts."""

    default = manifest.get("trace_contract_ref")
    refs: set[str] = set()
    claims = manifest.get("claims")
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, Mapping) or claim.get("receipt_type") != "trace_contract":
                continue
            value = claim.get("trace_contract_ref", default)
            if isinstance(value, str):
                refs.add(PurePosixPath(*_safe_parts(value)).as_posix())
    return refs


def _verify_manifest_transition(
    committed: Any, current: Mapping[str, Any], commit: str,
) -> None:
    """Allow only the post-commit source freeze and pending-to-verified claims."""

    if not isinstance(committed, Mapping):
        raise ProofError("source feature manifest must be an object")
    expected = deepcopy(dict(committed))
    observed = deepcopy(dict(current))
    expected_source = expected.get("source")
    observed_source = observed.get("source")
    if not isinstance(expected_source, dict) or not isinstance(observed_source, dict):
        raise ProofError("feature manifest source transition is malformed")
    if (
        expected_source.get("identity_status") != "pending_clean_commit"
        or expected_source.get("implementation_commit") is not None
        or observed_source.get("identity_status") != "frozen"
        or observed_source.get("implementation_commit") != commit
    ):
        raise ProofError(
            "feature manifest source may change only from pending/null to frozen/source commit"
        )
    observed_source["identity_status"] = "pending_clean_commit"
    observed_source["implementation_commit"] = None

    expected_claims = expected.get("claims")
    observed_claims = observed.get("claims")
    if (
        not isinstance(expected_claims, list)
        or not isinstance(observed_claims, list)
        or len(expected_claims) != len(observed_claims)
    ):
        raise ProofError("feature manifest claims differ from the source commit")
    for index, (prior, current_claim) in enumerate(zip(expected_claims, observed_claims)):
        if not isinstance(prior, dict) or not isinstance(current_claim, dict):
            raise ProofError(f"feature manifest claim {index} is malformed")
        if prior.get("status") != "pending" or current_claim.get("status") not in {
            "pending", "verified",
        }:
            raise ProofError(
                "feature manifest claim status may change only from pending to verified"
            )
        current_claim["status"] = "pending"
    if observed != expected:
        raise ProofError(
            "feature manifest differs from the source commit outside the allowed freeze/status fields"
        )


def _generated_packet_paths(
    root: Path,
    packet_prefix: str,
    commit: str,
    committed_manifest: Mapping[str, Any],
) -> set[str]:
    """Compile the closed set of receipt and media outputs declared by source policy."""

    allowed: set[str] = {"artifact-manifest.json"}

    def add(value: Any, *, label: str) -> None:
        if not isinstance(value, str):
            raise ProofError(f"{label} must be a packet-relative path")
        allowed.add(PurePosixPath(*_safe_parts(value)).as_posix())

    claims = committed_manifest.get("claims")
    if not isinstance(claims, list):
        raise ProofError("source feature manifest claims must be an array")
    for index, claim in enumerate(claims):
        if not isinstance(claim, Mapping):
            raise ProofError(f"source feature manifest claim {index} is malformed")
        add(claim.get("receipt_ref"), label=f"claim {index} receipt_ref")

    gates = committed_manifest.get("gates")
    if not isinstance(gates, list):
        raise ProofError("source feature manifest gates must be an array")
    for index, gate in enumerate(gates):
        if not isinstance(gate, Mapping):
            raise ProofError(f"source feature manifest gate {index} is malformed")
        add(gate.get("receipt_path"), label=f"gate {index} receipt_path")
        scenario = gate.get("scenario_output_path")
        if scenario is None:
            gate_id = gate.get("id")
            if not isinstance(gate_id, str) or not ID_RE.fullmatch(gate_id):
                raise ProofError(f"source feature manifest gate {index} id is malformed")
            scenario = f"receipts/scenarios/{gate_id}.json"
        add(scenario, label=f"gate {index} scenario_output_path")

    capture = committed_manifest.get("capture")
    if not isinstance(capture, Mapping):
        raise ProofError("source feature manifest capture must be an object")
    required_media = capture.get("required_media", [])
    if not isinstance(required_media, list):
        raise ProofError("source feature manifest required_media must be an array")
    for index, relative in enumerate(required_media):
        add(relative, label=f"required_media[{index}]")
    add(
        capture.get("media_receipt_ref", "receipts/browser/media-receipt.json"),
        label="capture media_receipt_ref",
    )

    narration_bytes = _committed_packet_bytes(
        root,
        commit,
        packet_prefix,
        "narration.engineering.json",
        label="source engineering narration",
    )
    narration = _bounded_json_bytes(narration_bytes, label="source engineering narration")
    segments = narration.get("segments") if isinstance(narration, Mapping) else None
    if not isinstance(segments, list):
        raise ProofError("source engineering narration segments must be an array")
    for index, segment in enumerate(segments):
        if isinstance(segment, Mapping) and "visual_receipt_ref" in segment:
            visual_ref = segment.get("visual_receipt_ref")
            if not isinstance(visual_ref, str) or PurePosixPath(visual_ref).suffix != ".svg":
                raise ProofError(
                    "engineering narration visual_receipt_ref must declare an SVG output"
                )
            add(
                visual_ref,
                label=f"engineering narration segment {index} visual_receipt_ref",
            )
    return allowed


def _verify_checkout_identity(
    root: Path,
    packet: Path,
    commit: str,
    current_manifest: Mapping[str, Any],
) -> None:
    """Prove source policy is immutable and only declared packet outputs changed."""

    top_level_raw = _git_bytes(
        root, ["rev-parse", "--show-toplevel"], label="repository root",
    ).rstrip(b"\r\n")
    if not top_level_raw:
        raise ProofError("repository root: git returned an empty worktree path")
    try:
        top_level = Path(os.fsdecode(top_level_raw)).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ProofError("repository root: git returned an invalid worktree path") from exc
    if os.path.normcase(str(top_level)) != os.path.normcase(str(root)):
        raise ProofError("repo_root must be the Git worktree root")

    try:
        packet_relative = packet.relative_to(root)
    except ValueError as exc:
        raise ProofError("feature packet must be inside the Git worktree root") from exc
    if not packet_relative.parts:
        raise ProofError("feature packet cannot be the Git worktree root")
    packet_prefix = PurePosixPath(*packet_relative.parts).as_posix()
    prefix_key = _path_key(packet_prefix)

    committed_manifest = _bounded_json_bytes(
        _committed_packet_bytes(
            root,
            commit,
            packet_prefix,
            "feature-manifest.json",
            label="source feature manifest",
        ),
        label="source feature manifest",
    )
    _verify_manifest_transition(committed_manifest, current_manifest, commit)
    if not isinstance(committed_manifest, Mapping):
        raise ProofError("source feature manifest must be an object")
    allowed_outputs = _generated_packet_paths(
        root, packet_prefix, commit, committed_manifest,
    )
    allowed_keys = {_path_key(path) for path in allowed_outputs}
    source_packet_paths = {
        _path_key(path[len(packet_prefix) + 1 :])
        for path in _git_nul_paths(
            root,
            ["ls-tree", "-r", "-z", "--name-only", commit, "--", packet_prefix],
            label="source packet paths",
        )
        if path.startswith(packet_prefix + "/")
    }
    collisions = sorted(allowed_keys & source_packet_paths)
    if collisions:
        raise ProofError(
            "declared generated packet path is tracked policy/evidence at the source commit: "
            + repr(collisions[0])
        )

    committed_decisions = _committed_packet_bytes(
        root,
        commit,
        packet_prefix,
        "decision-log.jsonl",
        label="source decision log",
    )
    current_decisions = _read_bytes(
        _resolve_in(packet, "decision-log.jsonl"), MAX_TEXT_BYTES,
    )
    if not _canonical_line_endings(current_decisions).startswith(
        _canonical_line_endings(committed_decisions)
    ):
        raise ProofError("decision-log.jsonl must preserve source bytes and append only")
    _committed_packet_bytes(
        root, commit, packet_prefix, "HANDOFF.md", label="source handoff",
    )
    _resolve_in(packet, "HANDOFF.md")

    def packet_relative_path(path: str) -> str | None:
        key = _path_key(path)
        if not key.startswith(prefix_key + "/"):
            return None
        return path[len(packet_prefix) + 1 :]

    mutable_tracked = {
        _path_key("feature-manifest.json"),
        _path_key("decision-log.jsonl"),
        _path_key("HANDOFF.md"),
        *allowed_keys,
    }
    trace_contract_refs = {
        _path_key(path) for path in _trace_contract_refs(committed_manifest)
    }

    tracked = sorted(
        set(
            _git_nul_paths(
                root,
                [
                    "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv",
                    "--ignore-submodules=none", "--no-renames", commit, "--",
                ],
                label="checkout tracked paths",
            )
        )
    )
    for path in tracked:
        relative = packet_relative_path(path)
        if relative is None:
            raise ProofError(
                "checkout tracked path differs from the declared commit outside "
                f"the feature packet: {path!r}"
            )
        if _path_key(relative) not in mutable_tracked:
            if _path_key(relative) in trace_contract_refs:
                try:
                    _source_bound_trace_contract_sha256(
                        root, packet, commit, relative,
                    )
                    continue
                except ProofError:
                    pass
            raise ProofError(
                "checkout packet policy path differs from the declared commit: "
                f"{relative!r}"
            )

    untracked = sorted(
        set(
            _git_nul_paths(
                root,
                ["ls-files", "--others", "--exclude-standard", "-z", "--"],
                label="checkout untracked paths",
            )
        )
    )
    for path in untracked:
        relative = packet_relative_path(path)
        if relative is None:
            raise ProofError(
                "checkout has non-ignored untracked path outside the feature packet: "
                f"{path!r}"
            )
        if _path_key(relative) not in allowed_keys:
            raise ProofError(
                "checkout has undeclared untracked path inside the feature packet: "
                f"{relative!r}"
            )

    packet_untracked = sorted(
        set(
            _git_nul_paths(
                root,
                ["ls-files", "--others", "-z", "--", packet_prefix],
                label="checkout packet untracked paths",
            )
        )
    )
    for path in packet_untracked:
        relative = packet_relative_path(path)
        if relative is None or _path_key(relative) not in allowed_keys:
            raise ProofError(
                "checkout has undeclared untracked path inside the feature packet: "
                f"{path!r}"
            )


def _verify_execution_checkout(
    root: Path, packet: Path, manifest: Mapping[str, Any],
) -> None:
    """Bind declared policy files and every other executable checkout path."""

    current = _read_json(_resolve_in(packet, "feature-manifest.json"))
    if not isinstance(current, Mapping) or current != manifest:
        raise ProofError("feature manifest changed during source-bound execution")
    source = current.get("source")
    if not isinstance(source, Mapping):
        raise ProofError("feature manifest source must be an object")
    try:
        packet_relative = packet.relative_to(root)
    except ValueError as exc:
        raise ProofError("feature packet must be inside the Git worktree root") from exc
    packet_prefix = PurePosixPath(*packet_relative.parts).as_posix()
    newline_portable_paths = {
        f"{packet_prefix}/{relative}" for relative in _trace_contract_refs(current)
    }
    _verify_source_identity(
        root, source, newline_portable_paths=newline_portable_paths,
    )
    _verify_checkout_identity(
        root,
        packet,
        str(source.get("implementation_commit", "")),
        current,
    )


@contextmanager
def _packet_lock(packet: Path, *, timeout_seconds: float = 60.0) -> Iterable[None]:
    """Serialize packet mutation across both threads and OS processes."""

    key = str(packet.resolve(strict=True)).casefold()
    if not _THREAD_MUTATION_LOCK.acquire(timeout=timeout_seconds):
        raise ProofError("feature-proof packet is busy")
    handle = None
    locked = False
    deadline = time.monotonic() + timeout_seconds
    try:
        lock_root = Path(tempfile.gettempdir()) / "feature-proof-locks"
        lock_root.mkdir(parents=True, exist_ok=True)
        lock_path = lock_root / f"{sha256(key.encode()).hexdigest()}.lock"
        handle = lock_path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
            os.fsync(handle.fileno())
        while not locked:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise ProofError("feature-proof packet is busy") from exc
                time.sleep(0.05)
        yield
    finally:
        if locked:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        if handle is not None:
            handle.close()
        _THREAD_MUTATION_LOCK.release()


def _parse_time(value: Any, label: str, report: Report) -> datetime | None:
    if not isinstance(value, str):
        report.error(f"{label}: timestamp must be a string")
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("timezone is required")
        return moment.astimezone(timezone.utc)
    except ValueError as exc:
        report.error(f"{label}: malformed timestamp ({exc})")
        return None


def _active_when(when: Any, *, model_attempted: bool, ui_applicable: bool) -> bool:
    if when in (None, "always"):
        return True
    if when == "model_attempted":
        return model_attempted
    if when == "model_not_attempted":
        return not model_attempted
    if when == "ui_applicable":
        return ui_applicable
    if when == "never":
        return False
    raise ProofError(f"unsupported condition: {when}")


def _finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _validate_metric_type(
    key: str,
    value: Any,
    report: Report,
    *,
    location: str,
) -> None:
    """Apply the one closed semantic type assigned to an admitted metric."""

    if key in NONNEGATIVE_NUMERIC_METRIC_KEYS:
        if not _finite_number(value) or value < 0:
            report.error(f"{location}: metric {key} must be a nonnegative number")
    elif key in NONNEGATIVE_INTEGER_METRIC_KEYS:
        if not _finite_number(value) or value < 0:
            report.error(f"{location}: metric {key} must be a nonnegative number")
        if type(value) is not int:
            report.error(f"{location}: metric {key} must be an integer")
    elif key in BOOLEAN_METRIC_KEYS:
        if type(value) is not bool:
            report.error(f"{location}: metric {key} must be boolean")
    elif key in SHA256_METRIC_KEYS:
        if type(value) is not str or not SHA_RE.fullmatch(value):
            report.error(f"{location}: metric {key} must be a SHA-256 digest")
    elif key in CLOSED_IDENTIFIER_METRIC_KEYS:
        if (
            type(value) is not str
            or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", value)
        ):
            report.error(
                f"{location}: metric {key} must be a bounded closed identifier"
            )


def _validate_trace_contract(
    contract: Mapping[str, Any], report: Report, *, location: str,
) -> set[str]:
    """Validate the closed contract and return names that must be unique."""

    _exact_keys(contract, TRACE_CONTRACT_FIELDS, report, location)
    if contract.get("schema_version") != "feature-proof-trace/v1":
        report.error(f"{location}: unsupported schema")
    for key in ("trace_name", "required_root"):
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", str(contract.get(key, ""))):
            report.error(f"{location}: {key} must be a bounded closed identifier")

    addressed = {str(contract.get("required_root", ""))}
    runtime_span_names = {str(contract.get("required_root", ""))}
    for collection, required_when in (("required_spans", True), ("optional_spans", False)):
        rows = contract.get(collection)
        if not isinstance(rows, list):
            report.error(f"{location}: {collection} must be an array")
            continue
        seen: set[str] = set()
        for index, row in enumerate(rows):
            row_location = f"{location}.{collection}[{index}]"
            if not isinstance(row, Mapping):
                report.error(f"{row_location}: span specification must be an object")
                continue
            expected = {"name", "parent", "kind", "when"} if required_when else {
                "name", "parent", "kind",
            }
            if not required_when and "when" in row:
                expected.add("when")
            _exact_keys(row, expected, report, row_location)
            name = str(row.get("name", ""))
            if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", name) or name in seen:
                report.error(f"{row_location}: name is malformed or duplicated")
            seen.add(name)
            addressed.add(name)
            runtime_span_names.add(name)
            parent = row.get("parent")
            if parent is not None:
                if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", str(parent)):
                    report.error(f"{row_location}: parent is malformed")
                addressed.add(str(parent))
            if str(row.get("kind", "")).lower() not in {
                "chain", "retriever", "guardrail", "generation", "evaluator", "span", "model",
            }:
                report.error(f"{row_location}: kind is unsupported")
            try:
                _active_when(
                    row.get("when"), model_attempted=False, ui_applicable=True,
                )
            except ProofError as exc:
                report.error(f"{row_location}: {exc}")

    ordered = contract.get("ordered_pairs")
    if not isinstance(ordered, list):
        report.error(f"{location}: ordered_pairs must be an array")
    else:
        seen_pairs: set[tuple[str, str]] = set()
        for index, pair in enumerate(ordered):
            if (
                not isinstance(pair, list)
                or len(pair) != 2
                or not all(isinstance(name, str) and name for name in pair)
            ):
                report.error(f"{location}.ordered_pairs[{index}]: must contain two span names")
                continue
            typed = (pair[0], pair[1])
            if typed in seen_pairs:
                report.error(f"{location}.ordered_pairs[{index}]: pair is duplicated")
            seen_pairs.add(typed)
            addressed.update(typed)

    groups = contract.get("parallel_groups")
    if not isinstance(groups, list):
        report.error(f"{location}: parallel_groups must be an array")
    else:
        group_ids: set[str] = set()
        for index, group in enumerate(groups):
            group_location = f"{location}.parallel_groups[{index}]"
            if not isinstance(group, Mapping):
                report.error(f"{group_location}: group must be an object")
                continue
            _exact_keys(group, {"id", "spans", "min_overlap_ms"}, report, group_location)
            group_id = str(group.get("id", ""))
            if not ID_RE.fullmatch(group_id) or group_id in group_ids:
                report.error(f"{group_location}: id is malformed or duplicated")
            group_ids.add(group_id)
            names = group.get("spans")
            if (
                not isinstance(names, list)
                or len(names) < 2
                or len(names) != len(set(map(str, names)))
                or not all(isinstance(name, str) and name for name in names)
            ):
                report.error(f"{group_location}: spans must contain unique names")
            else:
                addressed.update(names)
            if not _finite_number(group.get("min_overlap_ms")) or group["min_overlap_ms"] < 0:
                report.error(f"{group_location}: min_overlap_ms must be finite and nonnegative")

    metrics = contract.get("metrics")
    if not isinstance(metrics, Mapping):
        report.error(f"{location}: metrics must be an object")
    else:
        for name, spec in metrics.items():
            metric_location = f"{location}.metrics.{name}"
            addressed.add(str(name))
            if not isinstance(spec, Mapping):
                report.error(f"{metric_location}: specification must be an object")
                continue
            expected = {"required", "when"}
            if "required_values" in spec:
                expected.add("required_values")
            _exact_keys(spec, expected, report, metric_location)
            required = spec.get("required")
            if (
                not isinstance(required, list)
                or len(required) != len(set(map(str, required)))
                or not all(key in ALLOWED_METRIC_KEYS for key in required)
            ):
                report.error(f"{metric_location}: required metrics must be unique closed keys")
                required = []
            required_values = spec.get("required_values", {})
            if not isinstance(required_values, Mapping):
                report.error(f"{metric_location}: required_values must be an object")
                required_values = {}
            elif any(key not in required for key in required_values):
                report.error(f"{metric_location}: required_values must be a subset of required")
            missing_semantics = sorted(SEMANTIC_REQUIRED_VALUES.intersection(required) - set(required_values))
            if missing_semantics:
                report.error(
                    f"{metric_location}: semantic required values are missing for "
                    + ", ".join(missing_semantics)
                )
            for key, value in required_values.items():
                if not isinstance(value, (str, int, float, bool)) or (
                    isinstance(value, float) and not math.isfinite(value)
                ):
                    report.error(f"{metric_location}: required value {key} is not a finite scalar")
                elif key in ALLOWED_METRIC_KEYS:
                    _validate_metric_type(
                        str(key), value, report, location=metric_location,
                    )
            try:
                _active_when(
                    spec.get("when"), model_attempted=False, ui_applicable=True,
                )
            except ProofError as exc:
                report.error(f"{metric_location}: {exc}")
        for name in sorted(runtime_span_names):
            if not name:
                continue
            spec = metrics.get(name)
            if not isinstance(spec, Mapping):
                report.error(f"{location}.metrics: missing closed success contract for {name}")
                continue
            required = spec.get("required")
            required_values = spec.get("required_values")
            if not isinstance(required, list) or "status" not in required:
                report.error(f"{location}.metrics.{name}: status is required for success semantics")
            if not isinstance(required_values, Mapping) or "status" not in required_values:
                report.error(f"{location}.metrics.{name}: expected status is required for success semantics")

    requirements = contract.get("required_scores")
    if not isinstance(requirements, list):
        report.error(f"{location}: required_scores must be an array")
    else:
        score_names: set[str] = set()
        for index, requirement in enumerate(requirements):
            score_location = f"{location}.required_scores[{index}]"
            if isinstance(requirement, str):
                name = requirement
            elif isinstance(requirement, Mapping):
                allowed = {"name", "min_value"} if "min_value" in requirement else {"name", "equals"}
                _exact_keys(requirement, allowed, report, score_location)
                name = str(requirement.get("name", ""))
                for field_name in ("min_value", "equals"):
                    if field_name in requirement and not _finite_number(requirement[field_name]):
                        report.error(f"{score_location}: {field_name} must be finite numeric")
            else:
                report.error(f"{score_location}: requirement is malformed")
                continue
            if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", name) or name in score_names:
                report.error(f"{score_location}: score name is malformed or duplicated")
            score_names.add(name)

    privacy = contract.get("must_not_capture")
    if not isinstance(privacy, Mapping):
        report.error(f"{location}: must_not_capture must be an object")
    else:
        _exact_keys(privacy, {"keys", "patterns"}, report, f"{location}.must_not_capture")
        keys = privacy.get("keys")
        if (
            not isinstance(keys, list)
            or len(keys) != len(set(map(_closed_key, keys)))
            or not all(isinstance(key, str) and _closed_key(key) for key in keys)
        ):
            report.error(f"{location}: must_not_capture keys must be unique names")
        patterns = privacy.get("patterns")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) and len(pattern) <= 256 for pattern in patterns
        ):
            report.error(f"{location}: must_not_capture patterns must be bounded strings")
        else:
            for pattern in patterns:
                try:
                    re.compile(pattern, re.I)
                except re.error as exc:
                    report.error(f"{location}: invalid must_not_capture pattern ({exc})")

    limits = contract.get("limits")
    if not isinstance(limits, Mapping):
        report.error(f"{location}: limits must be an object")
    else:
        _exact_keys(
            limits, {"max_spans", "max_receipt_bytes", "max_latency_ms"},
            report, f"{location}.limits",
        )
        if (
            isinstance(limits.get("max_spans"), bool)
            or not isinstance(limits.get("max_spans"), int)
            or not 1 <= limits["max_spans"] <= 256
        ):
            report.error(f"{location}: max_spans must be an integer from 1 to 256")
        if (
            isinstance(limits.get("max_receipt_bytes"), bool)
            or not isinstance(limits.get("max_receipt_bytes"), int)
            or not 1 <= limits["max_receipt_bytes"] <= MAX_JSON_BYTES
        ):
            report.error(f"{location}: max_receipt_bytes must be bounded")
        if not _finite_number(limits.get("max_latency_ms")) or limits["max_latency_ms"] <= 0:
            report.error(f"{location}: max_latency_ms must be finite and positive")
    return addressed


def validate_trace(
    trace: Mapping[str, Any],
    contract: Mapping[str, Any],
    implementation_commit: str,
    report: Report,
    *,
    location: str = "trace",
    expected_claim_id: str | None = None,
    expected_contract_sha256: str | None = None,
    expected_source_identity_sha256: str | None = None,
) -> None:
    addressed_names = _validate_trace_contract(
        contract, report, location=f"{location}.contract",
    )
    if trace.get("schema_version") != "feature-proof-trace-receipt/v1":
        report.error(f"{location}: unsupported trace receipt schema")
        return
    _exact_keys(trace, TRACE_RECEIPT_FIELDS, report, location)
    claim_definition = trace.get("claim_definition")
    if not isinstance(claim_definition, Mapping):
        report.error(f"{location}: claim definition is missing")
    else:
        _exact_keys(
            claim_definition, CLAIM_DEFINITION_FIELDS, report,
            f"{location}.claim_definition",
        )
        if trace.get("claim_definition_sha256") != sha256(
            _canonical(claim_definition)
        ).hexdigest():
            report.error(f"{location}: claim definition digest is invalid")
    if expected_claim_id is not None and trace.get("claim_id") != expected_claim_id:
        report.error(f"{location}: claim id does not match the manifest")
    if (
        expected_contract_sha256 is not None
        and trace.get("trace_contract_sha256") != expected_contract_sha256
    ):
        report.error(f"{location}: trace contract digest does not match")
    if (
        expected_source_identity_sha256 is not None
        and trace.get("source_identity_sha256") != expected_source_identity_sha256
    ):
        report.error(f"{location}: trace source identity does not match the manifest")
    for key in (
        "trace_contract_sha256", "source_identity_sha256", "raw_langfuse_sha256",
    ):
        if not SHA_RE.fullmatch(str(trace.get(key, ""))):
            report.error(f"{location}: {key} must be a SHA-256 digest")
    if trace.get("release") != implementation_commit:
        report.error(f"{location}: trace release does not match implementation commit")
    if trace.get("trace_name") != contract.get("trace_name"):
        report.error(f"{location}: trace name does not match contract")
    source = trace.get("source")
    if (
        not isinstance(source, Mapping)
        or source.get("provider") != "langfuse"
        or source.get("retrieval") != "authenticated_api"
        or not SHA_RE.fullmatch(str(source.get("raw_sha256", "")))
    ):
        report.error(f"{location}: source must be an authenticated Langfuse API retrieval")
    elif set(source) != {"provider", "retrieval", "trace_id", "raw_sha256"}:
        report.error(f"{location}: trace source schema is not closed")
    elif trace.get("raw_langfuse_sha256") != source.get("raw_sha256"):
        report.error(f"{location}: raw Langfuse digest binding does not match")
    elif trace.get("trace_id") != source.get("trace_id"):
        report.error(f"{location}: authenticated source trace id does not match")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(trace.get("trace_id", ""))):
        report.error(f"{location}: trace_id is malformed")
    _parse_time(trace.get("captured_at"), f"{location}.captured_at", report)
    model_attempted = trace.get("model_attempted")
    if not isinstance(model_attempted, bool):
        report.error(f"{location}: model_attempted must be boolean")
        model_attempted = False
    spans = trace.get("spans")
    limits = contract.get("limits") if isinstance(contract.get("limits"), Mapping) else {}
    max_receipt_bytes = limits.get("max_receipt_bytes")
    if (
        isinstance(max_receipt_bytes, int)
        and not isinstance(max_receipt_bytes, bool)
        and len(_canonical(trace)) > max_receipt_bytes
    ):
        report.error(f"{location}: trace receipt exceeds the contract byte limit")
    max_spans_raw = limits.get("max_spans")
    max_spans = (
        max_spans_raw
        if type(max_spans_raw) is int and 1 <= max_spans_raw <= 256
        else 256
    )
    max_latency_raw = limits.get("max_latency_ms")
    max_latency_ms: float | None = None
    if max_latency_raw is not None:
        if (
            isinstance(max_latency_raw, bool)
            or not isinstance(max_latency_raw, (int, float))
            or max_latency_raw <= 0
        ):
            report.error(f"{location}: max_latency_ms must be a positive number")
        else:
            max_latency_ms = float(max_latency_raw)
    if not isinstance(spans, list):
        report.error(f"{location}: spans must be an array")
        return
    if len(spans) > max_spans:
        report.error(f"{location}: exceeds {max_spans} spans")
        return
    by_id: dict[str, Mapping[str, Any]] = {}
    times: dict[str, tuple[datetime, datetime]] = {}
    for index, span in enumerate(spans):
        label = f"{location}.spans[{index}]"
        if not isinstance(span, Mapping):
            report.error(f"{label}: span must be an object")
            continue
        _exact_keys(span, SPAN_FIELDS, report, label)
        span_id = str(span.get("span_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", span_id) or span_id in by_id:
            report.error(f"{label}: span id is missing or duplicated")
            continue
        span_name = str(span.get("name", ""))
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", span_name):
            report.error(f"{label}: span name is malformed")
        kind = str(span.get("kind", "")).lower()
        if kind not in {"chain", "retriever", "guardrail", "generation", "evaluator", "span", "model"}:
            report.error(f"{label}: span kind is unsupported")
        if span.get("status") not in {"ok", "error"}:
            report.error(f"{label}: span status is unsupported")
        elif span.get("status") == "error":
            report.error(f"{label}: failed/error span cannot prove a passing trace claim")
        by_id[span_id] = span
        start = _parse_time(span.get("start_time"), f"{label}.start_time", report)
        end = _parse_time(span.get("end_time"), f"{label}.end_time", report)
        if start and end:
            if end < start:
                report.error(f"{label}: start must not follow end")
            elif (
                max_latency_ms is not None
                and (end - start).total_seconds() * 1000 > max_latency_ms
            ):
                report.error(
                    f"{label}: observed interval exceeds the "
                    f"{max_latency_ms:g} ms contract limit"
                )
            times[span_id] = (start, end)
        if not isinstance(span.get("metrics", {}), Mapping):
            report.error(f"{label}: metrics must be an object")
        else:
            metrics = span.get("metrics", {})
            if len(metrics) > 64:
                report.error(f"{label}: metrics exceed 64 fields")
            for key, value in metrics.items():
                if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
                    report.error(f"{label}: metric key is malformed")
                elif key not in ALLOWED_METRIC_KEYS:
                    report.error(f"{label}: metric {key} is outside the closed schema")
                if not isinstance(value, (str, int, float, bool)):
                    report.error(f"{label}: metric {key} must be a scalar")
                elif isinstance(value, float) and not math.isfinite(value):
                    report.error(f"{label}: metric {key} must be finite")
                elif isinstance(value, str) and len(value) > 128:
                    report.error(f"{label}: metric {key} is unbounded")
                if key in ALLOWED_METRIC_KEYS:
                    _validate_metric_type(key, value, report, location=label)
            if (
                max_latency_ms is not None
                and isinstance(metrics.get("latency_ms"), (int, float))
                and not isinstance(metrics.get("latency_ms"), bool)
                and metrics["latency_ms"] > max_latency_ms
            ):
                report.error(
                    f"{label}: latency_ms exceeds the "
                    f"{max_latency_ms:g} ms contract limit"
                )
            token_keys = {"input_tokens", "output_tokens", "total_tokens"}
            present_token_keys = token_keys.intersection(metrics)
            if present_token_keys and present_token_keys != token_keys:
                report.error(f"{label}: token metrics must be complete or absent")
            elif present_token_keys == token_keys:
                input_tokens = metrics.get("input_tokens")
                output_tokens = metrics.get("output_tokens")
                total_tokens = metrics.get("total_tokens")
                if (
                    type(input_tokens) is int
                    and type(output_tokens) is int
                    and type(total_tokens) is int
                    and total_tokens != input_tokens + output_tokens
                ):
                    report.error(f"{label}: token totals do not reconcile")

    for span_id, span in by_id.items():
        parent_id = span.get("parent_span_id")
        if parent_id is not None and parent_id not in by_id:
            report.error(f"{location}: span {span_id} has a missing parent")
            continue
        if parent_id in times and span_id in times:
            child_start, child_end = times[span_id]
            parent_start, parent_end = times[str(parent_id)]
            if child_start < parent_start or child_end > parent_end:
                report.error(f"{location}: span {span_id} lies outside its parent interval")

    roots = [span for span in by_id.values() if span.get("parent_span_id") is None]
    required_root = contract.get("required_root")
    if len(roots) != 1 or roots[0].get("name") != required_root:
        report.error(f"{location}: expected one root span named {required_root}")

    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for span in by_id.values():
        by_name.setdefault(str(span.get("name", "")), []).append(span)
    for name in sorted(addressed_names):
        if name and len(by_name.get(name, [])) > 1:
            report.error(f"{location}: contract-addressable span name is duplicated: {name}")
    ui_applicable = True
    for spec in contract.get("required_spans", []):
        if not isinstance(spec, Mapping):
            report.error(f"{location}: required span specification must be an object")
            continue
        try:
            active = _active_when(
                spec.get("when"), model_attempted=model_attempted, ui_applicable=ui_applicable
            )
        except ProofError as exc:
            report.error(f"{location}: {exc}")
            continue
        if not active:
            continue
        name = str(spec.get("name", ""))
        matches = by_name.get(name, [])
        if not matches:
            report.error(f"{location}: required span is missing: {name}")
            continue
        if len(matches) != 1:
            continue
        expected_parent = spec.get("parent")
        expected_kind = str(spec.get("kind", "")).lower()
        for span in matches:
            parent = by_id.get(str(span.get("parent_span_id")))
            if expected_parent is not None and (not parent or parent.get("name") != expected_parent):
                report.error(f"{location}: span {name} has the wrong parent")
            if expected_kind and str(span.get("kind", "")).lower() != expected_kind:
                report.error(f"{location}: span {name} has the wrong kind")

    for spec in contract.get("optional_spans", []):
        if not isinstance(spec, Mapping):
            report.error(f"{location}: optional span specification must be an object")
            continue
        name = str(spec.get("name", ""))
        expected_parent = spec.get("parent")
        expected_kind = str(spec.get("kind", "")).lower()
        for span in by_name.get(name, []):
            parent = by_id.get(str(span.get("parent_span_id")))
            if expected_parent is not None and (not parent or parent.get("name") != expected_parent):
                report.error(f"{location}: optional span {name} has the wrong parent")
            if expected_kind and str(span.get("kind", "")).lower() != expected_kind:
                report.error(f"{location}: optional span {name} has the wrong kind")

    for pair in contract.get("ordered_pairs", []):
        if not isinstance(pair, list) or len(pair) != 2:
            report.error(f"{location}: ordered pair must contain two span names")
            continue
        left, right = by_name.get(str(pair[0]), []), by_name.get(str(pair[1]), [])
        if not left or not right:
            continue
        if any(
            times.get(str(a.get("span_id")), (datetime.max.replace(tzinfo=timezone.utc),) * 2)[1]
            > times.get(str(b.get("span_id")), (datetime.min.replace(tzinfo=timezone.utc),) * 2)[0]
            for a in left
            for b in right
        ):
            report.error(f"{location}: ordered spans overlap or run out of order: {pair[0]} -> {pair[1]}")

    for group in contract.get("parallel_groups", []):
        if not isinstance(group, Mapping) or not isinstance(group.get("spans"), list):
            report.error(f"{location}: parallel group must be an object with spans")
            continue
        names = group["spans"]
        if len(names) < 2:
            report.error(f"{location}: parallel group needs at least two span names")
            continue
        selected = [by_name.get(str(name), []) for name in names]
        if any(not matches for matches in selected):
            report.error(f"{location}: parallel group has a missing span")
            continue
        candidates = [matches[0] for matches in selected]
        intervals = [times.get(str(span.get("span_id"))) for span in candidates]
        if any(interval is None for interval in intervals):
            continue
        overlap = (min(interval[1] for interval in intervals if interval) - max(
            interval[0] for interval in intervals if interval
        )).total_seconds() * 1000
        minimum_raw = group.get("min_overlap_ms")
        if not _finite_number(minimum_raw) or minimum_raw < 0:
            continue
        minimum = float(minimum_raw)
        if overlap <= 0 or overlap < minimum:
            report.error(f"{location}: parallel group has no positive measured overlap")

    metric_contract = contract.get("metrics", {})
    if not isinstance(metric_contract, Mapping):
        report.error(f"{location}: metrics contract must be an object")
    else:
        for name, spec in metric_contract.items():
            if not isinstance(spec, Mapping):
                report.error(f"{location}: metric specification for {name} must be an object")
                continue
            try:
                active = _active_when(
                    spec.get("when"), model_attempted=model_attempted, ui_applicable=True
                )
            except ProofError as exc:
                report.error(f"{location}: {exc}")
                continue
            if not active:
                continue
            for span in by_name.get(str(name), []):
                metrics = span.get("metrics", {})
                for key in spec.get("required", []):
                    if key not in metrics or metrics[key] is None:
                        report.error(f"{location}: span {name} lacks required metric {key}")
                required_values = spec.get("required_values", {})
                if isinstance(required_values, Mapping):
                    for key, expected in required_values.items():
                        if metrics.get(key) != expected:
                            report.error(
                                f"{location}: span {name} metric {key} does not equal "
                                f"the contract value"
                            )

    generation_spans = [
        span
        for span in by_id.values()
        if str(span.get("kind", "")).lower() in {"generation", "model"}
        or "model" in span.get("metrics", {})
    ]
    if model_attempted:
        if not generation_spans:
            report.error(f"{location}: model_attempted has no generation span")
        required = {
            "model",
            "prompt_version",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cost_usd",
            "latency_ms",
        }
        if generation_spans and not any(
            required.issubset(set(span.get("metrics", {}))) for span in generation_spans
        ):
            report.error(f"{location}: model span lacks model/version/token/cost/latency metrics")
    else:
        for span in generation_spans:
            if span.get("metrics", {}).get("model_attempted") is True:
                report.error(f"{location}: span-level model attempt contradicts model_attempted=false")

    required_scores = contract.get("required_scores", [])
    scores = trace.get("scores", [])
    if not isinstance(required_scores, list):
        report.error(f"{location}: required_scores must be an array")
    elif not isinstance(scores, list):
        report.error(f"{location}: scores must be an array")
    else:
        by_score: dict[str, list[Any]] = {}
        for index, score in enumerate(scores):
            if not isinstance(score, Mapping):
                report.error(f"{location}: score must be an object")
                continue
            _exact_keys(score, {"name", "value"}, report, f"{location}.scores[{index}]")
            name = str(score.get("name", ""))
            if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", name):
                report.error(f"{location}: score name is malformed")
                continue
            if name in by_score:
                report.error(f"{location}: score name is duplicated: {name}")
            value = score.get("value")
            if not _finite_number(value):
                report.error(f"{location}: score {name} must be finite numeric")
            by_score.setdefault(name, []).append(score.get("value"))
        for requirement in required_scores:
            if isinstance(requirement, str):
                name, minimum, expected = requirement, None, None
            elif isinstance(requirement, Mapping):
                name = str(requirement.get("name", ""))
                minimum = requirement.get("min_value")
                expected = requirement.get("equals")
                if minimum is not None and (
                    isinstance(minimum, bool) or not isinstance(minimum, (int, float))
                ):
                    report.error(f"{location}: score {name} min_value must be numeric")
                    continue
            else:
                report.error(f"{location}: required score specification is malformed")
                continue
            values = by_score.get(name, [])
            if not values:
                report.error(f"{location}: required score is missing: {name}")
                continue
            if minimum is not None and not any(
                not isinstance(value, bool)
                and isinstance(value, (int, float))
                and value >= minimum
                for value in values
            ):
                report.error(f"{location}: score {name} is below {minimum}")
            if expected is not None and expected not in values:
                report.error(f"{location}: score {name} does not equal {expected}")

    privacy = contract.get("must_not_capture", {})
    if not isinstance(privacy, Mapping):
        report.error(f"{location}: must_not_capture must be an object")
    else:
        _privacy_scan(
            trace,
            report,
            location,
            extra_keys=privacy.get("keys", []),
            extra_patterns=privacy.get("patterns", []),
        )


def _require_equal(report: Report, condition: bool, message: str) -> None:
    if not condition:
        report.error(message)


def _validate_generic_receipt(
    receipt: Mapping[str, Any], claim: Mapping[str, Any], commit: str,
    source_identity_sha256: str, report: Report, location: str,
) -> bool:
    valid = True
    if not _exact_keys(receipt, GENERIC_RECEIPT_FIELDS, report, location):
        valid = False
    for condition, message in (
        (receipt.get("schema_version") == "feature-proof-receipt/v1", "unsupported schema"),
        (receipt.get("receipt_type") == claim.get("receipt_type"), "receipt type mismatch"),
        (receipt.get("claim_id") == claim.get("id"), "claim id mismatch"),
        (receipt.get("source_commit") == commit, "stale source commit"),
        (
            receipt.get("source_identity_sha256") == source_identity_sha256,
            "source identity mismatch",
        ),
        (receipt.get("passed") is True, "receipt does not pass"),
    ):
        if not condition:
            report.error(f"{location}: {message}")
            valid = False
    return valid


def _validate_claim_derivation(
    packet: Path,
    receipt: Mapping[str, Any],
    claim: Mapping[str, Any],
    source_identity_sha256: str,
    report: Report,
    location: str,
) -> None:
    """Prove a claim receipt was compiled from one executed scenario gate."""

    derived = receipt.get("derived_from")
    if not isinstance(derived, Mapping):
        report.error(f"{location}: structured scenario derivation is missing")
        return
    _exact_keys(derived, DERIVATION_FIELDS, report, f"{location}.derived_from")
    scenario_ref = derived.get("scenario_output_ref")
    gate_ref = derived.get("gate_receipt_ref")
    if not isinstance(scenario_ref, str) or not isinstance(gate_ref, str):
        report.error(f"{location}: scenario and gate receipt references are required")
        return
    try:
        scenario_path = _resolve_in(packet, scenario_ref)
        gate_path = _resolve_in(packet, gate_ref)
        scenario = _read_json(scenario_path)
        gate = _read_json(gate_path)
    except (ProofError, FileNotFoundError) as exc:
        report.error(f"{location}: derivation is unreadable ({exc})")
        return
    if not isinstance(scenario, Mapping) or not isinstance(gate, Mapping):
        report.error(f"{location}: derivation inputs must be objects")
        return
    scenario_sha = _sha_file(scenario_path)
    gate_sha = _sha_file(gate_path)
    for condition, message in (
        (derived.get("scenario_output_sha256") == scenario_sha, "scenario output digest mismatch"),
        (derived.get("gate_receipt_sha256") == gate_sha, "gate receipt digest mismatch"),
        (scenario.get("schema_version") == "feature-proof-scenario-output/v1", "scenario output schema mismatch"),
        (scenario.get("source_identity_sha256") == source_identity_sha256, "scenario source identity mismatch"),
        (gate.get("source_identity_sha256") == source_identity_sha256, "gate source identity mismatch"),
        (gate.get("scenario_output_ref") == scenario_ref, "gate scenario reference mismatch"),
        (gate.get("scenario_output_sha256") == scenario_sha, "gate scenario digest mismatch"),
        (gate.get("passed") is True, "deriving gate did not pass"),
    ):
        if not condition:
            report.error(f"{location}: {message}")
    claims = scenario.get("claims")
    if not isinstance(claims, list) or len(claims) > 256:
        report.error(f"{location}: scenario claims must be a bounded array")
        return
    matches = [
        row for row in claims
        if isinstance(row, Mapping) and row.get("claim_id") == claim.get("id")
    ]
    if len(matches) != 1:
        report.error(f"{location}: scenario must contain exactly one matching claim")
        return
    row = matches[0]
    if row.get("receipt_type") != claim.get("receipt_type"):
        report.error(f"{location}: scenario receipt type mismatch")
    if row.get("passed") is not True:
        report.error(f"{location}: scenario claim did not pass")
    if _canonical(row.get("evidence")) != _canonical(receipt.get("evidence")):
        report.error(f"{location}: compiled evidence differs from scenario output")


def _validate_claim_receipt(
    packet: Path,
    claim: Mapping[str, Any],
    commit: str,
    contract: Mapping[str, Any],
    report: Report,
    gates: Sequence[Mapping[str, Any]] = (),
    source_identity_sha256: str = "",
    trace_contract_sha256: str | None = None,
) -> None:
    claim_id = str(claim.get("id", ""))
    receipt_type = str(claim.get("receipt_type", ""))
    reference = claim.get("receipt_ref")
    if not isinstance(reference, str):
        report.error(f"claim {claim_id}: receipt_ref is missing")
        return
    try:
        receipt_path = _resolve_in(packet, reference)
        receipt = _read_json(receipt_path)
    except (ProofError, FileNotFoundError) as exc:
        report.error(f"claim {claim_id}: unreadable receipt ({exc})")
        return
    if not isinstance(receipt, Mapping):
        report.error(f"claim {claim_id}: receipt must be an object")
        return
    location = f"claim {claim_id}"
    if not _validate_claim_binding(receipt, claim, report, location):
        return
    if receipt_type == "trace_contract":
        validate_trace(
            receipt, contract, commit, report, location=location,
            expected_claim_id=claim_id,
            expected_contract_sha256=trace_contract_sha256,
            expected_source_identity_sha256=source_identity_sha256,
        )
        if not any(error.startswith(location) for error in report.errors):
            report.verified_claims.append(claim_id)
        return
    if not _validate_generic_receipt(
        receipt, claim, commit, source_identity_sha256, report, location,
    ):
        return
    _validate_claim_derivation(
        packet, receipt, claim, source_identity_sha256, report, location,
    )
    _privacy_scan(receipt, report, location)
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        report.error(f"{location}: evidence must be an object")
        return
    _validate_evidence_value(
        evidence, claim.get("evidence_schema"), report, f"{location}.evidence",
    )

    if receipt_type == "idempotent":
        first, second = evidence.get("first", {}), evidence.get("second", {})
        _require_equal(report, isinstance(first, Mapping) and isinstance(second, Mapping), f"{location}: two attempts are required")
        if isinstance(first, Mapping) and isinstance(second, Mapping):
            _require_equal(report, bool(first.get("identity")) and first.get("identity") == second.get("identity"), f"{location}: durable identity changed")
            _require_equal(report, SHA_RE.fullmatch(str(first.get("command_sha256", ""))) is not None and first.get("command_sha256") == second.get("command_sha256"), f"{location}: retry command digest changed")
            _require_equal(report, first.get("created") is True, f"{location}: first attempt did not create the durable identity")
            _require_equal(report, second.get("created") is False, f"{location}: second attempt created state")
        _require_equal(report, evidence.get("durable_count_before") == evidence.get("durable_count_after"), f"{location}: retry changed durable count")
    elif receipt_type == "versioned":
        old, new = evidence.get("previous", {}), evidence.get("current", {})
        _require_equal(report, isinstance(old, Mapping) and isinstance(new, Mapping), f"{location}: previous/current versions are required")
        if isinstance(old, Mapping) and isinstance(new, Mapping):
            old_version, new_version = old.get("version"), new.get("version")
            _require_equal(
                report,
                type(old_version) is int
                and type(new_version) is int
                and old_version > 0
                and new_version > old_version,
                f"{location}: receipt must prove a strictly increasing positive version transition",
            )
            _require_equal(report, old.get("retrievable") is True and new.get("retrievable") is True, f"{location}: both versions must remain retrievable")
            previous_retrieval = old.get("retrieval")
            current_retrieval = new.get("retrieval")
            _require_equal(
                report,
                isinstance(previous_retrieval, Mapping)
                and re.fullmatch(
                    r"[A-Za-z0-9._:/-]{1,128}",
                    str(previous_retrieval.get("authority", "")),
                ) is not None
                and SHA_RE.fullmatch(str(previous_retrieval.get("receipt_sha256", ""))) is not None
                and SHA_RE.fullmatch(str(previous_retrieval.get("snapshot_sha256", ""))) is not None,
                f"{location}: previous version needs immutable receipt/snapshot coordinates",
            )
            _require_equal(
                report,
                isinstance(current_retrieval, Mapping)
                and re.fullmatch(
                    r"[A-Za-z0-9._:/-]{1,128}",
                    str(current_retrieval.get("authority", "")),
                ) is not None,
                f"{location}: current version needs a bounded retrieval authority",
            )
    elif receipt_type == "parallel":
        trace_ref = evidence.get("trace_ref")
        spans = evidence.get("spans")
        if not isinstance(trace_ref, str) or not isinstance(spans, list) or len(spans) < 2:
            report.error(f"{location}: trace_ref and at least two span names are required")
        else:
            try:
                trace = _read_json(_resolve_in(packet, trace_ref))
                local_contract = dict(contract)
                local_contract["parallel_groups"] = [{"spans": spans, "min_overlap_ms": evidence.get("min_overlap_ms", 0)}]
                validate_trace(trace, local_contract, commit, report, location=location)
            except (ProofError, FileNotFoundError) as exc:
                report.error(f"{location}: parallel trace is unreadable ({exc})")
    elif receipt_type == "fail_closed":
        _require_equal(report, evidence.get("expected_status") == evidence.get("observed_status"), f"{location}: refusal status mismatch")
        _require_equal(report, isinstance(evidence.get("observed_status"), int) and 400 <= evidence["observed_status"] < 500, f"{location}: refusal must be a 4xx")
        _require_equal(report, evidence.get("expected_error_code") == evidence.get("observed_error_code"), f"{location}: refusal body code mismatch")
        _require_equal(report, SHA_RE.fullmatch(str(evidence.get("response_body_sha256", ""))) is not None, f"{location}: refusal body digest is missing")
        _require_equal(report, evidence.get("forbidden_side_effect_count") == 0, f"{location}: refusal produced a forbidden side effect")
        state_before = evidence.get("state_sha256_before")
        state_after = evidence.get("state_sha256_after")
        _require_equal(
            report,
            SHA_RE.fullmatch(str(state_before)) is not None and state_before == state_after,
            f"{location}: refusal changed durable state",
        )
        tables_before = evidence.get("table_sha256_before")
        tables_after = evidence.get("table_sha256_after")
        _require_equal(
            report,
            isinstance(tables_before, Mapping)
            and bool(tables_before)
            and tables_before == tables_after
            and all(SHA_RE.fullmatch(str(value)) is not None for value in tables_before.values()),
            f"{location}: refusal changed a durable table",
        )
    elif receipt_type == "citation_grounded":
        _require_equal(report, evidence.get("source_id") == evidence.get("rendered_source_id"), f"{location}: rendered source does not resolve")
        _require_equal(report, evidence.get("source_revision") == evidence.get("rendered_revision"), f"{location}: source revision mismatch")
        _require_equal(report, evidence.get("excerpt_sha256") == evidence.get("rendered_excerpt_sha256") and SHA_RE.fullmatch(str(evidence.get("excerpt_sha256", ""))) is not None, f"{location}: excerpt digest mismatch")
        _require_equal(report, evidence.get("resolved") is True, f"{location}: citation was not resolved")
    elif receipt_type == "human_reviewed":
        actor, owner = str(evidence.get("actor_digest", "")), str(evidence.get("owner_digest", ""))
        _require_equal(report, SHA_RE.fullmatch(actor) is not None and SHA_RE.fullmatch(owner) is not None, f"{location}: actor/owner digests are malformed")
        _require_equal(report, actor != owner and evidence.get("distinct_from_owner") is True, f"{location}: reviewer is not distinct from owner")
        _require_equal(
            report,
            re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", str(evidence.get("role", ""))) is not None,
            f"{location}: reviewer role is not a bounded identifier",
        )
        _require_equal(
            report,
            type(evidence.get("version")) is int and evidence.get("version") > 0,
            f"{location}: reviewed version must be a positive integer",
        )
        _require_equal(
            report,
            re.fullmatch(
                r"[A-Za-z0-9._:/-]{1,128}",
                str(evidence.get("disposition", "")),
            ) is not None
            and evidence.get("persisted") is True,
            f"{location}: durable review disposition is missing",
        )
    elif receipt_type == "no_duplicate_job":
        first, second = evidence.get("first", {}), evidence.get("second", {})
        _require_equal(report, isinstance(first, Mapping) and isinstance(second, Mapping), f"{location}: two job attempts are required")
        if isinstance(first, Mapping) and isinstance(second, Mapping):
            _require_equal(report, bool(first.get("idempotency_key")) and first.get("idempotency_key") == second.get("idempotency_key"), f"{location}: idempotency key changed")
            _require_equal(report, SHA_RE.fullmatch(str(first.get("command_sha256", ""))) is not None and first.get("command_sha256") == second.get("command_sha256"), f"{location}: repeated job command digest changed")
            _require_equal(report, bool(first.get("job_id")) and first.get("job_id") == second.get("job_id"), f"{location}: duplicate job identity")
            _require_equal(report, second.get("reused") is True, f"{location}: second command did not reuse the job")
        _require_equal(report, evidence.get("durable_job_count_before") == evidence.get("durable_job_count_after"), f"{location}: duplicate job was added")
    elif receipt_type == "gate":
        _require_equal(report, evidence.get("exit_code") == 0, f"{location}: gate exit code is nonzero")
        _require_equal(report, SHA_RE.fullmatch(str(evidence.get("command_sha256", ""))) is not None, f"{location}: gate command digest is missing")
        gate_id = evidence.get("gate_id")
        gate = next((item for item in gates if item.get("id") == gate_id), None)
        if gates:
            _require_equal(report, gate is not None, f"{location}: gate id does not exist in the manifest")
        if gate is not None:
            _require_equal(report, evidence.get("command_sha256") == sha256(_canonical(gate.get("command"))).hexdigest(), f"{location}: gate command digest mismatch")
            _require_equal(report, evidence.get("observed_literal") == gate.get("expected_literal"), f"{location}: gate literal mismatch")
        else:
            _require_equal(report, bool(evidence.get("observed_literal")), f"{location}: gate literal is missing")

    if not any(error.startswith(location) for error in report.errors):
        report.verified_claims.append(claim_id)


def _validate_decision_log(packet: Path, report: Report) -> None:
    path = packet / "decision-log.jsonl"
    if not path.exists():
        report.error("decision-log.jsonl is missing")
        return
    try:
        text = _read_bytes(path, MAX_TEXT_BYTES).decode("utf-8")
    except (ProofError, UnicodeDecodeError) as exc:
        report.error(f"decision log is unreadable: {exc}")
        return
    ids: set[str] = set()
    last_time: datetime | None = None
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            report.error(f"decision log line {index} is empty")
            continue
        try:
            row = json.loads(line, object_pairs_hook=_duplicate_safe_object)
        except (json.JSONDecodeError, ProofError) as exc:
            report.error(f"decision log line {index} is malformed: {exc}")
            continue
        if not isinstance(row, Mapping) or not REQUIRED_DECISION_FIELDS.issubset(row):
            report.error(f"decision log line {index} lacks required append-only fields")
            continue
        entry_id = str(row.get("id", ""))
        if entry_id in ids:
            report.error(f"decision log duplicates id {entry_id}")
        ids.add(entry_id)
        moment = _parse_time(row.get("timestamp"), f"decision log line {index}", report)
        if moment and last_time and moment < last_time:
            report.error("decision log is not chronological append order")
        if moment:
            last_time = moment
        if not isinstance(row.get("evidence"), list):
            report.error(f"decision log line {index} evidence must be an array")
        _privacy_scan(row, report, f"decision log line {index}")


def _validate_story(packet: Path, claims: set[str], report: Report) -> None:
    try:
        story = _read_json(_resolve_in(packet, "storyboard.json"))
    except (ProofError, FileNotFoundError) as exc:
        report.error(f"storyboard is unreadable: {exc}")
        return
    scenes = story.get("scenes") if isinstance(story, Mapping) else None
    beats = ["premise", "viewer_question", "comparison_axis", "conflict", "evidence", "verdict", "exit_decision"]
    if not isinstance(scenes, list) or len(scenes) != 7:
        report.error("storyboard must contain exactly seven scenes")
        return
    for index, (scene, beat) in enumerate(zip(scenes, beats), 1):
        if not isinstance(scene, Mapping) or scene.get("scene") != index or scene.get("beat") != beat:
            report.error(f"storyboard scene {index} does not match the seven-beat contract")
            continue
        ids = scene.get("claim_ids")
        if not isinstance(ids, list) or not ids or any(item not in claims for item in ids):
            report.error(f"storyboard scene {index} has missing or unknown claim ids")


def _validate_narration(
    packet: Path,
    mode: str,
    claims: Mapping[str, Mapping[str, Any]],
    report: Report,
    product_forbidden: set[str],
) -> None:
    relative = f"narration.{mode}.json"
    try:
        narration = _read_json(_resolve_in(packet, relative))
    except (ProofError, FileNotFoundError) as exc:
        report.error(f"{relative} is unreadable: {exc}")
        return
    segments = narration.get("segments") if isinstance(narration, Mapping) else None
    if narration.get("mode") != mode or not isinstance(segments, list) or not segments:
        report.error(f"{relative} has the wrong mode or no segments")
        return
    for index, segment in enumerate(segments, 1):
        if not isinstance(segment, Mapping):
            report.error(f"{relative} segment {index} must be an object")
            continue
        claim_ids = segment.get("claim_ids")
        if not isinstance(claim_ids, list) or not claim_ids:
            report.error(f"{relative} segment {index} makes an unreceipted claim")
            continue
        for claim_id in claim_ids:
            claim = claims.get(str(claim_id))
            if claim is None:
                report.error(f"{relative} segment {index} references unknown claim {claim_id}")
            elif claim.get("status") == "failed":
                report.error(f"{relative} segment {index} narrates a failed claim {claim_id}")
            elif mode not in claim.get("modes", []):
                report.error(f"{relative} segment {index} uses claim {claim_id} in the wrong mode")
        if mode == "product":
            text = f"{segment.get('spoken', '')} {segment.get('caption', '')}".lower()
            words = set(re.findall(r"[a-z]+", text))
            forbidden = sorted(words & product_forbidden)
            if forbidden:
                report.error(f"{relative} segment {index} contains product-mode code terms: {', '.join(forbidden)}")
    if mode == "engineering":
        final = segments[-1]
        if final.get("scene") != 7:
            report.error("engineering narration must end at Scene 7")
        trace_ref = final.get("visual_receipt_ref")
        if not isinstance(trace_ref, str):
            report.error("engineering Scene 7 must reference its trace waterfall")
        else:
            try:
                waterfall = _resolve_in(packet, trace_ref)
                trace_claim = next(
                    (
                        claims.get(str(claim_id))
                        for claim_id in final.get("claim_ids", [])
                        if claims.get(str(claim_id), {}).get("receipt_type") == "trace_contract"
                    ),
                    None,
                )
                if trace_claim is None:
                    report.error("engineering Scene 7 must cite a trace_contract claim")
                else:
                    receipt_ref = trace_claim.get("receipt_ref")
                    if not isinstance(receipt_ref, str):
                        report.error("engineering Scene 7 trace claim has no normalized receipt")
                    else:
                        try:
                            normalized = _resolve_in(packet, receipt_ref)
                            digest = _sha_file(normalized)
                            rendered = _read_bytes(waterfall, MAX_TEXT_BYTES).decode("utf-8")
                            if f'data-trace-sha256="{digest}"' not in rendered:
                                report.error("engineering Scene 7 waterfall is not bound to its normalized trace")
                        except FileNotFoundError:
                            report.wait("engineering Scene 7 normalized trace is pending")
                        except (ProofError, UnicodeDecodeError) as exc:
                            report.error(f"engineering Scene 7 waterfall is invalid: {exc}")
            except FileNotFoundError:
                report.wait("engineering Scene 7 trace waterfall is pending")
            except ProofError as exc:
                report.error(f"engineering Scene 7 trace reference is unsafe: {exc}")


def _validate_gates(
    packet: Path,
    gates: Any,
    commit: str,
    source_identity_sha256: str,
    ui_applicable: bool,
    report: Report,
) -> None:
    if not isinstance(gates, list):
        report.error("manifest gates must be an array")
        return
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, Mapping):
            report.error("gate must be an object")
            continue
        gate_id = str(gate.get("id", ""))
        if not ID_RE.fullmatch(gate_id) or gate_id in seen:
            report.error(f"gate id is malformed or duplicated: {gate_id}")
            continue
        seen.add(gate_id)
        command = gate.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            report.error(f"gate {gate_id}: command must be a nonempty argv array")
        expected_literal = gate.get("expected_literal")
        if (
            not isinstance(expected_literal, str)
            or not expected_literal.strip()
            or len(expected_literal) > 500
        ):
            report.error(f"gate {gate_id}: expected_literal must be bounded nonempty text")
        ref = gate.get("receipt_path")
        if not isinstance(ref, str):
            report.error(f"gate {gate_id}: receipt_path is missing")
            continue
        try:
            _safe_parts(ref)
        except ProofError as exc:
            report.error(f"gate {gate_id}: receipt_path is unsafe ({exc})")
            continue
        try:
            active = _active_when(gate.get("when"), model_attempted=False, ui_applicable=ui_applicable)
        except ProofError as exc:
            report.error(f"gate {gate_id}: {exc}")
            continue
        if not active:
            continue
        try:
            receipt = _read_json(_resolve_in(packet, ref))
        except FileNotFoundError:
            report.wait(f"gate {gate_id} receipt is pending")
            continue
        except ProofError as exc:
            report.error(f"gate {gate_id}: unsafe or malformed receipt ({exc})")
            continue
        if not isinstance(receipt, Mapping):
            report.error(f"gate {gate_id}: receipt must be an object")
            continue
        _exact_keys(receipt, GATE_RECEIPT_FIELDS, report, f"gate {gate_id}")
        expected_hash = sha256(_canonical(command)).hexdigest()
        stream_binding = {
            "stdout_bytes": receipt.get("stdout_bytes"),
            "stdout_sha256": receipt.get("stdout_sha256"),
            "stderr_bytes": receipt.get("stderr_bytes"),
            "stderr_sha256": receipt.get("stderr_sha256"),
        }
        expected_output_hash = sha256(_canonical(stream_binding)).hexdigest()
        for condition, message in (
            (receipt.get("schema_version") == "feature-proof-gate/v1", "schema mismatch"),
            (receipt.get("gate_id") == gate_id, "gate id mismatch"),
            (receipt.get("source_commit") == commit, "stale source commit"),
            (receipt.get("source_identity_sha256") == source_identity_sha256, "source identity mismatch"),
            (receipt.get("argv") == command, "argv mismatch"),
            (receipt.get("command_sha256") == expected_hash, "command digest mismatch"),
            (receipt.get("exit_code") == 0, "nonzero exit code"),
            (receipt.get("passed") is True, "gate did not pass"),
            (receipt.get("expected_literal") == gate.get("expected_literal"), "expected literal mismatch"),
            (receipt.get("observed_literal") == gate.get("expected_literal"), "expected literal missing"),
            (SHA_RE.fullmatch(str(receipt.get("stdout_sha256", ""))) is not None, "stdout digest missing"),
            (SHA_RE.fullmatch(str(receipt.get("stderr_sha256", ""))) is not None, "stderr digest missing"),
            (receipt.get("output_sha256") == expected_output_hash, "output digest mismatch"),
            (
                isinstance(receipt.get("stdout_bytes"), int)
                and 0 <= receipt.get("stdout_bytes", -1) <= MAX_GATE_STREAM_BYTES,
                "stdout byte bound is invalid",
            ),
            (
                isinstance(receipt.get("stderr_bytes"), int)
                and 0 <= receipt.get("stderr_bytes", -1) <= MAX_GATE_STREAM_BYTES,
                "stderr byte bound is invalid",
            ),
        ):
            if not condition:
                report.error(f"gate {gate_id}: {message}")
        _parse_time(receipt.get("captured_at"), f"gate {gate_id}.captured_at", report)
        scenario_ref = receipt.get("scenario_output_ref")
        scenario_sha = receipt.get("scenario_output_sha256")
        if (scenario_ref is None) != (scenario_sha is None):
            report.error(f"gate {gate_id}: scenario reference/digest must be both present or absent")
        elif scenario_ref is not None:
            try:
                scenario_path = _resolve_in(packet, str(scenario_ref))
                if not SHA_RE.fullmatch(str(scenario_sha)) or _sha_file(scenario_path) != scenario_sha:
                    report.error(f"gate {gate_id}: scenario output digest mismatch")
            except (ProofError, FileNotFoundError) as exc:
                report.error(f"gate {gate_id}: scenario output is invalid ({exc})")
        _privacy_scan(receipt, report, f"gate {gate_id}")


def _validate_media(packet: Path, capture: Mapping[str, Any], commit: str, report: Report) -> None:
    required = capture.get("required_media", [])
    if not isinstance(required, list) or not required:
        report.error("UI capture must declare required_media")
        return
    files: dict[str, Path] = {}
    for relative in required:
        try:
            files[str(relative)] = _resolve_in(packet, str(relative))
        except FileNotFoundError:
            report.wait(f"media artifact is pending: {relative}")
        except ProofError as exc:
            report.error(f"media artifact path is unsafe: {exc}")
    receipt_ref = capture.get("media_receipt_ref", "receipts/browser/media-receipt.json")
    try:
        receipt = _read_json(_resolve_in(packet, str(receipt_ref)))
    except FileNotFoundError:
        report.wait("media receipt is pending")
        return
    except ProofError as exc:
        report.error(f"media receipt is unsafe or malformed: {exc}")
        return
    if not isinstance(receipt, Mapping) or receipt.get("schema_version") != "feature-proof-media/v1":
        report.error("media receipt schema is invalid")
        return
    _exact_keys(
        receipt, {"schema_version", "source_commit", "files"}, report, "media receipt",
    )
    if receipt.get("source_commit") != commit:
        report.error("media receipt is stale")
    rows = receipt.get("files")
    if not isinstance(rows, list):
        report.error("media receipt files must be an array")
        return
    for index, row in enumerate(rows):
        if isinstance(row, Mapping):
            _exact_keys(
                row, {"path", "bytes", "sha256"}, report,
                f"media receipt.files[{index}]",
            )
    by_path = {str(row.get("path")): row for row in rows if isinstance(row, Mapping)}
    for relative, path in files.items():
        row = by_path.get(relative)
        if not row:
            report.error(f"media receipt does not cover {relative}")
            continue
        if row.get("bytes") != path.stat().st_size or row.get("sha256") != _sha_file(path):
            report.error(f"media artifact hash or size changed: {relative}")
    _privacy_scan(receipt, report, "media receipt")


def _artifact_file_identity(
    path: Path,
    relative: str,
    *,
    portable_text: bool,
) -> tuple[int, str]:
    if portable_text and PurePosixPath(relative).suffix.lower() in MAIN_PORTABLE_TEXT_SUFFIXES:
        payload = _canonical_line_endings(_read_bytes(path, HARD_MAX_PACKET_BYTES))
        return len(payload), sha256(payload).hexdigest()
    return path.stat().st_size, _sha_file(path)


def _validate_artifact_manifest(
    packet: Path,
    files: list[Path],
    manifest: Mapping[str, Any],
    commit: str,
    report: Report,
    *,
    portable_text: bool = False,
) -> None:
    _exact_keys(
        manifest,
        {
            "schema_version", "feature_id", "implementation_commit", "generated_at",
            "files", "packet_sha256",
        },
        report,
        "artifact manifest",
    )
    if manifest.get("schema_version") != "feature-proof-artifacts/v1":
        report.error("artifact manifest schema is invalid")
        return
    if manifest.get("implementation_commit") != commit:
        report.error("artifact manifest is stale")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        report.error("artifact manifest files must be an array")
        return
    expected_paths = sorted(
        path.relative_to(packet).as_posix()
        for path in files
        if path.name != "artifact-manifest.json"
    )
    actual_paths = [str(row.get("path")) for row in rows if isinstance(row, Mapping)]
    if actual_paths != sorted(actual_paths) or actual_paths != expected_paths:
        report.error("artifact manifest coverage/order does not match packet files")
        return
    for row in rows:
        if not isinstance(row, Mapping):
            report.error("artifact manifest file row must be an object")
            continue
        _exact_keys(
            row, {"path", "bytes", "sha256"}, report,
            f"artifact manifest file {row.get('path', 'unknown')}",
        )
        relative = str(row.get("path"))
        try:
            path = _resolve_in(packet, relative)
        except (ProofError, FileNotFoundError) as exc:
            report.error(f"artifact manifest path is invalid: {exc}")
            continue
        observed_bytes, observed_sha256 = _artifact_file_identity(
            path,
            relative,
            portable_text=portable_text,
        )
        if row.get("bytes") != observed_bytes or row.get("sha256") != observed_sha256:
            report.error(f"artifact changed after manifest publication: {relative}")
    if manifest.get("packet_sha256") != sha256(_canonical(rows)).hexdigest():
        report.error("artifact manifest packet digest is invalid")


def _validate_regular_blob_tree(
    tree: bytes,
    report: Report,
    *,
    label: str,
) -> None:
    """Reject symlinks, gitlinks, and malformed entries in a sealed packet tree."""

    for entry in tree.split(b"\0"):
        if not entry:
            continue
        header, separator, path = entry.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3 or not path:
            report.error(f"{label} contains a malformed Git tree entry")
            continue
        mode, object_type, _ = fields
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            display_path = path.decode("utf-8", errors="backslashreplace")
            display_mode = mode.decode("ascii", errors="replace")
            display_type = object_type.decode("ascii", errors="replace")
            report.error(
                f"{label} contains unsupported Git entry "
                f"{display_mode} {display_type}: {display_path}"
            )


def _has_committed_artifact_seal(root: Path, packet: Path) -> bool:
    """Return whether HEAD history already owns this packet's first seal."""

    try:
        packet_relative = packet.relative_to(root)
    except ValueError as exc:
        raise ProofError("Git seal packet must be inside the repository root") from exc
    artifact_relative = (
        PurePosixPath(*packet_relative.parts) / "artifact-manifest.json"
    ).as_posix()
    history = _git_bytes(
        root,
        [
            "log",
            "-1",
            "--format=%H",
            "--diff-filter=A",
            "--full-history",
            "HEAD",
            "--",
            artifact_relative,
        ],
        label="artifact Git seal presence",
    ).strip()
    return bool(history)


def _validate_main_portable_git_seal(
    root: Path,
    packet: Path,
    feature_manifest: Mapping[str, Any],
    artifact_manifest: Mapping[str, Any],
    report: Report,
    *,
    allow_uncommitted: bool,
) -> None:
    """Bind one strict packet forever to its first artifact-add Git tree."""

    source = feature_manifest.get("source")
    if not isinstance(source, Mapping):
        report.error("Git seal feature source is malformed")
        return
    implementation_commit = str(source.get("implementation_commit", ""))
    feature_id = str(feature_manifest.get("feature_id", ""))
    if artifact_manifest.get("feature_id") != feature_id:
        report.error("Git seal artifact feature_id differs from the feature manifest")
    if artifact_manifest.get("implementation_commit") != implementation_commit:
        report.error(
            "Git seal artifact implementation_commit differs from the feature source"
        )
    try:
        packet_relative = packet.relative_to(root)
    except ValueError:
        report.error("Git seal packet must be inside the repository root")
        return
    packet_prefix = PurePosixPath(*packet_relative.parts).as_posix()
    artifact_relative = f"{packet_prefix}/artifact-manifest.json"
    history = _git_bytes(
        root,
        [
            "log",
            "--reverse",
            "--format=%H",
            "--diff-filter=A",
            "--full-history",
            "HEAD",
            "--",
            artifact_relative,
        ],
        label="artifact Git seal history",
    ).decode("ascii", errors="strict").splitlines()
    if not history:
        tracked = _git_bytes(
            root,
            ["ls-tree", "-z", "HEAD", "--", artifact_relative],
            label="artifact Git seal HEAD path",
        )
        if tracked:
            report.error("tracked artifact manifest has no available Git add seal")
        elif not allow_uncommitted:
            report.wait("artifact Git seal is pending commit")
        return
    if len(history) != 1:
        report.error("artifact Git seal path must have exactly one add commit")
        return
    seal_commit = history[0]
    if not COMMIT_RE.fullmatch(seal_commit):
        report.error("artifact Git seal commit is malformed")
        return
    try:
        if not _git_is_ancestor(
            root,
            implementation_commit,
            seal_commit,
            label="artifact Git seal source",
        ):
            report.error(
                "artifact Git seal commit does not descend from the implementation commit"
            )
    except ProofError as exc:
        report.error(str(exc))
        return
    sealed_bytes = _git_bytes(
        root,
        ["show", f"{seal_commit}:{artifact_relative}"],
        label="sealed artifact manifest",
    )
    try:
        sealed_manifest = _bounded_json_bytes(
            sealed_bytes,
            label="sealed artifact manifest",
        )
    except ProofError as exc:
        report.error(str(exc))
        return
    if not isinstance(sealed_manifest, Mapping):
        report.error("sealed artifact manifest must be an object")
        return
    if sealed_manifest.get("feature_id") != feature_id:
        report.error("sealed artifact feature_id differs from the feature manifest")
    if sealed_manifest.get("implementation_commit") != implementation_commit:
        report.error(
            "sealed artifact implementation_commit differs from the feature source"
        )
    current_bytes = _read_bytes(packet / "artifact-manifest.json", MAX_JSON_BYTES)
    if _canonical_line_endings(current_bytes) != _canonical_line_endings(sealed_bytes):
        report.error("artifact manifest differs from its immutable Git seal")
    sealed_tree = _git_bytes(
        root,
        ["ls-tree", "-r", "-z", seal_commit, "--", packet_prefix],
        label="sealed packet tree",
    )
    head_tree = _git_bytes(
        root,
        ["ls-tree", "-r", "-z", "HEAD", "--", packet_prefix],
        label="current packet tree",
    )
    _validate_regular_blob_tree(sealed_tree, report, label="sealed packet tree")
    _validate_regular_blob_tree(head_tree, report, label="current packet tree")
    if head_tree != sealed_tree:
        report.error("packet Git tree or file modes differ from its immutable seal")
    try:
        _git_bytes(
            root,
            [
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--ignore-submodules=none",
                "HEAD",
                "--",
                packet_prefix,
            ],
            label="sealed packet worktree",
        )
    except ProofError:
        report.error("packet worktree differs from its sealed HEAD tree")


def _validate_verification_matrix(
    manifest: Mapping[str, Any], claims: Mapping[str, Mapping[str, Any]], report: Report
) -> None:
    rows = manifest.get("verification_matrix")
    if not isinstance(rows, list):
        report.error("verification_matrix must be an array")
        return
    claim_receipts = {
        str(claim.get("receipt_ref"))
        for claim in claims.values()
        if isinstance(claim.get("receipt_ref"), str)
    }
    gates = manifest.get("gates")
    gate_ids = {
        str(gate.get("id"))
        for gate in gates
        if isinstance(gates, list) and isinstance(gate, Mapping)
    } if isinstance(gates, list) else set()
    seen_ids: set[str] = set()
    seen_categories: set[str] = set()
    for index, row in enumerate(rows):
        location = f"verification_matrix[{index}]"
        if not isinstance(row, Mapping):
            report.error(f"{location} must be an object")
            continue
        scenario_id = str(row.get("id", ""))
        if not ID_RE.fullmatch(scenario_id) or scenario_id in seen_ids:
            report.error(f"{location} id is malformed or duplicated")
        seen_ids.add(scenario_id)
        category = str(row.get("category", ""))
        if category not in REQUIRED_SCENARIO_CATEGORIES:
            report.error(f"{location} category is unsupported: {category}")
        else:
            seen_categories.add(category)
        for field_name in ("persona", "goal", "behavior"):
            value = row.get(field_name)
            if not isinstance(value, str) or not value.strip() or len(value) > 1_000:
                report.error(f"{location}.{field_name} must be bounded nonempty text")
        if not isinstance(row.get("ui_applicable"), bool):
            report.error(f"{location}.ui_applicable must be boolean")
        receipt_ref = row.get("expected_receipt")
        gate_id = row.get("gate_id")
        if (receipt_ref is None) == (gate_id is None):
            report.error(f"{location} must name exactly one expected_receipt or gate_id")
        elif receipt_ref is not None:
            try:
                _safe_parts(str(receipt_ref))
            except ProofError as exc:
                report.error(f"{location}.expected_receipt is unsafe ({exc})")
            if str(receipt_ref) not in claim_receipts:
                report.error(f"{location}.expected_receipt is not owned by a claim")
        elif str(gate_id) not in gate_ids:
            report.error(f"{location}.gate_id does not name a manifest gate")
    missing = sorted(REQUIRED_SCENARIO_CATEGORIES - seen_categories)
    if missing:
        report.error(f"verification_matrix lacks required categories: {', '.join(missing)}")


def _validate_manifest_contract(
    manifest: Mapping[str, Any], claims: Mapping[str, Mapping[str, Any]], report: Report
) -> None:
    title = manifest.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 200:
        report.error("manifest title must be bounded nonempty text")
    business = manifest.get("business")
    if not isinstance(business, Mapping):
        report.error("manifest business must be an object")
    else:
        for field_name in (
            "persona", "decision", "problem", "concrete_failure", "success_measure",
        ):
            value = business.get(field_name)
            if not isinstance(value, str) or not value.strip() or len(value) > 2_000:
                report.error(f"manifest business.{field_name} must be bounded nonempty text")

    authority = manifest.get("authority")
    if not isinstance(authority, Mapping):
        report.error("manifest authority must be an object")
    else:
        for field_name in ("deterministic", "model", "human", "forbidden"):
            values = authority.get(field_name)
            if (
                not isinstance(values, list)
                or not values
                or any(
                    not isinstance(value, str) or not value.strip() or len(value) > 2_000
                    for value in values
                )
            ):
                report.error(f"manifest authority.{field_name} must be nonempty bounded text")

    contracts = manifest.get("contracts")
    anchor_ids = {
        str(anchor.get("id"))
        for anchor in contracts.get("code_anchors", [])
        if isinstance(contracts, Mapping) and isinstance(anchor, Mapping)
    } if isinstance(contracts, Mapping) else set()
    if isinstance(contracts, Mapping):
        for direction in ("inputs", "outputs"):
            values = contracts.get(direction)
            if not isinstance(values, list) or not values:
                report.error(f"manifest contracts.{direction} must be a nonempty array")
                continue
            for index, value in enumerate(values):
                if not isinstance(value, Mapping):
                    report.error(f"manifest contracts.{direction}[{index}] must be an object")
                    continue
                name = value.get("name")
                if not isinstance(name, str) or not name.strip() or len(name) > 500:
                    report.error(f"manifest contracts.{direction}[{index}].name is invalid")
                if str(value.get("code_anchor", "")) not in anchor_ids:
                    report.error(f"manifest contracts.{direction}[{index}] has an unknown code anchor")

    claim_receipts = {
        str(claim.get("receipt_ref"))
        for claim in claims.values()
        if isinstance(claim.get("receipt_ref"), str)
    }
    attacks = manifest.get("attacks")
    if not isinstance(attacks, list) or not attacks:
        report.error("manifest attacks must be a nonempty array")
    else:
        attack_ids: set[str] = set()
        for index, attack in enumerate(attacks):
            location = f"manifest attacks[{index}]"
            if not isinstance(attack, Mapping):
                report.error(f"{location} must be an object")
                continue
            attack_id = str(attack.get("id", ""))
            if not ID_RE.fullmatch(attack_id) or attack_id in attack_ids:
                report.error(f"{location} id is malformed or duplicated")
            attack_ids.add(attack_id)
            for field_name in ("persona", "scenario"):
                value = attack.get(field_name)
                if not isinstance(value, str) or not value.strip() or len(value) > 2_000:
                    report.error(f"{location}.{field_name} must be bounded nonempty text")
            receipt_ref = attack.get("expected_receipt")
            try:
                _safe_parts(str(receipt_ref))
            except ProofError as exc:
                report.error(f"{location}.expected_receipt is unsafe ({exc})")
            if str(receipt_ref) not in claim_receipts:
                report.error(f"{location}.expected_receipt is not owned by a claim")

    capture = manifest.get("capture")
    if not isinstance(capture, Mapping):
        report.error("manifest capture must be an object")
        return
    if not isinstance(capture.get("ui_applicable"), bool):
        report.error("manifest capture.ui_applicable must be boolean")
    for field_name in ("route", "theme", "fixture", "storyboard_ref", "media_receipt_ref"):
        value = capture.get(field_name)
        if not isinstance(value, str) or not value.strip() or len(value) > 1_000:
            report.error(f"manifest capture.{field_name} must be bounded nonempty text")
    for field_name in ("storyboard_ref", "media_receipt_ref"):
        try:
            _safe_parts(str(capture.get(field_name, "")))
        except ProofError as exc:
            report.error(f"manifest capture.{field_name} is unsafe ({exc})")
    viewport = capture.get("viewport")
    if not isinstance(viewport, Mapping) or any(
        isinstance(viewport.get(axis), bool)
        or not isinstance(viewport.get(axis), int)
        or not 240 <= viewport[axis] <= 8_192
        for axis in ("width", "height")
    ):
        report.error("manifest capture.viewport must contain bounded integer dimensions")
    if not isinstance(capture.get("reduced_motion"), bool):
        report.error("manifest capture.reduced_motion must be boolean")
    forbidden_terms = capture.get("product_forbidden_terms")
    if (
        not isinstance(forbidden_terms, list)
        or any(
            not isinstance(term, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", term)
            for term in forbidden_terms
        )
    ):
        report.error("manifest capture.product_forbidden_terms must be closed lowercase terms")
    media = capture.get("required_media")
    if not isinstance(media, list) or any(not isinstance(path, str) for path in media):
        report.error("manifest capture.required_media must be an array of paths")
    else:
        for path in media:
            try:
                _safe_parts(path)
            except ProofError as exc:
                report.error(f"manifest capture.required_media path is unsafe ({exc})")


def check_packet(
    packet: Path | str,
    *,
    repo_root: Path | str | None = None,
    require_artifact_manifest: bool = True,
    _allow_uncommitted_git_seal: bool = False,
) -> dict[str, Any]:
    packet = Path(packet)
    root = (Path(repo_root) if repo_root is not None else Path.cwd()).resolve(strict=True)
    report = Report()
    try:
        _reject_symlink_ancestors(packet)
        packet = packet.resolve(strict=True)
        if not packet.is_dir():
            raise ProofError("packet path is not a directory")
        manifest_path = _resolve_in(packet, "feature-manifest.json")
        manifest = _read_json(manifest_path)
        if not isinstance(manifest, Mapping):
            raise ProofError("feature manifest must be an object")
        report.feature_id = str(manifest.get("feature_id", "unknown"))
        if manifest.get("schema_version") != "feature-proof/v1":
            report.error("feature manifest schema is unsupported")
        if not ID_RE.fullmatch(report.feature_id):
            report.error("feature_id must be lowercase kebab-case")
        limits = manifest.get("limits", {}) if isinstance(manifest.get("limits"), Mapping) else {}
        packet_limit = int(limits.get("max_packet_bytes", MAX_PACKET_BYTES))
        files = _scan_packet(packet, packet_limit)
        report.checked_files = len(files)
        _privacy_scan(manifest, report, "feature manifest")

        source = manifest.get("source")
        sealed_history = False
        if not isinstance(source, Mapping):
            report.error("manifest source must be an object")
            commit = ""
            source_digest = ""
        else:
            identity_status = source.get("identity_status")
            implementation_commit = source.get("implementation_commit")
            integrity_contract = source.get("integrity_contract")
            integrity_supported = integrity_contract in {
                None,
                MAIN_PORTABLE_INTEGRITY_CONTRACT,
            }
            if not integrity_supported:
                report.error("source.integrity_contract is unsupported")
            if identity_status == "frozen":
                commit = str(implementation_commit or "")
                if not COMMIT_RE.fullmatch(commit):
                    report.error("frozen implementation_commit is malformed")
                elif integrity_supported:
                    try:
                        sealed_history = (
                            integrity_contract == MAIN_PORTABLE_INTEGRITY_CONTRACT
                            and _has_committed_artifact_seal(root, packet)
                        )
                        if not sealed_history:
                            _verify_execution_checkout(root, packet, manifest)
                    except ProofError as exc:
                        report.error(str(exc))
            elif identity_status == "pending_clean_commit":
                commit = ""
                if implementation_commit is not None:
                    report.error("pending source identity must use a null implementation_commit")
                report.wait("source identity is pending a clean implementation commit")
            else:
                commit = ""
                report.error("source.identity_status must be frozen or pending_clean_commit")
            source_digest = _source_identity_sha256(source)
            if not COMMIT_RE.fullmatch(str(source.get("base_commit", ""))):
                report.error("base_commit is malformed")
            paths = source.get("implementation_paths")
            if not isinstance(paths, list) or not paths:
                report.error("implementation_paths must be a nonempty array")
            else:
                for relative in paths:
                    try:
                        normalized = PurePosixPath(
                            *_safe_parts(str(relative))
                        ).as_posix()
                        if sealed_history:
                            object_type = _git_bytes(
                                root,
                                ["cat-file", "-t", f"{commit}:{normalized}"],
                                label=f"sealed implementation path {normalized}",
                            ).strip()
                            if object_type != b"blob":
                                raise ProofError(
                                    "sealed implementation path is not a Git blob"
                                )
                        else:
                            _resolve_in(root, normalized)
                    except (ProofError, FileNotFoundError) as exc:
                        report.error(f"implementation path is invalid: {relative} ({exc})")

        contracts = manifest.get("contracts")
        if not isinstance(contracts, Mapping):
            report.error("manifest contracts must be an object")
        else:
            anchors = contracts.get("code_anchors")
            if not isinstance(anchors, list) or not anchors:
                report.error("code_anchors must be a nonempty array")
            else:
                anchor_ids: set[str] = set()
                for anchor in anchors:
                    if not isinstance(anchor, Mapping):
                        report.error("code anchor must be an object")
                        continue
                    anchor_id = str(anchor.get("id", ""))
                    if not ID_RE.fullmatch(anchor_id) or anchor_id in anchor_ids:
                        report.error(f"code anchor id is malformed or duplicated: {anchor_id}")
                    anchor_ids.add(anchor_id)
                    try:
                        anchor_relative = PurePosixPath(
                            *_safe_parts(str(anchor.get("path", "")))
                        ).as_posix()
                        if sealed_history:
                            object_type = _git_bytes(
                                root,
                                ["cat-file", "-t", f"{commit}:{anchor_relative}"],
                                label=f"sealed code anchor {anchor_id}",
                            ).strip()
                            if object_type != b"blob":
                                raise ProofError("sealed code anchor is not a Git blob")
                            anchor_bytes = _git_bytes(
                                root,
                                ["show", f"{commit}:{anchor_relative}"],
                                label=f"sealed code anchor {anchor_id}",
                            )
                        else:
                            path = _resolve_in(root, anchor_relative)
                            anchor_bytes = _read_bytes(path, MAX_TEXT_BYTES)
                        text = anchor_bytes.decode("utf-8")
                        if str(anchor.get("symbol", "")) not in text:
                            report.error(f"code anchor symbol is stale: {anchor_id}")
                    except (ProofError, FileNotFoundError, UnicodeDecodeError) as exc:
                        report.error(f"code anchor is invalid: {anchor_id} ({exc})")

        trace_ref = manifest.get("trace_contract_ref")
        contract_sha: str | None = None
        try:
            contract_path = _resolve_in(packet, str(trace_ref))
            contract = _read_json(contract_path)
            if not isinstance(contract, Mapping) or contract.get("schema_version") != "feature-proof-trace/v1":
                report.error("trace contract schema is invalid")
                contract = {}
            else:
                contract_sha = _source_bound_trace_contract_sha256(
                    root, packet, commit, str(trace_ref),
                )
                _validate_trace_contract(contract, report, location="trace contract")
        except (ProofError, FileNotFoundError) as exc:
            report.error(f"trace contract is unreadable: {exc}")
            contract = {}

        claims_raw = manifest.get("claims")
        claims: dict[str, Mapping[str, Any]] = {}
        if not isinstance(claims_raw, list) or not claims_raw:
            report.error("manifest claims must be a nonempty array")
        else:
            for claim in claims_raw:
                if not isinstance(claim, Mapping):
                    report.error("claim must be an object")
                    continue
                claim_id = str(claim.get("id", ""))
                if not ID_RE.fullmatch(claim_id) or claim_id in claims:
                    report.error(f"claim id is malformed or duplicated: {claim_id}")
                    continue
                claims[claim_id] = claim
                receipt_type = claim.get("receipt_type")
                expected_claim_fields = set(CLAIM_FIELDS)
                if receipt_type == "trace_contract" and "trace_contract_ref" in claim:
                    expected_claim_fields.add("trace_contract_ref")
                if receipt_type != "trace_contract":
                    expected_claim_fields.add("evidence_schema")
                _exact_keys(
                    claim, expected_claim_fields, report, f"claim {claim_id} definition",
                )
                if receipt_type not in CLAIM_TYPES:
                    report.error(f"claim {claim_id}: unsupported receipt type")
                if receipt_type == "trace_contract":
                    if "evidence_schema" in claim:
                        report.error(f"claim {claim_id}: trace claims use a trace contract, not evidence_schema")
                else:
                    evidence_schema = claim.get("evidence_schema")
                    _validate_evidence_schema(
                        evidence_schema, report, f"claim {claim_id}.evidence_schema",
                    )
                if claim.get("status") not in {"pending", "verified", "failed"}:
                    report.error(f"claim {claim_id}: status must be pending, verified, or failed")
                text = claim.get("text")
                if not isinstance(text, str) or not text.strip() or len(text) > 2_000:
                    report.error(f"claim {claim_id}: text must be bounded and nonempty")
                modes = claim.get("modes")
                if (
                    not isinstance(modes, list)
                    or not modes
                    or any(not isinstance(mode, str) for mode in modes)
                    or len(modes) != len(set(modes))
                    or any(mode not in {"product", "engineering"} for mode in modes)
                ):
                    report.error(f"claim {claim_id}: modes must be unique product/engineering values")
                if not isinstance(claim.get("required"), bool):
                    report.error(f"claim {claim_id}: required must be boolean")
                try:
                    _safe_parts(str(claim.get("receipt_ref", "")))
                except ProofError as exc:
                    report.error(f"claim {claim_id}: receipt_ref is unsafe ({exc})")
                claim_contract = contract
                claim_contract_sha = contract_sha
                claim_contract_ref = claim.get("trace_contract_ref")
                if claim_contract_ref is not None:
                    try:
                        loaded_contract_path = _resolve_in(packet, str(claim_contract_ref))
                        loaded_contract = _read_json(loaded_contract_path)
                        if not isinstance(loaded_contract, Mapping) or loaded_contract.get("schema_version") != "feature-proof-trace/v1":
                            report.error(f"claim {claim_id}: trace contract schema is invalid")
                        else:
                            claim_contract = loaded_contract
                            claim_contract_sha = _source_bound_trace_contract_sha256(
                                root, packet, commit, str(claim_contract_ref),
                            )
                            _validate_trace_contract(
                                loaded_contract, report,
                                location=f"claim {claim_id} trace contract",
                            )
                    except (ProofError, FileNotFoundError) as exc:
                        report.error(f"claim {claim_id}: trace contract is unreadable ({exc})")
                if claim.get("status") == "pending":
                    report.wait(f"claim {claim_id} receipt is pending")
                elif claim.get("status") == "failed":
                    report.error(f"claim {claim_id} is marked failed")
                else:
                    _validate_claim_receipt(
                        packet,
                        claim,
                        commit,
                        claim_contract,
                        report,
                        gates=manifest.get("gates", []) if isinstance(manifest.get("gates"), list) else [],
                        source_identity_sha256=source_digest,
                        trace_contract_sha256=claim_contract_sha,
                    )

        _validate_manifest_contract(manifest, claims, report)
        _validate_verification_matrix(manifest, claims, report)

        _validate_decision_log(packet, report)
        _validate_story(packet, set(claims), report)
        capture = manifest.get("capture") if isinstance(manifest.get("capture"), Mapping) else {}
        forbidden_raw = capture.get("product_forbidden_terms", DEFAULT_PRODUCT_FORBIDDEN)
        forbidden = (
            set(forbidden_raw)
            if isinstance(forbidden_raw, list)
            and all(isinstance(term, str) for term in forbidden_raw)
            else set(DEFAULT_PRODUCT_FORBIDDEN)
        )
        _validate_narration(packet, "product", claims, report, forbidden)
        _validate_narration(packet, "engineering", claims, report, forbidden)
        ui_applicable = capture.get("ui_applicable") is True
        _validate_gates(
            packet, manifest.get("gates"), commit, source_digest, ui_applicable, report,
        )
        if ui_applicable:
            _validate_media(packet, capture, commit, report)

        handoff = packet / "HANDOFF.md"
        if not handoff.is_file():
            report.error("HANDOFF.md is missing")
        elif handoff.stat().st_size > MAX_TEXT_BYTES:
            report.error("HANDOFF.md is unbounded")

        artifact_path = packet / "artifact-manifest.json"
        if artifact_path.exists():
            try:
                artifact_manifest = _read_json(artifact_path)
                if isinstance(artifact_manifest, Mapping):
                    portable_artifact = (
                        isinstance(source, Mapping)
                        and source.get("integrity_contract")
                        == MAIN_PORTABLE_INTEGRITY_CONTRACT
                    )
                    _validate_artifact_manifest(
                        packet,
                        files,
                        artifact_manifest,
                        commit,
                        report,
                        portable_text=portable_artifact,
                    )
                    if portable_artifact:
                        _validate_main_portable_git_seal(
                            root,
                            packet,
                            manifest,
                            artifact_manifest,
                            report,
                            allow_uncommitted=_allow_uncommitted_git_seal,
                        )
                else:
                    report.error("artifact manifest must be an object")
            except ProofError as exc:
                report.error(f"artifact manifest is malformed: {exc}")
        elif require_artifact_manifest:
            report.wait("artifact-manifest.json is pending finalization")
    except (ProofError, FileNotFoundError, TypeError, ValueError) as exc:
        report.error(str(exc))
    return report.as_dict()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent, prefix=".feature-proof-"
    )
    temporary = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_file(input_path: Path | str, output_path: Path | str) -> dict[str, Any]:
    source = Path(input_path)
    raw_bytes = _read_bytes(source, MAX_JSON_BYTES)
    try:
        raw = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"Langfuse export is malformed: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ProofError("Langfuse export must be one object")
    privacy_report = Report(feature_id="normalization")
    _privacy_scan(raw, privacy_report, "raw Langfuse export")
    if privacy_report.errors:
        raise ProofError("; ".join(privacy_report.errors))
    normalized = normalize_langfuse_export(raw, raw_bytes)
    if set(normalized) != TRACE_STAGING_FIELDS:
        raise ProofError("normalized Langfuse staging schema is not closed")
    _atomic_json(Path(output_path), normalized)
    return normalized


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", delete=False, dir=path.parent, prefix=".feature-proof-"
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _bounded_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[int, bytes, bytes]:
    """Run shell-free while draining each output stream into a hard memory cap."""

    if not 1 <= timeout_seconds <= MAX_GATE_SECONDS:
        raise ProofError(f"gate timeout must be between 1 and {MAX_GATE_SECONDS} seconds")
    if not argv or not all(isinstance(value, str) and value for value in argv):
        raise ProofError("gate argv must be a nonempty array of nonempty strings")
    try:
        resolved = shutil.which(argv[0], path=env.get("PATH"))
    except (OSError, ValueError) as exc:
        raise ProofError(f"gate executable resolution was unsafe: {argv[0]!r}") from exc
    if resolved is None:
        raise ProofError(f"gate executable was not found: {argv[0]!r}")
    if not Path(resolved).is_absolute():
        raise ProofError(f"gate executable resolution was unsafe: {argv[0]!r}")
    try:
        executable = Path(resolved).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProofError(f"gate executable resolution was unsafe: {argv[0]!r}") from exc
    if not executable.is_file():
        raise ProofError(f"gate executable resolution is not a regular file: {argv[0]!r}")
    execution_argv = [str(executable), *argv[1:]]
    try:
        process = subprocess.Popen(
            execution_argv,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise ProofError(f"gate process could not start: {exc}") from exc
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = threading.Event()

    def drain(name: str, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    return
                remaining = MAX_GATE_STREAM_BYTES - len(outputs[name])
                if len(chunk) > remaining:
                    if remaining > 0:
                        outputs[name].extend(chunk[:remaining])
                    exceeded.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                outputs[name].extend(chunk)
        finally:
            stream.close()

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=5)
        raise ProofError(f"gate exceeded its {timeout_seconds}-second timeout") from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if any(thread.is_alive() for thread in threads):
        raise ProofError("gate output reader did not terminate")
    if exceeded.is_set():
        raise ProofError(f"gate output exceeded {MAX_GATE_STREAM_BYTES} bytes per stream")
    return exit_code, bytes(outputs["stdout"]), bytes(outputs["stderr"])


def _execution_context(
    packet: Path | str, repo_root: Path | str,
) -> tuple[Path, Path, dict[str, Any], Mapping[str, Any], str, str]:
    packet_path = Path(packet)
    _reject_symlink_ancestors(packet_path)
    packet_path = packet_path.resolve(strict=True)
    root = Path(repo_root).resolve(strict=True)
    manifest = _read_json(_resolve_in(packet_path, "feature-manifest.json"))
    if not isinstance(manifest, dict):
        raise ProofError("feature manifest must be an object")
    source = manifest.get("source")
    if not isinstance(source, Mapping):
        raise ProofError("manifest source must be an object")
    if source.get("identity_status") != "frozen":
        raise ProofError("receipt execution requires source.identity_status=frozen")
    commit = str(source.get("implementation_commit", ""))
    if not COMMIT_RE.fullmatch(commit):
        raise ProofError("receipt execution requires a valid clean implementation commit")
    _verify_execution_checkout(root, packet_path, manifest)
    return packet_path, root, manifest, source, commit, _source_identity_sha256(source)


def _validate_scenario_output(
    value: Any,
    *,
    gate_id: str,
    source_identity_sha256: str,
    manifest_claims: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "gate_id", "source_identity_sha256", "claims",
    }:
        raise ProofError("scenario output must contain only its v1 binding fields")
    if value.get("schema_version") != "feature-proof-scenario-output/v1":
        raise ProofError("scenario output schema is unsupported")
    if value.get("gate_id") != gate_id:
        raise ProofError("scenario output gate id does not match the executed gate")
    if value.get("source_identity_sha256") != source_identity_sha256:
        raise ProofError("scenario output source identity does not match the manifest")
    claims = value.get("claims")
    if not isinstance(claims, list) or not 1 <= len(claims) <= 256:
        raise ProofError("scenario output must contain 1-256 claim results")
    claim_contracts: dict[str, Mapping[str, Any]] = {}
    for claim in manifest_claims:
        if not isinstance(claim, Mapping):
            raise ProofError("manifest claim contract is malformed")
        manifest_claim_id = str(claim.get("id", ""))
        if not ID_RE.fullmatch(manifest_claim_id) or manifest_claim_id in claim_contracts:
            raise ProofError("manifest claim contract has a malformed or duplicate id")
        claim_contracts[manifest_claim_id] = claim
    evidence_report = Report(feature_id="scenario-output")
    seen: set[str] = set()
    for index, row in enumerate(claims):
        if not isinstance(row, dict) or set(row) != {
            "claim_id", "receipt_type", "passed", "evidence",
        }:
            raise ProofError(f"scenario claim {index} must contain only typed v1 fields")
        claim_id = str(row.get("claim_id", ""))
        if not ID_RE.fullmatch(claim_id) or claim_id in seen:
            raise ProofError(f"scenario claim {index} has a malformed or duplicate id")
        seen.add(claim_id)
        if row.get("receipt_type") not in CLAIM_TYPES - {"trace_contract", "parallel"}:
            raise ProofError(f"scenario claim {claim_id} has an unsupported compiled type")
        claim_contract = claim_contracts.get(claim_id)
        if claim_contract is None:
            raise ProofError(f"scenario claim {claim_id} is not declared by the manifest")
        if row.get("receipt_type") != claim_contract.get("receipt_type"):
            raise ProofError(f"scenario claim {claim_id} receipt type differs from the manifest")
        if not isinstance(row.get("passed"), bool):
            raise ProofError(f"scenario claim {claim_id} passed must be boolean")
        if not isinstance(row.get("evidence"), dict):
            raise ProofError(f"scenario claim {claim_id} evidence must be an object")
        _validate_evidence_value(
            row["evidence"], claim_contract.get("evidence_schema"), evidence_report,
            f"scenario claim {claim_id}.evidence",
        )
    privacy = Report(feature_id="scenario-output")
    _privacy_scan(value, privacy, "scenario output")
    errors = evidence_report.errors + privacy.errors
    if errors:
        raise ProofError("; ".join(sorted(set(errors))))
    return value


def _preflight_mutation(packet: Path, root: Path) -> None:
    report = check_packet(packet, repo_root=root, require_artifact_manifest=False)
    if report["status"] == "FAIL":
        raise ProofError("packet preflight failed: " + "; ".join(report["errors"]))


def _publish_exact_or_recover(
    path: Path, value: Mapping[str, Any], *, label: str,
) -> Mapping[str, Any]:
    if path.exists():
        existing = _read_json(path)
        if not isinstance(existing, Mapping) or _canonical(existing) != _canonical(value):
            raise ProofError(f"conflicting existing {label}")
        return existing
    _atomic_json(path, value)
    return value


def _gate_retry_identity(receipt: Mapping[str, Any]) -> bytes:
    stable = {
        key: receipt.get(key)
        for key in (
            "schema_version", "gate_id", "source_commit", "source_identity_sha256",
            "argv", "command_sha256", "exit_code", "passed", "expected_literal",
            "observed_literal", "scenario_output_ref", "scenario_output_sha256",
        )
    }
    return _canonical(stable)


def _run_gate_locked(
    packet: Path | str,
    gate_id: str,
    *,
    repo_root: Path | str,
    timeout_seconds: int = 900,
    expect_scenario_output: bool = False,
) -> dict[str, Any]:
    """Execute one manifest argv and atomically publish a hash-only gate receipt."""

    packet_path, root, manifest, source, commit, source_digest = _execution_context(
        packet, repo_root,
    )
    _preflight_mutation(packet_path, root)
    gates = manifest.get("gates")
    gate = next(
        (row for row in gates if isinstance(row, Mapping) and row.get("id") == gate_id),
        None,
    ) if isinstance(gates, list) else None
    if not isinstance(gate, Mapping):
        raise ProofError(f"unknown manifest gate: {gate_id}")
    argv = gate.get("command")
    expected_literal = gate.get("expected_literal")
    receipt_ref = gate.get("receipt_path")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(value, str) and value for value in argv)
        or not isinstance(expected_literal, str)
        or not expected_literal
        or not isinstance(receipt_ref, str)
    ):
        raise ProofError(f"gate {gate_id} has an invalid execution contract")
    _safe_parts(receipt_ref)
    with tempfile.TemporaryDirectory(prefix="feature-proof-gate-") as temporary:
        scenario_stage = Path(temporary) / "scenario-output.json"
        child_env = dict(os.environ)
        child_env.pop("PYTHONOPTIMIZE", None)
        child_env.pop("PYTEST_ADDOPTS", None)
        child_env.update({
            "FEATURE_PROOF_PACKET": str(packet_path),
            "FEATURE_PROOF_GATE_ID": gate_id,
            "FEATURE_PROOF_SOURCE_IDENTITY_SHA256": source_digest,
            "FEATURE_PROOF_COMMAND_SHA256": sha256(_canonical(argv)).hexdigest(),
            "FEATURE_PROOF_EXPECTED_LITERAL": expected_literal,
            "FEATURE_PROOF_SCENARIO_OUTPUT": str(scenario_stage),
        })
        exit_code, stdout, stderr = _bounded_command(
            argv, cwd=root, env=child_env, timeout_seconds=timeout_seconds,
        )
        _verify_execution_checkout(root, packet_path, manifest)
        try:
            stdout_text = stdout.decode("utf-8")
            stderr_text = stderr.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProofError("gate output must be UTF-8 text") from exc
        privacy = Report(feature_id=gate_id)
        _privacy_scan(
            {"stdout": stdout_text, "stderr": stderr_text}, privacy, f"gate {gate_id} output",
        )
        if privacy.errors:
            raise ProofError("; ".join(privacy.errors))
        literal_seen = expected_literal in stdout_text or expected_literal in stderr_text
        if exit_code != 0 or not literal_seen:
            summary = _command_output_sha256(stdout, stderr)
            raise ProofError(
                f"gate did not pass (exit={exit_code}, literal={literal_seen}, output_sha256={summary})"
            )
        scenario: dict[str, Any] | None = None
        scenario_ref: str | None = None
        scenario_sha: str | None = None
        if expect_scenario_output:
            if not scenario_stage.is_file() or scenario_stage.is_symlink():
                raise ProofError("gate did not produce its fresh structured scenario output")
            scenario = _validate_scenario_output(
                _read_json(scenario_stage), gate_id=gate_id,
                source_identity_sha256=source_digest,
                manifest_claims=(
                    manifest.get("claims", ())
                    if isinstance(manifest.get("claims"), list) else ()
                ),
            )
        if scenario is not None:
            configured = gate.get("scenario_output_path")
            scenario_ref = (
                str(configured) if isinstance(configured, str)
                else f"receipts/scenarios/{gate_id}.json"
            )
            scenario_path = _resolve_in(packet_path, scenario_ref, must_exist=False)
            _publish_exact_or_recover(
                scenario_path, scenario, label=f"scenario output for gate {gate_id}",
            )
            scenario_sha = _sha_file(scenario_path)

    receipt = {
        "schema_version": "feature-proof-gate/v1",
        "gate_id": gate_id,
        "source_commit": commit,
        "source_identity_sha256": source_digest,
        "argv": argv,
        "command_sha256": sha256(_canonical(argv)).hexdigest(),
        "exit_code": exit_code,
        "passed": True,
        "expected_literal": expected_literal,
        "observed_literal": expected_literal,
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256(stderr).hexdigest(),
        "output_sha256": _command_output_sha256(stdout, stderr),
        "scenario_output_ref": scenario_ref,
        "scenario_output_sha256": scenario_sha,
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    destination = _resolve_in(packet_path, receipt_ref, must_exist=False)
    if destination.exists():
        existing = _read_json(destination)
        if (
            not isinstance(existing, Mapping)
            or _gate_retry_identity(existing) != _gate_retry_identity(receipt)
        ):
            raise ProofError(f"conflicting existing gate receipt for {gate_id}")
        return dict(existing)
    _atomic_json(destination, receipt)
    return receipt


def run_gate(
    packet: Path | str,
    gate_id: str,
    *,
    repo_root: Path | str,
    timeout_seconds: int = 900,
    expect_scenario_output: bool = False,
) -> dict[str, Any]:
    packet_path = Path(packet).resolve(strict=True)
    with _packet_lock(packet_path):
        return _run_gate_locked(
            packet_path, gate_id, repo_root=repo_root,
            timeout_seconds=timeout_seconds,
            expect_scenario_output=expect_scenario_output,
        )


def _compile_claim_locked(
    packet: Path | str,
    claim_id: str,
    scenario_ref: str,
    *,
    repo_root: Path | str,
) -> dict[str, Any]:
    """Compile one typed claim only from a passing gate-bound scenario row."""

    packet_path, root, manifest, _source, commit, source_digest = _execution_context(
        packet, repo_root,
    )
    _preflight_mutation(packet_path, root)
    claims = manifest.get("claims")
    claim = next(
        (row for row in claims if isinstance(row, Mapping) and row.get("id") == claim_id),
        None,
    ) if isinstance(claims, list) else None
    if not isinstance(claim, Mapping):
        raise ProofError(f"unknown manifest claim: {claim_id}")
    if claim.get("status") not in {"pending", "verified"}:
        raise ProofError("compile-claim requires a pending or verified claim")
    if claim.get("receipt_type") in {"trace_contract", "parallel"}:
        raise ProofError("trace and overlap claims must use normalized telemetry receipts")
    scenario_path = _resolve_in(packet_path, scenario_ref)
    scenario_raw = _read_json(scenario_path)
    scenario_gate_id = (
        str(scenario_raw.get("gate_id", ""))
        if isinstance(scenario_raw, Mapping) else ""
    )
    scenario = _validate_scenario_output(
        scenario_raw, gate_id=scenario_gate_id,
        source_identity_sha256=source_digest,
        manifest_claims=(
            manifest.get("claims", ())
            if isinstance(manifest.get("claims"), list) else ()
        ),
    )
    gate_id = str(scenario["gate_id"])
    gates = manifest.get("gates")
    gate = next(
        (row for row in gates if isinstance(row, Mapping) and row.get("id") == gate_id),
        None,
    ) if isinstance(gates, list) else None
    if not isinstance(gate, Mapping):
        raise ProofError("scenario output does not name a manifest gate")
    gate_ref = str(gate.get("receipt_path", ""))
    gate_path = _resolve_in(packet_path, gate_ref)
    gate_receipt = _read_json(gate_path)
    if not isinstance(gate_receipt, Mapping):
        raise ProofError("deriving gate receipt must be an object")
    gate_report = Report(feature_id=str(manifest.get("feature_id", "unknown")))
    capture = manifest.get("capture")
    _validate_gates(
        packet_path, [gate], commit, source_digest,
        bool(capture.get("ui_applicable")) if isinstance(capture, Mapping) else False,
        gate_report,
    )
    if gate_report.errors:
        raise ProofError("deriving gate is invalid: " + "; ".join(gate_report.errors))
    if gate_receipt.get("scenario_output_ref") != scenario_ref:
        raise ProofError("deriving gate is not bound to the selected scenario output")
    matching = [
        row for row in scenario["claims"]
        if row.get("claim_id") == claim_id
    ]
    if len(matching) != 1:
        raise ProofError("scenario output must contain exactly one selected claim")
    row = matching[0]
    if row.get("receipt_type") != claim.get("receipt_type") or row.get("passed") is not True:
        raise ProofError("scenario output does not pass the manifest's typed claim")
    receipt = {
        "schema_version": "feature-proof-receipt/v1",
        "receipt_type": claim.get("receipt_type"),
        "claim_id": claim_id,
        "claim_definition": _claim_definition(claim),
        "claim_definition_sha256": _claim_definition_sha256(claim),
        "source_commit": commit,
        "source_identity_sha256": source_digest,
        "passed": True,
        "evidence": row["evidence"],
        "derived_from": {
            "scenario_output_ref": scenario_ref,
            "scenario_output_sha256": _sha_file(scenario_path),
            "gate_receipt_ref": gate_ref,
            "gate_receipt_sha256": _sha_file(gate_path),
        },
    }
    receipt_ref = str(claim.get("receipt_ref", ""))
    destination = _resolve_in(packet_path, receipt_ref, must_exist=False)
    prior_manifest = (packet_path / "feature-manifest.json").read_bytes()
    _publish_exact_or_recover(
        destination, receipt, label=f"claim receipt for {claim_id}",
    )
    trace_ref = claim.get("trace_contract_ref", manifest.get("trace_contract_ref"))
    contract = _read_json(_resolve_in(packet_path, str(trace_ref)))
    validation = Report(feature_id=str(manifest.get("feature_id", "unknown")))
    _validate_claim_receipt(
        packet_path, claim, commit,
        contract if isinstance(contract, Mapping) else {}, validation,
        gates=gates if isinstance(gates, list) else (),
        source_identity_sha256=source_digest,
    )
    if validation.errors:
        raise ProofError("compiled claim is invalid: " + "; ".join(validation.errors))
    if claim.get("status") == "verified":
        return receipt
    updated = dict(manifest)
    updated["claims"] = [
        {**item, "status": "verified"} if isinstance(item, Mapping) and item.get("id") == claim_id else item
        for item in claims
    ]
    _atomic_json(packet_path / "feature-manifest.json", updated)
    packet_report = check_packet(
        packet_path, repo_root=root, require_artifact_manifest=False,
    )
    if packet_report["status"] == "FAIL":
        _atomic_text(packet_path / "feature-manifest.json", prior_manifest.decode("utf-8"))
        raise ProofError("claim promotion made the packet invalid: " + "; ".join(packet_report["errors"]))
    return receipt


def compile_claim(
    packet: Path | str,
    claim_id: str,
    scenario_ref: str,
    *,
    repo_root: Path | str,
) -> dict[str, Any]:
    packet_path = Path(packet).resolve(strict=True)
    with _packet_lock(packet_path):
        return _compile_claim_locked(
            packet_path, claim_id, scenario_ref, repo_root=repo_root,
        )


def _provider_json(value: Any, *, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        encoded = dict(value)
    else:
        dump = getattr(value, "model_dump", None)
        if not callable(dump):
            raise ProofError(f"authenticated Langfuse {label} is not serializable")
        encoded = dump(mode="json", by_alias=True, exclude_none=True)
    if not isinstance(encoded, dict):
        raise ProofError(f"authenticated Langfuse {label} must be an object")
    return encoded


def _normalize_langfuse_credential(value: str | None) -> str:
    """Normalize secret-manager wrappers without ever echoing credential bytes."""

    if (
        not isinstance(value, str)
        or len(value) > MAX_LANGFUSE_CREDENTIAL_SOURCE_CHARS
    ):
        raise ProofError(
            "authenticated Langfuse retrieval credential is missing or malformed"
        )
    normalized = value.strip().lstrip("\ufeff").strip()
    if (
        not normalized
        or len(normalized) > MAX_LANGFUSE_CREDENTIAL_CHARS
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in normalized)
    ):
        raise ProofError(
            "authenticated Langfuse retrieval credential is missing or malformed"
        )
    return normalized


def _bounded_langfuse_base_url(value: str) -> str:
    """Allow HTTPS self-hosts plus one exact loopback-only HTTP development origin."""

    normalized = value.strip().rstrip("/")
    if normalized == LOCAL_LANGFUSE_ORIGIN:
        return normalized
    if LANGFUSE_HTTPS_ORIGIN.fullmatch(normalized) and "@" not in normalized:
        return normalized
    raise ProofError(
        "LANGFUSE_BASE_URL must be a bounded HTTPS origin or the fixed loopback origin"
    )


def _trace_context_from_observations(
    trace_id: str,
    observations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Rebuild the trace envelope from v4 observation trace-context fields."""

    if not observations:
        raise ProofError("authenticated Langfuse returned no observations for the trace")
    for observation in observations:
        if observation.get("traceId", observation.get("trace_id")) != trace_id:
            raise ProofError("authenticated Langfuse returned an observation from another trace")
    project_ids = [
        observation.get("projectId", observation.get("project_id"))
        for observation in observations
    ]
    if any(value is None for value in project_ids) or len(set(map(str, project_ids))) != 1:
        raise ProofError("authenticated Langfuse trace crosses project boundaries")

    roots = [
        observation
        for observation in observations
        if observation.get("isRootObservation", observation.get("is_root_observation")) is True
    ]
    if not roots:
        roots = [
            observation
            for observation in observations
            if observation.get(
                "parentObservationId", observation.get("parent_observation_id")
            ) is None
        ]
    if len(roots) != 1:
        raise ProofError("authenticated Langfuse trace does not have one bounded root")
    root = roots[0]

    trace_name_values = [
        observation.get("traceName", observation.get("trace_name"))
        for observation in observations
    ]
    release_values = [observation.get("release") for observation in observations]
    if (
        any(value is None for value in trace_name_values)
        or any(value is None for value in release_values)
        or len(set(map(str, trace_name_values))) != 1
        or len(set(map(str, release_values))) != 1
    ):
        raise ProofError("authenticated Langfuse trace context is missing or inconsistent")
    trace_names = set(map(str, trace_name_values))
    releases = set(map(str, release_values))
    trace_name = root.get("traceName", root.get("trace_name"))
    release = root.get("release")
    if str(trace_name) not in trace_names or str(release) not in releases:
        raise ProofError("authenticated Langfuse root lacks trace context")
    timestamp = root.get("startTime", root.get("start_time"))
    if timestamp is None:
        raise ProofError("authenticated Langfuse root lacks a start timestamp")
    metadata = root.get("metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        raise ProofError("authenticated Langfuse root metadata is malformed")
    return {
        "id": trace_id,
        "name": trace_name,
        "release": release,
        "timestamp": timestamp,
        "metadata": dict(metadata),
    }


def _validate_langfuse_score_authority(
    trace_id: str,
    project_id: str,
    observation_ids: set[str],
    scores: Sequence[Mapping[str, Any]],
) -> None:
    """Fail closed unless every score is owned by this project and trace."""

    for score in scores:
        score_project = score.get("projectId", score.get("project_id"))
        if score_project is None or str(score_project) != project_id:
            raise ProofError("authenticated Langfuse score crosses project boundaries")
        subject = score.get("subject")
        if not isinstance(subject, Mapping):
            raise ProofError("authenticated Langfuse score lacks a bounded subject")
        kind = subject.get("kind")
        subject_id = subject.get("id")
        if kind == "trace":
            if subject_id != trace_id:
                raise ProofError("authenticated Langfuse score belongs to another trace")
            continue
        if kind == "observation":
            subject_trace_id = subject.get("traceId", subject.get("trace_id"))
            if subject_trace_id != trace_id or subject_id not in observation_ids:
                raise ProofError("authenticated Langfuse score belongs to another trace")
            continue
        raise ProofError("authenticated Langfuse score is not trace-bound")


def _langfuse_request_options(deadline: float) -> dict[str, int]:
    remaining = deadline - time.monotonic()
    request_seconds = math.floor(remaining)
    if request_seconds < 1:
        raise ProofError("authenticated Langfuse retrieval exceeded its bounded deadline")
    return {
        "timeout_in_seconds": min(
            int(MAX_LANGFUSE_REQUEST_SECONDS),
            request_seconds,
        ),
        "max_retries": 0,
    }


def _bounded_langfuse_close(close: Callable[[], None] | None, deadline: float) -> None:
    if (
        not callable(close)
        or min(MAX_LANGFUSE_SHUTDOWN_SECONDS, deadline - time.monotonic()) <= 0
    ):
        return
    finished = threading.Event()

    def run() -> None:
        try:
            close()
        except BaseException:
            # Retrieval success/failure is authoritative; SDK cleanup must not
            # replace it with an unrelated shutdown exception.
            pass
        finally:
            finished.set()

    try:
        worker = threading.Thread(
            target=run,
            name="feature-proof-langfuse-http-close",
            daemon=True,
        )
        worker.start()
    except BaseException:
        return
    remaining = min(MAX_LANGFUSE_SHUTDOWN_SECONDS, deadline - time.monotonic())
    if remaining > 0:
        finished.wait(remaining)


def _fetch_langfuse_export(
    trace_id: str,
    *,
    timeout_seconds: float = MAX_LANGFUSE_FETCH_SECONDS,
) -> dict[str, Any]:
    """Fetch one immutable v4 trace and bounded children through authenticated SDK reads."""

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ProofError("authenticated Langfuse retrieval timeout is invalid")
    fetch_started = time.monotonic()
    deadline = fetch_started + min(
        float(timeout_seconds),
        MAX_LANGFUSE_FETCH_SECONDS,
    )
    read_deadline = deadline - MAX_LANGFUSE_SHUTDOWN_SECONDS
    if read_deadline - fetch_started < 1:
        raise ProofError("authenticated Langfuse retrieval exceeded its bounded deadline")

    public_key = _normalize_langfuse_credential(
        os.environ.get("LANGFUSE_PUBLIC_KEY"),
    )
    secret_key = _normalize_langfuse_credential(
        os.environ.get("LANGFUSE_SECRET_KEY"),
    )
    try:
        import httpx
        from langfuse.api import LangfuseAPI
    except ImportError as exc:
        raise ProofError("authenticated Langfuse retrieval requires the official SDK") from exc

    base_url = _bounded_langfuse_base_url(
        os.environ.get("LANGFUSE_BASE_URL", DEFAULT_LANGFUSE_ORIGIN),
    )
    http_client = None
    try:
        request_timeout = min(
            MAX_LANGFUSE_REQUEST_SECONDS,
            max(1.0, read_deadline - time.monotonic()),
        )
        http_client = httpx.Client(
            timeout=request_timeout,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        )
        kwargs: dict[str, Any] = {
            "username": public_key,
            "password": secret_key,
            "x_langfuse_sdk_name": "feature-proof",
            "x_langfuse_public_key": public_key,
            "base_url": base_url,
            "timeout": request_timeout,
            "httpx_client": http_client,
        }
        api = LangfuseAPI(**kwargs)
        observation_page = api.observations.get_many(
            trace_id=trace_id,
            fields=(
                "core,basic,metadata,model,usage,prompt,metrics,trace_context"
            ),
            limit=257,
            request_options=_langfuse_request_options(read_deadline),
        )
        observation_cursor = getattr(
            getattr(observation_page, "meta", None), "cursor", None,
        )
        observations = [
            _provider_json(row, label="observation")
            for row in getattr(observation_page, "data", ())
        ]
        if observation_cursor or len(observations) > 256:
            raise ProofError("authenticated Langfuse trace exceeds 256 observations")
        trace = _trace_context_from_observations(trace_id, observations)
        project_id = str(
            observations[0].get("projectId", observations[0].get("project_id"))
        )
        observation_ids = {str(observation.get("id")) for observation in observations}

        scores: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for page_index, page_limit in enumerate((100, 100, 57)):
            score_page = api.scores_v3.get_many_v3(
                trace_id=trace_id,
                fields="details,subject,annotation",
                limit=page_limit,
                cursor=cursor,
                request_options=_langfuse_request_options(read_deadline),
            )
            scores.extend(
                _provider_json(row, label="score")
                for row in getattr(score_page, "data", ())
            )
            if len(scores) > 256:
                raise ProofError("authenticated Langfuse trace exceeds 256 scores")
            next_cursor = getattr(getattr(score_page, "meta", None), "cursor", None)
            if not next_cursor:
                break
            if next_cursor in seen_cursors:
                raise ProofError("authenticated Langfuse score pagination repeated a cursor")
            if page_index == 2:
                raise ProofError("authenticated Langfuse trace exceeds bounded score pages")
            seen_cursors.add(next_cursor)
            cursor = str(next_cursor)
        _validate_langfuse_score_authority(
            trace_id, project_id, observation_ids, scores,
        )

        observations.sort(key=_canonical)
        scores.sort(key=_canonical)
        raw = {"trace": trace, "observations": observations, "scores": scores}
        if len(_canonical(raw)) > MAX_JSON_BYTES:
            raise ProofError("authenticated Langfuse export exceeds the byte limit")
        if time.monotonic() >= read_deadline:
            raise ProofError("authenticated Langfuse retrieval exceeded its bounded deadline")
        return raw
    except ProofError:
        raise
    except Exception as exc:
        raise ProofError(
            f"authenticated Langfuse retrieval failed ({type(exc).__name__})"
        ) from exc
    finally:
        _bounded_langfuse_close(
            getattr(http_client, "close", None),
            deadline,
        )


def _read_langfuse_cache(path: Path) -> bytes:
    _reject_symlink_ancestors(path)
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ProofError("Langfuse export cache does not exist") from exc
    if resolved.is_symlink() or not resolved.is_file():
        raise ProofError("Langfuse export cache must be a regular file")
    return _read_bytes(resolved, MAX_JSON_BYTES)


def _normalize_authenticated_export(
    raw: Mapping[str, Any],
    raw_bytes: bytes,
    *,
    trace_id: str,
    extra_keys: Iterable[str] = (),
    extra_patterns: Iterable[str] = (),
) -> tuple[dict[str, Any], str]:
    privacy = Report(feature_id="trace-export")
    _privacy_scan(
        raw, privacy, "raw Langfuse export",
        extra_keys=RAW_TRACE_FORBIDDEN_KEYS | set(extra_keys),
        extra_patterns=extra_patterns,
        allow_empty_forbidden=True,
    )
    if privacy.errors:
        raise ProofError("; ".join(privacy.errors))
    provider_export: Mapping[str, Any] = raw
    observations = raw.get("observations")
    if isinstance(observations, list):
        normalized_observations: list[Any] = []
        changed = False
        for row in observations:
            if not isinstance(row, Mapping):
                normalized_observations.append(row)
                continue
            root_flags = [
                row[key]
                for key in ("isRootObservation", "is_root_observation")
                if key in row
            ]
            if any(not isinstance(value, bool) for value in root_flags):
                raise ProofError("Langfuse root-observation flag is not boolean")
            if len(set(root_flags)) > 1:
                raise ProofError("Langfuse root-observation flags conflict")
            if root_flags and root_flags[0] is True:
                normalized_row = dict(row)
                normalized_row["parentObservationId"] = None
                normalized_row["parent_observation_id"] = None
                normalized_observations.append(normalized_row)
                changed = True
            else:
                normalized_observations.append(row)
        if changed:
            normalized_export = dict(raw)
            normalized_export["observations"] = normalized_observations
            provider_export = normalized_export
    try:
        # Langfuse v4 represents a caller-supplied trace ID with an SDK-owned,
        # non-exported remote parent while also marking the observation as the
        # provider root. Honor only that literal provider root flag; the closed
        # topology validator still rejects multiple, missing, or wrongly named
        # roots. Keep raw_bytes unchanged so provenance binds the provider bytes.
        normalized = normalize_langfuse_export(provider_export, raw_bytes)
    except (TypeError, ValueError) as exc:
        raise ProofError(f"Langfuse export cannot be normalized: {exc}") from exc
    if set(normalized) != TRACE_STAGING_FIELDS:
        raise ProofError("normalized Langfuse staging schema is not closed")
    if normalized.get("trace_id") != trace_id:
        raise ProofError("authenticated Langfuse export does not match the requested trace id")
    return normalized, sha256(raw_bytes).hexdigest()


def _verify_trace_claim_locked(
    packet: Path | str,
    claim_id: str,
    trace_id: str,
    *,
    repo_root: Path | str,
    langfuse_export_cache: Path | str | None = None,
    fetch_langfuse_export: Callable[[str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fetch, validate, and publish one authenticated Langfuse trace."""

    packet_path, root, manifest, _source, commit, source_digest = _execution_context(
        packet, repo_root,
    )
    _preflight_mutation(packet_path, root)
    claims = manifest.get("claims")
    claim = next(
        (row for row in claims if isinstance(row, Mapping) and row.get("id") == claim_id),
        None,
    ) if isinstance(claims, list) else None
    if not isinstance(claim, Mapping):
        raise ProofError(f"unknown manifest claim: {claim_id}")
    if claim.get("receipt_type") != "trace_contract":
        raise ProofError("verify-trace-claim accepts only trace_contract claims")
    if claim.get("status") not in {"pending", "verified"}:
        raise ProofError("verify-trace-claim requires a pending or verified claim")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", trace_id):
        raise ProofError("trace_id is malformed")

    contract_ref = claim.get("trace_contract_ref", manifest.get("trace_contract_ref"))
    contract_path = _resolve_in(packet_path, str(contract_ref))
    contract = _read_json(contract_path)
    if (
        not isinstance(contract, Mapping)
        or contract.get("schema_version") != "feature-proof-trace/v1"
    ):
        raise ProofError("trace claim contract is invalid")
    privacy_contract = contract.get("must_not_capture")
    fetcher = fetch_langfuse_export or _fetch_langfuse_export
    try:
        fetched = fetcher(trace_id)
    except ProofError:
        raise
    except Exception as exc:
        raise ProofError(
            f"authenticated Langfuse retrieval failed ({type(exc).__name__})"
        ) from exc
    if not isinstance(fetched, Mapping):
        raise ProofError("authenticated Langfuse retrieval returned a non-object")
    raw_export = dict(fetched)
    raw_bytes = _canonical(raw_export)
    if len(raw_bytes) > MAX_JSON_BYTES:
        raise ProofError("authenticated Langfuse export exceeds the byte limit")
    if langfuse_export_cache is not None:
        cache_bytes = _read_langfuse_cache(Path(langfuse_export_cache))
        if cache_bytes != raw_bytes:
            raise ProofError(
                "Langfuse export cache bytes differ from authenticated retrieval"
            )
    candidate, raw_sha = _normalize_authenticated_export(
        raw_export,
        raw_bytes,
        trace_id=trace_id,
        extra_keys=(
            privacy_contract.get("keys", [])
            if isinstance(privacy_contract, Mapping) else ()
        ),
        extra_patterns=(
            privacy_contract.get("patterns", [])
            if isinstance(privacy_contract, Mapping) else ()
        ),
    )
    contract_sha = _source_bound_trace_contract_sha256(
        root, packet_path, commit, str(contract_ref),
    )
    receipt = {
        **candidate,
        "schema_version": "feature-proof-trace-receipt/v1",
        "source": {
            "provider": "langfuse",
            "retrieval": "authenticated_api",
            "trace_id": trace_id,
            "raw_sha256": raw_sha,
        },
        "claim_id": claim_id,
        "claim_definition": _claim_definition(claim),
        "claim_definition_sha256": _claim_definition_sha256(claim),
        "trace_contract_sha256": contract_sha,
        "source_identity_sha256": source_digest,
        "raw_langfuse_sha256": raw_sha,
    }
    validation = Report(feature_id=str(manifest.get("feature_id", "unknown")))
    validate_trace(
        receipt, contract, commit, validation, location=f"claim {claim_id}",
        expected_claim_id=claim_id,
        expected_contract_sha256=contract_sha,
        expected_source_identity_sha256=source_digest,
    )
    if validation.errors:
        raise ProofError(
            "normalized trace receipt is invalid: " + "; ".join(validation.errors)
        )

    receipt_ref = str(claim.get("receipt_ref", ""))
    destination = _resolve_in(packet_path, receipt_ref, must_exist=False)
    manifest_path = packet_path / "feature-manifest.json"
    prior_manifest = manifest_path.read_bytes()
    updated = dict(manifest)
    updated["claims"] = [
        {**item, "status": "verified"}
        if isinstance(item, Mapping) and item.get("id") == claim_id
        else item
        for item in claims
    ]

    _publish_exact_or_recover(
        destination, receipt, label=f"trace receipt for {claim_id}",
    )
    if claim.get("status") == "verified":
        return receipt
    try:
        _atomic_json(manifest_path, updated)
        packet_report = check_packet(
            packet_path, repo_root=root, require_artifact_manifest=False,
        )
        if packet_report["status"] == "FAIL":
            raise ProofError(
                "trace claim promotion made the packet invalid: "
                + "; ".join(packet_report["errors"])
            )
    except (OSError, ProofError, ValueError):
        _atomic_text(manifest_path, prior_manifest.decode("utf-8"))
        raise
    return receipt


def verify_trace_claim(
    packet: Path | str,
    claim_id: str,
    trace_id: str,
    *,
    repo_root: Path | str,
    langfuse_export_cache: Path | str | None = None,
) -> dict[str, Any]:
    packet_path = Path(packet).resolve(strict=True)
    with _packet_lock(packet_path):
        return _verify_trace_claim_locked(
            packet_path,
            claim_id,
            trace_id,
            repo_root=repo_root,
            langfuse_export_cache=langfuse_export_cache,
        )


def render_trace_waterfall(
    trace_path: Path | str, svg_path: Path | str, html_path: Path | str
) -> dict[str, Any]:
    """Render deterministic pixels from one normalized receipt and nothing else."""

    source_path = Path(trace_path)
    source_bytes = _read_bytes(source_path, MAX_JSON_BYTES)
    trace = _read_json(source_path)
    if not isinstance(trace, Mapping) or trace.get("schema_version") != "feature-proof-trace-receipt/v1":
        raise ProofError("waterfall input must be a normalized feature-proof trace receipt")
    source = trace.get("source")
    if (
        not isinstance(source, Mapping)
        or source.get("provider") != "langfuse"
        or source.get("retrieval") != "authenticated_api"
        or source.get("trace_id") != trace.get("trace_id")
        or set(source) != {"provider", "retrieval", "trace_id", "raw_sha256"}
        or not SHA_RE.fullmatch(str(source.get("raw_sha256", "")))
    ):
        raise ProofError("waterfall input lacks authenticated Langfuse source binding")
    privacy = Report(feature_id="trace-waterfall")
    _privacy_scan(trace, privacy, "trace waterfall input")
    if privacy.errors:
        raise ProofError("; ".join(privacy.errors))
    spans = trace.get("spans")
    if not isinstance(spans, list) or not spans or len(spans) > 256:
        raise ProofError("waterfall needs between 1 and 256 spans")

    parsed: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(spans):
        if not isinstance(row, Mapping):
            raise ProofError(f"waterfall span {index} is not an object")
        span_id = str(row.get("span_id", ""))
        if not span_id or span_id in by_id:
            raise ProofError("waterfall span ids must be present and unique")
        start = datetime.fromisoformat(str(row.get("start_time", "")).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(row.get("end_time", "")).replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or end < start:
            raise ProofError(f"waterfall span {span_id} has an invalid interval")
        item = {
            "span_id": span_id,
            "parent_span_id": row.get("parent_span_id"),
            "name": str(row.get("name", "unnamed")),
            "kind": str(row.get("kind", "span")).lower(),
            "status": str(row.get("status", "ok")).lower(),
            "start": start,
            "end": end,
        }
        parsed.append(item)
        by_id[span_id] = item
    for item in parsed:
        parent_id = item["parent_span_id"]
        if parent_id is not None and parent_id not in by_id:
            raise ProofError(f"waterfall span {item['span_id']} has a missing parent")
        if parent_id is not None:
            parent = by_id[str(parent_id)]
            if item["start"] < parent["start"] or item["end"] > parent["end"]:
                raise ProofError(f"waterfall span {item['span_id']} lies outside its parent")
    if len([item for item in parsed if item["parent_span_id"] is None]) != 1:
        raise ProofError("waterfall trace must contain exactly one user-action root")
    parsed.sort(key=lambda row: (row["start"], row["end"], row["name"], row["span_id"]))

    def depth(item: Mapping[str, Any]) -> int:
        seen: set[str] = set()
        parent_id = item["parent_span_id"]
        value = 0
        while parent_id is not None:
            if str(parent_id) in seen:
                raise ProofError("waterfall trace contains a parent cycle")
            seen.add(str(parent_id))
            value += 1
            parent_id = by_id[str(parent_id)]["parent_span_id"]
        return value

    sibling_overlap_ms = 0.0
    for left_index, left in enumerate(parsed):
        for right in parsed[left_index + 1 :]:
            if left["parent_span_id"] != right["parent_span_id"]:
                continue
            overlap = (min(left["end"], right["end"]) - max(left["start"], right["start"])).total_seconds() * 1000
            sibling_overlap_ms = max(sibling_overlap_ms, overlap)

    start_all = min(item["start"] for item in parsed)
    end_all = max(item["end"] for item in parsed)
    duration_ms = max((end_all - start_all).total_seconds() * 1000, 0.001)
    width, label_width, timeline_width = 1200, 270, 880
    row_height, top, bottom = 38, 116, 58
    height = top + len(parsed) * row_height + bottom
    trace_digest = sha256(source_bytes).hexdigest()
    colors = {"generation": "#a78bfa", "model": "#a78bfa", "guardrail": "#fbbf24", "retriever": "#34d399", "chain": "#60a5fa"}
    rows: list[str] = []
    for index, item in enumerate(parsed):
        y = top + index * row_height
        offset_ms = (item["start"] - start_all).total_seconds() * 1000
        span_ms = (item["end"] - item["start"]).total_seconds() * 1000
        x = label_width + offset_ms / duration_ms * timeline_width
        bar_width = max(1.5, span_ms / duration_ms * timeline_width)
        color = "#f87171" if item["status"] == "error" else colors.get(item["kind"], "#94a3b8")
        indent = "  " * min(depth(item), 6)
        available = max(12, 38 - len(indent))
        full_name = indent + item["name"]
        display_name = (
            full_name
            if len(full_name) <= 38
            else indent + item["name"][: available - 1] + "…"
        )
        rows.extend(
            [
                f'<text x="20" y="{y + 19}" class="label">{html_escape(display_name)}<title>{html_escape(full_name)}</title></text>',
                f'<rect x="{x:.3f}" y="{y + 4}" width="{bar_width:.3f}" height="22" rx="4" fill="{color}" opacity="0.92"/>',
                f'<text x="{min(x + bar_width + 7, width - 92):.3f}" y="{y + 20}" class="metric">{span_ms:.2f} ms</text>',
            ]
        )
    overlap_label = (
        f"Measured sibling overlap: {sibling_overlap_ms:.2f} ms"
        if sibling_overlap_ms > 0
        else "Measured sibling overlap: none"
    )
    svg = "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc" data-trace-sha256="{trace_digest}">',
            f'<title id="title">Trace waterfall for {html_escape(str(trace.get("trace_name", "run")))}</title>',
            f'<desc id="desc">Bars use the receipt timestamps. {html_escape(overlap_label)}. Parent-child nesting is not parallel evidence.</desc>',
            f'<metadata>{{"schema":"feature-proof-waterfall/v1","trace_sha256":"{trace_digest}"}}</metadata>',
            '<style>.bg{fill:#07111f}.title{fill:#f8fafc;font:600 20px system-ui}.sub{fill:#94a3b8;font:13px system-ui}.label{fill:#dbeafe;font:12px ui-monospace,monospace}.metric{fill:#cbd5e1;font:11px ui-monospace,monospace}.grid{stroke:#1e293b;stroke-width:1}</style>',
            f'<rect class="bg" width="{width}" height="{height}"/>',
            f'<text x="20" y="34" class="title">{html_escape(str(trace.get("trace_name", "Trace")))}</text>',
            f'<text x="20" y="58" class="sub">Release {html_escape(str(trace.get("release", "unknown")))} · {len(parsed)} spans · {duration_ms:.2f} ms</text>',
            f'<text x="20" y="80" class="sub">{html_escape(overlap_label)} · nested work is not parallel evidence</text>',
            *[
                f'<line x1="{label_width + fraction * timeline_width:.3f}" y1="96" x2="{label_width + fraction * timeline_width:.3f}" y2="{height - 34}" class="grid"/>'
                for fraction in (0, 0.25, 0.5, 0.75, 1)
            ],
            *rows,
            f'<text x="20" y="{height - 18}" class="sub">Receipt SHA-256 {trace_digest}</text>',
            "</svg>",
            "",
        ]
    )
    html = "\n".join(
        [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            f"<title>{html_escape(str(trace.get('trace_name', 'Trace')))} waterfall</title>",
            '<style>html,body{margin:0;background:#07111f;color:#f8fafc}main{max-width:1200px;margin:auto}svg{display:block;width:100%;height:auto}</style>',
            "</head><body><main>",
            svg.rstrip(),
            "</main></body></html>",
            "",
        ]
    )
    _atomic_text(Path(svg_path), svg)
    _atomic_text(Path(html_path), html)
    return {
        "schema_version": "feature-proof-waterfall/v1",
        "trace_sha256": trace_digest,
        "spans": len(parsed),
        "duration_ms": round(duration_ms, 6),
        "sibling_overlap_ms": round(max(sibling_overlap_ms, 0), 6),
        "svg": str(svg_path),
        "html": str(html_path),
    }


def _render_template(name: str, replacements: Mapping[str, str]) -> str:
    assets = Path(__file__).resolve().parent.parent / "assets"
    text = _read_bytes(assets / name, MAX_TEXT_BYTES).decode("utf-8")
    for key, value in replacements.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def init_packet(
    packet: Path | str,
    feature_id: str,
    title: str,
    *,
    implementation_commit: str,
    implementation_path: str,
    anchor_symbol: str,
) -> Path:
    if not ID_RE.fullmatch(feature_id):
        raise ProofError("feature id must be lowercase kebab-case")
    if not COMMIT_RE.fullmatch(implementation_commit):
        raise ProofError("implementation commit must be 7-64 lowercase hex characters")
    _safe_parts(implementation_path)
    if not anchor_symbol.strip():
        raise ProofError("anchor symbol is required")
    replacements = {
        "FEATURE_ID": feature_id,
        "TITLE": title,
        "IMPLEMENTATION_COMMIT": implementation_commit,
        "IMPLEMENTATION_PATH": implementation_path.replace("\\", "/"),
        "ANCHOR_SYMBOL": anchor_symbol,
    }
    target = Path(packet).absolute()
    _reject_symlink_ancestors(target)
    if target.exists() or target.is_symlink():
        raise ProofError("init refuses to overwrite an existing packet")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".feature-proof-init-", dir=target.parent))
    try:
        for relative in ("before", "receipts/tests", "receipts/traces", "receipts/browser", "media"):
            (stage / relative).mkdir(parents=True, exist_ok=True)
        mapping = {
            "feature-manifest.template.json": "feature-manifest.json",
            "trace-contract.template.json": "trace-contract.json",
            "storyboard.template.json": "storyboard.json",
        }
        for template, output in mapping.items():
            rendered = _render_template(template, replacements)
            if output == "feature-manifest.json":
                manifest = _bounded_json_bytes(
                    rendered.encode("utf-8"), label="feature manifest template",
                )
                if not isinstance(manifest, dict) or not isinstance(manifest.get("source"), dict):
                    raise ProofError("feature manifest template source is malformed")
                manifest["source"]["identity_status"] = "pending_clean_commit"
                manifest["source"]["implementation_commit"] = None
                _atomic_json(stage / output, manifest)
            else:
                (stage / output).write_text(rendered, encoding="utf-8", newline="\n")
        narration = _render_template("narration.template.json", replacements)
        (stage / "narration.product.json").write_text(narration.replace("{{MODE}}", "product"), encoding="utf-8", newline="\n")
        (stage / "narration.engineering.json").write_text(narration.replace("{{MODE}}", "engineering"), encoding="utf-8", newline="\n")
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        decision = {
            "id": "decision-0001-contract",
            "timestamp": timestamp,
            "decision": "Adopt feature-proof/v1 without claiming unobserved completion.",
            "why": "A feature may be narrated only after its named receipt passes.",
            "rejected_alternative": "A hand-written done checklist without artifact or trace binding.",
            "evidence": ["feature-manifest.json", "trace-contract.json"],
            "trigger_to_revisit": "A required claim cannot be represented by the v1 receipt types.",
            "supersedes": None,
        }
        (stage / "decision-log.jsonl").write_text(json.dumps(decision, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (stage / "HANDOFF.md").write_text(f"# {title} handoff\n\nStatus: **PENDING**. Receipts and media have not yet passed.\n", encoding="utf-8", newline="\n")
        os.replace(stage, target)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return target


def _artifact_rows(
    packet: Path,
    *,
    portable_text: bool = False,
) -> list[dict[str, Any]]:
    files = _scan_packet(packet, HARD_MAX_PACKET_BYTES)
    rows = []
    for path in files:
        if path.name == "artifact-manifest.json":
            continue
        relative = path.relative_to(packet).as_posix()
        observed_bytes, observed_sha256 = _artifact_file_identity(
            path,
            relative,
            portable_text=portable_text,
        )
        rows.append(
            {
                "path": relative,
                "bytes": observed_bytes,
                "sha256": observed_sha256,
            }
        )
    return sorted(rows, key=lambda row: row["path"])


def _finalize_packet_locked(
    packet: Path | str, *, repo_root: Path | str | None = None,
) -> dict[str, Any]:
    packet = Path(packet).resolve(strict=True)
    root = Path(repo_root).resolve(strict=True) if repo_root is not None else Path.cwd().resolve(strict=True)
    _, _, execution_manifest, source, _, _ = _execution_context(packet, root)
    portable_artifact = (
        source.get("integrity_contract") == MAIN_PORTABLE_INTEGRITY_CONTRACT
    )
    preflight = check_packet(
        packet,
        repo_root=repo_root,
        require_artifact_manifest=False,
        _allow_uncommitted_git_seal=True,
    )
    if preflight["status"] != "PASS":
        raise ProofError(f"finalization refused: {json.dumps(preflight, sort_keys=True)}")
    destination = packet / "artifact-manifest.json"
    if destination.exists():
        existing = _read_json(destination)
        if not isinstance(existing, Mapping):
            raise ProofError("conflicting existing artifact manifest")
        final = check_packet(
            packet,
            repo_root=repo_root,
            require_artifact_manifest=True,
            _allow_uncommitted_git_seal=True,
        )
        if final["status"] != "PASS":
            raise ProofError("conflicting existing artifact manifest")
        return dict(existing)
    manifest = execution_manifest
    rows = _artifact_rows(packet, portable_text=portable_artifact)
    artifact = {
        "schema_version": "feature-proof-artifacts/v1",
        "feature_id": manifest["feature_id"],
        "implementation_commit": manifest["source"]["implementation_commit"],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": rows,
        "packet_sha256": sha256(_canonical(rows)).hexdigest(),
    }
    _atomic_json(destination, artifact)
    final = check_packet(
        packet,
        repo_root=repo_root,
        require_artifact_manifest=True,
        _allow_uncommitted_git_seal=True,
    )
    if final["status"] != "PASS":
        destination.unlink(missing_ok=True)
        raise ProofError(f"final manifest failed self-verification: {json.dumps(final, sort_keys=True)}")
    return artifact


def finalize_packet(
    packet: Path | str, *, repo_root: Path | str | None = None,
) -> dict[str, Any]:
    packet_path = Path(packet).resolve(strict=True)
    with _packet_lock(packet_path):
        return _finalize_packet_locked(packet_path, repo_root=repo_root)


def _print(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    initialize = sub.add_parser("init", help="atomically initialize a pending packet")
    initialize.add_argument("packet")
    initialize.add_argument("--feature-id", required=True)
    initialize.add_argument("--title", required=True)
    initialize.add_argument("--implementation-commit", required=True)
    initialize.add_argument("--implementation-path", required=True)
    initialize.add_argument("--anchor-symbol", required=True)
    normalize = sub.add_parser("normalize", help="normalize one exported Langfuse trace")
    normalize.add_argument("input")
    normalize.add_argument("output")
    waterfall = sub.add_parser(
        "render-waterfall", help="render deterministic SVG and HTML from a normalized trace"
    )
    waterfall.add_argument("trace")
    waterfall.add_argument("--svg", required=True)
    waterfall.add_argument("--html", required=True)
    gate_run = sub.add_parser(
        "run-gate", help="execute one manifest argv and publish its bounded atomic receipt"
    )
    gate_run.add_argument("packet")
    gate_run.add_argument("--gate-id", required=True)
    gate_run.add_argument("--repo-root", default=".")
    gate_run.add_argument("--timeout-seconds", type=int, default=900)
    gate_run.add_argument("--expect-scenario-output", action="store_true")
    claim_compile = sub.add_parser(
        "compile-claim", help="compile one typed claim from gate-bound scenario output"
    )
    claim_compile.add_argument("packet")
    claim_compile.add_argument("--claim-id", required=True)
    claim_compile.add_argument("--scenario-output", required=True)
    claim_compile.add_argument("--repo-root", default=".")
    trace_verify = sub.add_parser(
        "verify-trace-claim",
        help="fetch an authenticated Langfuse trace and atomically promote its claim",
    )
    trace_verify.add_argument("packet")
    trace_verify.add_argument("--claim-id", required=True)
    trace_verify.add_argument("--trace-id", required=True)
    trace_verify.add_argument("--langfuse-export-cache")
    trace_verify.add_argument("--repo-root", default=".")
    check = sub.add_parser("check", help="validate a packet and its receipts")
    check.add_argument("packet")
    check.add_argument("--repo-root", default=".")
    check.add_argument("--allow-pending", action="store_true")
    finalize = sub.add_parser("finalize", help="publish the verified artifact manifest last")
    finalize.add_argument("packet")
    finalize.add_argument("--repo-root", default=".")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            path = init_packet(
                args.packet,
                args.feature_id,
                args.title,
                implementation_commit=args.implementation_commit,
                implementation_path=args.implementation_path,
                anchor_symbol=args.anchor_symbol,
            )
            _print({"status": "PENDING", "packet": str(path)})
            return 0
        if args.command == "normalize":
            _print(normalize_file(args.input, args.output))
            return 0
        if args.command == "render-waterfall":
            _print(render_trace_waterfall(args.trace, args.svg, args.html))
            return 0
        if args.command == "run-gate":
            _print(run_gate(
                args.packet,
                args.gate_id,
                repo_root=args.repo_root,
                timeout_seconds=args.timeout_seconds,
                expect_scenario_output=args.expect_scenario_output,
            ))
            return 0
        if args.command == "compile-claim":
            _print(compile_claim(
                args.packet,
                args.claim_id,
                args.scenario_output,
                repo_root=args.repo_root,
            ))
            return 0
        if args.command == "verify-trace-claim":
            _print(verify_trace_claim(
                args.packet,
                args.claim_id,
                args.trace_id,
                repo_root=args.repo_root,
                langfuse_export_cache=args.langfuse_export_cache,
            ))
            return 0
        if args.command == "check":
            report = check_packet(args.packet, repo_root=args.repo_root)
            _print(report)
            return 0 if report["status"] == "PASS" or (args.allow_pending and report["status"] == "PENDING") else 1
        if args.command == "finalize":
            _print(finalize_packet(args.packet, repo_root=args.repo_root))
            return 0
    except (ProofError, FileNotFoundError, ValueError) as exc:
        _print({"status": "FAIL", "error": str(exc)})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
