"""Run probe calls and capture what came back.

This module records raw facts about each call (size, error flag, content
types, latency). Probe *rules* (P1-P5) will read these results; keeping the
capture separate means rules can be tested on saved results with no server.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp_lint.fixtures import Probe, check_probe
from mcp_lint.models import ToolDef
from mcp_lint.text import estimate_tokens

PREVIEW_CHARS = 400


@dataclass
class ProbeResult:
    tool: str
    label: str
    args: dict[str, Any]
    expect_error: bool
    status: str  # "ok" | "tool_error" | "protocol_error" | "skipped" | "blocked"
    reason: str | None = None  # why skipped/blocked, or the protocol error text
    text: str = ""  # all text content joined; what the agent would read
    content_types: dict[str, int] = field(default_factory=dict)
    structured: Any = None
    chars: int = 0
    tokens: int = 0  # estimated, same method as definition tokens
    latency_ms: int | None = None
    target: str | None = None  # parameter a bad-args probe gets wrong
    auto: bool = False  # generated, not from a fixtures file
    may_succeed: bool = False  # success on this expect_error probe is not a defect

    @property
    def error_text(self) -> str:
        """What the agent would read for a failed call."""
        if self.status == "protocol_error":
            # reason is "ExceptionType: message"; the type name is client-side.
            reason = self.reason or ""
            return reason.split(": ", 1)[1] if ": " in reason else reason
        return self.text or (json.dumps(self.structured) if self.structured is not None else "")

    @property
    def ran(self) -> bool:
        return self.status in ("ok", "tool_error", "protocol_error")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("text")
        d["preview"] = self.text[:PREVIEW_CHARS]
        return d


def _base(p: Probe) -> dict[str, Any]:
    return {"tool": p.tool, "label": p.label, "args": p.args, "expect_error": p.expect_error,
            "target": p.target, "auto": p.auto, "may_succeed": p.may_succeed}


def capture(probe: Probe, result: Any, latency_ms: int) -> ProbeResult:
    """Turn a CallToolResult into a ProbeResult."""
    texts, kinds = [], Counter()
    for block in result.content or []:
        kind = getattr(block, "type", "unknown")
        kinds[kind] += 1
        if kind == "text":
            texts.append(block.text)
        elif kind == "resource" and getattr(block.resource, "text", None):
            texts.append(block.resource.text)
    structured = result.structured_content
    text = "\n".join(texts)
    # Agents see structured content too, so count it when there's no text form.
    counted = text if text else (json.dumps(structured) if structured is not None else "")
    return ProbeResult(
        **_base(probe),
        status="tool_error" if result.is_error else "ok",
        text=text,
        content_types=dict(kinds),
        structured=structured,
        chars=len(counted),
        tokens=estimate_tokens(counted),
        latency_ms=latency_ms,
    )


async def call_probe(session: Any, probe: Probe, tools: dict[str, ToolDef], timeout: float) -> ProbeResult:
    if probe.skip:
        return ProbeResult(**_base(probe), status="skipped", reason="marked skip")
    problems = check_probe(probe, tools)
    if problems:
        return ProbeResult(**_base(probe), status="blocked", reason="; ".join(problems))
    start = time.perf_counter()
    try:
        result = await session.call_tool(probe.tool, probe.args, read_timeout_seconds=timeout)
    except Exception as exc:  # noqa: BLE001 - a protocol error is itself a probe outcome
        return ProbeResult(
            **_base(probe),
            status="protocol_error",
            reason=f"{type(exc).__name__}: {exc}",
            latency_ms=round((time.perf_counter() - start) * 1000),
        )
    return capture(probe, result, round((time.perf_counter() - start) * 1000))
