"""Input normalization: NFKC plus removal of invisible/control characters.

Attackers hide instructions with zero-width or bidi-override characters and full-width
look-alikes; normalizing first means every guardrail sees the same canonical text.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from guardrail_sdk import Payload

# C0/C1 controls except \t \n \r, zero-width chars, bidi overrides/isolates, BOM.
_STRIP_RE = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def normalize_text(value: str) -> str:
    return _STRIP_RE.sub("", unicodedata.normalize("NFKC", value))


def _normalize_any(value: Any) -> Any:
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, list):
        return [_normalize_any(v) for v in value]
    if isinstance(value, dict):
        return {k: _normalize_any(v) for k, v in value.items()}
    return value


def normalize_payload(payload: Payload) -> Payload:
    data = payload.model_dump(mode="python")
    if data.get("text") is not None:
        data["text"] = normalize_text(data["text"])
    for m in data.get("messages") or []:
        m["content"] = normalize_text(m["content"])
    for c in data.get("chunks") or []:
        c["text"] = normalize_text(c["text"])
    if data.get("tool_call") is not None:
        data["tool_call"]["arguments"] = _normalize_any(data["tool_call"]["arguments"])
        data["tool_call"]["result"] = _normalize_any(data["tool_call"]["result"])
    return Payload.model_validate(data)
