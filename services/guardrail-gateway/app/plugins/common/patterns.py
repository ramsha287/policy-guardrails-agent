"""Rules for regular expressions that come from assignment config (editors, not code).

Python's `re` has no time limit, and one catastrophically backtracking pattern, such as `(a+)+$`,
can stall a gateway's event loop. Detecting that in general is hard and easy to get around, so
config patterns follow simple rules instead:

- no unbounded repetition of a group: `(...)+`, `(...)*` and `(...){2,}` are refused (bounded
  `(...)?` and `(...){1,10}` are allowed); repeat single characters or classes instead
  (`\\w+`, `[a-z]{2,}`);
- no backreferences, named groups or inline flags (`\\1`, `(?P<x>...)`, `(?i)`): matching is
  already case-insensitive, and each pattern is compiled on its own;
- at most 300 characters, and it must compile.

On top of that, config patterns only ever see the first `CONFIG_SCAN_LIMIT` characters of each
text, which bounds the cost of what remains (`\\w*\\w*x` is polynomial, not exponential).
"""

from __future__ import annotations

import re

MAX_PATTERN = 300
CONFIG_SCAN_LIMIT = 16_384  # characters of each text that config patterns look at
MAX_GROUP_REPEAT = 10

_FORBIDDEN = (
    (re.compile(r"\\[1-9]"), "backreferences"),
    (re.compile(r"\(\?P[<=]"), "named groups"),
    (re.compile(r"\(\?<?[aiLmsux-]+[:)]"), "inline flags"),
)


def _group_quantifiers(pattern: str) -> list[str]:
    """The quantifier that follows each closing parenthesis (outside character classes)."""
    out, i, in_class = [], 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
            if pattern[i + 1 : i + 2] == "]":  # "[]...]" : a literal ] first
                i += 1
        elif ch == ")":
            m = re.match(r"[+*?]|\{\d*(?:,\d*)?\}", pattern[i + 1 :])
            if m:
                out.append(m.group(0))
        i += 1
    return out


def check_pattern(pattern: str) -> str:
    """Return the pattern, or raise ValueError when it is too long, invalid or risky."""
    if len(pattern) > MAX_PATTERN:
        raise ValueError(f"patterns are at most {MAX_PATTERN} characters")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regular expression {pattern!r}: {exc}") from exc
    for rx, what in _FORBIDDEN:
        if rx.search(pattern):
            raise ValueError(f"pattern {pattern!r}: {what} are not allowed in config patterns")
    for q in _group_quantifiers(pattern):
        if q in ("+", "*"):
            raise ValueError(
                f"pattern {pattern!r} repeats a group without a limit; repeat a character or class instead"
            )
        if q.startswith("{"):
            bounds = q[1:-1].split(",")
            upper = bounds[-1] if len(bounds) == 2 else bounds[0]
            if not upper or int(upper) > MAX_GROUP_REPEAT:
                raise ValueError(f"pattern {pattern!r} repeats a group more than {MAX_GROUP_REPEAT} times")
    return pattern
