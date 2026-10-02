"""Action descriptors: what a request actually does, worked out by parsing it, not by asking a model.

"Export the last 10,000 customer records" arrives as a tool call. Parsing it gives exact facts the
policy and the risk engine can use, and a parser can't be prompt-injected:

    {"kind": "sql", "verb": "read", "target": "public.customers", "tables": ["public.customers"],
     "columns": ["email", "phone"], "rows_requested": 10000, "has_filter": false, ...}

The parsers are deliberately conservative. Anything they can't classify comes back as
`verb="unknown"`, which the risk engine treats as high risk rather than guessing. The SQL parser is
a small tokenizer (no dependency): it reads the statement type, tables, selected columns, LIMIT and
whether there is a WHERE clause. It is not a full SQL grammar; when in doubt it says so in `notes`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

Kind = Literal["sql", "http", "file", "message", "model", "unknown"]
Verb = Literal["read", "write", "delete", "send", "execute", "admin", "unknown"]

_SQL_KEYS = ("sql", "query", "statement")
_URL_KEYS = ("url", "uri", "endpoint")
_PATH_KEYS = ("path", "file", "filename", "key", "object", "prefix")
_RECIPIENT_KEYS = ("to", "recipient", "recipients", "cc", "bcc", "email")
_MESSAGE_PREFIXES = ("email.", "mail.", "slack.", "teams.", "chat.", "sms.", "webhook.", "notify.")
_ROW_ARG_KEYS = ("limit", "max_rows", "rows", "count", "top", "page_size")

# verb from words in the tool/action name (e.g. crm.customers.export -> read, files.delete -> delete)
_NAME_VERBS: list[tuple[Verb, tuple[str, ...]]] = [
    ("delete", ("delete", "remove", "drop", "purge", "destroy", "truncate", "erase")),
    ("admin", ("grant", "revoke", "admin", "permission", "role", "policy", "config")),
    ("execute", ("exec", "execute", "run", "shell", "eval", "script", "invoke", "command")),
    ("send", ("send", "email", "notify", "publish", "post_message", "message", "webhook", "share", "upload")),
    ("write", ("create", "update", "put", "post", "write", "insert", "set", "save", "patch", "modify", "edit")),
    ("read", ("get", "list", "read", "search", "fetch", "query", "describe", "lookup", "find", "export", "select")),
]

_VERB_SEVERITY: dict[str, int] = {
    "read": 0, "send": 1, "write": 2, "execute": 3, "delete": 3, "admin": 4, "unknown": 5,
}  # fmt: skip


@dataclass(frozen=True)
class ActionDescriptor:
    kind: Kind
    verb: Verb
    target: str | None = None  # main table, host, path or recipient domain
    tables: tuple[str, ...] = ()
    columns: tuple[str, ...] = ()
    rows_requested: int | None = None  # None = unknown or unbounded
    has_limit: bool | None = None
    has_filter: bool | None = None
    destination: Literal["internal", "external"] | None = None
    destination_host: str | None = None
    statements: int = 1
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def parsed(self) -> bool:
        return self.kind != "unknown" and self.verb != "unknown"

    @property
    def writes(self) -> bool:
        return self.verb in ("write", "delete", "send", "execute", "admin")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tables"], d["columns"], d["notes"] = list(self.tables), list(self.columns), list(self.notes)
        return d


def describe(
    *,
    stage: str,
    action: str,
    resource: str | None,
    tool_name: str | None,
    tool_arguments: Mapping[str, Any] | None,
    request_arguments: Mapping[str, Any] | None,
    tool_metadata: Mapping[str, Any] | None,
    internal_domains: Iterable[str] = (),
) -> ActionDescriptor:
    """Describe one request. Never raises: unparseable input gives kind/verb "unknown"."""
    name = tool_name or action
    args: dict[str, Any] = {**(request_arguments or {}), **(tool_arguments or {})}
    meta = dict(tool_metadata or {})
    domains = tuple(d.lower().lstrip(".") for d in internal_domains if d)
    try:
        if stage in ("input", "output") and not tool_name:
            return ActionDescriptor("model", "execute", target=resource or action)
        if stage == "retrieval":
            return ActionDescriptor("file", "read", target=resource or action)
        sql = _first_str(args, _SQL_KEYS)
        if meta.get("kind") == "sql" or (sql is not None and _looks_like_sql(sql)):
            return _describe_sql(sql or "", args, resource)
        url = _first_str(args, _URL_KEYS)
        if url is not None or meta.get("kind") == "http":
            return _describe_http(url or "", args, name, domains)
        if name.lower().startswith(_MESSAGE_PREFIXES) or _first_present(args, _RECIPIENT_KEYS):
            return _describe_message(args, name, domains)
        path = _first_str(args, _PATH_KEYS)
        if path is not None or meta.get("kind") == "file":
            bucket = _first_str(args, ("bucket", "container"))
            target = f"{bucket}/{path}" if bucket and path else (path or resource)
            return ActionDescriptor("file", _verb_from_name(name), target=target)
        return ActionDescriptor("unknown", _verb_from_name(name), target=resource, notes=("no parser for this tool",))
    except Exception as exc:  # noqa: BLE001 - a parser bug must never break a request; be conservative
        return ActionDescriptor("unknown", "unknown", target=resource, notes=(f"parser error: {type(exc).__name__}",))


def sql_text(tool_arguments: Mapping[str, Any] | None, request_arguments: Mapping[str, Any] | None) -> str | None:
    """The SQL string `describe()` parsed (same key order and precedence), for the dry run."""
    args: dict[str, Any] = {**(request_arguments or {}), **(tool_arguments or {})}
    return _first_str(args, _SQL_KEYS)


# ---- helpers ------------------------------------------------------------------------------------


def _first_str(args: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def _first_present(args: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for k in keys:
        if args.get(k):
            return args[k]
    return None


def _verb_from_name(name: str) -> Verb:
    words = [w for w in re.split(r"[^a-z0-9]+", name.lower()) if w]
    joined = "_".join(words)
    for verb, needles in _NAME_VERBS:
        for n in needles:
            if n in words or (("_" in n) and n in joined):
                return verb
    return "unknown"


def _int_arg(args: Mapping[str, Any]) -> int | None:
    for k in _ROW_ARG_KEYS:
        v = args.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int) and v >= 0:
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return None


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Also decodes the integer/hex forms browsers and curl accept (http://134744072/ is 8.8.8.8)."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d+|0x[0-9a-f]+", h):
            return ipaddress.ip_address(int(h, 0))
    except ValueError:
        return None
    return None


def _is_internal_host(host: str, domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return False
    ip = _as_ip(host)
    if ip is not None:
        return ip.is_private or ip.is_loopback or ip.is_link_local
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*", host):  # other numeric forms (0x8.8.8.8): external
        return False
    if host == "localhost" or "." not in host or host.endswith((".svc", ".cluster.local", ".internal", ".local")):
        return True
    return any(host == d or host.endswith("." + d) for d in domains)


# ---- SQL ----------------------------------------------------------------------------------------

_SQL_START = re.compile(
    r"^\s*(select|with|insert|update|delete|merge|upsert|replace|truncate|drop|alter|create|grant|revoke|copy|"
    r"explain|show|describe|desc|call|exec|execute|vacuum|analyze)\b",
    re.I,
)
_IDENT = r'(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*))*'
_FROM_LIST = re.compile(
    r"\bfrom\s+(" + _IDENT + r"(?:\s*(?:as\s+)?\w+)?(?:\s*,\s*" + _IDENT + r"(?:\s*(?:as\s+)?\w+)?)*)", re.I
)
_TABLE_AFTER = re.compile(r"\b(?:join|into|update|table|truncate(?:\s+table)?)\s+(?:only\s+)?(" + _IDENT + ")", re.I)
_LIMIT = re.compile(r"\blimit\s+(\d+)|\bfetch\s+(?:first|next)\s+(\d+)\s+rows?\b|\btop\s*\(?\s*(\d+)", re.I)
_KEYWORDS = {"select", "where", "group", "order", "limit", "having", "join", "on", "left", "right", "inner", "outer",
             "full", "cross", "union", "as", "lateral", "set", "values"}  # fmt: skip


def _looks_like_sql(text: str) -> bool:
    cleaned, _ = _scan_sql(text)
    return bool(_SQL_START.match(cleaned))


def _scan_sql(sql: str) -> tuple[str, list[str]]:
    """One pass over the text: string literals become '', comments become a space.

    Doing both in one pass matters: stripping comments first would let a quoted '--' hide the
    rest of a line (SELECT '--'; DROP TABLE t). Anything that can't be scanned with certainty
    (unterminated string or comment, backslash escapes whose meaning depends on the database) is
    reported in the second value, and the caller treats the statement as unknown.
    """
    out: list[str] = []
    problems: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        two = sql[i : i + 2]
        if two == "--":
            j = sql.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif two == "/*":
            j = sql.find("*/", i + 2)
            if j < 0:
                problems.append("unterminated comment")
                break
            out.append(" ")
            i = j + 2
        elif ch == "'":
            j = i + 1
            while True:
                k = sql.find("'", j)
                if k < 0:
                    problems.append("unterminated string")
                    i = n
                    break
                if "\\" in sql[j:k]:
                    problems.append("backslash escape in string")
                if sql[k + 1 : k + 2] == "'":  # '' is an escaped quote
                    j = k + 2
                    continue
                i = k + 1
                break
            out.append("''")
        elif ch in ('"', "`"):
            k = sql.find(ch, i + 1)
            if k < 0:
                problems.append("unterminated identifier")
                break
            out.append(sql[i : k + 1])
            i = k + 1
        elif ch == "$":
            m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                k = sql.find(tag, i + len(tag))
                if k < 0:
                    problems.append("unterminated dollar-quoted string")
                    break
                out.append("''")
                i = k + len(tag)
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out), problems


def _clean_ident(raw: str) -> str:
    parts = [p.strip().strip('"`[]') for p in re.split(r"\s*\.\s*", raw.strip())]
    return ".".join(p for p in parts if p)


def _split_top_level(text: str) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [o.strip() for o in out if o.strip()]


def _statement_verb(stmt: str) -> tuple[Verb, list[str]]:
    notes: list[str] = []
    m = _SQL_START.match(stmt)
    first = m.group(1).lower() if m else ""
    if first == "with":
        if re.search(r"\b(insert|update|delete|merge)\b", stmt, re.I):
            return "write", ["data-modifying CTE"]
        return "read", notes
    if first in ("select", "explain", "show", "describe", "desc"):
        if first == "select" and re.search(r"\binto\s+(?!@)", stmt, re.I) and not re.search(r"\binsert\b", stmt, re.I):
            return "write", ["SELECT INTO creates a table"]
        if re.search(r"\bfor\s+update\b", stmt, re.I):
            notes.append("row locks (FOR UPDATE)")
        return "read", notes
    if first in ("insert", "update", "merge", "upsert", "replace"):
        return "write", notes
    if first in ("delete", "truncate", "drop"):
        return "delete", notes
    if first in ("alter", "create", "grant", "revoke", "vacuum", "analyze"):
        return "admin", notes
    if first == "copy":
        if re.search(r"\bto\b", stmt, re.I):
            return "read", ["COPY ... TO exports data"]
        return "write", notes
    if first in ("call", "exec", "execute"):
        return "execute", ["stored procedure: effects unknown"]
    return "unknown", ["unrecognised statement"]


def _describe_sql(sql: str, args: Mapping[str, Any], resource: str | None) -> ActionDescriptor:
    text, problems = _scan_sql(sql)
    statements = [s for s in (p.strip() for p in text.split(";")) if s]
    if not statements:
        return ActionDescriptor("sql", "unknown", target=resource, statements=0, notes=("empty statement",))
    if problems:  # can't be sure what runs: don't guess
        return ActionDescriptor(
            "sql", "unknown", target=resource, statements=len(statements), notes=tuple(dict.fromkeys(problems))
        )
    notes: list[str] = []
    verbs: list[Verb] = []
    for st in statements:
        v, n = _statement_verb(st)
        verbs.append(v)
        notes.extend(n)
    if len(statements) > 1:
        notes.append("multiple statements")
    verb = max(verbs, key=lambda v: _VERB_SEVERITY[v])
    stmt = statements[0]

    tables: list[str] = []
    for fm in _FROM_LIST.finditer(stmt):
        for item in _split_top_level(fm.group(1)):
            name = re.match(_IDENT, item)
            if name and name.group(0).lower() not in _KEYWORDS:
                tables.append(_clean_ident(name.group(0)))
    for tm in _TABLE_AFTER.finditer(stmt):
        if tm.group(1).lower() not in _KEYWORDS:
            tables.append(_clean_ident(tm.group(1)))
    tables = list(dict.fromkeys(tables))

    columns: list[str] = []
    sel = re.search(r"\bselect\s+(?:distinct\s+)?(.*?)\bfrom\b", stmt, re.I | re.S)
    if sel:
        for col in _split_top_level(sel.group(1)):
            alias = re.search(r"(?:\bas\s+)?([\w$\"*]+)\s*$", col, re.I)
            columns.append(alias.group(1).strip('"') if alias else col)

    limits = [int(next(g for g in m.groups() if g)) for m in _LIMIT.finditer(stmt)]
    rows = min(limits) if limits else None
    if rows is None and _int_arg(args) is not None:
        # A `limit` argument next to the SQL is only a claim: the tool may ignore it. Trust the SQL.
        notes.append("row limit only in tool arguments (not trusted)")
    has_filter = bool(re.search(r"\bwhere\b", stmt, re.I))
    target = tables[0] if tables else resource
    return ActionDescriptor(
        "sql",
        verb,
        target=target,
        tables=tuple(tables),
        columns=tuple(columns),
        rows_requested=rows,
        has_limit=rows is not None,
        has_filter=has_filter,
        statements=len(statements),
        notes=tuple(dict.fromkeys(notes)),
    )


# ---- HTTP / messages ----------------------------------------------------------------------------


def _describe_http(url: str, args: Mapping[str, Any], name: str, domains: tuple[str, ...]) -> ActionDescriptor:
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = (parts.hostname or "").lower()
    method = str(args.get("method") or "").upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        verb: Verb = "read"
    elif method == "DELETE":
        verb = "delete"
    elif method in ("POST", "PUT", "PATCH"):
        verb = "send"
    else:
        verb = _verb_from_name(name)
        if verb == "unknown":
            verb = "send" if args.get("body") or args.get("json") or args.get("data") else "read"
    internal = _is_internal_host(host, domains)
    return ActionDescriptor(
        "http",
        verb,
        target=(host + (parts.path or "")) if host else None,
        destination=("internal" if internal else "external") if host else None,
        destination_host=host or None,
        rows_requested=_int_arg(args),
        notes=() if host else ("no host in URL",),
    )


def _recipients(args: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for k in _RECIPIENT_KEYS:
        v = args.get(k)
        if isinstance(v, str):
            out.extend(p.strip() for p in re.split(r"[,;\s]+", v) if p.strip())
        elif isinstance(v, list):
            out.extend(str(x).strip() for x in v if str(x).strip())
    return out


def _describe_message(args: Mapping[str, Any], name: str, domains: tuple[str, ...]) -> ActionDescriptor:
    recipients = _recipients(args)
    hosts = sorted({r.rsplit("@", 1)[1].lower() for r in recipients if "@" in r})
    webhook = _first_str(args, ("webhook_url", "webhook", "callback_url"))
    if webhook:
        hosts.append((urlsplit(webhook).hostname or "").lower())
    external = [h for h in hosts if h and not _is_internal_host(h, domains)]
    if hosts:
        destination: Literal["internal", "external"] | None = "external" if external else "internal"
    elif name.lower().startswith(("slack.", "teams.", "chat.")) and not webhook:
        destination = "internal"  # a workspace channel; external sharing shows up as a webhook/recipient
    else:
        destination = None
    main_host = (external or hosts)[0] if (external or hosts) else None
    return ActionDescriptor(
        "message",
        "send",
        target=main_host,
        destination=destination,
        destination_host=main_host,
        notes=() if destination else ("recipient unknown",),
    )
