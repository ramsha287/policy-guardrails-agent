from app.context.descriptors import describe


def tool(name, args=None, meta=None, resource=None, domains=("acme.com",)):
    return describe(
        stage="tool",
        action=name,
        resource=resource,
        tool_name=name,
        tool_arguments=args or {},
        request_arguments=None,
        tool_metadata=meta,
        internal_domains=domains,
    )


def test_bulk_export_query_is_parsed_exactly():
    d = tool(
        "db.query", {"sql": "SELECT email, phone AS mobile, address FROM public.customers ORDER BY id DESC LIMIT 10000"}
    )
    assert (d.kind, d.verb) == ("sql", "read")
    assert d.tables == ("public.customers",) and d.target == "public.customers"
    assert d.columns == ("email", "mobile", "address")
    assert d.rows_requested == 10000 and d.has_limit and d.has_filter is False
    assert d.parsed and not d.writes


def test_sql_statement_kinds():
    assert tool("db.query", {"query": "delete from orders where id = 1"}).verb == "delete"
    assert tool("db.query", {"query": "UPDATE accounts SET plan='x' WHERE id=2"}).verb == "write"
    assert tool("db.query", {"query": "GRANT ALL ON t TO bob"}).verb == "admin"
    assert tool("db.query", {"query": "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"}).verb == "write"
    copy = tool("db.query", {"query": "COPY customers TO '/tmp/x.csv'"})
    assert copy.verb == "read" and "COPY ... TO exports data" in copy.notes
    assert tool("db.query", {"query": "CALL refresh_all()"}).verb == "execute"


def test_sql_injection_tricks_are_seen_not_hidden():
    # a second statement after a comment and a string that contains a fake LIMIT
    d = tool("db.query", {"sql": "SELECT * FROM users WHERE name = 'x LIMIT 5'; -- harmless\n DROP TABLE users"})
    assert d.verb == "delete" and d.statements == 2 and "multiple statements" in d.notes
    assert d.rows_requested is None and d.has_limit is False


def test_sql_joins_fetch_first_and_argument_limit():
    d = tool(
        "db.query",
        {
            "sql": 'SELECT c.id FROM crm.customers c JOIN "crm"."orders" o ON o.cid = c.id FETCH FIRST 50 ROWS ONLY',
            "limit": 20,
        },
    )
    assert set(d.tables) == {"crm.customers", "crm.orders"}
    assert d.rows_requested == 50  # the SQL's own limit; a `limit` argument is not trusted


def test_unbounded_read_has_no_rows_and_no_filter():
    d = tool("db.query", {"sql": "select * from customers"})
    assert d.rows_requested is None and d.has_limit is False and d.has_filter is False and d.columns == ("*",)


def test_http_destination_internal_vs_external():
    ext = tool("http.post", {"url": "https://webhook.site/abc", "method": "POST", "json": {}})
    assert (ext.kind, ext.verb, ext.destination, ext.destination_host) == ("http", "send", "external", "webhook.site")
    internal = tool("http.get", {"url": "https://api.acme.com/v1/orders?id=1"})
    assert (internal.verb, internal.destination) == ("read", "internal")
    assert tool("http.get", {"url": "http://10.0.0.7/x"}).destination == "internal"
    assert tool("http.get", {"url": "http://billing.default.svc/x"}).destination == "internal"
    # look-alike domain is not internal
    assert tool("http.get", {"url": "https://acme.com.evil.io/"}).destination == "external"


def test_messages_classify_recipients():
    d = tool("email.send", {"to": ["ann@acme.com", "x@gmail.com"], "subject": "hi"})
    assert (d.kind, d.verb, d.destination, d.destination_host) == ("message", "send", "external", "gmail.com")
    assert tool("email.send", {"to": "ann@acme.com"}).destination == "internal"
    assert tool("slack.post_message", {"channel": "#ops"}).destination == "internal"
    assert tool("slack.post_message", {"webhook_url": "https://hooks.example.org/x"}).destination == "external"


def test_files_and_unknown_tools():
    f = tool("s3.delete_object", {"bucket": "reports", "key": "q3.csv"})
    assert (f.kind, f.verb, f.target) == ("file", "delete", "reports/q3.csv")
    u = tool("crm.thing", {"x": 1})
    assert (u.kind, u.verb) == ("unknown", "unknown") and not u.parsed
    assert tool("crm.customers.export", {}).verb == "read"
    assert tool("jira.create_issue", {"summary": "s"}).verb == "write"


def test_stages_without_tools():
    assert describe(stage="input", action="llm.chat", resource=None, tool_name=None, tool_arguments=None,
                    request_arguments=None, tool_metadata=None).kind == "model"  # fmt: skip
    assert describe(stage="retrieval", action="kb.search", resource="kb://hr", tool_name=None, tool_arguments=None,
                    request_arguments=None, tool_metadata=None).verb == "read"  # fmt: skip


def test_parser_never_raises():
    d = tool("db.query", {"sql": "SELECT (((( FROM"})
    assert d.kind == "sql"
    d = tool("http.get", {"url": "::::"})
    assert d.kind == "http"


def test_quoted_comment_markers_cannot_hide_statements():
    d = tool("db.query", {"sql": "SELECT '--'; DROP TABLE customers"})
    assert d.verb == "delete" and d.statements == 2
    d = tool("db.query", {"sql": "SELECT '/*' AS a; DELETE FROM customers; SELECT '*/'"})
    assert d.verb == "delete" and d.statements == 3
    d = tool("db.query", {"sql": "SELECT $$ ; DROP TABLE x $$ AS s FROM t WHERE 1=1 LIMIT 1"})
    assert d.verb == "read" and d.statements == 1


def test_unscannable_sql_is_unknown_not_guessed():
    for sql in ("SELECT 'abc FROM t", "SELECT 1 /* open", "SELECT 'it\\'s'; DROP TABLE t", 'SELECT "col FROM t'):
        d = tool("db.query", {"sql": sql})
        assert (d.kind, d.verb) == ("sql", "unknown"), sql


def test_limit_argument_does_not_override_the_sql():
    d = tool("db.query", {"sql": "SELECT * FROM customers", "limit": 1})
    assert d.rows_requested is None and d.has_limit is False
    assert "row limit only in tool arguments (not trusted)" in d.notes


def test_numeric_ip_hosts_are_decoded():
    assert tool("http.post", {"url": "http://134744072/x", "method": "POST"}).destination == "external"  # 8.8.8.8
    assert tool("http.post", {"url": "http://0x7f000001/x", "method": "POST"}).destination == "internal"
    assert tool("http.post", {"url": "http://2130706433/x", "method": "POST"}).destination == "internal"
    assert tool("http.post", {"url": "http://0x8.8.8.8/x", "method": "POST"}).destination == "external"
    assert tool("http.get", {"url": "https://cafe.acme.com/x"}).destination == "internal"
