import { describe, expect, it } from "vitest";

import { Api } from "../src/lib/api";
import { buildGuardRequest, encodedBlob, newSessionId, SCENARIOS, type PlaygroundForm } from "../src/lib/playground";

const base: PlaygroundForm = {
  stage: "input",
  agent: " research-agent ",
  action: "llm.chat",
  resource: "",
  userId: "u1",
  sessionId: "s-1",
  classification: "INTERNAL",
  text: "hello",
  toolName: "http.post",
  toolArgs: '{"url": "https://example.net"}',
  toolResult: "",
};

describe("playground requests", () => {
  it("builds the agent's request body per stage", () => {
    expect(buildGuardRequest(base)).toEqual({
      agent_id: "research-agent",
      action: "llm.chat",
      user_id: "u1",
      session_id: "s-1",
      data_classification: "INTERNAL",
      payload: { text: "hello" },
    });
    const chunks = buildGuardRequest({ ...base, stage: "retrieval", text: "one\n\n two " }).payload;
    expect(chunks).toEqual({ chunks: [{ id: "c1", text: "one" }, { id: "c2", text: "two" }] });
    const tool = buildGuardRequest({ ...base, stage: "tool", toolResult: '{"note": "x"}', resource: "crm" });
    expect(tool.payload).toEqual({ tool_call: { name: "http.post", arguments: { url: "https://example.net" }, result: { note: "x" } } });
    expect(tool.resource).toBe("crm");
    const textResult = buildGuardRequest({ ...base, stage: "tool", toolResult: "plain text" }).payload;
    expect(textResult).toEqual({ tool_call: { name: "http.post", arguments: { url: "https://example.net" }, result: "plain text" } });
    expect(() => buildGuardRequest({ ...base, stage: "tool", toolArgs: "[1]" })).toThrow();
    const noSession = buildGuardRequest({ ...base, sessionId: "", userId: "" });
    expect("session_id" in noSession || "user_id" in noSession).toBe(false);
  });

  it("ships valid scenarios", () => {
    const ids = SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const s of SCENARIOS) {
      const form = { ...base, toolResult: "", ...s.form() };
      expect(buildGuardRequest(form).agent_id.length > 0).toBe(true);
      expect(s.expect.length > 0).toBe(true);
    }
    expect(SCENARIOS.find((s) => s.id === "exfil-2")?.session).toBe("same");
    expect(/[0-9=]/.test(encodedBlob())).toBe(false); // digits would look like a phone number
    expect(newSessionId()).not.toBe(newSessionId());
  });

  it("calls the playground and decision log endpoints", async () => {
    const calls: [string, RequestInit | undefined][] = [];
    const api = new Api("cpk_x", async (url, init) => {
      calls.push([url, init]);
      return new Response(JSON.stringify({ decisions: [] }), { status: 200 });
    });
    await api.playground({ environment: "dev", stage: "tool", gateway_key: "gk_a", request: buildGuardRequest(base) });
    await api.playgroundEscalation("esc 1", { environment: "dev", gateway_key: "gk_a" });
    await api.decisions({ agent_id: "research-agent", decision: "", hours: 24 });
    await api.decision("req-1");
    expect(calls.map((c) => c[0])).toEqual([
      "/cp/v1/playground",
      "/cp/v1/playground/escalations/esc%201",
      "/cp/v1/decisions?agent_id=research-agent&hours=24",
      "/cp/v1/decisions/req-1",
    ]);
    expect(JSON.parse(String(calls[0]?.[1]?.body)).gateway_key).toBe("gk_a");
  });
});
