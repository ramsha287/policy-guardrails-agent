import { describe, expect, it } from "vitest";

import { Api, ApiError, queryString, toApiError } from "../src/lib/api";

function fakeFetch(status: number, body: unknown, seen: { url?: string; init?: RequestInit }[] = []) {
  return async (url: string, init?: RequestInit) => {
    seen.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

describe("api client", () => {
  it("builds query strings without empty values", () => {
    expect(queryString({ status: "pending", tenant_id: "", x: undefined, n: 0 })).toBe("?status=pending&n=0");
    expect(queryString({})).toBe("");
  });

  it("sends the admin key and JSON body to /cp/v1", async () => {
    const seen: { url?: string; init?: RequestInit }[] = [];
    const api = new Api("cpk_test", fakeFetch(200, { id: "r1" }, seen));
    await api.decideReview("r/1", true, "fine");
    expect(seen[0]?.url).toBe("/cp/v1/reviews/r%2F1/approve");
    const headers = seen[0]?.init?.headers as Record<string, string>;
    expect(headers["X-Admin-Key"]).toBe("cpk_test");
    expect(seen[0]?.init?.body).toBe(JSON.stringify({ note: "fine" }));
    expect(seen[0]?.init?.credentials).toBe("omit");
  });

  it("turns error bodies into ApiError with details", async () => {
    const api = new Api("k", fakeFetch(422, { error: "snapshot is invalid", errors: ["config: bad"], warnings: ["w"] }));
    await expect(api.publish("dev", "")).rejects.toMatchObject({ status: 422, message: "snapshot is invalid", errors: ["config: bad"], warnings: ["w"] });
  });

  it("understands FastAPI detail bodies and non-JSON errors", async () => {
    const e1 = await toApiError(new Response(JSON.stringify({ detail: "nope" }), { status: 400 }));
    expect(e1.message).toBe("nope");
    const e2 = await toApiError(new Response("<html>bad gateway</html>", { status: 502, statusText: "Bad Gateway" }));
    expect(e2).toBeInstanceOf(ApiError);
    expect(e2.message).toBe("Bad Gateway");
  });

  it("signs out on 401", async () => {
    let signedOut = false;
    const api = new Api("k", fakeFetch(401, { error: "revoked" }), () => {
      signedOut = true;
    });
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(signedOut).toBe(true);
  });

  it("returns undefined for 204", async () => {
    const api = new Api("k", async () => new Response(null, { status: 204 }));
    expect(await api.deleteAgent("acme", "bot")).toBeUndefined();
  });
});
