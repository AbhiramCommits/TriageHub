import { afterEach, describe, expect, it, vi } from "vitest";

import { bulkTransition, filtersToParams } from "../api/client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("encodes filters as repeated query parameters", () => {
    const params = filtersToParams({
      state: "open",
      severity: "high",
      rule_id: "rule.one",
      repo: "acme/api",
      search: "eval",
    });
    expect(params.get("state")).toBe("open");
    expect(params.get("severity")).toBe("high");
    expect(params.get("rule_id")).toBe("rule.one");
    expect(params.get("repo")).toBe("acme/api");
    expect(params.get("search")).toBe("eval");
    expect(params.get("limit")).toBe("100");
  });

  it("posts the exact bulk transition body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ updated: [], skipped: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await bulkTransition({
      finding_ids: ["a", "b"],
      action: "mute",
      assignee_user_id: "user-1",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/findings/bulk-transition");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(JSON.parse(String(init.body))).toEqual({
      finding_ids: ["a", "b"],
      action: "mute",
      assignee_user_id: "user-1",
    });
  });
});
