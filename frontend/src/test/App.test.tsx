import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { bulkTransition, listFindings, listUsers } from "../api/client";
import type { Finding } from "../types";
import { renderApp } from "./utils";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    listFindings: vi.fn(),
    listUsers: vi.fn(),
    bulkTransition: vi.fn(),
  };
});

const listFindingsMock = vi.mocked(listFindings);
const listUsersMock = vi.mocked(listUsers);
const bulkTransitionMock = vi.mocked(bulkTransition);

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    workspace_id: "ws-1",
    rule_id: "python.lang.security.audit.eval-detected",
    severity: "high",
    message: "Avoid eval() on untrusted input",
    repo: "acme/payments-api",
    file_path: "app/api/charges.py",
    start_line: 42,
    end_line: 42,
    line_fingerprint: "abc123",
    code_snippet: 'result = eval(request.args["expr"])',
    rule_rationale: "eval executes arbitrary code.",
    state: "open",
    assignee_user_id: null,
    first_seen_at: "2026-11-01T10:00:00Z",
    triaged_at: null,
    notification_variant: "A",
    ...overrides,
  };
}

function page(items: Finding[]) {
  return { items, next_cursor: null };
}

beforeEach(() => {
  listFindingsMock.mockReset();
  listUsersMock.mockReset();
  bulkTransitionMock.mockReset();
  listUsersMock.mockResolvedValue([]);
  bulkTransitionMock.mockResolvedValue({ updated: [], skipped: [] });
});

describe("TriageHub console", () => {
  it("syncs filters into the URL query string", async () => {
    listFindingsMock.mockResolvedValue(page([makeFinding()]));
    const user = userEvent.setup();
    renderApp();

    await screen.findByText("Avoid eval() on untrusted input");
    await user.selectOptions(screen.getByLabelText("Severity"), "high");

    await waitFor(() => {
      expect(window.location.search).toContain("severity=high");
    });
    expect(listFindingsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: "high" }),
    );

    await user.selectOptions(screen.getByLabelText("State"), "open");
    await waitFor(() => {
      expect(window.location.search).toContain("state=open");
      expect(window.location.search).toContain("severity=high");
    });
  });

  it("supports the keyboard navigation sequence", async () => {
    const rows = [
      makeFinding({ id: "a", start_line: 1 }),
      makeFinding({ id: "b", start_line: 2 }),
      makeFinding({ id: "c", start_line: 3 }),
    ];
    listFindingsMock.mockResolvedValue(page(rows));
    renderApp();
    await screen.findAllByTestId("finding-row");

    const fire = (key: string) =>
      act(() => {
        window.dispatchEvent(new KeyboardEvent("keydown", { key }));
      });

    fire("j");
    await waitFor(() => {
      expect(screen.getAllByTestId("finding-row")[0]).toHaveAttribute("aria-current", "true");
    });
    fire("j");
    await waitFor(() => {
      expect(screen.getAllByTestId("finding-row")[1]).toHaveAttribute("aria-current", "true");
    });
    fire("x");
    await waitFor(() => {
      expect(screen.getAllByRole("checkbox")[2]).toBeChecked();
    });
    fire("a");
    await waitFor(() => {
      expect(bulkTransitionMock).toHaveBeenCalledWith(
        expect.objectContaining({ finding_ids: ["b"], action: "accept" }),
      );
    });
    fire("Enter");
    expect(await screen.findByRole("complementary", { name: "Finding detail" })).toBeInTheDocument();
    fire("Escape");
    await waitFor(() => {
      expect(screen.queryByRole("complementary", { name: "Finding detail" })).not.toBeInTheDocument();
    });
    fire("?");
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });

  it("sends the selected findings as one bulk request", async () => {
    const rows = [makeFinding({ id: "a" }), makeFinding({ id: "b", start_line: 7 })];
    listFindingsMock.mockResolvedValue(page(rows));
    const user = userEvent.setup();
    renderApp();
    await screen.findAllByTestId("finding-row");

    await user.click(screen.getByLabelText("Select all visible findings"));
    await user.click(screen.getByRole("button", { name: "Mute" }));

    await waitFor(() => {
      expect(bulkTransitionMock).toHaveBeenCalledTimes(1);
    });
    expect(bulkTransitionMock).toHaveBeenCalledWith({
      finding_ids: ["a", "b"],
      action: "mute",
      assignee_user_id: undefined,
    });
  });

  it("rolls back an optimistic update when the server returns 500", async () => {
    const row = makeFinding();
    listFindingsMock.mockResolvedValue(page([row]));
    let rejectRequest: (error: Error) => void = () => undefined;
    bulkTransitionMock.mockImplementation(
      () =>
        new Promise((_resolve, reject) => {
          rejectRequest = reject;
        }),
    );
    const user = userEvent.setup();
    renderApp();
    await screen.findAllByTestId("finding-row");

    await user.click(screen.getByLabelText("Select all visible findings"));
    await user.click(screen.getByRole("button", { name: "Accept" }));

    await waitFor(() => {
      expect(screen.getByText("accepted")).toBeInTheDocument();
    });
    rejectRequest(new Error("Request failed with 500"));

    await waitFor(() => {
      expect(screen.getByText("open")).toBeInTheDocument();
    });
    expect(await screen.findByTestId("toast")).toHaveTextContent("accept failed");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("distinguishes no findings from no filter matches", async () => {
    listFindingsMock.mockResolvedValue(page([]));
    const user = userEvent.setup();
    renderApp();

    expect(await screen.findByText("No findings yet")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Search"), "eval");
    expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  });

  it("shows an error state with a working retry", async () => {
    listFindingsMock.mockRejectedValueOnce(new Error("backend down"));
    listFindingsMock.mockResolvedValueOnce(page([makeFinding()]));
    const user = userEvent.setup();
    renderApp();

    expect(await screen.findByRole("alert")).toHaveTextContent("backend down");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Avoid eval() on untrusted input")).toBeInTheDocument();
  });
});
