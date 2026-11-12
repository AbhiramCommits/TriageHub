import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";

import App from "../App";

export function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

export function renderApp(): ReturnType<typeof render> {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <App />
    </QueryClientProvider>,
  );
}

