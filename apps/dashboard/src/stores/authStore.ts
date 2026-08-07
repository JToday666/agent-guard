import { defineStore } from "pinia";
import { computed, ref } from "vue";

import type { BrowserSessionDto } from "../api/guard-api-types";
import { getAuthErrorMessage } from "../utils/auth-error-messages";

export const useAuthStore = defineStore("auth", () => {
  const status = ref<"idle" | "loading" | "authenticated" | "error">("idle");
  const csrfToken = ref("");
  const expiresAt = ref<string | null>(null);
  const error = ref<string | null>(null);
  const isAuthenticated = computed(() => status.value === "authenticated");

  function invalidateSession(message: string): void {
    csrfToken.value = "";
    expiresAt.value = null;
    error.value = message;
    status.value = "error";
  }

  async function bootstrap(): Promise<void> {
    if (status.value === "loading" || status.value === "authenticated") return;
    if (import.meta.env.MODE === "mock") {
      csrfToken.value = "mock_csrf";
      expiresAt.value = new Date(Date.now() + 60 * 60_000).toISOString();
      status.value = "authenticated";
      return;
    }

    status.value = "loading";
    error.value = null;
    try {
      const { requestJson } = await import("../api/guard-http-client");
      const url = new URL(window.location.href);
      const launchCode = url.searchParams.get("launch_code");
      const session = launchCode
        ? await requestJson<BrowserSessionDto>("/auth/browser/exchange", {
            method: "POST",
            body: JSON.stringify({ launch_code: launchCode }),
          })
        : await requestJson<BrowserSessionDto>("/auth/browser/me");
      csrfToken.value = session.csrf_token;
      expiresAt.value = session.expires_at;
      status.value = "authenticated";
      if (launchCode) {
        url.searchParams.delete("launch_code");
        window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
      }
    } catch (reason) {
      invalidateSession(getAuthErrorMessage(reason));
    }
  }

  return {
    status,
    csrfToken,
    expiresAt,
    error,
    isAuthenticated,
    invalidateSession,
    bootstrap,
  };
});
