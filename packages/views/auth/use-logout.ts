"use client";

import { useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@multica/core/auth";
import { clearClientSessionData } from "@multica/core/platform";
import { paths } from "@multica/core/paths";
import { useNavigation } from "../navigation";

/**
 * Performs a complete logout: clears per-workspace client storage, legacy
 * cookies, the desktop tab state, the entire React Query cache, the
 * in-memory auth store, and finally navigates to /login. Wraps what was
 * previously duplicated in app-sidebar's logout handler so NoAccessPage's
 * "Sign in as a different user" and any future entry point can use the
 * same flow.
 *
 * Without a unified logout, callers that only do `navigate('/login')`
 * leave the auth cookie + React Query cache + local storage intact —
 * AuthInitializer then silently re-authenticates the user on the login
 * page and redirects them back where they came from.
 */
export function useLogout() {
  const queryClient = useQueryClient();
  const authLogout = useAuthStore((s) => s.logout);
  const { push } = useNavigation();

  return useCallback(() => {
    // Keep an explicit logout from racing the login page's silent SSO effect.
    // The server finishes the Hydra logout after this tab has left the app.
    if (typeof window !== "undefined") {
      try {
        window.sessionStorage.setItem("multica_explicit_logout", "1");
      } catch {
        // The signed_out URL below still guards this navigation.
      }
    }
    // Shared with the session-expiry path, which has to erase exactly the
    // same client-side state — see core's platform/session-cleanup for what
    // and why.
    clearClientSessionData(queryClient);
    authLogout();

    // Navigate to /login explicitly. authLogout() clears state but doesn't
    // move the URL — without this the caller might be on a workspace URL
    // which renders null (layout gates on user) and leaves the user
    // stuck on a blank page.
    push(`${paths.login()}?signed_out=1`);
  }, [queryClient, authLogout, push]);
}
