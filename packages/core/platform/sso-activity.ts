/** Reports actual browser input without letting background traffic renew SSO idle time. */
export function watchSSOActivity(
  send: () => Promise<unknown>,
  isAuthenticated: () => boolean,
  now: () => number = Date.now,
): () => void {
  if (typeof window === "undefined") return () => {};
  let lastSentAt = Number.NEGATIVE_INFINITY;
  let pending = false;
  const onInput = () => {
    if (!isAuthenticated() || pending) return;
    const sentAt = now();
    if (sentAt - lastSentAt < 60_000) return;
    lastSentAt = sentAt;
    pending = true;
    void send()
      .catch(() => undefined)
      .finally(() => {
        pending = false;
      });
  };
  window.addEventListener("pointerdown", onInput, { passive: true });
  window.addEventListener("keydown", onInput, { passive: true });
  return () => {
    window.removeEventListener("pointerdown", onInput);
    window.removeEventListener("keydown", onInput);
  };
}
