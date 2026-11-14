/** @vitest-environment jsdom */
import { expect, it, vi } from "vitest";
import { watchSSOActivity } from "./sso-activity";

it("reports authenticated user input once per minute without counting visibility", async () => {
  let now = 0;
  const send = vi.fn().mockResolvedValue(undefined);
  const stop = watchSSOActivity(send, () => true, () => now);
  window.dispatchEvent(new Event("pointerdown"));
  await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  await new Promise((resolve) => setTimeout(resolve, 0));
  window.dispatchEvent(new Event("keydown"));
  expect(send).toHaveBeenCalledTimes(1);
  document.dispatchEvent(new Event("visibilitychange"));
  expect(send).toHaveBeenCalledTimes(1);
  now = 61_000;
  window.dispatchEvent(new Event("keydown"));
  await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(2));
  stop();
});

it("throttles failed activity reports", async () => {
  let now = 0;
  const send = vi.fn().mockRejectedValue(new Error("SSO unavailable"));
  const stop = watchSSOActivity(send, () => true, () => now);
  window.dispatchEvent(new Event("pointerdown"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  window.dispatchEvent(new Event("pointerdown"));
  expect(send).toHaveBeenCalledTimes(1);
  now = 61_000;
  window.dispatchEvent(new Event("pointerdown"));
  expect(send).toHaveBeenCalledTimes(2);
  stop();
});
