// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";
import { setLoggedInCookie } from "./auth-cookie";

describe("setLoggedInCookie", () => {
  beforeEach(() => window.sessionStorage.clear());

  it("clears the explicit logout marker after a new login", () => {
    window.sessionStorage.setItem("multica_explicit_logout", "1");
    setLoggedInCookie();
    expect(window.sessionStorage.getItem("multica_explicit_logout")).toBeNull();
  });
});
