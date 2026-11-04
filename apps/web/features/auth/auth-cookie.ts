const COOKIE_NAME = "multica_logged_in";

export function setLoggedInCookie() {
  document.cookie = `${COOKIE_NAME}=1; path=/; max-age=31536000; samesite=lax`;
  try {
    window.sessionStorage.removeItem("multica_explicit_logout");
  } catch {
    // Browser storage can be unavailable even when cookie auth works.
  }
}

export function clearLoggedInCookie() {
  document.cookie = `${COOKIE_NAME}=; path=/; max-age=0`;
}
