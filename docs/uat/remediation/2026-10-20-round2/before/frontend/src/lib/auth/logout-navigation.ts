/** Complete the browser handoff to the provider's end-session endpoint. */
export function followLogoutRedirect(redirectUrl: string) {
  window.location.replace(redirectUrl);
}
