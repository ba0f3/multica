"use strict";
let csrf = "";
let challenge = "";
let initialization = Promise.resolve();
let expiryTimer;
let generation = 0;
let authenticationBusy = false;
class StaleControlResponse extends Error {}
const el = (id) => document.getElementById(id);
const values = (form) => Object.fromEntries(new FormData(form).entries());
const uuid = (value) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error("Enter a valid ID.");
  return value;
};
const clearSource = () => {
  el("result").textContent = ""; el("identity-list").textContent = ""; el("session").textContent = "";
};
const signedOut = () => {
  generation++;
  csrf = ""; challenge = ""; clearTimeout(expiryTimer);
  el("controls").hidden = true; el("login").hidden = false;
  clearSource();
  el("verify-code").reset(); el("verify-code").hidden = true;
};
const current = (epoch) => { if (epoch !== generation) throw new StaleControlResponse(); };
async function request(path, method = "GET", body, workspace, epoch = generation, proof = csrf) {
  current(epoch);
  if (path.startsWith("/api/") && !csrf) throw new StaleControlResponse();
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = proof;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (workspace) headers["X-Workspace-ID"] = uuid(workspace);
  const response = await fetch(path, { method, headers, credentials: "same-origin", cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body) });
  current(epoch);
  if (!response.ok) {
    if (response.status === 401 && !(method === "POST" && path === "/auth/session")) signedOut();
    throw new Error(response.status === 401 ? "Sign in again." : "The request is unavailable.");
  }
  return response;
}
async function json(response, epoch) {
  const body = await response.json();
  current(epoch);
  return body;
}
function showSession(session, epoch) {
  current(epoch);
  generation++;
  const active = generation;
  clearSource();
  csrf = session.csrf_token;
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(() => { if (generation === active) signedOut(); }, Math.max(0, Math.min(900000, Date.parse(session.expires_at) - Date.now())));
  el("login").hidden = true; el("controls").hidden = false;
  el("session").textContent = "Account " + session.user_id + " · expires " + session.expires_at;
  el("verify-code").reset();
}
function bind(id, action) {
  el(id).addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = values(event.currentTarget);
    await initialization;
    const epoch = generation;
    el("message").textContent = "";
    try { await action(input, epoch); }
    catch (error) { if (epoch === generation && !(error instanceof StaleControlResponse)) el("message").textContent = error.message; }
  });
}
async function authenticate(action) {
  if (authenticationBusy) return;
  authenticationBusy = true;
  try { await action(); } finally { authenticationBusy = false; }
}
bind("request-code", (v, epoch) => authenticate(async () => {
  const receipt = await json(await request("/auth/code", "POST", { email: v.email }, undefined, epoch), epoch);
  current(epoch);
  challenge = receipt.challenge_id; el("verify-code").hidden = false;
  el("message").textContent = "If the account is available, a sign-in code has been sent.";
}));
bind("verify-code", (v, epoch) => authenticate(async () => {
  const session = await json(await request("/auth/session", "POST", { challenge_id: challenge, code: v.code }, undefined, epoch), epoch);
  showSession(session, epoch);
}));
el("logout").addEventListener("click", async () => {
  if (authenticationBusy) return;
  authenticationBusy = true;
  const proof = csrf;
  signedOut();
  const epoch = generation;
  try {
    await json(await request("/auth/session", "DELETE", undefined, undefined, epoch, proof), epoch);
    current(epoch);
    el("message").textContent = "Signed out.";
  } catch {
    if (epoch === generation) el("message").textContent = "Displayed data cleared. Server sign-out could not be confirmed.";
  } finally { authenticationBusy = false; }
});
el("identities").addEventListener("click", async () => {
  const epoch = generation;
  try { const profile = await json(await request("/api/me/git-identities", "GET", undefined, undefined, epoch), epoch); current(epoch); el("identity-list").textContent = JSON.stringify(profile, null, 2); }
  catch (error) { if (epoch === generation && !(error instanceof StaleControlResponse)) el("message").textContent = error.message; }
});
async function display(path, method, body, workspace) {
  const epoch = generation;
  const response = await request(path, method, body, workspace, epoch);
  const content = await response.text();
  current(epoch);
  el("result").textContent = content;
}
bind("generate", (v) => display("/api/me/git-identities", "POST", { provider_id: uuid(v.provider_id), request_id: crypto.randomUUID(), consent_project_ids: v.projects.split(",").map((x) => uuid(x.trim())) }));
bind("key-action", (v) => {
  const identity = uuid(v.identity);
  if (v.action === "revoke" || v.action === "cleanup") return display("/api/me/git-identities/" + identity + "/" + v.action, "POST", {});
  if (!/^[1-9][0-9]*$/.test(v.generation)) throw new Error("Enter a valid generation.");
  return display("/api/me/git-identities/" + identity + "/" + v.generation + "/" + v.action, "POST", {});
});
bind("run", (v) => display("/api/me/git-runs", "POST", { agent_id: uuid(v.agent_id), issue_id: uuid(v.issue_id), repository_id: uuid(v.repository_id), operations: ["read"] }, v.workspace));
bind("run-status", (v) => display("/api/me/git-runs/" + uuid(v.context), "GET"));
el("revoke-run").addEventListener("click", async () => {
  const epoch = generation;
  try { await display("/api/me/git-runs/" + uuid(values(el("run-status")).context) + "/revoke", "POST", {}); }
  catch (error) { if (epoch === generation && !(error instanceof StaleControlResponse)) el("message").textContent = error.message; }
});
bind("output", (v) => display("/api/me/git-outputs/" + uuid(v.output), "GET"));
bind("grant", (v) => display("/api/projects/" + uuid(v.project) + "/git-policy/grants", "PUT", { subject_kind: v.subject_kind, subject_id: uuid(v.subject_id), role: v.role }));
initialization = (async () => {
  const epoch = generation;
  try { showSession(await json(await request("/auth/session", "GET", undefined, undefined, epoch), epoch), epoch); }
  catch { if (epoch === generation) signedOut(); }
})();
