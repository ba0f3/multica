const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "protected_control.js"), "utf8");
const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function mount(fetch) {
  const elements = new Map();
  const timers = new Map();
  const requests = [];
  let timerID = 0;
  function element(name) {
    if (!elements.has(name)) elements.set(name, {
      hidden: name === "controls" || name === "verify-code",
      textContent: "", values: {}, listeners: {},
      set innerHTML(_) { throw new Error("untrusted HTML insertion"); },
      addEventListener(kind, callback) { this.listeners[kind] = callback; },
      reset() { this.values = {}; },
    });
    return elements.get(name);
  }
  const context = {
    document: {getElementById: element},
    FormData: class { constructor(form) { this.form = form; } entries() { return Object.entries(this.form.values); } },
    fetch: async (route, options) => { requests.push({route, options}); return fetch(route, options); },
    crypto: {randomUUID: () => id},
    Date, Math,
    setTimeout: (callback) => {const key = ++timerID; timers.set(key, callback); return key;},
    clearTimeout: (key) => timers.delete(key),
    get localStorage() { throw new Error("persistent credential/source storage"); },
    get sessionStorage() { throw new Error("persistent credential/source storage"); },
  };
  vm.runInNewContext(source, context);
  const flush = () => new Promise((resolve) => setImmediate(resolve));
  return {
    element, requests, timers, flush,
    async submit(name, values) {const form = element(name); form.values = values; await form.listeners.submit({currentTarget:form, preventDefault(){}});},
    async click(name) { await element(name).listeners.click(); },
  };
}
const response = (status, body) => ({status, ok:status >= 200 && status < 300, json:async () => body, text:async () => typeof body === "string" ? body : JSON.stringify(body)});
const session = () => ({user_id:id, csrf_token:"synthetic-csrf", expires_at:new Date(Date.now()+900000).toISOString()});

test("login, protected source rendering, CSRF and uncertain logout", async () => {
  const malicious = '<img src=x onerror="throw new Error()">';
  const ui = mount(async (route, options) => {
    if (route === "/auth/session" && options.method === "GET") return response(401, {});
    if (route === "/auth/code") return response(202, {challenge_id:id});
    if (route === "/auth/session" && options.method === "POST") return response(200, session());
    if (route === "/auth/session" && options.method === "DELETE") throw new Error("synthetic network failure");
    if (route === "/api/me/git-outputs/"+id) return response(200, malicious);
    throw new Error("unexpected endpoint "+route);
  });
  await ui.flush();
  await ui.submit("request-code", {email:"human@fixture.invalid"});
  assert.equal(ui.element("verify-code").hidden, false);
  await ui.submit("verify-code", {code:"123456"});
  assert.equal(ui.element("controls").hidden, false);
  await ui.submit("output", {output:id});
  assert.equal(ui.element("result").textContent, malicious);
  const request = ui.requests.find((r) => r.route === "/api/me/git-outputs/"+id);
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.headers.Authorization, undefined);
  await ui.click("logout");
  assert.equal(ui.element("result").textContent, "");
  assert.equal(ui.element("controls").hidden, true);
  assert.match(ui.element("message").textContent, /could not be confirmed/);
  const logout = ui.requests.find((r) => r.options.method === "DELETE");
  assert.equal(logout.options.headers["X-CSRF-Token"], "synthetic-csrf");
});

test("initial session discovery cannot erase a newly requested challenge", async () => {
  let release;
  const discovery = new Promise((resolve) => { release = resolve; });
  const ui = mount(async (route) => {
    if (route === "/auth/session") return discovery;
    if (route === "/auth/code") return response(202, {challenge_id:id});
    throw new Error("unexpected endpoint");
  });
  const submission = ui.submit("request-code", {email:"human@fixture.invalid"});
  await ui.flush();
  assert.equal(ui.requests.length, 1);
  release(response(401, {}));
  await submission;
  assert.equal(ui.element("verify-code").hidden, false);
});

test("wrong code permits another attempt and expiry clears displayed source", async () => {
  let attempts = 0;
  const ui = mount(async (route, options) => {
    if (route === "/auth/session" && options.method === "GET") return response(401, {});
    if (route === "/auth/code") return response(202, {challenge_id:id});
    if (route === "/auth/session" && options.method === "POST") return response(++attempts === 1 ? 401 : 200, session());
    throw new Error("unexpected endpoint");
  });
  await ui.flush();
  await ui.submit("request-code", {email:"human@fixture.invalid"});
  await ui.submit("verify-code", {code:"111111"});
  assert.equal(ui.element("verify-code").hidden, false);
  await ui.submit("verify-code", {code:"123456"});
  const logins = ui.requests.filter((r) => r.route === "/auth/session" && r.options.method === "POST");
  assert.equal(JSON.parse(logins[1].options.body).challenge_id, id);
  ui.element("result").textContent = "synthetic stored source";
  assert.equal(ui.timers.size, 1);
  [...ui.timers.values()][0]();
  assert.equal(ui.element("result").textContent, "");
  assert.equal(ui.element("controls").hidden, true);
});

for (const surface of ["output", "identities"]) test("late A "+surface+" body cannot repopulate after B login", async () => {
  let resolveBody;
  const delayed = new Promise((resolve) => {resolveBody = resolve;});
  const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const ui = mount(async (route, options) => {
    if (route === "/auth/session" && options.method === "GET") return response(200, session());
    if (route === "/auth/session" && options.method === "DELETE") return response(200, {});
    if (route === "/auth/code") return response(202, {challenge_id:id});
    if (route === "/auth/session" && options.method === "POST") return response(200, {...session(), user_id:other});
    if (route === "/api/me/git-outputs/"+id) return {ok:true, status:200, text:() => delayed};
    if (route === "/api/me/git-identities") return {ok:true, status:200, json:() => delayed};
    throw new Error("unexpected endpoint "+route);
  });
  await ui.flush();
  const pending = surface === "output" ? ui.submit("output", {output:id}) : ui.click("identities");
  await ui.flush();
  await ui.click("logout");
  await ui.submit("request-code", {email:"other@fixture.invalid"});
  await ui.submit("verify-code", {code:"123456"});
  resolveBody(surface === "output" ? "synthetic A private source" : {identities:["synthetic A private identity"]});
  await pending;
  assert.equal(ui.element("result").textContent, "");
  assert.equal(ui.element("identity-list").textContent, "");
  assert.match(ui.element("session").textContent, new RegExp(other));
});

test("late initial session JSON cannot undo sign-out", async () => {
  let resolveBody;
  const delayed = new Promise((resolve) => {resolveBody = resolve;});
  const ui = mount(async (route, options) => {
    if (options.method === "GET") return {ok:true, status:200, json:() => delayed};
    if (options.method === "DELETE") return response(200, {});
    throw new Error("unexpected endpoint "+route);
  });
  await ui.flush();
  await ui.click("logout");
  resolveBody(session());
  await ui.flush();
  assert.equal(ui.element("controls").hidden, true);
  assert.equal(ui.element("session").textContent, "");
});


test("native form fallback never puts credentials in a GET URL", () => {
  const html = fs.readFileSync(path.join(__dirname, "protected_control.html"), "utf8");
  const forms = [...html.matchAll(/<form\b[^>]*>/gi)];
  assert.ok(forms.length > 0);
  for (const [tag] of forms) assert.match(tag, /\bmethod="post"/i);
});
