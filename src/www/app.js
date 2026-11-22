/* Dentrado frontend (vanilla). "Lives its own life": the whole
 * shell is cached by the service worker; all state lives in IndexedDB.
 *
 * Session model: the browser generates a P-256 keypair (the private
 * half — a non-extractable CryptoKey), passes WebAuthn and gets a cert
 * {jti, exp}. Every authorized request is signed by the session
 * key (x-jti/x-ts/x-sig over path‖ts‖body) — no cookies, no CSRF.
 *
 * The server's canonical wire codec repeated in js (DataView, LE):
 * u8 ‖ u64(len)+bytes — see wire.rs.
 *
 * UI: icons come from the /icons.svg sprite (Lucide, ISC); screens
 * are rendered into #app by the hash router at the bottom. */

"use strict";

// ---------------------------------------------------------------- b64u

const b64u = (bytes) => {
  let s = "";
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

// ---------------------------------------------------------------- wire codec

function encBegin() {
  const chunks = [];
  return {
    u8(v) {
      chunks.push(Uint8Array.of(v));
    },
    u64(v) {
      const b = new ArrayBuffer(8);
      new DataView(b).setBigUint64(0, BigInt(v), true);
      chunks.push(new Uint8Array(b));
    },
    str(s) {
      this.bytes(new TextEncoder().encode(s));
    },
    bytes(b) {
      this.u64(b.length);
      chunks.push(b);
    },
    raw(b) {
      chunks.push(b);
    },
    out() {
      const len = chunks.reduce((a, x) => a + x.length, 0);
      const o = new Uint8Array(len);
      let p = 0;
      for (const x of chunks) {
        o.set(x, p);
        p += x.length;
      }
      return o;
    },
  };
}
const V = 7;
const msgRequest = (method, path, ts, body) => {
  const e = encBegin();
  e.u8(V);
  e.str("request");
  e.str(method);
  e.str(path);
  e.u64(ts);
  e.bytes(body);
  return e.out();
};
const msgPop = (kind, challenge, pk) => {
  const e = encBegin();
  e.u8(V);
  e.str(kind);
  e.str(challenge);
  e.raw(pk);
  return e.out();
};
const msgOneshot = (attBytes, nonce) => {
  const e = encBegin();
  e.u8(V);
  e.str("oneshot");
  e.bytes(attBytes);
  e.raw(nonce);
  return e.out();
};
const encOneshot = (attBytes, nonce, sig) => {
  const e = encBegin();
  e.u8(V);
  e.bytes(attBytes);
  e.raw(nonce);
  e.raw(sig);
  return e.out();
};

// ---------------------------------------------------------------- IndexedDB

function idb() {
  return new Promise((res, rej) => {
    const q = indexedDB.open("dentrado-is", 1);
    q.onupgradeneeded = () => q.result.createObjectStore("kv");
    q.onsuccess = () => res(q.result);
    q.onerror = () => rej(q.error);
  });
}
async function idbGet(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv").objectStore("kv").get(k);
    t.onsuccess = () => res(t.result);
    t.onerror = () => rej(t.error);
  });
}
async function idbSet(k, v) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readwrite").objectStore("kv").put(v, k);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}
async function idbDel(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction("kv", "readwrite").objectStore("kv").delete(k);
    t.onsuccess = () => res();
    t.onerror = () => rej(t.error);
  });
}

const SESSIONS = "sessions";
const ACTIVE = "activeProfile";
// Per-profile, purely local UI hint: "a passkey has been used/added for
// this profile in this browser". It never proves which credential lives
// here (hybrid login exists) and is never sent to the server.
const HAS_PASSKEY = "hasPasskey";

// Sessions are kept as a LIST keyed by account_pk, so the browser can
// hold several signed-in profiles at once and switch between them
// without another passkey ceremony.
async function loadSessions() {
  let list = await idbGet(SESSIONS);
  if (!Array.isArray(list)) list = [];
  const live = list.filter((s) => s.exp * 1000 >= Date.now() + 60_000);
  if (live.length !== list.length) await idbSet(SESSIONS, live);
  return live;
}

async function getActiveSession() {
  const list = await loadSessions();
  if (!list.length) {
    await idbDel(ACTIVE);
    return null;
  }
  const activePk = await idbGet(ACTIVE);
  const active = list.find((s) => s.account?.account_pk === activePk) ?? list[0];
  if (active.account?.account_pk !== activePk) {
    await idbSet(ACTIVE, active.account?.account_pk ?? null);
  }
  return active;
}

async function setActiveSession(pk) {
  await idbSet(ACTIVE, pk);
}

async function removeSession(pk) {
  const list = await loadSessions();
  const next = list.filter((s) => s.account?.account_pk !== pk);
  await idbSet(SESSIONS, next);
  const activePk = await idbGet(ACTIVE);
  if (activePk === pk) await idbSet(ACTIVE, next[0]?.account?.account_pk ?? null);
}

// The dashboard only needs a coarse, local hint: did this browser ever
// sign in with (or add) a passkey for the profile? If not — e.g. it
// joined via a connect code — we show the "add a passkey" banner.
async function getPasskeyFlags() {
  return (await idbGet(HAS_PASSKEY)) ?? {};
}
async function setHasPasskey(pk, on) {
  const flags = await getPasskeyFlags();
  if (on) flags[pk] = true;
  else delete flags[pk];
  await idbSet(HAS_PASSKEY, flags);
}
async function hasPasskeyFor(pk) {
  const flags = await getPasskeyFlags();
  return flags[pk] === true;
}

// ---------------------------------------------------------------- crypto & webauthn

async function newSessionKey() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // non-extractable: the private half never leaves the browser
    ["sign", "verify"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { key: kp.privateKey, pk: raw.slice(1) }; // 04‖x‖y → x‖y (64B)
}
const signMsg = (key, msg) =>
  crypto.subtle
    .sign({ name: "ECDSA", hash: "SHA-256" }, key, msg)
    .then((s) => new Uint8Array(s));

// begin responses arrive as parsed JSON: {challenge, options{…}} —
// only the b64u fields inside need decoding
const createOptions = (o) => {
  o.challenge = unb64u(o.challenge);
  for (const c of o.excludeCredentials ?? []) c.id = unb64u(c.id);
  o.user.id = unb64u(o.user.id);
  return o;
};
const getOptions = (o) => {
  o.challenge = unb64u(o.challenge);
  for (const c of o.allowCredentials ?? []) c.id = unb64u(c.id);
  return o;
};
const serializeCreate = (cred) => ({
  id: cred.id,
  rawId: b64u(new Uint8Array(cred.rawId)),
  type: cred.type,
  ua: navigator.userAgent,
  response: {
    clientDataJSON: b64u(new Uint8Array(cred.response.clientDataJSON)),
    attestationObject: b64u(new Uint8Array(cred.response.attestationObject)),
  },
});
const serializeGet = (cred) => ({
  id: cred.id,
  rawId: b64u(new Uint8Array(cred.rawId)),
  type: cred.type,
  response: {
    clientDataJSON: b64u(new Uint8Array(cred.response.clientDataJSON)),
    authenticatorData: b64u(new Uint8Array(cred.response.authenticatorData)),
    signature: b64u(new Uint8Array(cred.response.signature)),
    userHandle: cred.response.userHandle ? b64u(new Uint8Array(cred.response.userHandle)) : null,
  },
});

// ---------------------------------------------------------------- API

async function handle(resp) {
  const j = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(j.error || `HTTP ${resp.status}`);
  return j;
}
const api = (path, body) =>
  fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  }).then(handle);

async function authedApiFor(s, path, body) {
  const bodyBytes = new TextEncoder().encode(JSON.stringify(body ?? {}));
  const ts = Math.floor(Date.now() / 1000);
  const sig = await signMsg(s.key, msgRequest("POST", path, ts, bodyBytes));
  return fetch(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-jti": s.jti,
      "x-ts": String(ts),
      "x-sig": b64u(sig),
    },
    body: bodyBytes,
  }).then(handle);
}

async function authedApi(path, body) {
  const s = await getActiveSession();
  if (!s) {
    go("#/login");
    throw new Error("no session — please sign in again");
  }
  return authedApiFor(s, path, body);
}

// The finish body: the session key's PoP over (kind ‖ challenge ‖ pk),
// with the authenticator response MERGED at the top level — the server
// reads response.clientDataJSON directly (see passkey.rs wa_parse and
// the tests' attestation_json merge).
async function finishBody(kind, challenge, key, pk, credential) {
  const sig = await signMsg(key, msgPop(kind, challenge, pk));
  return { challenge, session_pk: b64u(pk), pop: b64u(sig), ...credential };
}

async function saveSession(j, key) {
  const list = await loadSessions();
  const pk = j.account.account_pk;
  const next = list.filter((s) => s.account?.account_pk !== pk);
  next.push({
    key,
    jti: j.jti,
    exp: j.exp,
    cert: j.cert,
    account: j.account,
  });
  await idbSet(SESSIONS, next);
  await idbSet(ACTIVE, pk);
  await refreshProfileMenu();
}

// ---------------------------------------------------------------- ui kit

const app = document.getElementById("app");
const $ = (sel) => app.querySelector(sel);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const render = (html) => {
  app.innerHTML = html;
};

// sprite icon: <svg class="i"><use href="/icons.svg#i-name"/></svg>
const I = (name) => `<svg class="i" aria-hidden="true"><use href="/icons.svg#i-${name}"/></svg>`;

const go = (hash) => {
  location.hash = hash;
};
const fmtDate = (unix) =>
  new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(new Date(unix * 1000));
const shortId = (s) => (s.length > 16 ? `${s.slice(0, 10)}…${s.slice(-6)}` : s);

// A stable hue per key/account: small coloured orbs instead of repeating
// the same key glyph down the page.
const hueOf = (s) => {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 360;
  return h;
};
const profileLabel = (accountPk) => `Profile ${String(accountPk).slice(0, 8)}`;
const fmtExpiry = (exp) => {
  const ms = exp * 1000 - Date.now();
  if (ms <= 0) return "expired";
  const days = Math.floor(ms / 86_400_000);
  if (days >= 1) return `${days} day${days === 1 ? "" : "s"}`;
  const hours = Math.max(1, Math.floor(ms / 3_600_000));
  return `${hours} hour${hours === 1 ? "" : "s"}`;
};

const copyText = (text, msg = "Copied") =>
  navigator.clipboard.writeText(text).then(() => toast(msg, "ok"));

const TOAST_ICON = { ok: "check", err: "circle-alert", info: "" };
function toast(msg, kind = "info") {
  const t = document.getElementById("toast");
  t.dataset.kind = kind;
  t.querySelector(".t-icon").innerHTML = TOAST_ICON[kind] ? I(TOAST_ICON[kind]) : "";
  t.querySelector(".t-msg").textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 4000);
}

// Button busy state: disabled + inline spinner; errors → toast.
const busy = async (btn, f) => {
  btn.disabled = true;
  btn.classList.add("loading");
  try {
    await f();
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
  }
};

// Native confirm() replacement — a styled modal, automation-friendly.
function askConfirm({ title, body, confirm = "Confirm", cancel = "Cancel", danger = false }) {
  return new Promise((res) => {
    const root = document.getElementById("modal-root");
    root.innerHTML = `
      <div class="modal-root" data-overlay>
        <div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}">
          <h3>${esc(title)}</h3>
          <p>${esc(body)}</p>
          <div class="actions">
            <button class="btn btn-ghost" data-cancel>${esc(cancel)}</button>
            <button class="btn ${danger ? "btn-danger" : "btn-primary"}" data-ok>${esc(confirm)}</button>
          </div>
        </div>
      </div>`;
    const done = (v) => {
      root.innerHTML = "";
      document.removeEventListener("keydown", onKey);
      res(v);
    };
    const onKey = (e) => e.key === "Escape" && done(false);
    document.addEventListener("keydown", onKey);
    root.querySelector("[data-overlay]").onclick = (e) => e.target.hasAttribute("data-overlay") && done(false);
    root.querySelector("[data-cancel]").onclick = () => done(false);
    root.querySelector("[data-ok]").onclick = () => done(true);
    root.querySelector("[data-ok]").focus();
  });
}

// Profile switcher: a single global menu (top-right) on every screen.
// Switching only changes which local session key signs requests.
const menuRoot = document.getElementById("account-menu");
const currentPath = () => location.hash.replace(/^#/, "").split("?")[0];

function closeProfileMenu() {
  const pop = menuRoot.querySelector("#profile-menu-pop");
  const backdrop = menuRoot.querySelector("#profile-menu-backdrop");
  const btn = menuRoot.querySelector("#profile-menu-btn");
  if (pop) pop.hidden = true;
  if (backdrop) backdrop.hidden = true;
  if (btn) btn.setAttribute("aria-expanded", "false");
}

async function refreshProfileMenu() {
  const sessions = await loadSessions();
  if (!sessions.length) {
    menuRoot.innerHTML = "";
    menuRoot.hidden = true;
    document.body.classList.remove("has-account-menu");
    return;
  }
  const active = await getActiveSession();
  const activePk = active?.account?.account_pk ?? sessions[0].account?.account_pk ?? "";
  const current = active?.account?.name || profileLabel(activePk);
  const hue = hueOf(active?.account?.account_pk || active?.account?.identity || activePk);
  const items = sessions
    .map((ss) => {
      const pk = ss.account?.account_pk ?? "";
      const name = ss.account?.name || profileLabel(pk);
      const isActive = pk === activePk;
      return `
        <div class="menu-profile${isActive ? " is-active" : ""}">
          <button type="button" class="menu-switch" data-switch="${esc(pk)}"${isActive ? ` aria-current="true"` : ""}>
            <span class="key-orb" style="--hue:${hueOf(pk)}" aria-hidden="true">${esc(String(pk).slice(0, 2))}</span>
            <span class="grow">
              <span class="menu-name">${esc(name)}</span>
              <span class="menu-sub">${isActive ? "Current profile" : "Click to switch"}</span>
            </span>
          </button>
          <button type="button" class="iconbtn menu-signout" data-signout="${esc(pk)}" title="Sign out ${esc(name)}" aria-label="Sign out ${esc(name)}">${I("log-out")}</button>
        </div>`;
    })
    .join("");
  menuRoot.hidden = false;
  document.body.classList.add("has-account-menu");
  menuRoot.innerHTML = `
    <div class="profile-menu">
      <button id="profile-menu-btn" class="profile-menu-btn" aria-haspopup="menu" aria-expanded="false">
        <span class="avatar mini" style="--hue:${hue}" aria-hidden="true">${esc(String(activePk).slice(0, 2))}</span>
        <span class="menu-current">${esc(current)}</span>
        ${I("chevron-down")}
      </button>
      <div id="profile-menu-backdrop" class="menu-backdrop" hidden></div>
      <div id="profile-menu-pop" class="menu-pop" role="menu" hidden>
        <div class="menu-head">Profiles</div>
        ${items}
        <div class="menu-sep"></div>
        <button type="button" class="menu-action" data-new>${I("plus")} New</button>
      </div>
    </div>`;

  const btn = menuRoot.querySelector("#profile-menu-btn");
  const pop = menuRoot.querySelector("#profile-menu-pop");
  const backdrop = menuRoot.querySelector("#profile-menu-backdrop");
  const setOpen = (open) => {
    pop.hidden = !open;
    backdrop.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
  };
  btn.onclick = () => setOpen(pop.hidden);
  backdrop.onclick = () => setOpen(false);
  menuRoot.querySelectorAll("[data-switch]").forEach((b) => {
    b.onclick = () => switchProfile(b.dataset.switch);
  });
  menuRoot.querySelectorAll("[data-signout]").forEach((b) => {
    b.onclick = () => signOutProfile(b.dataset.signout);
  });
  menuRoot.querySelector("[data-new]").onclick = () => {
    closeProfileMenu();
    go("#/login");
  };
}

async function switchProfile(pk) {
  closeProfileMenu();
  const active = await getActiveSession();
  const same = active?.account?.account_pk === pk;
  if (!same) {
    await setActiveSession(pk);
    await refreshProfileMenu();
    toast("Profile switched", "ok");
  }
  const path = currentPath();
  if (path === "/dashboard" || path === "/authorize" || path === "" || path === "/") {
    if (!same) route();
  } else {
    go("#/dashboard");
  }
}

async function signOutProfile(pk) {
  closeProfileMenu();
  const active = await getActiveSession();
  const wasActive = active?.account?.account_pk === pk;
  const list = await loadSessions();
  const target = list.find((ss) => ss.account?.account_pk === pk);
  if (target) {
    try {
      await authedApiFor(target, "/logout", {});
    } catch {
      // the session may already be gone; local removal is what matters
    }
    await removeSession(pk);
  }
  await refreshProfileMenu();
  const rest = await loadSessions();
  if (!rest.length) {
    go("#/login");
    toast("Signed out", "ok");
    return;
  }
  const path = currentPath();
  if (path !== "/login" && path !== "/register" && path !== "/enroll") route();
  toast(wasActive ? "Signed out; switched to another profile" : "Profile signed out", "ok");
}

// ---------------------------------------------------------------- views

function viewLogin(params = new URLSearchParams()) {
  const rawNext = params.get("next") || "";
  const next = rawNext.startsWith("#/") ? rawNext : "#/dashboard";
  render(`
    <div class="auth">
      <div class="auth-card">
        <h1>Sign into the Dentrado net</h1>
        <button id="login" class="btn btn-primary btn-lg btn-block"><span class="btn-glyph">${I("fingerprint")}</span> Sign in with a passkey</button>
        <p class="hint">No, passkeys aren't scary, I swear</p>
      </div>
      <div class="alt-links">
        <a href="#/register">${I("user-round-plus")} Sign up a new profile </a>
        <span class="dot">·</span>
        <a href="#/enroll">${I("ticket")} Connect to a session on another device </a>
      </div>
    </div>`);
  $("#login").onclick = (e) =>
    busy(e.currentTarget, async () => {
      const { challenge, options } = await api("/webauthn/login/begin");
      const cred = await navigator.credentials.get({ publicKey: getOptions(options) });
      const s = await newSessionKey();
      const body = await finishBody("login-pop", challenge, s.key, s.pk, serializeGet(cred));
      const j = await api("/webauthn/login/finish", body);
      await saveSession(j, s.key);
      await setHasPasskey(j.account.account_pk, true);
      go(next);
    });
}

function viewRegister() {
  render(`
    <div class="auth">
      <div class="auth-card">
        <h1>Sign up</h1>
        <p class="lead">One click away. Deeper verification (such as email) might be requested later</p>
        <label for="profile-name">Profile name <span class="muted">(optional)</span></label>
        <input id="profile-name" maxlength="64" placeholder="e.g. Primary" autocomplete="nickname" spellcheck="false">
        <p class="hint">Profile name is NOT your username, it's a private tag that is meant to help you distinguish your profiles</p>
        <button id="reg" class="btn btn-primary btn-lg btn-block"><span class="btn-glyph">${I("key-round")}</span> Create a passkey &amp; a profile</button>
      </div>
      <div class="alt-links">
        <a href="#/login">${I("arrow-left")} I already have a profile</a>
      </div>
    </div>`);
  $("#reg").onclick = (e) =>
    busy(e.currentTarget, async () => {
      const name = $("#profile-name").value.trim();
      const { challenge, options } = await api("/webauthn/register/begin", { name });
      const cred = await navigator.credentials.create({ publicKey: createOptions(options) });
      const s = await newSessionKey();
      const body = await finishBody("register-pop", challenge, s.key, s.pk, serializeCreate(cred));
      const j = await api("/webauthn/register/finish", body);
      await saveSession(j, s.key);
      await setHasPasskey(j.account.account_pk, true);
      go("#/dashboard");
    });
}

function viewEnroll(params) {
  render(`
    <div class="auth">
      <div class="auth-card">
        <span class="eyebrow">New device</span>
        <h1>Connect a device</h1>
        <p class="lead">Go to the dashboard of your existing sign-in, generate a one-time key and paste it here</p>
        <label for="words">Code (12 words)</label>
        <textarea id="words" rows="3" placeholder="twelve words, separated by spaces" spellcheck="false" autocomplete="off"></textarea>
        <button id="enroll" class="btn btn-primary btn-lg btn-block">Connect this device</button>
        <p class="hint">The code is ONE-TIME only. Add a passkey on this device later via the dashboard.</p>
      </div>
      <div class="alt-links">
        <a href="#/login">${I("arrow-left")} Back to sign in</a>
      </div>
    </div>`);
  if (params.get("code")) $("#words").value = params.get("code");
  $("#enroll").onclick = (e) =>
    busy(e.currentTarget, async () => {
      const words = $("#words").value.trim().replace(/\s+/g, " ").toLowerCase();
      const { challenge } = await api("/connect/enroll/begin", { words });
      const s = await newSessionKey();
      const body = await finishBody("enroll-pop", challenge, s.key, s.pk, {});
      const j = await api("/connect/enroll/finish", body);
      await saveSession(j, s.key);
      go("#/dashboard");
    });
}

async function viewDashboard() {
  render(`<div class="page"><div class="loading-block"><span class="spin"></span> Loading account…</div></div>`);
  let a;
  try {
    a = await authedApi("/account", {});
  } catch (e) {
    render(`
      <div class="auth">
        <div class="auth-card">
          <h1>Session unavailable</h1>
          <div class="banner">${esc(e.message)}</div>
          <a class="btn btn-primary btn-lg btn-block" href="#/login" style="margin-top:1rem">Sign in</a>
        </div>
      </div>`);
    return;
  }
  const s = await getActiveSession();
  if (!s) {
    go("#/login");
    return;
  }
  const sessions = await loadSessions();
  const hasPasskey = await hasPasskeyFor(a.account_pk);
  const profile = a.name || profileLabel(a.account_pk);
  const hue = hueOf(a.account_pk || a.identity);

  const creds = a.creds
    .map((c, i) => {
      // The first credential is the account's root: it can never be
      // unlinked, so no button is shown for it.
      const canUnlink = i > 0;
      const ua = c.ua
        ? `<div class="sub ua" title="${esc(c.ua)}">${esc(c.ua)}</div>`
        : "";
      return `
      <div class="item">
        <span class="key-orb" style="--hue:${hueOf(c.id)}" aria-hidden="true">${esc(c.id.slice(0, 2))}</span>
        <div class="grow">
          <div class="mono" title="${esc(c.id)}">${esc(shortId(c.id))}</div>
          <div class="sub">Added ${fmtDate(c.added_at)}</div>
          ${ua}
        </div>
        <div class="item-actions">
          ${
            canUnlink
              ? `<button class="link-danger" data-drop="${esc(c.id)}" title="Unlink this passkey">Unlink</button>`
              : `<span class="badge subtle" title="The first passkey can never be unlinked">Primary</span>`
          }
        </div>
      </div>`;
    })
    .join("");

  // The banner is purely local: it appears until THIS browser has used
  // or added a passkey for the profile. It says nothing about which
  // credential is where (hybrid login makes that unknowable).
  const linkNotice = hasPasskey
    ? ""
    : `<div class="banner warn" role="status">${I("circle-alert")}<span>You've logged in via one-time code. Add a passkey on this device.</span></div>`;

  const addBlock = `
    <div class="section-foot">
      <p class="muted small">${
        hasPasskey
          ? "You've already logged in via passkey on this device, but you can add another one."
          : "Sign in here next time without reaching for another device."
      }</p>
      <button id="add-cred" class="btn btn-ghost${hasPasskey ? " is-muted" : ""}">${I("plus")} Add a passkey for this device</button>
    </div>`;

  render(`
    <div class="page">
      ${linkNotice}
      <div class="profile-card">
        <span class="avatar" style="--hue:${hue}" aria-hidden="true">${esc(String(a.account_pk).slice(0, 2))}</span>
        <div class="grow">
          <span class="eyebrow">Profile</span>
          <h1 class="profile-name">${esc(profile)}</h1>
          <div class="id-line">
            <code title="${esc(a.identity)}">${esc(a.identity)}</code>
            <button class="iconbtn" id="copy-id" title="Copy identity" aria-label="Copy identity">${I("copy")}</button>
          </div>
        </div>
      </div>

      <div class="stats">
        <span class="stat"><strong>${a.creds.length}</strong> passkey${a.creds.length === 1 ? "" : "s"}</span>
        <span class="stat"><strong>${fmtExpiry(s.exp)}</strong> left in this session</span>
      </div>

      <section class="section">
        <div class="section-head">
          <h2>${I("key-round")} Passkeys</h2>
          <span class="count">${a.creds.length}</span>
        </div>
        <div class="card list">${creds}</div>
        ${addBlock}
      </section>

      <section class="section">
        <div class="section-head"><h2>${I("ticket")} Add a device</h2></div>
        <div class="card">
          <p class="muted small">Generates a 12-word code so that another device can sign in to this profile; add a passkey there when convenient.
          Don't share with strangers.</p>
          <div class="section-foot">
            <p class="muted small">The code is valid for a few minutes.</p>
            <button id="connect" class="btn btn-ghost">Issue a one-time connect code</button>
          </div>
          <div id="code-out"></div>
        </div>
      </section>

      <section class="section">
        <div class="section-head"><h2>${I("server")} Profile home</h2></div>
        <div class="card">
          <p class="muted small">The Dentrado instance that stores your profile details.</p>
          <div class="bio-line">
            <span class="bio-scheme">https://</span>
            <input id="bio" value="${esc((a.bio_homeserver || "").replace(/^https?:\/\//i, ""))}" placeholder="dentrado.example" spellcheck="false" autocomplete="off" readonly>
            <span class="bio-actions" id="bio-actions">
              <button type="button" class="iconbtn" id="bio-edit" title="Edit profile home" aria-label="Edit profile home">${I("pencil")}</button>
            </span>
          </div>
        </div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Session</h2></div>
        <div class="card">
          <p class="small">This browser holds ${sessions.length} signed-in profile${sessions.length === 1 ? "" : "s"}.</p>
          <p class="muted small">The active session expires ${fmtDate(s.exp)}. Use the profile menu above to switch or sign out.</p>
        </div>
      </section>
    </div>`);

  $("#copy-id").onclick = () => copyText(a.identity, "Identity copied");

  const addBtn = $("#add-cred");
  if (addBtn)
    addBtn.onclick = (e) =>
      busy(e.currentTarget, async () => {
        const { challenge, options } = await authedApi("/cred/add/begin");
        const cred = await navigator.credentials.create({ publicKey: createOptions(options) });
        await authedApi("/cred/add/finish", { challenge, ...serializeCreate(cred) });
        await setHasPasskey(a.account_pk, true);
        toast("Passkey added", "ok");
        viewDashboard();
      });

  app.querySelectorAll("[data-drop]").forEach((b) => {
    b.onclick = () =>
      busy(b, async () => {
        const id = b.dataset.drop;
        const ok = await askConfirm({
          title: "Unlink this passkey?",
          body: `${shortId(id)} will no longer be able to sign in to this profile. Older passkeys keep working.`,
          confirm: "Unlink",
          danger: true,
        });
        if (!ok) return;
        // Ordered step-up: the server offers ONLY older credentials in
        // the allowList and re-checks the ordering at finish.
        const { challenge, options } = await authedApi("/cred/drop/begin", { id });
        const assertion = await navigator.credentials.get({ publicKey: getOptions(options) });
        await authedApi("/cred/drop/finish", {
          challenge,
          response: serializeGet(assertion),
        });
        toast("Passkey unlinked", "ok");
        viewDashboard();
      });
  });

  $("#connect").onclick = (e) =>
    busy(e.currentTarget, async () => {
      const { challenge, options } = await authedApi("/connect/start");
      const cred = await navigator.credentials.get({ publicKey: getOptions(options) });
      // NB: unlike the *finish endpoints, /connect/finish keeps the
      // authenticator response NESTED — the route unwraps "response"
      // itself and verifies it (route.rs: connect_step_finish).
      const { words, expires } = await authedApi("/connect/finish", {
        challenge,
        response: serializeGet(cred),
      });
      const chips = words
        .split(/\s+/)
        .map(
          (w, i) =>
            `<span class="word"><span class="word-n">${i + 1}</span>${esc(w)}</span>`,
        )
        .join("");
      $("#code-out").innerHTML = `
        <div class="code-out">
          <p class="muted small">One-time, valid until ${fmtDate(expires)}.</p>
          <div class="words-grid" aria-label="Connect code">${chips}</div>
          <button id="copy" class="btn btn-ghost">Copy code</button>
        </div>`;
      $("#copy").onclick = () => copyText(words, "Code copied");
    });

  const bioInput = $("#bio");
  const bioActions = $("#bio-actions");
  const bioInitial = bioInput.value;
  const setBioEditing = (on) => {
    bioInput.readOnly = !on;
    bioInput.classList.toggle("is-editing", on);
    bioActions.innerHTML = on
      ? `<button type="button" class="iconbtn" id="bio-cancel" title="Cancel" aria-label="Cancel">${I("x")}</button>
         <button type="button" class="iconbtn" id="bio-save" title="Save" aria-label="Save">${I("check")}</button>`
      : `<button type="button" class="iconbtn" id="bio-edit" title="Edit profile home" aria-label="Edit profile home">${I("pencil")}</button>`;
    if (on) bioInput.focus();
    else bioInput.value = bioInitial;
  };
  bioActions.onclick = (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (b.id === "bio-edit") return setBioEditing(true);
    if (b.id === "bio-cancel") return setBioEditing(false);
    if (b.id === "bio-save")
      busy(b, async () => {
        const raw = bioInput.value
          .trim()
          .replace(/^https?:\/\//i, "")
          .replace(/\/+$/, "");
        await authedApi("/account", { bio_homeserver: raw ? `https://${raw}` : null });
        toast("Profile home saved", "ok");
        viewDashboard();
      });
  };
}

// The only place an attestation may land on the relying party's
// origin. The RP reserves this path; it must serve its OWN code there
// — never user content and never a redirect off-origin.
const CALLBACK_PATH = "/.well-known/dentrado/callback";

async function viewAuthorize(params) {
  const audRaw = params.get("aud");
  const nonce = params.get("nonce");
  const callbackParam = params.get("callback");
  const bad = (why) =>
    render(`
      <div class="auth">
        <div class="auth-card">
          <h1>Authorization</h1>
          <div class="banner">${esc(why)}</div>
        </div>
      </div>`);
  if (!audRaw || !nonce)
    return bad("incomplete link: aud and nonce are required");

  // `aud` is a BARE ORIGIN. If a path were allowed here, the caller
  // would choose WHICH PAGE on that origin receives the token — a wiki
  // page or an open redirect could then read the fragment and forward
  // it. The origin is also displayed verbatim, so it must be canonical.
  let audUrl;
  try {
    audUrl = new URL(audRaw);
  } catch {
    return bad("aud must be an absolute http(s) origin");
  }
  if (audUrl.protocol !== "https:" && audUrl.protocol !== "http:")
    return bad("aud must be an http(s) origin");
  if (audUrl.origin !== audRaw)
    return bad(
      `aud must be a bare origin: send ${audUrl.origin} — ` +
        "without a path, query, fragment, userinfo or default port",
    );
  const aud = audUrl.origin;
  const audDisplay = aud.startsWith("https://") ? aud.substring(8) : aud;

  // The RP never picks the landing page. A caller-supplied callback is
  // accepted only when it is exactly the derived well-known endpoint;
  // anything else is refused rather than silently ignored.
  const callback = new URL(CALLBACK_PATH, audUrl).href;
  if (callbackParam && callbackParam !== callback)
    return bad(
      `the callback is fixed at ${callback}: ` +
        "a custom path could be user content that forwards the token",
    );

  // TODO: `cancel` kinda barely makes any sense right now.

  render(`
    <div class="auth">
      <div class="auth-card">
        <span class="eyebrow">Sign-in request</span>
        <h1>Authorize ${esc(audDisplay)}?</h1>
        <p class="lead"><code>${esc(audDisplay)}</code> asks for a one-time confirmation of
        your Dentrado identity.</p>
        <div class="row auth-actions">
          <button id="deny" class="btn btn-ghost">Cancel</button>
          <button id="allow" class="btn btn-primary">${I("check")} Allow</button>
        </div>
      </div>
    </div>`);
  $("#deny").onclick = () => go("#/dashboard");
  $("#allow").onclick = (e) =>
    busy(e.currentTarget, async () => {
      const s = await getActiveSession();
      if (!s) {
        toast("Sign in to continue", "info");
        go(`#/login?next=${encodeURIComponent(location.hash)}`);
        return;
      }
      const j = await authedApi("/authorize", { aud, nonce });
      const att = unb64u(j.attestation);
      const nb = unb64u(nonce);
      const sig = await signMsg(s.key, msgOneshot(att, nb));
      const oneshot = b64u(encOneshot(att, nb, sig));
      location.href = `${callback}#oneshot=${encodeURIComponent(oneshot)}`;
    });
}

// ---------------------------------------------------------------- router

function route() {
  const [path, qs] = location.hash.replace(/^#/, "").split("?");
  const params = new URLSearchParams(qs || "");
  refreshProfileMenu();
  switch (path) {
    case "/login":
      return viewLogin(params);
    case "/register":
      return viewRegister();
    case "/enroll":
      return viewEnroll(params);
    case "/authorize":
      return viewAuthorize(params);
    default: {
      const goDash = () => {
        getActiveSession().then((s) => (s ? viewDashboard() : viewLogin()));
      };
      if (path === "" || path === "/") return goDash();
      return goDash();
    }
  }
}
window.addEventListener("hashchange", route);
route();

// A new service worker took over → reload the page
// so the shell picks up fresh resources (once, no loops).
let refreshing = false;
navigator.serviceWorker?.addEventListener("controllerchange", () => {
  if (refreshing) return;
  refreshing = true;
  location.reload();
});
