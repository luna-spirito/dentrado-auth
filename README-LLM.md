# auth — the Dentrado identity layer (v7, minimal rewrite)

The Identity Server (IS) at the smallest possible size: **WebAuthn is
the only login method → an account (1 account = 1 profile) → a session
certificate on a client-born key → an attestation for third-party
instances**. Keys: **a root phrase (offline) + ONE non-rotating
signer** — no journals, no EOL; a re-issue is an incident procedure
(a new bundle + restart). The service stores no profile data — one
optional field (bio homeserver). HTTPS lives in the process itself
(rustls); a reverse proxy in front of the service does not exist as a
class. The frontend is vanilla JS under a service worker, living its
own life (fully cached shell).

This is the project's only document. Status marks in section headers:
**[✓] implemented**, **[×] consciously dropped**, **[→] planned**.
The v6 implementation (email/IdP, cookie sessions, events, CRL, the
site validator) lives in `legacy-src/` as history — the current model
is described here.

## 1. [✓] Login model

**Account 1:1 profile.** The service stores only: the account key, the
login methods (WebAuthn creds), the live sessions, an optional
user-facing profile name, and ONE optional field — the bio homeserver
(the URL of the Dentrado instance holding the profile details). The
config default is copied into a new account at creation; clearing the
field leaves it empty (there is no implicit fallback afterwards).
Identity: `@<hex64(account_pk)>@<origin>`, self-certifying.

**WebAuthn** — N creds per account, resident/discoverable, UV always
required; ES256 + Ed25519, attestation none, hand-rolled verification
(no webauthn library). Login passes an empty `allowCredentials`, so the
authenticator shows its account picker; each profile has a stable
`user.id` and a readable `user.name` (the chosen profile name, or
`Profile <hex8>`) to keep multiple profiles distinguishable. Sync
factories sync keys inside their ecosystems; across ecosystems — the
connect code (below).

**The session key is born at the client.** The browser generates a
P-256 keypair (WebCrypto ECDSA, non-extractable), proves possession to
the server with a PoP signature (`msg_pop(kind, challenge,
session_pk)`) in the finish request — and receives a **session
certificate** (7 days). After that, every request carries the
`x-jti`/`x-ts`/`x-sig` headers — the session key's signature over
(method, path, ts, exact body), a 300 s window. **No cookies → no
CSRF**; the body is signed along with the method and path → no replay
between endpoints or methods.

**The session certificate** (`Cert`, the TLS-fullchain model — a
self-contained document): the root-signed header `{root_pk,
authorizer_pk, origin, issued_at}` + the cert part `{session_pk,
account_pk, iat, exp, jti}` + authorizer_sig + account_sig. Not JWT:
a fixed algorithm, no `alg` confusion. The point of the double
signature: a thief with the signer bundle cannot mint certs for OTHER
existing accounts — the account key is needed too, and it lives only
inside an object sealed with the pepper.

**Attestation + oneshot** — authorizing on a third-party instance:

- `POST /authorize {aud, nonce}` (PoP) → an **attestation**: "the
  session key `session_pk` passed WebAuthn for account `account_pk`
  and may speak for it to `aud`". Short-lived (300 s); `aud` binds it
  to one instance — a stolen attestation is useless elsewhere. The
  nonce does not enter the attestation: the session key signs it, and
  the instance itself checks freshness (its own nonce).
- `aud` is a **bare origin** (no path/query/fragment/userinfo). The
  consent screen shows exactly that origin, and the oneshot is
  delivered ONLY to the fixed endpoint
  `https://<aud>/.well-known/dentrado/callback` — there is no
  caller-supplied callback. A custom path would let user content on
  the RP origin (a wiki page, an open redirect) read the fragment and
  forward the token.
- The **oneshot** is assembled by the frontend: the attestation + the
  instance's nonce + the session signature. Client clocks take no part
  in the document — freshness comes only from the attestation (`exp`)
  and the nonce. The instance needs ONE pin: `is_id` travels inside
  the header of every document.
- The relying party calls
  `Oneshot::verify(now, pinned_is_id, aud, nonce)`: it checks the pin
  first (the attestation's root must BE the pinned `is_id` — a foreign
  root can mint self-consistent documents, so nothing else about them
  is even examined), then root → signer → account → session, `exp`,
  the EXACT audience, and the EXACT nonce it issued. It must also bind
  that nonce to the BROWSER that started the flow (a `state` cookie or
  equivalent) and burn it after success: an attacker who starts the
  flow gets a genuine nonce too, so possession of a nonce proves only
  "some browser started a flow", not "this browser consented".

**Connect** — how a new device joins an existing account. A live
session shows a one-time **admission code**; the new device redeems
the code and gives birth to ITS OWN key. Key material never travels:
a key born on someone else's device widens the compromise domain and
kills per-device revocation.

- **The code**: 12 words / 128 bits of entropy + 4 checksum bits (the
  BIP39 ENT/32 rule), TTL 300 s, single-use, RAM-only (never hits
  disk); the pending entry key = sha256(entropy16), the words are
  stored nowhere. The different length (a root phrase has 24 words) is
  structural domain separation: a root phrase cannot be redeemed as a
  code, a code is not a key.
- **Issuance always requires a step-up**: in v7 an account always has
  webauthn, so `POST /connect/start` demands a fresh assertion by one
  of the account's creds (`allowCredentials` = the account's creds, UV
  required). No session is issued — a stolen PoP session is not enough
  to widen the account.
- **Redemption**: `POST /connect/enroll/begin {words}` (no session) →
  a PoP challenge bound to the code's account →
  `POST /connect/enroll/finish`: the code burns, a cert is issued to
  the device's FRESH session key. No passkey ceremony is required: the
  device can add its own passkey from the dashboard later.
- **Burn on a successful finish, not on begin**: a flappy browser does
  not eat the code; a failed enrollment attempt keeps the code alive.
- **Defense-in-depth**: only the PoP session of the same account may
  finish a step-up challenge (another one is refused).

**Credentials are ordered**:

- Credentials are kept in the order they were added; `creds[0]` is the
  account's first key and **can never be unlinked** (it is the root of
  the account's login methods).
- Unlinking a credential requires a step-up by a credential that was
  added **before** it: `POST /cred/drop/begin {id}` returns a challenge
  whose `allowCredentials` contains only older creds, and
  `POST /cred/drop/finish` re-checks the ordering server-side. The
  client's picker is never trusted on its own. Example: with X→Y→Z→W,
  unlinking Z needs X or Y; W is refused.
- Each credential stores an optional client-supplied **User Agent** for
  display in the dashboard. It is a hint, never an authorization input:
  the server keeps no device/session inference ("this device" cannot be
  known when hybrid login is possible).

**Keys and boot**:

- **root** — the offline key, existing only as a 24-word seed phrase
  (`auth root genkey`, the wg genkey convention: stdout = the secret,
  no files, paper/safe). `is_id = pubkey(root)` — the IS identity, the
  only thing instances pin. root ≠ signer, always. Rootkey compromise
  is a catastrophe, resolved by social means (§6); k-of-n — later.
- **signer** — the SINGLE key signing certs and attestations. It does
  not rotate and has no EOL. It lives only in the bundle `[32B seed][
  root-signed Header]` — the server's permanent secret (0400/0600,
  checked at boot), fed at EVERY start; the keys are not in state.redb.
- `auth signer new` issues bundles any number of times: all bundles of
  one root share the is_id, the signer is fresh each time. A re-issue
  is an incident procedure (hygiene), NOT a calendar. `auth init` /
  rotations do not exist: installing an IS = a directory + a bundle +
  a pepper + serve.

## 2. [✓] Storage privacy ("the DB knows the minimum")

Storage — **redb** (single-file ACID, WAL + fsync, page checksums),
schema 1 (pre-release; no migrations — wipe the DB on a schema change).
Two data tables: the kv table (keys
`k = HMAC(pepper, "key-v1/{key}")`, values
`v = seal(KDF(pepper, "value-v1", {key}), value)` — domain separation
of lookup vs encryption) and the `sessions` table (keys
`HMAC(pepper, "session-v1/{hex(jti)}")`). **In v7 there are no
plaintext tables** — profile data does not exist as a class. The
schema lives in ONE module (`src/storage/`: tables, row names, ALL
record types, sealed formats, the vault, the typed read/write
operations) — nowhere else in the tree knows a row name:

| row (table) | body | mode |
|---|---|---|
| `auth/{cred_id}` (kv) | `V1 |` account_key (login cred → account key) | sealed |
| `account/{hex(account_key)}` (kv) | `V1 |` account (keys, creds, name, bio, per-cred UA) | sealed |
| `session-v1/{hex(jti)}` (sessions) | `V1 |` {account_key, session_pk, exact exp} | sealed ‖ coarse EOL (u64, public) |

Every sealed plaintext starts with a **version byte** (`[V:u8][body]`,
all rows V1 while pre-release): a different version is an explicit
error, because there are NO migration arms — the dev database is wiped
on a format change. Not row-versioned: the crypto envelope itself, and
the table set (a table-set change is a new SCHEMA — old databases
refused, pre-release).

**The coarse public EOL.** Next to every sealed session row the
`sessions` table stores a coarse expiry: `(exp/30d + 1)·30d` — month
precision — plus a random +30d jitter, so the public column never
reveals even the month exactly; `coarse > exp` always. It is a GC
hint ONLY: authentication reads the sealed exp (AEAD — a tampered DB
cannot extend a session), and the boot sweep deletes rows whose
coarse EOL has passed. Logout deletes the row; a login writes ONLY
this row (the account row is not rewritten — no races on it).

Registering a new account is atomic: insert-if-absent of the `auth/…`
row (a redb transaction; two registrations of one cred race → one
wins) + the account row. Connect codes, step-up and webauthn
challenges are RAM-only, never on disk.

No keys in the DB: the signer lives in the bundle, the root on paper.
The `pepper` (32 bytes, 0400/0600) lives OUTSIDE the state directory
(serve refuses a pepper inside `--dir`); when absent, serve creates it
with a LOUD warning "if this is not a first boot — STOP, or every
account becomes unlinkable".

Keys are orthogonal to the pepper: a bundle re-issue does not touch
accounts, a lost pepper does not touch keys. A stolen state.redb
without the pepper is noise; a live IS compromise is fatal in any
architecture (§5).

## 3. [✓] Wire format (v7) and API

A strict binary codec (`codec/bin.rs`; the documents in `wire.rs`,
the signer header in `keys/header.rs`): u64 LE, length prefixes,
fixed field order, a version in the first byte, the decoder requires
full consumption (anti-malleability).

```
Header      = v7 | root_pk | authorizer_pk | origin | issued_at | root_sig
Cert        = v7 | header | root_sig | session_pk | account_pk
              | iat | exp | jti | authorizer_sig | account_sig
Attestation = v7 | header | root_sig | session_pk | account_pk
              | aud | iat | exp | authorizer_sig | account_sig
Oneshot     = v7 | attestation | nonce(32) | session_sig   # client-assembled
```

Events (`Event`) and the CRL are cut out — deferred (§9, §10); the
only documents are the cert, the attestation and the client-assembled
oneshot.

API (one origin; all JSON; errors are `{"error":…}`):

```
GET  /keys                        # is_id — the instances' trust line

POST /webauthn/register/begin     # {name?} → {challenge, options}
POST /webauthn/register/finish    # {challenge, session_pk, pop, …webauthn}
                                  # → {cert, jti, exp, account}  (new account)
POST /webauthn/login/begin        # resident creds, empty allowList
POST /webauthn/login/finish       # → {cert, jti, exp, account}

POST /connect/enroll/begin        # {words} → {challenge}; no session, by code
POST /connect/enroll/finish       # {challenge, session_pk, pop} → code burn + cert

# ---- PoP paths (x-jti/x-ts/x-sig) ----
POST /connect/start               # a step-up challenge (allowList = creds)
POST /connect/finish              # assertion → {words, expires}
POST /cred/add/begin|finish       # a new cred for an existing account (+ optional ua)
POST /cred/drop/begin             # {id} → step-up challenge; allowList = OLDER creds
POST /cred/drop/finish            # {challenge, response} → the target is unlinked
POST /authorize                   # {aud, nonce} → {attestation, expires}
POST /account                     # {} read | {bio_homeserver: str|null; empty clears}
POST /logout                      # deletes the session row
```

The PoP middleware: `x-jti` (b64u) + `x-ts` (±300 s) + `x-sig` (b64u
signature by the session key over `msg_request(method, path, ts,
body)`), verified against the `session/{jti}` row. A session is a DB
row, not a cookie.

Frontend (`src/www/`, vanilla JS, embedded via `include_bytes!`): the
shell (index/app.js/style.css/sw.js/icons.svg) is fully cached by the
service worker (cache-first, precached by list; API paths are
network-only) and lives its own life. Dual-theme design system
(system preference + `[data-theme]`), accent from the brand logo;
icons — the Lucide sprite `icons.svg` (ISC, see `icons/LICENSE`);
the logo itself — `logo.svg` (the dntrd keyhole). Hash router: `#/login`,
`#/register`, `#/enroll` (+`?code=` from a link), `#/dashboard`
(passkeys, the connect code with step-up, the bio homeserver), a
global top-right profile dropdown with per-profile sign-out, `#/authorize?aud&nonce` — consent →
attestation → oneshot → redirect to
`https://<aud>/.well-known/dentrado/callback#oneshot=…`. The session
keys + certs of all signed-in profiles live in IndexedDB
(`CryptoKey`, non-extractable), keyed by account public key, with an
active-profile pointer: "Switch profile" changes the active session
locally, "Sign out" deletes only that profile's session. The credential
IDs created by this browser are remembered separately so the dashboard
can mute (but never hide) "add this device" and warn when this browser
is not a sign-in key yet.

## 4. [✓] TLS — in the process itself

`--tls-cert/--tls-key` → in-process rustls (TLS 1.3 + 1.2, the ring
provider), thread-per-connection, no move to async. Motivation: a
reverse proxy in front of the IS is an extra compromise unit whose
pwn = pwn of the session traffic; v7 has none. Without the flags —
plain HTTP for dev/localhost (WebAuthn works on localhost without
TLS). PEM parsing — `rustls-pki-types` (`rustls-pemfile` is
archived, RUSTSEC-2025-0134). There are no cookies — no Secure flags
needed by construction.

## 5. [✓] Theft matrix

| what leaked | what the thief gets | remedy |
|---|---|---|
| the root phrase | everything, forever: mint signers, is_id does not change by itself | **only a new root + a manual re-pin of every instance** (§6); hence the phrase on paper/in a safe, not on disk |
| the bundle (signer seed) | mint certs for **new** accounts (not for existing ones: the account key under the pepper is needed too); **indefinitely** — a re-issue does not kill the old key | §6: a re-issue = hygiene, the cure = a new root |
| the pepper | with state.redb at hand — reading accounts, privacy | restore the pepper from backup; keys untouched |
| state.redb | noise without the pepper | — |
| a session key (x-sig) | requests in the session's name until exp; attestations to aud | `POST /logout` deletes the session row (see §9 — CRL deferred, the cert lives out its exp) |
| a connect code (screen/paper peeked) | ONE redemption within the TTL window: a new session joins the account | single-use + TTL 300 s + 128 bits of entropy + burn on a successful finish; issuing a code — only via a step-up |
| a live IS compromise | fatal in any architecture | stop + re-issue the bundle; accounts survive (same pepper) |

A device's WebAuthn key does not "leak" as a secret: it is not
extractable from the authenticator; the risk is the ecosystem's sync
factory — outside the IS's trust.

## 6. [✓] Incident procedures

**Re-issuing the signer (hygiene)**: `auth signer new --origin …`
under the same root → `serve --bundle` with the new bundle. is_id and
trust lines do not change, accounts and sessions survive, old certs
live out their exp.

**The nuclear runbook (a stolen signer or root phrase).** A key
without EOL is valid forever; the only cure is changing the anchor:

1. `auth root genkey` — a NEW root, a new phrase, into the safe.
2. Manually deliver the new `is_id` to the instances (out of band —
   in person/phone): replacing the pin. The old is_id removed →
   everything under it (the thief's signer included) dies instantly
   and entirely.
3. `auth signer new --origin …` under the new root → the bundle to
   the IS host.
4. `auth serve --bundle …` — the accounts survived (same pepper);
   clients re-mint certs by logging in again.
5. Destroy the old root phrase (assume it was copied, not guessed).

This is an expensive, manual, deliberately inconvenient procedure: it
must NOT be routine. If it became routine — the model is broken.

## 7. [✓] Quick start

```sh
# 1. root (on an offline machine, ONCE per IS; stdout — the seed
#    phrase, the wg genkey convention: it IS the secret)
auth root genkey
#    24 words → paper/safe; no root files exist at all; is_id on stderr
auth root pubkey   # the phrase on stdin → is_id (the "the paper IS
                   # the root the instances pin" cross-check)

# 2. the signer bundle — ALSO on the offline machine: stdin — the
#    words pasted from PAPER (no phrase.txt on any disk; the phrase
#    never travels to the IS host); stdout — the bundle [signer seed
#    + root-signed header], written under umask 077 — the file is
#    born 0600, no "0644 until chmod" window; --origin = the
#    canonical IS origin (host, web_origin and rp_id derive from it)
(umask 077; auth signer new --origin https://auth.example.org \
     > /secure/signer.bin)      # paste the 24 words, Enter, Ctrl-D
auth signer verify < /secure/signer.bin
#    then move ONLY signer.bin to the IS host (usb, or a pipe:
#    auth signer new --origin URL | ssh IS-HOST 'umask 077; cat > signer.bin')
#    and burn the copy on the offline machine afterwards

# 3. the pepper (32 bytes, 0400) — separate media, not the IS disk
#    (serve will create it on first boot — with a LOUD warning)
(umask 077; head -c 32 /dev/urandom > /secure/pepper.bin)

# 4. starting the IS: the bundle is fed at EVERY start; state.redb is
#    created by itself; init/rotate does not exist — a re-issue =
#    a new bundle + restart. --tls-* enables in-process HTTPS (rustls);
#    without them — plain HTTP (fine for localhost: WebAuthn works
#    without TLS there)
auth serve --dir /var/lib/dentrado-auth --bundle /secure/signer.bin \
     --pepper /secure/pepper.bin \
     --listen 127.0.0.1:7001 \
     --tls-cert /secure/fullchain.pem --tls-key /secure/privkey.pem \
     --bio-homeserver https://home.example.org   # opt. value for new accounts

# 5. a browser user: #/register ("create a profile") → a passkey;
#    sign in — #/login. To connect a SECOND device (another ecosystem,
#    air-gap): dashboard → "Connect code" (step-up) → 12 words on the
#    new device at #/enroll (a session, no passkey prompt); add a
#    passkey on that device from its dashboard.
```

**NixOS.** The flake ships a module (`nixosModules.dentrado-auth`,
`nix/module.nix`: a system user, a sandboxed systemd unit — read-only
filesystem except `/var/lib/dentrado-auth`, no capabilities — and an
opt-in firewall port):

```nix
services.dentrado-auth = {
  enable = true;
  bundle  = "/etc/dentrado-auth/signer.bin";    # 0400/0600, owned dentrado-auth
  pepper  = "/etc/dentrado-auth/pepper.bin";    # 0400/0600, owned dentrado-auth
  listen  = "0.0.0.0:7001";
  tlsCert = "/etc/dentrado-auth/fullchain.pem";
  tlsKey  = "/etc/dentrado-auth/privkey.pem";   # 0400/0600, owned dentrado-auth
  openFirewall = true;
};
```

After the first `nixos-rebuild switch` (which creates the
`dentrado-auth` user), chown the three secret files to it and restart:
`chown dentrado-auth:dentrado-auth /etc/dentrado-auth/* && chmod 0400
/etc/dentrado-auth/{signer.bin,pepper.bin,privkey.pem} && systemctl
restart dentrado-auth`.

A third-party Dentrado instance authorizes a user like this: redirect
to `https://auth.example.org/#/authorize?aud=<its origin>&nonce=<fresh>`
— `aud` is a BARE origin and `nonce` is the only parameter (a
`callback` parameter is either absent or must equal the derived
endpoint). The frontend shows the consent screen, fires
`POST /authorize`, assembles the oneshot and delivers it to the FIXED
`https://<aud>/.well-known/dentrado/callback#oneshot=…`. The instance
verifies the oneshot against its pinned `is_id` with
`Oneshot::verify(now, its pinned is_id, its origin, its nonce)` —
the pin first, then root → signer → account → session, four
signatures + `exp` + exact audience + its own nonce — then burns the
nonce. The shell also sends `frame-ancestors
'none'` / `X-Frame-Options: DENY` (no clickjacking of the consent
screen) and `Referrer-Policy: no-referrer`.

**The callback path is a contract, not a check.** The IdP cannot see
what the RP serves at `/.well-known/dentrado/callback`; it can only
refuse every other path. So the audience origin must be an
admin-controlled auth origin, and the RP must:

- serve its own code at `/.well-known/dentrado/callback` — never user
  content, never a redirect off-origin (a wiki page there can read
  `location.hash` and forward the oneshot);
- never use a wiki/user-content origin as `aud`: any page on that
  origin can start the same flow and receive the fragment;
- bind the nonce to the browser that started the flow (HttpOnly
  `state` cookie or equivalent) and burn it after one use;
- never forward the fragment — not to logs, not to another origin.

The browser binding is what stops the forwarding attack: the attacker
can start a flow and get a genuine nonce, but the oneshot is produced
in the VICTIM's browser, which does not carry the attacker's `state`
cookie. Without that binding, a forwarded token is a full login as its
victim. Residual risk: if the RP serves user content on the callback
path, redirects off-origin, or skips the browser binding, no IdP-side
check can save it.

## 8. [✓] Code, tests, dependencies

**Code.** A strict module tower (the map lives in `src/lib.rs`):
every module uses only modules BELOW it — no up-down dependency
zigzags. L0 `crypto` (primitives + the named key types
`SecretKey`/`PublicKey`/`Signature`), L1 `codec/` (bin — the
length-prefixed binary format, json, cbor), L2 `keys/` (mnemonic,
root, signer, `header` — the root-signed signer header), L3 `wire`
(the v7 documents: Cert/Attestation/Oneshot, `SessionPk`, `Jti`), L4
`storage/` (THE state.redb schema: store — tables+transactions,
vault — pepper+seal, records — ALL record types: Account, AuthRef,
SessionRow), L5 `net/` (HTTP/TLS), L6 `server/` (mod —
config/boot/minting, `login` — PoP/certs/attestations, `passkey` —
webauthn ceremonies, `connect` — codes, `route`, `www`), L7
`main.rs` (the CLI). Key material crosses module boundaries only in
named types — a bare `[u8; 32]` at an API answers no question (a
key? a hash? noise?). Fresh keys are born only inside their modules
(`SecretKey::generate`, `root::generate`, the authorizer seed inside
`signer::issue`, `Account::generate`): production code cannot hand
in a chosen seed. Effects — clock, randomness, disk, network — live
only in explicitly marked edges: every module header starts with a
"Pure." or "Edge: …" stamp; the map of effect sources is in
`src/lib.rs`. `unsafe` is forbidden across the crate.

**Tests.** `cargo test` — 95 tests: unit coverage of the cores (wire
v7 + codec strictness, mnemonic 12/24 + domain separation, seal/open,
store schema 1 + insert-if-absent + the sessions table + the boot
sweep, the coarse-EOL invariant, the http parser/limits, vault
guards, row codecs incl. the unknown-version error) +
integration on a synthetic authenticator (genuine
signatures — the checks run at full strength): the webauthn flow
(registration/login, restart survival, a foreign pepper makes accounts
unlinkable, origin/rp/PoP/key-swap/replay/UV negatives, cred add/drop
with ordered unlink authority + the first-cred guard + per-cred UA, the
bio homeserver, logout, session expiry),
the connect flow (step-up always, single-use, burn only on a
successful finish, a foreign authenticator/foreign session refused),
the authorize flow (an honest oneshot verifies — four signatures +
exp, each signature's tampering, nonce/key swap, aud binding, a
foreign IS cut off by the pin), the CLI contract (root genkey/pubkey,
signer new/verify + tampering, serve negatives: the bundle mode,
garbage, a pepper inside the state dir / a wrong size / a wide mode,
boot + `GET /keys` on a live socket). `cargo clippy --all-targets` —
0; `cargo deny check` — green (pre-commit + CI).

**Dependencies.** Seven direct ones: `ed25519-dalek`, `sha2`, `hmac`,
`getrandom`, `redb`, `p256` (WebAuthn ES256, RustCrypto), `rustls` +
`rustls-pki-types`. The "pure Rust, no C" policy has a SINGLE
exception: **ring** as the rustls crypto provider (the same pairing
as kolorinko). HTTP, the wire codec, JSON, CBOR, WebAuthn — std/own.
`deny.toml` — a narrow license allow-list (ISC added for ring),
yanked/advisories/unknown sources — deny.

## 9. [×] Dropped (consciously)

- **Email/SMTP and third-party IdPs** — an egress surface (outbound
  HTTPS, a relay, codes in inboxes) with no benefit to the trust
  model; email was a recovery root with a bloated theft matrix. In v7
  the only login method is WebAuthn.
- **Cookie sessions and CSRF tokens** — replaced by PoP headers
  (x-jti/x-ts/x-sig): the signature is bound to path+ts+body, no
  cross-endpoint replay; the cookie does not exist as a class.
- **Profile data** (nickname, handle, avatar, PoW armor, the
  `profile/`, `handle/`, `avatar/` tables) — the IS stores nothing
  but keys and one optional bio homeserver field. 1 account = 1
  profile.
- **A reverse proxy / Caddy** — TLS is terminated by the process
  itself (rustls, §4): pwing the proxy no longer equals pwing the
  traffic.
- **Events (Event) and the site validator (site.rs)** — cut from v7;
  oneshot verification is the instance's duty (`Oneshot::verify` in
  `wire.rs`, one implementation for tests and future instances).
- **Leptos/frameworks** — the frontend is vanilla JS + a service
  worker, zero JS libraries on principle; rendering the connect code
  as QR — for the same reason (a phone covers hybrid QR, air-gap —
  the words).
- **Rotations/EOL/a journal** — one non-rotating signer, a re-issue =
  an incident procedure, a runbook for theft (§6).
- **Wire v6/V6 documents and older schemas** — old DBs and certificates
  are refused (pre-release, a conscious break; wipe the dev DB).
- **The word "ceremony"** — it is gone: there is a key, a phrase, a
  code.

## 10. [→] Planned (consciously deferred)

- **CRL / cert revocation** — "CRL later". The v1 policy: `logout`
  deletes the session row (no new attestations or signed requests),
  but the cert itself lives out its exp (7 days) — a known cost;
  attestations are short-lived (300 s), which softens the window.
  When we return to it — per-session `sha256(session_pk)` entries
  (they do not link accounts) + GlobalBefore, a journal replay at
  boot.
- **k-of-n over the root phrase** (sharing) — a rootkey compromise is
  a catastrophe, currently resolved by social means (§6).
- **The doomsday hash** (`HMAC(root_seed, "doomsday")` in the header
  — a provable way to declare "this root means nothing anymore") —
  easier to survive with the runbook, see the v6 README in `legacy/`.
- **Witnesses** (k-of-n observers blocking a re-issue) — protection
  against a malicious IS operator; a separate big topic.
- **The engineering park**: HTTP keep-alive, redb compaction,
  verification levels >1 (there is no level as a class now), webauthn
  BE/BS bits as a "strength" signal of a method.
