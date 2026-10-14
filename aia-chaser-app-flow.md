# AIA Chaser — App Flow Document

AIA Chaser is a library, so its "app" has three surfaces that each need a defined flow:

1. **The developer journey**: installing, configuring, verifying, shipping.
2. **Runtime flows**: what happens inside the package for each network stack.
3. **The Playground app** (`/example`): a Flutter app that exercises every feature and hosts the `AiaDiagnosticsView` widget. It is the only surface with literal screens, and the navigation below is specified so an AI coding agent can build it without guessing.

**Login / signup flow:** not applicable. The package and Playground have no accounts, and the only principal is the host app.
**Payment / upgrade flow:** not applicable. The package is free and open source with no monetization.

---

## 1. Developer journey

```
 Hit the error ─► Find README ─► Run diagnose() ─► Read report
      │                                                  │
      │                              ┌───────────────────┴──────────────┐
      │                       Server omitted chain?               Device lacks CA?
      │                              │                                  │
      │                      Share report with server owner      Add seed cert or pin
      │                              │                                  │
      └──────────────► Add AiaConfig + install adapters ◄───────────────┘
                                     │
                          Verify in Playground / own app
                                     │
                     Remove old badCertificateCallback / proceed()
                                     │
                              Ship; watch events
```

Steps in order:

1. **Diagnose first.** README step 1 is `AiaChaser.diagnose(host)`. This tells the developer whether the cause is an incomplete server chain or an unknown CA, which decides the config.
2. **Add the dependency** for the stacks in use (core plus any of webview, dio, http adapters).
3. **Write `AiaConfig`** listing hosts and failure policies.
4. **Install** `AiaHttpOverrides` and/or adapters, and `AiaWebViewHandler.install(...)`.
5. **Verify** with the Playground (or the app) that each stack loads the host; watch the event stream.
6. **Delete** old bypass code using the migration guide.
7. **Ship** with `unsafeAllow` absent from production config.

## 2. Runtime flows

### 2.1 `dart:io` flow (global overrides or scoped client)

```
 request to host H
   │
   ▼
 handshake fails chain check ──► badCertificateCallback(cert, H, port)   [sync]
                                      │
                         policy for H?─no──► return false (platform decision stands)
                                      │yes
                         sha256(cert.der) in ValidatedLeafStore? ─yes─► return true
                                      │no
                         pin matches (cert-sha256)? ─yes─► return true
                                      │no
                         policy = unsafeAllow & guard ok? ─yes─► return true (+warning event)
                                      │no
                         schedule validate(H, leaf) (single-flight) ──► return false
                                                                         │
                                         wrapper (Dio / http / factory) catches HandshakeException
                                         awaits pending validation
                                                │
                                      outcome validated / validatedByPin?
                                         yes ► retry once ► success
                                         no  ► surface original error
```

With **prewarm**, the store is already populated at startup, so the first request takes the first "yes" branch and never fails. For global `HttpOverrides` users without wrappers (for example `CachedNetworkImage`), a first-ever request to an un-prewarmed host fails once and later requests succeed; the README states this plainly and recommends prewarm.

### 2.2 WebView flow

```
 WebView loads https://H/page
   │
   ▼
 Android reports SSL error ─► setOnSSlAuthError handler (async)
   │
   policy for H? ─no─► error.cancel()
   │yes
   certificate bytes present? ─no─► apply failure policy (pin impossible → cancel)
   │yes
   validate(H, 443, leafDer)  ◄── cache hit: < 5 ms │ cold: AIA fetch(es)
   │
   outcome validated / validatedByPin ─► error.proceed()
   otherwise                          ─► failure policy: reject → cancel
                                                        unsafeAllow(guarded) → proceed + warning
```

### 2.3 Prewarm flow

At `initialize`, for each exact (non-wildcard) host in config: `prewarm(host, 443)` → native probe connects, captures the presented chain, runs the validation pipeline, and populates the verdict store. `PrewarmMode.background` returns immediately; `await` blocks `initialize` until done or deadline; `none` skips it. Wildcard hosts are learned on first use.

### 2.4 Diagnose flow

`diagnose(host)` → native probe (capture-only trust manager, never used for acceptance) → build `ChainReport` listing certificates the server sent, certificates AIA supplied, system trust verdict, plain-language cause, and suggested server fix.

---

## 3. Playground app: screens and navigation

**Navigation model:** bottom navigation bar with four tabs; detail screens push on top and back-navigate. Single-activity Android app; no deep links.

```
 [Hosts] ── Host Detail ── Chain Report
    │            └──────── Policy Editor
    └── Add Host
 [Lab] ── Dart HTTP tab | Dio tab | http tab | WebView tab
 [Events] ── Event Detail
 [Settings] ── Cache Manager, Config Viewer, About
```

Startup: splash → `AiaChaser.initialize(sampleConfig)` → Hosts tab. If initialization throws a configuration error (for example ambiguous host patterns), a full-screen error state shows the message and a "Copy error" action.

### S1. Hosts (tab 1)
- **Purpose:** list configured hosts with live status.
- **Elements:** list of host cards (hostname, policy chip, status chip: Validated / Rejected / Unknown / Pending, last checked time); FAB "Add host"; pull-to-refresh re-runs prewarm.
- **Actions:** tap card → S3 Host Detail; swipe to remove (with undo snackbar); FAB → S2.
- **Empty state:** illustration of a chain with a missing link, text "No hosts configured. Add one to diagnose a certificate chain.", primary button "Add host", secondary "Load sample hosts".
- **Error state:** card status Rejected with outcome label (for example "Rejected: hostname mismatch").
- **Success state:** green Validated chip, "via 1 fetched issuer" caption.

### S2. Add Host
- **Elements:** hostname field (validated live: normalization preview, IP/wildcard handling), port (default 443), policy dropdown (Reject, Pin fallback, Unsafe allow), pins field shown only for Pin fallback, "Probe now" toggle.
- **Actions:** Save → S1 and triggers prewarm; Cancel back.
- **Errors:** invalid hostname inline; ambiguous pattern shown as an error banner; selecting Unsafe allow shows a persistent red warning banner "Debug builds only".

### S3. Host Detail
- **Elements:** header (hostname, outcome chip, duration), tabs: Overview | Chain | Timeline. Overview: policy summary, cache status (verdict age/expiry), buttons "Re-validate", "Diagnose", "Edit policy".
- **Actions:** "Diagnose" → S4; "Edit policy" → S5; "Re-validate" clears the verdict for that host and re-runs.
- **Empty state:** no events yet shows "Not checked yet. Tap Re-validate."
- **Error state:** outcome-specific explanation card (see Chain Report cause text) with "Copy report".

### S4. Chain Report
- **Elements:** vertical chain diagram: each certificate as a node (subject CN, issuer CN, validity range, key type, SHA-256 short fingerprint, badge "Sent by server" / "Fetched via AIA" / "Seed" / "System root"); gaps drawn as dashed connectors labelled "missing". Bottom card: **Cause** (plain language) and **Suggested fix** (for example "Serve fullchain.pem instead of cert.pem").
- **Actions:** Copy report (redacted), Share, tap a node to expand details (SANs, AIA URL, key usage).
- **Empty / loading:** skeleton nodes with "Probing host…", cancellable; 8 s deadline.
- **Error states:** DNS/connection failure ("Could not reach host: <reason>"); probe timeout; each with Retry.
- **Success:** all nodes connected, green completion badge, "Chain complete after fetching 1 certificate".

### S5. Policy Editor
- **Elements:** same fields as S2 plus per-host timeouts and "retry once" toggle; "Test this policy" button that validates against the host.
- **Actions:** Save applies by re-initializing configuration (shows a snackbar "Policy applied"). Discard prompts if dirty.

### S6. Lab (tab 2)
- **Purpose:** prove each stack works against a chosen host.
- **Elements:** URL field (history dropdown), segmented tabs: **dart:io**, **Dio**, **http**, **WebView**. Each non-WebView tab has "GET" and a result panel (status, headers, byte count, duration, retry-used badge). WebView tab hosts a `WebViewWidget` with a thin progress bar and a reload button.
- **Actions:** GET runs the request; a "Compare without package" toggle runs the same request with the package disabled so the failure is visible side by side.
- **Empty state:** "Enter a URL and run a request."
- **Error state:** exception type and message in a mono-font box with "Copy".
- **Success state:** green status, "Validated via AIA (1 fetch)" or "Cache hit".

### S7. Events (tab 3)
- **Elements:** reverse-chronological list from `AiaChaser.events`; filter chips (All, Validations, Fetches, Policy, Cache); each row shows time, type icon, host, outcome, duration.
- **Actions:** tap → Event Detail (full JSON, no cert bodies); overflow menu "Clear", "Export".
- **Empty state:** "No events yet. Run a request from the Lab."
- **Cap:** newest 500 events; older ones drop silently with a footer note.

### S8. Settings (tab 4)
- **Cache Manager:** counts and sizes of issuer cache and verdicts; buttons "Clear issuer cache", "Clear verdicts", confirmation dialog for each; result snackbar.
- **Config Viewer:** read-only rendering of the active `AiaConfig` (secrets none), with Copy.
- **About:** package versions, license, links to docs and security policy, Android API level, WebView version.
- **Unsafe mode indicator:** if any host uses `unsafeAllow`, a persistent red banner appears app-wide.

---

## 4. Button and action reference

| Action | Effect |
|---|---|
| Add host / Save | Adds pattern to config, triggers prewarm for exact hosts |
| Re-validate | Drops verdict for the host, runs `validate` |
| Diagnose | Runs `diagnose`, opens Chain Report |
| Copy report | Copies redacted text report to clipboard, shows "Copied" snackbar |
| Compare without package (Lab) | Runs the same request through a vanilla client |
| Clear issuer cache | Deletes cached issuer certificates and index |
| Clear verdicts | Empties in-memory verdict stores on both sides |

## 5. State summary

| State | Where | Treatment |
|---|---|---|
| Empty | Hosts, Events, Lab, Host Detail | Illustration + one-line explanation + single primary action |
| Loading | Chain Report, Prewarm, Lab requests | Skeleton or progress indicator with cancel |
| Error | Config, probe, request, validation outcome | Cause in plain words, copyable detail, retry where meaningful |
| Success | Validation, request, chain complete | Green chip or banner, short "how" caption (fetched / cache / pin) |
