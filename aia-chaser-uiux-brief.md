# AIA Chaser — UI/UX Design Brief

For a library, the "user experience" has four layers, in priority order: **(1) the API a developer types, (2) the error and log messages they read, (3) the docs they follow, (4) the visual surfaces** (`AiaDiagnosticsView` and the Playground app). Layers 1–3 are specified first because most users will never open a UI. The visual surfaces come after, with the concrete values an AI app builder needs.

---

## 1. Overall design style and rationale

**Style: calm, technical, evidence-first.** The audience is developers who arrive stressed (something is broken, possibly in production) and want confidence that a security-sensitive tool is trustworthy. So the look is a restrained developer-tool style: lots of whitespace, monospace for identifiers, and color used only to carry meaning (valid, warning, rejected). No marketing gloss, no illustration-heavy hero. The visual tone is closer to a network inspector than a consumer app.

## 2. API experience principles (layer 1)

- **Safe by default, loud when unsafe.** The default failure policy is `reject`. The only way to accept without validation is a method literally named `unsafeAllow`.
- **One config object.** Everything lives in `AiaConfig`; adapters take no configuration of their own.
- **Names say what they do:** `chase`, `pinFallback`, `unsafeAllow`, `passthrough`, `prewarm`.
- **Failures are typed:** `ValidationOutcome` values are the same everywhere (results, events, reports, docs).
- **Time to first success:** a developer should go from install to a working request in under 10 lines of config and one line per adapter.

## 3. Message design (layer 2)

Every log line and exception follows the same shape: **what happened, to which host, why, what to do.**

```
[AiaChaser] booking.example.com: rejected (aiaFetchFailed)
  AIA issuer URL http://r11.i.example.org/ timed out after 3000 ms.
  Next: check device connectivity, add the issuer to seedAssets, or configure a pin.
```

Rules:
- Plain sentences; no stack-trace-only errors.
- The "Next:" line is mandatory for every non-success outcome.
- A `docs` link per outcome (stable anchors in `/docs/diagnosis.md`).
- Hostnames and short fingerprints (first 12 hex characters) only; never certificate bodies.
- `unsafeAllow` use logs a warning every time: `[AiaChaser] WARNING booking.example.com accepted WITHOUT validation (unsafeAllow).`

## 4. Documentation experience (layer 3)

- **README order:** (1) one-paragraph problem statement with the three symptoms, (2) "Diagnose in 30 seconds", (3) install, (4) 10-line config, (5) per-stack snippets, (6) policy table, (7) "Is this safe?" with the threat-model summary, (8) migration from `proceed()` / `badCertificateCallback`.
- **Diagram first:** a single chain diagram (server sends 1 of 3 certs → AIA fills the gap) near the top; it does more than prose.
- **Honesty section:** limitations listed plainly (no revocation checking; first request to un-prewarmed hosts under global overrides fails once; Android-only fix).
- **Docs site:** none. `/docs` markdown plus dartdoc on pub.dev keeps maintenance low for a solo author.

## 5. Visual surfaces: `AiaDiagnosticsView` and Playground app

### Color palette

| Role | Name | Light | Dark |
|---|---|---|---|
| Primary | Signal Blue | `#2563EB` | `#60A5FA` |
| Background | Paper / Ink | `#F8FAFC` | `#0B1220` |
| Surface | Card | `#FFFFFF` | `#111A2E` |
| Border | Hairline | `#E2E8F0` | `#22304A` |
| Text primary | Ink / Snow | `#0F172A` | `#E5EAF3` |
| Text secondary | Slate | `#475569` | `#9AA7BD` |
| Valid | Chain Green | `#16A34A` | `#4ADE80` |
| Warning / chased | Amber | `#D97706` | `#FBBF24` |
| Rejected / unsafe | Alarm Red | `#DC2626` | `#F87171` |
| Missing link | Dashed Gray | `#94A3B8` | `#64748B` |

**Meaning is never carried by color alone:** every status chip also has an icon and a text label.

### Typography
- **UI text:** the platform default (Roboto on Android, SF on iOS) via Material 3 text theme. Reason: no font assets, zero package weight.
- **Identifiers (hostnames, fingerprints, URLs, JSON):** system monospace (`monospace`), 13 sp.
- **Scale:** title 20 sp / 600, section header 16 sp / 600, body 14 sp, caption 12 sp, chip label 12 sp / 500.
- **Docs and README:** GitHub-rendered defaults; no custom fonts.

### Component style
- **Material 3**, `useMaterial3: true`, seed color Signal Blue, custom semantic colors via a `ThemeExtension<AiaColors>` so the widget works under the host app's theme.
- **Status chip:** pill, 28 dp height, icon + label, tinted background at 12% of the status color, text in the status color.
- **Certificate node card:** 12 dp radius, 1 dp hairline border, no elevation; header (subject CN, bold), subtext (issuer CN), key-value rows in monospace, source badge top-right ("Sent by server", "Fetched via AIA", "Seed", "System root").
- **Chain connector:** 2 dp vertical line between nodes; solid for linked, dashed gray for a missing link with the label "missing".
- **Buttons:** filled for the single primary action per screen; outlined for secondary; text for tertiary. 48 dp minimum touch target. Destructive actions (clear cache) use red text button plus confirmation dialog.
- **Cards:** 12 dp radius, 16 dp padding, 1 dp border, no shadows (flat, inspector-like).
- **Banners:** full-width, 12 dp padding; red for unsafe mode (persistent), amber for degraded, blue for info.

### Layout rules
- 8 dp spacing grid; 16 dp screen padding on phones, 24 dp on tablets.
- One column on phones; list-detail two-pane (list left 360 dp, detail right) when width ≥ 840 dp.
- Maximum content width 720 dp for text-heavy screens.
- Long values (fingerprints, URLs) truncate in the middle with a copy action; never wrap awkwardly.
- Safe-area insets respected; the bottom navigation bar uses `NavigationBar` with four destinations.

### Mobile vs. desktop
- **Mobile (primary):** all Playground screens are phone-first; Android is the only platform where the fix runs.
- **Tablet / foldable:** two-pane layout for Hosts / Host Detail and Events / Event Detail.
- **Desktop / web:** not a target for the example app. Documentation is read in a browser and is responsive by virtue of GitHub rendering.

### Dashboard design direction
The Hosts tab is the dashboard: a scannable list ordered by status severity (Rejected first, then Pending, then Validated), each card showing hostname, policy, outcome, and last-checked time. A header summary row shows counts ("3 validated · 1 rejected · 0 pending") and cache stats (issuer entries, verdict entries). No charts: the data are states, not trends.

### Button and card style summary
Flat cards with hairline borders, pill chips for state, one filled primary button per screen, outlined secondary, red-text destructive. Icons from Material Symbols (outlined): `verified_user` valid, `link_off` missing link, `warning` caution, `gpp_bad` rejected, `content_copy` copy.

### Motion and feedback
- Probing: indeterminate linear progress at the top of the card, no spinners over content.
- State changes (Pending → Validated) animate chip color over 200 ms; reduce-motion respected.
- Copy actions confirm with a snackbar "Copied".

### Accessibility
- Contrast ≥ 4.5:1 for all text in both themes (palette above verified at those values).
- Every chip and icon has a semantic label; certificate nodes read as "Certificate 2 of 3, subject …, fetched via AIA, valid until …".
- Dynamic text scaling to 200% without clipping; touch targets ≥ 48 dp.
- Status never conveyed by color alone.

## 6. Inspiration references

- **Chrome DevTools Security panel / Network Inspector**: chain visualization and calm status coding.
- **SSL Labs report**: plain-language cause plus fix, certificate path display.
- **Sentry and Dio README structure**: problem-first, snippet-heavy documentation.
- **Material 3 / Flutter DevTools**: component language and density for the Playground.
- **`package:logging` conventions**: levels and message formatting.

## 7. Overall experience the developer should walk away with

"I understood exactly why my app failed, I changed a few lines, nothing is being blindly trusted anymore, and I can show my reviewer the evidence."
