# AIA Chaser — Backend Schema (Data Model)

AIA Chaser has no server, no accounts, and no database engine. The "backend" is the **native layer plus its caches**. This document specifies the package's data model in table form so the structures can be implemented directly (files + JSON index on disk, plain objects in memory) and lifted into SQLite later if ever needed. Table names are logical; the physical storage for each is stated.

**Users table:** not applicable. The package has no users. The only principal is the host app process, and the nearest equivalent is the immutable `AiaConfig` instance (see `host_policy` and `pin`).
**Authentication / session table:** not applicable. There are no sessions. The package's "trust" is established per validation (system trust store or explicit pin), and nothing about trust is persisted (see rules below).

**Naming conventions:** `snake_case`; hashes are lowercase hex SHA-256 unless noted; timestamps are UTC epoch milliseconds.

---

## 1. Storage map

| Logical table | Physical storage | Lifetime | Persisted? |
|---|---|---|---|
| `host_policy`, `pin` | In-memory objects built from `AiaConfig` | Process | No (config is code) |
| `issuer_cache` | DER files + `index.json` under `<cacheDir>/aia_chaser/v1/` | TTL 30 days default | **Yes** (public certs only) |
| `seed_certificate` | Flutter assets, loaded at `initialize` | App version | Shipped with app |
| `validation_cache` | In-memory map, Kotlin side **and** `ValidatedLeafStore` on Dart side | Process; TTL ≤ 24 h | **No** |
| `diag_event` | In-memory ring buffer (Dart side), 500 entries | Process | No |
| `chain_report` | Transient return value | One call | No |

**Design rule: nothing that grants trust is ever persisted.** Persisted issuer certificates are inert: every use re-verifies signature linkage and re-runs the system trust check, so editing the cache cannot create trust. Verdicts live only in memory.

## 2. Tables

### 2.1 `host_policy`  (in-memory)

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `host_pattern` | text | **PK**, normalized (lowercase, IDNA) | Exact host, `*.suffix`, or IP literal |
| `chase` | bool | not null, default true | If false, host uses pin-only logic |
| `on_failure` | enum(`reject`,`pin_fallback`,`unsafe_allow`) | not null, default `reject` | |
| `allow_unsafe_in_release` | bool | not null, default false | Only meaningful for `unsafe_allow` |
| `connect_timeout_ms` | int | null = inherit | Per-host override |
| `read_timeout_ms` | int | null = inherit | Per-host override |
| `retry_once` | bool | not null, default true | Wrapper retry after learn-on-failure |
| `prewarm` | bool | not null, default true for exact hosts | Wildcards never prewarm |

Constraints: no two patterns may resolve ambiguously for the same host at the same specificity (error at `initialize`). `unsafe_allow` in a release build without `allow_unsafe_in_release` throws at `initialize`.

### 2.2 `pin`  (in-memory)

| Column | Type | Constraints |
|---|---|---|
| `pin_id` | int | **PK**, autoincrement |
| `host_pattern` | text | **FK → host_policy.host_pattern**, on delete cascade |
| `type` | enum(`spki_sha256`,`cert_sha256`) | not null |
| `value` | text | not null (base64 for SPKI, hex for cert) |

Unique: (`host_pattern`, `type`, `value`).

### 2.3 `issuer_cache`  (persisted, `index.json` + `<url_hash>.der`)

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `url_hash` | text | **PK** | SHA-256 of the normalized AIA URL; also the DER filename |
| `url` | text | not null | Original `caIssuers` URL |
| `cert_sha256` | text | not null, indexed | Fingerprint of the cached certificate |
| `subject_dn` | text | not null | For lookup by `top.issuer` |
| `issuer_dn` | text | not null | |
| `not_after` | int | not null | Entry is skipped if certificate expired |
| `fetched_at` | int | not null | |
| `expires_at` | int | not null | `fetched_at + issuerTtl` |
| `size_bytes` | int | not null, ≤ 65536 | |
| `source` | enum(`network`,`disk`,`seed`) | not null | Provenance for diagnostics |

Bounds: at most **64 entries** and **2 MB** total; least-recently-used eviction. Index version field `schema_version = 1`; unknown version → cache wiped and rebuilt.

### 2.4 `seed_certificate`  (assets, loaded at init)

| Column | Type | Constraints |
|---|---|---|
| `cert_sha256` | text | **PK** |
| `subject_dn` | text | not null, indexed |
| `issuer_dn` | text | not null |
| `not_after` | int | not null |
| `asset_path` | text | not null |

Seeds enter the chain-building pool exactly like cached issuers and carry no extra trust.

### 2.5 `validation_cache`  (in-memory, both sides)

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `host` | text | **PK part 1** | Exact host (not the pattern) |
| `leaf_sha256` | text | **PK part 2** | |
| `port` | int | not null | |
| `outcome` | `ValidationOutcome` | not null | Only `validated`/`validatedByPin` allow the sync callback to return true |
| `chain_sha256` | text[] | | Ordered leaf → top |
| `validated_at` | int | not null | |
| `expires_at` | int | not null | `min(validated_at + validationTtl, earliest not_after in chain)` |
| `policy_applied` | enum(`system_trust`,`pin`,`unsafe`,`none`) | not null | |

Negative outcomes are cached for a short TTL (60 s) to avoid hammering a dead AIA server; positive outcomes for up to 24 h. `clearCaches(verdicts)` empties both sides together.

### 2.6 `diag_event`  (in-memory ring buffer, 500 entries)

| Column | Type | Notes |
|---|---|---|
| `id` | int **PK**, autoincrement | |
| `ts` | int | |
| `type` | enum(`chain_validated`,`aia_fetched`,`aia_fetch_failed`,`policy_decision`,`cache_hit`,`retry_attempted`,`prewarm_completed`) | |
| `host` | text, indexed | |
| `leaf_sha12` | text | First 12 hex chars only |
| `outcome` | `ValidationOutcome`, nullable | |
| `duration_ms` | int, nullable | |
| `detail` | json, nullable | URL, error class, never certificate bodies |

### 2.7 `ValidationOutcome` (shared enum)

`validated`, `validatedByPin`, `rejectedUntrusted`, `rejectedHostname`, `rejectedExpired`, `aiaUnavailable`, `aiaFetchFailed`, `maxDepthExceeded`, `noCertificate`, `policyUnsafeAllowed`, `notConfigured`.

## 3. Relationships

```
 host_policy 1 ──── * pin
 host_policy 1 ──── * validation_cache   (via resolved host → pattern lookup; no stored FK)
 validation_cache * ── * issuer_cache / seed_certificate   (through chain_sha256 membership)
 diag_event * ──── 1 host (by hostname text)
```

Cross-references are by hash and hostname, not foreign keys, because verdicts and events are in-memory and must survive cache eviction independently.

## 4. Indexes worth calling out

| Index | Why |
|---|---|
| `issuer_cache(subject_dn)` | Chain builder looks up "who issued the top certificate" by DN; hot path |
| `issuer_cache(cert_sha256)` | Dedupe and diagnostics |
| `seed_certificate(subject_dn)` | Same lookup as above |
| `validation_cache(host, leaf_sha256)` (PK) | Sync callback lookup, must be O(1) |
| `diag_event(host)` | Per-host timeline in Host Detail |
| `host_policy` resolved via sorted-specificity table | Longest-suffix match without scanning |

## 5. Permissions

| Actor | Read | Write |
|---|---|---|
| Host app (Dart code) | Config, events, cache stats, reports | Config at `initialize`, `clearCaches` |
| Package native code | All tables | `issuer_cache`, `validation_cache` |
| Other apps on the device | **Nothing** | **Nothing** |
| Anything on the network | Nothing | Nothing |

Enforcement: cache files live in `Context.cacheDir` (app-private, not external storage), created with private mode; no `ContentProvider`, no exported components, no file sharing intent. The Pigeon channel is internal to the app process.

## 6. Data ownership rules

1. All data belongs to the host app. The package collects nothing and transmits nothing except unauthenticated HTTP(S) GETs for AIA issuer certificates.
2. The AIA request reveals only the issuer URL and the device's IP address to the CA's server, not the host the user visited. This is stated in the README privacy section.
3. `clearCaches(scope)` lets the app delete issuer files, verdicts, or both at any time (for example on logout or "clear app data" features).
4. Uninstalling the app deletes everything. The OS may also evict `cacheDir`; the package treats a missing cache as a normal cold start.
5. A schema version bump wipes `issuer_cache` rather than migrating it, since entries are re-fetchable.
6. No personal data is stored. Hostnames appear only in memory (events, verdicts) and in config the app itself supplied.
7. Exported diagnostic reports are redacted by default (fingerprints truncated, no certificate bodies, no IPs); including full fingerprints is an explicit opt-in flag.

## 7. Example `index.json`

```json
{
  "schema_version": 1,
  "entries": [
    {
      "url_hash": "3b9f…",
      "url": "http://r11.i.example.org/",
      "cert_sha256": "a41c…",
      "subject_dn": "CN=R11,O=Example CA,C=US",
      "issuer_dn": "CN=Example Root,O=Example CA,C=US",
      "not_after": 1861919999000,
      "fetched_at": 1760400000000,
      "expires_at": 1762992000000,
      "size_bytes": 1301,
      "source": "network"
    }
  ]
}
```
