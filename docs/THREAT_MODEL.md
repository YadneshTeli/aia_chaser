# Threat Model & Security Specification

AIA Chaser is a security-sensitive library designed to restore TLS authentication when servers omit intermediate certificates. This document outlines the cryptographic threat model, attack vectors considered, and mitigations implemented.

---

## 1. Threat Matrix

| Threat / Attack Vector | Severity | Mitigation Strategy |
|---|---|---|
| **Man-in-the-Middle (MitM) Attacker** presents a forged leaf certificate | **Critical** | Leaf certificates must cryptographically chain to an official root CA in the Android platform trust store (`X509TrustManagerExtensions`), or match an explicit developer `Pin`. Hostname matching (RFC 6125) and validity dates are strictly enforced. |
| **Server-Side Request Forgery (SSRF)** via malicious AIA `caIssuers` URLs | **High** | `AiaFetcher` resolves hostnames and checks every resolved IP before opening a socket. Private, loopback, link-local, carrier-grade NAT, and IPv4-mapped IPv6 addresses are blocked. Redirects are re-validated before every hop. |
| **Denial of Service (DoS)** via oversized AIA responses | **Medium** | Streaming reads enforce a strict 64 KiB threshold (`maxBytes`). Streams exceeding 64 KiB immediately abort with `aiaFetchFailed`. |
| **Infinite AIA Loops & Depth Bombs** | **Medium** | Certificate fingerprints are tracked in a visited set. Re-encountering any previously seen certificate terminates chain building. Chain depth is strictly capped at `maxDepth` (default 4). |
| **Slowloris / Hanging AIA Endpoints** | **Low** | Connection timeout (3000 ms) and read timeout (3000 ms). Total validation budget hard-capped at 8000 ms. |
| **Tampered On-Disk Cache** | **High** | On-disk cache (`<cacheDir>/aia_chaser/v1/`) stores **only public certificates**, never trust decisions. Any cached certificate retrieved on subsequent runs is re-verified via `cert.verify(issuer.publicKey)` and authenticated against the system trust store. Modifying cache files cannot forge trust. |
| **Policy Misconfiguration** (`unsafeAllow` in production) | **Critical** | `FailurePolicy.unsafeAllow()` throws a runtime `AiaSecurityException` in release builds unless `allowInRelease: true` is explicitly configured. Every usage generates an un-suppressible `WARNING` log and an `AiaEvent`. |

---

## 2. Zero-Trust Invariant

**"Downloading a certificate over AIA never confers trust."**

A certificate obtained from an AIA HTTP endpoint is treated as completely untrusted input. It only serves as a candidate intermediate certificate to link the presented leaf certificate to a root already present in the device's hardware-backed or system trust store.

```
Untrusted Network Input (Leaf Cert)
         │
         ▼
AIA Chased Certificate (Untrusted Intermediate)
         │
         ▼
Cryptographic Linkage Check (cert.verify(issuer.publicKey))
         │
         ▼
Android Conscrypt / X509TrustManagerExtensions System Check
         │
       Is issuer signed by an Android Trusted Root?
             /                  \
            No                  Yes
           /                      \
      REJECTED                  VALIDATED
```

---

## 3. Anti-SSRF Enforcement Details

`AiaFetcher` intercepts all HTTP GET requests intended for CA endpoints and checks resolved IP addresses against the following blocked ranges:

- **IPv4 Loopback**: `127.0.0.0/8`
- **IPv4 Private (RFC 1918)**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **IPv4 Link-Local (RFC 3927)**: `169.254.0.0/16`
- **IPv4 Carrier-Grade NAT (RFC 6598)**: `100.64.0.0/10`
- **IPv6 Loopback**: `::1`
- **IPv6 Link-Local**: `fe80::/10`
- **IPv6 Unique-Local**: `fc00::/7`
- **IPv4-Mapped IPv6**: `::ffff:0:0/96` mapping to any private IPv4 range.
