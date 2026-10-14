# Security Policy

## Supported Versions

Only the latest release of AIA Chaser receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Security is paramount to AIA Chaser. The library's core responsibility is preventing insecure TLS bypasses while fetching missing intermediate certificates via AIA.

If you discover a security vulnerability (such as a bypass of chain validation, SSRF in AIA fetching, buffer overflow in ASN.1 parsing, or unsafe cache manipulation):

1. **Do NOT open a public GitHub issue.**
2. Send an email with details and a minimal reproducible proof-of-concept to: `security@aiachaser.dev`
3. We will acknowledge receipt within 48 hours and coordinate a coordinated disclosure timeline (typically 90 days or less).
4. Credit will be given in our release notes and changelog once a patch is published.

## Threat Model Guarantees

- **No Implicit Trust**: Certificates downloaded via AIA are treated as untrusted network inputs. They enter the certificate pool and are validated against the Android platform trust store (`X509TrustManagerExtensions`), RFC 6125 SAN hostname matching, and validity dates before any connection is permitted.
- **SSRF Prevention**: AIA endpoints resolving to private, loopback, link-local, or unique-local IP addresses are strictly rejected before any socket connection is attempted.
- **Cache Integrity**: Persistent disk caches store only public X.509 certificates. Trust verdicts are never stored on disk.
