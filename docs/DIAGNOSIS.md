# Certificate Chain Diagnosis & Troubleshooting Guide

This guide explains how to use **AIA Chaser's Diagnostic API** to inspect SSL/TLS certificates, interpret `ChainReport` objects, and remediate incomplete certificate chains on the server side.

---

## 1. Using the Diagnostic API

AIA Chaser provides a non-invasive diagnostic probe that opens a raw TLS socket to a target host, downloads the certificates served by the server, traces the Authority Information Access (AIA) extension URIs, and analyzes whether the chain can be completed and trusted by the OS trust store.

```dart
import 'package:aia_chaser/aia_chaser.dart';

Future<void> runDiagnostics(String domain) async {
  final ChainReport report = await AiaChaser.diagnose(
    domain,
    port: 443,
    timeout: const Duration(seconds: 8),
  );

  print('Diagnostic report for ${report.host}:${report.port}');
  print('Trust Status: ${report.trustStatus}');
  print('Is Complete: ${report.isComplete}');
  print('Certificates served by server: ${report.chain.length}');
  print('Issuers chased via AIA: ${report.chasedIssuers.length}');

  if (!report.isComplete) {
    print('Recommended Fix: ${report.recommendedFix}');
  }
}
```

---

## 2. Understanding `ChainReport` Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `host` | `String` | The target hostname probed. |
| `port` | `int` | The TLS port (defaults to 443). |
| `chain` | `List<CertInfo>` | Array of certificates actually delivered by the remote TLS handshake. |
| `trustStatus` | `String` | Validation verdict (`trusted`, `missing_intermediate`, `expired`, `untrusted_root`, `pinned`). |
| `recommendedFix` | `String?` | Actionable instructions for server administrators to resolve the issue. |
| `chasedIssuers` | `List<String>` | URIs discovered in certificate AIA extensions and successfully downloaded. |
| `isComplete` | `bool` | `true` if the server serves a self-contained, fully-trusted chain without needing AIA resolution. |

### Certificate Metadata (`CertInfo`)

For every certificate in the chain, `CertInfo` provides:
- **`subject`**: Distinguished Name (DN) of the certificate owner (e.g., `CN=api.example.com`).
- **`issuer`**: Distinguished Name of the issuing CA (e.g., `CN=R3, O=Let's Encrypt, C=US`).
- **`serialNumber`**: Hex-encoded serial number.
- **`notBefore` / `notAfter`**: Epoch millisecond timestamps indicating validity window.
- **`aiaIssuers`**: List of HTTP URIs pointing to the issuing CA's DER certificate.
- **`sha256Hex`**: Cryptographic fingerprint (SHA-256) of the certificate DER bytes.
- **`isSelfSigned`**: `true` if subject matches issuer and signature self-verifies (Root CA).

---

## 3. Common Diagnoses & Root Causes

### 1. Incomplete Chain (`missing_intermediate`)
- **Symptom:** Dart/Flutter throws `HandshakeException: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`, while Chrome and Safari load the website without warning.
- **Cause:** Desktop browsers chase AIA URLs automatically or cache intermediates from previous visits. Dart's BoringSSL engine and Android WebView do not. The server sent only the leaf certificate.
- **Verification:** `report.isComplete == false` and `report.chasedIssuers.isNotEmpty`.

### 2. Expired Certificate in Chain (`expired`)
- **Symptom:** Handshake fails with `certificate has expired`.
- **Cause:** The leaf or one of the intermediate certificates has passed its `notAfter` timestamp.
- **Verification:** Inspect each `cert.notAfter` against `DateTime.now().millisecondsSinceEpoch`.

### 3. Missing AIA Extension (`no_aia_extension`)
- **Symptom:** Handshake fails and AIA Chaser cannot chase any intermediates.
- **Cause:** The leaf certificate lacks an `Authority Information Access` (OID 1.3.6.1.5.5.7.1.1) extension with `id-ad-caIssuers`.
- **Fix:** You must obtain a newly re-issued certificate from a CA that populates AIA extensions, or configure a fallback pin in `HostPolicy(onFailure: FailurePolicy.pinFallback([...]))`.

---

## 4. Server-Side Remediation

If you control the target backend, the permanent and standard fix is to configure the web server to serve the complete certificate chain (leaf + intermediates).

### Nginx
Ensure `ssl_certificate` points to the **full chain** file, NOT just the domain certificate:
```nginx
# ❌ INCORRECT (causes "unable to get local issuer certificate")
ssl_certificate /etc/letsencrypt/live/example.com/cert.pem;

# ✅ CORRECT
ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
```

### Apache (httpd)
On Apache 2.4.8 and newer:
```apache
SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
```
On Apache 2.4.7 or older:
```apache
SSLCertificateFile /etc/letsencrypt/live/example.com/cert.pem
SSLCACertificateFile /etc/letsencrypt/live/example.com/chain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
```

### Caddy
Caddy automatically manages and bundles full chains. If using custom certificates:
```caddy
example.com {
    tls /path/to/fullchain.pem /path/to/privkey.pem
}
```

### AWS Application Load Balancer (ALB)
When importing an SSL certificate into AWS ACM or ALB:
1. Paste the server certificate into **Certificate body**.
2. Paste the private key into **Certificate private key**.
3. Paste the intermediate bundle into **Certificate chain** (Do not leave this empty!).

---

## 5. Verification Using OpenSSL CLI

You can cross-reference AIA Chaser's diagnostic findings directly using the OpenSSL CLI:

```bash
# Check the raw certificates returned during TLS handshake
openssl s_client -connect api.example.com:443 -showcerts </dev/null

# Extract AIA extension from leaf certificate
openssl x509 -in leaf.pem -noout -text | grep -A 2 "Authority Information Access"
```
