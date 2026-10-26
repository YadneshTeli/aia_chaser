import Foundation
import Security
import CommonCrypto

#if os(iOS)
  import Flutter
  import UIKit
#elseif os(macOS)
  import FlutterMacOS
  import AppKit
#endif

public class AiaChaserPlugin: NSObject, FlutterPlugin, AiaChaserHostApi {

    private let binaryMessenger: FlutterBinaryMessenger?
    private var flutterApi: AiaChaserFlutterApi?
    private var customAnchors: [SecCertificate] = []
    // Incremented by configure(); stale validations must not write the verdict cache.
    private var configGeneration = 0
    private var inMemoryVerdicts: [String: CachedVerdict] = [:]
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "dev.aiachaser.validation", qos: .userInitiated, attributes: .concurrent)

    struct CachedVerdict {
        let outcome: ValidationOutcome
        let chainSha256Hex: [String]
        let fetchedUrls: [String]
        let expiresAt: Date
        let detail: String?
    }

    public init(binaryMessenger: FlutterBinaryMessenger? = nil) {
        self.binaryMessenger = binaryMessenger
        if let messenger = binaryMessenger {
            self.flutterApi = AiaChaserFlutterApi(binaryMessenger: messenger)
        }
        super.init()
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        let messenger = registrar.messenger()
        let instance = AiaChaserPlugin(binaryMessenger: messenger)
        AiaChaserHostApiSetup.setUp(binaryMessenger: messenger, api: instance)
    }

    func configure(config: NativeConfig) throws {
        lock.lock()
        defer { lock.unlock() }

        customAnchors.removeAll()
        configGeneration += 1
        // Verdicts were computed against the previous anchors; drop them.
        inMemoryVerdicts.removeAll()
        for path in config.seedCertPaths {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
               let cert = SecCertificateCreateWithData(nil, data as CFData) {
                customAnchors.append(cert)
            }
        }
        for typed in config.seedCertsDer {
            if let cert = SecCertificateCreateWithData(nil, typed.data as CFData) {
                customAnchors.append(cert)
            }
        }
    }

    func validate(request: ValidationRequest, completion: @escaping (Result<ValidationResult, Error>) -> Void) {
        let certData = request.leafDer.data
        guard let leafCert = SecCertificateCreateWithData(nil, certData as CFData) else {
            let res = ValidationResult(
                outcome: .noCertificate,
                chainSha256Hex: [],
                fetchedUrls: [],
                durationMs: 0,
                detail: "Unable to parse leaf certificate as X.509 DER"
            )
            completion(.success(res))
            return
        }

        let leafSha256 = sha256Hex(certData)
        let host = request.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let port = request.port
        let cacheKey = "\(host):\(port):\(leafSha256)"

        // Check in-memory cache
        lock.lock()
        if let cached = inMemoryVerdicts[cacheKey], cached.expiresAt > Date() {
            lock.unlock()
            emitEvent(type: "cache_hit", host: host, leafSha12: String(leafSha256.prefix(12)), outcome: cached.outcome, durationMs: 0, detail: "In-memory cache hit")
            let res = ValidationResult(
                outcome: cached.outcome,
                chainSha256Hex: cached.chainSha256Hex,
                fetchedUrls: cached.fetchedUrls,
                durationMs: 0,
                detail: cached.detail ?? "In-memory cache hit"
            )
            completion(.success(res))
            return
        }
        lock.unlock()

        queue.async { [weak self] in
            guard let self = self else { return }
            let startTime = DispatchTime.now()

            let policy = SecPolicyCreateSSL(true, host as CFString)
            var optionalTrust: SecTrust?
            let status = SecTrustCreateWithCertificates([leafCert] as CFArray, policy, &optionalTrust)

            guard status == errSecSuccess, let trust = optionalTrust else {
                let res = ValidationResult(
                    outcome: .rejectedUntrusted,
                    chainSha256Hex: [leafSha256],
                    fetchedUrls: [],
                    durationMs: 0,
                    detail: "SecTrustCreateWithCertificates failed with status: \(status)"
                )
                DispatchQueue.main.async {
                    completion(.success(res))
                }
                return
            }

            self.lock.lock()
            let anchors = self.customAnchors
            let generation = self.configGeneration
            self.lock.unlock()

            if !anchors.isEmpty {
                SecTrustSetAnchorCertificates(trust, anchors as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, false)
            }

            // Enable network fetching so iOS native TLS chases AIA caIssuers automatically
            SecTrustSetNetworkFetchAllowed(trust, true)

            var evalError: CFError?
            let isValid = SecTrustEvaluateWithError(trust, &evalError)

            var chainSha256: [String] = []
            let certCount = SecTrustGetCertificateCount(trust)
            for i in 0..<certCount {
                if let cert = SecTrustGetCertificateAtIndex(trust, i) {
                    let der = SecCertificateCopyData(cert) as Data
                    chainSha256.append(self.sha256Hex(der))
                }
            }
            if chainSha256.isEmpty {
                chainSha256.append(leafSha256)
            }

            let elapsedNs = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
            let elapsedMs = Int64(Double(elapsedNs) / 1_000_000.0)

            let outcome: ValidationOutcome
            let detail: String

            if isValid {
                outcome = .validated
                detail = "Full certificate chain verified and trusted by Apple Security framework"
            } else if let error = evalError {
                let nsError = error as NSError
                let desc = nsError.localizedDescription.lowercased()
                let code = nsError.code
                if code == -67818 || desc.contains("expired") || desc.contains("validity period") {
                    outcome = .rejectedExpired
                    detail = "Certificate has expired or is not yet valid: \(nsError.localizedDescription)"
                } else if code == -67602 || desc.contains("hostname") || desc.contains("name mismatch") {
                    outcome = .rejectedHostname
                    detail = "Hostname mismatch for \(host): \(nsError.localizedDescription)"
                } else {
                    outcome = .rejectedUntrusted
                    detail = "Certificate chain untrusted: \(nsError.localizedDescription)"
                }
            } else {
                outcome = .rejectedUntrusted
                detail = "Trust evaluation failed without specific error"
            }

            let ttl: TimeInterval = (outcome == .validated || outcome == .validatedByPin) ? 86400 : 60
            self.lock.lock()
            if generation == self.configGeneration {
                self.inMemoryVerdicts[cacheKey] = CachedVerdict(
                    outcome: outcome,
                    chainSha256Hex: chainSha256,
                    fetchedUrls: [],
                    expiresAt: Date().addingTimeInterval(ttl),
                    detail: detail
                )
            }
            self.lock.unlock()

            self.emitEvent(
                type: "chain_validated",
                host: host,
                leafSha12: String(leafSha256.prefix(12)),
                outcome: outcome,
                durationMs: elapsedMs,
                detail: detail
            )

            let result = ValidationResult(
                outcome: outcome,
                chainSha256Hex: chainSha256,
                fetchedUrls: [],
                durationMs: elapsedMs,
                detail: detail
            )

            DispatchQueue.main.async {
                completion(.success(result))
            }
        }
    }

    func prewarm(host: String, port: Int64, completion: @escaping (Result<ValidationResult, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let startTime = DispatchTime.now()
            let cleanHost = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

            guard let url = URL(string: "https://\(cleanHost):\(port)") else {
                let res = ValidationResult(
                    outcome: .policyUnsafeAllowed,
                    chainSha256Hex: [],
                    fetchedUrls: [],
                    durationMs: 0,
                    detail: "Invalid prewarm host/port URL: \(cleanHost):\(port)"
                )
                DispatchQueue.main.async {
                    completion(.success(res))
                }
                return
            }

            let sessionConfig = URLSessionConfiguration.ephemeral
            sessionConfig.timeoutIntervalForRequest = 10.0
            sessionConfig.timeoutIntervalForResource = 10.0

            self.lock.lock()
            let anchors = self.customAnchors
            self.lock.unlock()
            let delegate = PrewarmChallengeDelegate(host: cleanHost, anchors: anchors)
            let session = URLSession(configuration: sessionConfig, delegate: delegate, delegateQueue: nil)
            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"

            let task = session.dataTask(with: request) { _, _, error in
                session.finishTasksAndInvalidate()
                let elapsedNs = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
                let elapsedMs = Int64(Double(elapsedNs) / 1_000_000.0)

                let outcome: ValidationOutcome
                let detail: String
                if delegate.evaluated {
                    outcome = delegate.evaluationPassed ? .validated : .rejectedUntrusted
                    detail = delegate.evaluationPassed
                        ? "TLS prewarm handshake and trust chain evaluation completed"
                        : (delegate.lastErrorDetail ?? "TLS prewarm evaluation failed")
                } else {
                    outcome = .aiaFetchFailed
                    detail = "Network error before TLS trust evaluation: \(error?.localizedDescription ?? "unknown")"
                }
                let hashes = delegate.discoveredChainSha256

                let res = ValidationResult(
                    outcome: outcome,
                    chainSha256Hex: hashes,
                    fetchedUrls: [],
                    durationMs: elapsedMs,
                    detail: detail
                )

                DispatchQueue.main.async {
                    completion(.success(res))
                }
            }
            task.resume()
        }
    }

    func diagnose(host: String, port: Int64, timeoutMs: Int64, completion: @escaping (Result<ChainReport, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let startTime = DispatchTime.now()
            let cleanHost = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

            guard let url = URL(string: "https://\(cleanHost):\(port)") else {
                let report = ChainReport(
                    host: cleanHost,
                    port: port,
                    serverSentChain: [],
                    completedChain: [],
                    outcome: .policyUnsafeAllowed,
                    cause: "Invalid URL for diagnosis",
                    suggestedFix: "Check hostname and port format",
                    durationMs: 0
                )
                DispatchQueue.main.async {
                    completion(.success(report))
                }
                return
            }

            let sessionConfig = URLSessionConfiguration.ephemeral
            let timeoutSeconds = max(Double(timeoutMs) / 1000.0, 3.0)
            sessionConfig.timeoutIntervalForRequest = timeoutSeconds
            sessionConfig.timeoutIntervalForResource = timeoutSeconds

            self.lock.lock()
            let anchors = self.customAnchors
            self.lock.unlock()
            let delegate = DiagnoseChallengeDelegate(host: cleanHost, anchors: anchors)
            let session = URLSession(configuration: sessionConfig, delegate: delegate, delegateQueue: nil)
            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"

            let task = session.dataTask(with: request) { _, _, error in
                session.finishTasksAndInvalidate()
                let elapsedNs = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
                let elapsedMs = Int64(Double(elapsedNs) / 1_000_000.0)

                let isOk = delegate.evaluationPassed
                let serverChain = delegate.serverSentCerts
                let fullChain = delegate.completedCerts

                let outcome: ValidationOutcome
                let cause: String
                let fix: String

                if !delegate.evaluated {
                    outcome = .aiaFetchFailed
                    cause = "Network error before TLS trust evaluation: \(error?.localizedDescription ?? "unknown")"
                    fix = "Check connectivity, DNS, hostname and port, then retry."
                } else if isOk {
                    outcome = .validated
                    if fullChain.count > serverChain.count {
                        cause = "Server omitted intermediate certificate(s); AIA chasing resolved full chain."
                        fix = "Configure web server with full certificate bundle (leaf + intermediates)."
                    } else {
                        cause = "Full certificate chain complete and validated by system trust."
                        fix = "No changes needed; server SSL configuration is optimal."
                    }
                } else {
                    outcome = .rejectedUntrusted
                    cause = delegate.lastErrorDetail ?? "Server certificate chain failed system trust evaluation."
                    fix = "Verify server certificates are issued by a trusted root CA and not expired."
                }

                let report = ChainReport(
                    host: cleanHost,
                    port: port,
                    serverSentChain: serverChain,
                    completedChain: fullChain,
                    outcome: outcome,
                    cause: cause,
                    suggestedFix: fix,
                    durationMs: elapsedMs
                )

                DispatchQueue.main.async {
                    completion(.success(report))
                }
            }
            task.resume()
        }
    }

    func getCacheStats() throws -> CacheStats {
        lock.lock()
        defer { lock.unlock() }
        let count = Int64(inMemoryVerdicts.count)
        return CacheStats(
            issuerCacheCount: 0,
            issuerCacheBytes: 0,
            memoryVerdictCount: count
        )
    }

    func clearCaches(scope: ClearScope) throws {
        lock.lock()
        inMemoryVerdicts.removeAll()
        lock.unlock()
        URLCache.shared.removeAllCachedResponses()
    }

    private func emitEvent(type: String, host: String, leafSha12: String?, outcome: ValidationOutcome?, durationMs: Int64?, detail: String?) {
        guard let api = flutterApi else { return }
        let event = NativeEvent(
            type: type,
            host: host,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000),
            leafSha12: leafSha12,
            outcome: outcome,
            durationMs: durationMs,
            detailJson: detail
        )
        DispatchQueue.main.async {
            api.onNativeEvent(event: event) { _ in }
        }
    }

    private func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Challenge Delegates

private class PrewarmChallengeDelegate: NSObject, URLSessionDelegate {
    let host: String
    var evaluated = false
    var evaluationPassed = false
    var discoveredChainSha256: [String] = []
    var lastErrorDetail: String?

    let anchors: [SecCertificate]

    init(host: String, anchors: [SecCertificate]) {
        self.host = host
        self.anchors = anchors
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let policy = SecPolicyCreateSSL(true, host as CFString)
        SecTrustSetPolicies(trust, policy)
        SecTrustSetNetworkFetchAllowed(trust, true)
        if !anchors.isEmpty {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, false)
        }

        var evalError: CFError?
        evaluationPassed = SecTrustEvaluateWithError(trust, &evalError)
        evaluated = true
        if let err = evalError {
            lastErrorDetail = (err as NSError).localizedDescription
        }

        let count = SecTrustGetCertificateCount(trust)
        for i in 0..<count {
            if let cert = SecTrustGetCertificateAtIndex(trust, i) {
                let der = SecCertificateCopyData(cert) as Data
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                der.withUnsafeBytes {
                    _ = CC_SHA256($0.baseAddress, CC_LONG(der.count), &hash)
                }
                discoveredChainSha256.append(hash.map { String(format: "%02x", $0) }.joined())
            }
        }

        if evaluationPassed {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

private class DiagnoseChallengeDelegate: NSObject, URLSessionDelegate {
    let host: String
    var evaluated = false
    var evaluationPassed = false
    var serverSentCerts: [CertInfo] = []
    var completedCerts: [CertInfo] = []
    var lastErrorDetail: String?

    let anchors: [SecCertificate]

    init(host: String, anchors: [SecCertificate]) {
        self.host = host
        self.anchors = anchors
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let count = SecTrustGetCertificateCount(trust)
        var serverHashes = Set<String>()

        for i in 0..<count {
            if let cert = SecTrustGetCertificateAtIndex(trust, i) {
                let der = SecCertificateCopyData(cert) as Data
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                der.withUnsafeBytes {
                    _ = CC_SHA256($0.baseAddress, CC_LONG(der.count), &hash)
                }
                let shaHex = hash.map { String(format: "%02x", $0) }.joined()
                serverHashes.insert(shaHex)

                let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown"
                let info = CertInfo(
                    subjectDn: summary,
                    issuerDn: summary,
                    sha256Hex: shaHex,
                    notBeforeMs: 0,
                    notAfterMs: 0,
                    keyAlgorithm: "X.509",
                    source: .server,
                    sans: nil,
                    aiaUrl: nil
                )
                serverSentCerts.append(info)
            }
        }

        let policy = SecPolicyCreateSSL(true, host as CFString)
        SecTrustSetPolicies(trust, policy)
        SecTrustSetNetworkFetchAllowed(trust, true)
        if !anchors.isEmpty {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, false)
        }

        var evalError: CFError?
        evaluationPassed = SecTrustEvaluateWithError(trust, &evalError)
        evaluated = true
        if let err = evalError {
            lastErrorDetail = (err as NSError).localizedDescription
        }

        let finalCount = SecTrustGetCertificateCount(trust)
        for i in 0..<finalCount {
            if let cert = SecTrustGetCertificateAtIndex(trust, i) {
                let der = SecCertificateCopyData(cert) as Data
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                der.withUnsafeBytes {
                    _ = CC_SHA256($0.baseAddress, CC_LONG(der.count), &hash)
                }
                let shaHex = hash.map { String(format: "%02x", $0) }.joined()
                let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown"

                let src: CertSource
                if serverHashes.contains(shaHex) {
                    src = .server
                } else if i == finalCount - 1 && finalCount > 1 {
                    src = .systemRoot
                } else {
                    src = .aia
                }

                let info = CertInfo(
                    subjectDn: summary,
                    issuerDn: summary,
                    sha256Hex: shaHex,
                    notBeforeMs: 0,
                    notAfterMs: 0,
                    keyAlgorithm: "X.509",
                    source: src,
                    sans: nil,
                    aiaUrl: nil
                )
                completedCerts.append(info)
            }
        }

        if evaluationPassed {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
