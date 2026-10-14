package dev.aiachaser

import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Capture-only TLS probe for prewarming and diagnosing server certificate chains.
 */
class Prober(
    private val chainBuilder: ChainBuilder,
    private val trustValidator: TrustValidator
) {

    private val certFactory = CertificateFactory.getInstance("X.509")

    data class ProbeResult(
        val serverChain: List<X509Certificate>,
        val leafCert: X509Certificate?
    )

    /**
     * Connects to [host]:[port] using a capture-only trust manager and retrieves
     * the exact certificate chain presented by the remote server.
     */
    fun captureServerChain(host: String, port: Int, timeoutMs: Int): ProbeResult {
        val capturedChain = mutableListOf<X509Certificate>()

        val captureTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain != null) {
                    for (c in chain) {
                        capturedChain.add(c)
                    }
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(captureTrustManager), SecureRandom())
        val socketFactory: SSLSocketFactory = sslContext.socketFactory

        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        socket.soTimeout = timeoutMs

        val sslSocket = socketFactory.createSocket(socket, host, port, true) as SSLSocket
        try {
            sslSocket.startHandshake()
        } catch (_: Exception) {
            // Handshake might fail on untrusted certs or abort, but capturedChain will have certificates
        } finally {
            try {
                sslSocket.close()
            } catch (_: Exception) {}
        }

        val leaf = capturedChain.firstOrNull()
        return ProbeResult(serverChain = capturedChain, leafCert = leaf)
    }

    /**
     * Runs a full diagnosis on [host]:[port] and returns a detailed ChainReport.
     */
    fun diagnose(host: String, port: Int, timeoutMs: Int): ChainReport {
        val startTime = System.currentTimeMillis()
        val probe = try {
            captureServerChain(host, port, timeoutMs)
        } catch (e: Exception) {
            val elapsed = (System.currentTimeMillis() - startTime).toInt()
            return ChainReport(
                host = host,
                port = port.toLong(),
                serverSentChain = emptyList(),
                completedChain = emptyList(),
                outcome = ValidationOutcome.AIA_UNAVAILABLE,
                cause = "Failed to connect to $host:$port: ${e.message}",
                suggestedFix = "Verify DNS resolution and network connectivity to the target server.",
                durationMs = elapsed.toLong()
            )
        }

        val leaf = probe.leafCert
        if (leaf == null) {
            val elapsed = (System.currentTimeMillis() - startTime).toInt()
            return ChainReport(
                host = host,
                port = port.toLong(),
                serverSentChain = emptyList(),
                completedChain = emptyList(),
                outcome = ValidationOutcome.NO_CERTIFICATE,
                cause = "Server did not present any SSL/TLS certificates during handshake.",
                suggestedFix = "Ensure the server is running TLS and configured with a certificate.",
                durationMs = elapsed.toLong()
            )
        }

        // Hostname check
        if (!HostnameMatcher.verify(host, leaf)) {
            val elapsed = (System.currentTimeMillis() - startTime).toInt()
            return ChainReport(
                host = host,
                port = port.toLong(),
                serverSentChain = mapCertsToInfo(probe.serverChain, CertSource.SERVER),
                completedChain = mapCertsToInfo(probe.serverChain, CertSource.SERVER),
                outcome = ValidationOutcome.REJECTED_HOSTNAME,
                cause = "Certificate Subject Alternative Names (SANs) do not match host '$host'.",
                suggestedFix = "Issue a certificate that includes '$host' in its Subject Alternative Names.",
                durationMs = elapsed.toLong()
            )
        }

        // Validity check
        val now = Date()
        if (now.before(leaf.notBefore) || now.after(leaf.notAfter)) {
            val elapsed = (System.currentTimeMillis() - startTime).toInt()
            return ChainReport(
                host = host,
                port = port.toLong(),
                serverSentChain = mapCertsToInfo(probe.serverChain, CertSource.SERVER),
                completedChain = mapCertsToInfo(probe.serverChain, CertSource.SERVER),
                outcome = ValidationOutcome.REJECTED_EXPIRED,
                cause = "Leaf certificate is expired or not yet valid (Valid from ${leaf.notBefore} to ${leaf.notAfter}).",
                suggestedFix = "Renew the expired certificate on the server.",
                durationMs = elapsed.toLong()
            )
        }

        // Build chain via AIA
        val buildResult = chainBuilder.buildChain(leaf)
        val completedCerts = buildResult.chain

        // Validate completed chain against system trust
        val trustResult = trustValidator.validateSystemTrust(completedCerts, host)
        val elapsed = (System.currentTimeMillis() - startTime).toInt()

        val serverInfos = mapCertsToInfo(probe.serverChain, CertSource.SERVER)
        val completedInfos = mutableListOf<CertInfo>()

        for (c in completedCerts) {
            val isServerSent = probe.serverChain.any { it.subjectX500Principal == c.subjectX500Principal }
            val source = if (isServerSent) CertSource.SERVER else CertSource.AIA
            completedInfos.add(certToInfo(c, source))
        }

        return when (trustResult) {
            is TrustValidator.TrustResult.Trusted -> {
                val fetchedCount = buildResult.fetchedUrls.size
                val causeText = if (fetchedCount > 0) {
                    "Server sent an incomplete chain (${probe.serverChain.size} certs). AIA Chaser completed the chain by fetching $fetchedCount intermediate certificate(s)."
                } else {
                    "Server sent a valid and complete certificate chain."
                }
                val fixText = if (fetchedCount > 0) {
                    "Configure your web server to serve the full chain bundle (e.g. 'fullchain.pem' instead of 'cert.pem') to eliminate client-side AIA fetching."
                } else {
                    "No server changes required; certificate chain is properly configured."
                }

                ChainReport(
                    host = host,
                    port = port.toLong(),
                    serverSentChain = serverInfos,
                    completedChain = completedInfos,
                    outcome = ValidationOutcome.VALIDATED,
                    cause = causeText,
                    suggestedFix = fixText,
                    durationMs = elapsed.toLong()
                )
            }
            is TrustValidator.TrustResult.Pinned -> {
                ChainReport(
                    host = host,
                    port = port.toLong(),
                    serverSentChain = serverInfos,
                    completedChain = completedInfos,
                    outcome = ValidationOutcome.VALIDATED_BY_PIN,
                    cause = "Certificate validated by matching an explicit developer-configured pin.",
                    suggestedFix = "If this is a private or custom CA, ensure pins are updated when certificates rotate.",
                    durationMs = elapsed.toLong()
                )
            }
            is TrustValidator.TrustResult.Untrusted -> {
                val cause = if (buildResult.isSelfSigned) {
                    "Server certificate is self-signed and not trusted by the Android system trust store."
                } else if (buildResult.hitMaxDepth) {
                    "AIA chasing exceeded maximum chain depth (${completedCerts.size} certificates) without reaching a trusted root."
                } else {
                    "Certificate chain could not be verified against the Android system trust store: ${trustResult.reason}"
                }

                ChainReport(
                    host = host,
                    port = port.toLong(),
                    serverSentChain = serverInfos,
                    completedChain = completedInfos,
                    outcome = ValidationOutcome.REJECTED_UNTRUSTED,
                    cause = cause,
                    suggestedFix = "Ensure the server certificate is issued by a globally trusted Certificate Authority.",
                    durationMs = elapsed.toLong()
                )
            }
        }
    }

    private fun mapCertsToInfo(certs: List<X509Certificate>, defaultSource: CertSource): List<CertInfo> {
        return certs.map { certToInfo(it, defaultSource) }
    }

    private fun certToInfo(cert: X509Certificate, source: CertSource): CertInfo {
        val md = MessageDigest.getInstance("SHA-256")
        val sha256 = md.digest(cert.encoded).joinToString("") { "%02x".format(it) }
        val aiaUrls = chainBuilder.extractCaIssuersUrls(cert)

        return CertInfo(
            subjectDn = cert.subjectX500Principal.name,
            issuerDn = cert.issuerX500Principal.name,
            sha256Hex = sha256,
            notBeforeMs = cert.notBefore.time,
            notAfterMs = cert.notAfter.time,
            keyAlgorithm = cert.publicKey.algorithm ?: "RSA",
            source = source,
            sans = HostnameMatcher.getSans(cert),
            aiaUrl = aiaUrls.firstOrNull()
        )
    }
}
