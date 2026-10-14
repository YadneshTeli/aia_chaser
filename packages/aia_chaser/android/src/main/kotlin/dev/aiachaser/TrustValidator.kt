package dev.aiachaser

import android.net.http.X509TrustManagerExtensions
import android.util.Base64
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Validates constructed certificate chains using Android's system trust store (via X509TrustManagerExtensions)
 * and optional SPKI/Certificate SHA-256 pinning.
 */
class TrustValidator(
    private val trustUserCaCerts: Boolean = true
) {

    private val trustManager: X509TrustManager?
    private val trustManagerExtensions: X509TrustManagerExtensions?

    init {
        var tm: X509TrustManager? = null
        var tme: X509TrustManagerExtensions? = null
        try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            tm = tmf.trustManagers.firstOrNull { it is X509TrustManager } as? X509TrustManager
            if (tm != null) {
                try {
                    tme = X509TrustManagerExtensions(tm)
                } catch (_: Exception) {
                    // Fallback to standard X509TrustManager if Conscrypt extensions are unavailable
                }
            }
        } catch (_: Exception) {}
        trustManager = tm
        trustManagerExtensions = tme
    }

    sealed class TrustResult {
        data class Trusted(val fullChain: List<X509Certificate>) : TrustResult()
        data class Untrusted(val reason: String, val exception: Exception? = null) : TrustResult()
        data class Pinned(val matchedPin: String) : TrustResult()
    }

    /**
     * Validates [chain] against the system trust store for [host].
     */
    fun validateSystemTrust(chain: List<X509Certificate>, host: String): TrustResult {
        if (chain.isEmpty()) {
            return TrustResult.Untrusted("Certificate chain is empty")
        }

        val leaf = chain.first()
        val authType = deriveAuthType(leaf)
        val chainArray = chain.toTypedArray()

        return try {
            val tme = trustManagerExtensions
            if (tme != null) {
                val verified = tme.checkServerTrusted(chainArray, authType, host)
                TrustResult.Trusted(verified)
            } else {
                val tm = trustManager ?: return TrustResult.Untrusted("No system TrustManager available")
                tm.checkServerTrusted(chainArray, authType)
                TrustResult.Trusted(chain.toList())
            }
        } catch (e: CertificateException) {
            TrustResult.Untrusted("System trust evaluation failed: ${e.message}", e)
        } catch (e: Exception) {
            TrustResult.Untrusted("Unexpected validation error: ${e.message}", e)
        }
    }

    /**
     * Checks if any certificate in [chain] matches configured pins.
     * [pins] can contain:
     * - "sha256/<hex>" for certificate SHA-256
     * - "spki/<base64>" for SubjectPublicKeyInfo SHA-256
     */
    fun matchesPin(chain: List<X509Certificate>, pins: Set<String>): TrustResult {
        if (pins.isEmpty()) return TrustResult.Untrusted("No pins configured")
        if (chain.isEmpty()) return TrustResult.Untrusted("Empty chain")

        val leaf = chain.first()
        val leafCertHash = sha256Hex(leaf.encoded)

        for (pin in pins) {
            val clean = pin.trim()
            if (clean.startsWith("cert_sha256:", ignoreCase = true) || clean.startsWith("sha256/", ignoreCase = true)) {
                val expectedHex = clean.substringAfter(":").substringAfter("/").trim().lowercase()
                if (leafCertHash.equals(expectedHex, ignoreCase = true)) {
                    return TrustResult.Pinned(clean)
                }
            } else if (clean.startsWith("spki_sha256:", ignoreCase = true) || clean.startsWith("pin-sha256=\"", ignoreCase = true)) {
                val expectedBase64 = clean.substringAfter(":").replace("pin-sha256=\"", "").replace("\"", "").trim()
                for (cert in chain) {
                    val spkiHash = sha256Base64(cert.publicKey.encoded)
                    if (spkiHash == expectedBase64) {
                        return TrustResult.Pinned(clean)
                    }
                }
            }
        }

        return TrustResult.Untrusted("No configured pins matched the chain")
    }

    private fun deriveAuthType(cert: X509Certificate): String {
        val alg = cert.publicKey.algorithm ?: return "RSA"
        return when {
            alg.contains("RSA", ignoreCase = true) -> "RSA"
            alg.contains("EC", ignoreCase = true) -> "ECDSA"
            alg.contains("DSA", ignoreCase = true) -> "DSA"
            else -> alg
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun sha256Base64(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return Base64.encodeToString(md.digest(bytes), Base64.NO_WRAP)
    }
}
