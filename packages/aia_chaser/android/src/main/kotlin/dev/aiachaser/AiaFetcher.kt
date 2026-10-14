package dev.aiachaser

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

class AiaSecurityException(message: String) : SecurityException(message)
class AiaPayloadTooLargeException(message: String) : Exception(message)

/**
 * SSRF-hardened HTTP client for fetching missing CA certificates via AIA caIssuers URLs.
 */
class AiaFetcher(
    private val connectTimeoutMs: Int = 3000,
    private val readTimeoutMs: Int = 3000,
    private val maxBytes: Int = 64 * 1024,
    private val maxRedirects: Int = 3,
    private val blockPrivateAddresses: Boolean = true
) {

    private val certFactory = CertificateFactory.getInstance("X.509")

    /**
     * Fetches and parses certificates from the given [rawUrl].
     * Returns a list of certificates found (e.g. from DER, PEM, or PKCS#7 bundles).
     */
    fun fetchCertificates(rawUrl: String): List<X509Certificate> {
        val certBytes = fetchBytesWithSsrfProtection(rawUrl, 0)
        return parseCertificates(certBytes)
    }

    private fun fetchBytesWithSsrfProtection(rawUrl: String, redirectCount: Int): ByteArray {
        if (redirectCount > maxRedirects) {
            throw AiaSecurityException("Exceeded maximum redirect limit ($maxRedirects) for URL: $rawUrl")
        }

        val uri = URI(rawUrl)
        val scheme = uri.scheme?.lowercase(Locale.US)
        if (scheme != "http" && scheme != "https") {
            throw AiaSecurityException("Unsupported scheme '$scheme' in AIA URL: $rawUrl. Only http and https are permitted.")
        }

        val host = uri.host ?: throw AiaSecurityException("Missing host in AIA URL: $rawUrl")

        if (blockPrivateAddresses) {
            validateHostAddresses(host)
        }

        val url = uri.toURL()
        val connection = (url.openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false // Manually handle redirects to enforce SSRF checks on every hop
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AIA-Chaser/1.0 (Android; +https://github.com/aiachaser/aia_chaser)")
            setRequestProperty("Accept", "application/pkix-cert, application/x-x509-ca-cert, application/x-pkcs7-certificates, */*")
        }

        try {
            connection.connect()
            val responseCode = connection.responseCode

            // Handle redirects
            if (responseCode in 300..399) {
                val location = connection.getHeaderField("Location")
                    ?: throw AiaSecurityException("Redirect status $responseCode with missing Location header for $rawUrl")
                val resolvedTarget = uri.resolve(location).toString()
                return fetchBytesWithSsrfProtection(resolvedTarget, redirectCount + 1)
            }

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw Exception("AIA server returned HTTP $responseCode for $rawUrl")
            }

            val inputStream = connection.inputStream ?: throw Exception("Empty input stream for $rawUrl")
            return readStreamWithCap(inputStream, maxBytes)
        } finally {
            connection.disconnect()
        }
    }

    private fun validateHostAddresses(host: String) {
        val addresses = try {
            InetAddress.getAllByName(host)
        } catch (e: Exception) {
            throw AiaSecurityException("DNS resolution failed for AIA host '$host': ${e.message}")
        }

        for (addr in addresses) {
            if (isPrivateOrLocalAddress(addr)) {
                throw AiaSecurityException(
                    "AIA URL targets prohibited private/local network address (${addr.hostAddress}) for host: $host"
                )
            }
        }
    }

    /**
     * Checks if an IP address falls into loopback, private, link-local, or unique-local ranges.
     */
    fun isPrivateOrLocalAddress(addr: InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isLinkLocalAddress || addr.isSiteLocalAddress) {
            return true
        }

        if (addr.isAnyLocalAddress || addr.isMulticastAddress) {
            return true
        }

        when (addr) {
            is Inet4Address -> {
                val bytes = addr.address
                val b0 = bytes[0].toInt() and 0xFF
                val b1 = bytes[1].toInt() and 0xFF

                // 10.0.0.0/8
                if (b0 == 10) return true
                // 172.16.0.0/12
                if (b0 == 172 && (b1 in 16..31)) return true
                // 192.168.0.0/16
                if (b0 == 192 && b1 == 168) return true
                // 127.0.0.0/8
                if (b0 == 127) return true
                // 169.254.0.0/16
                if (b0 == 169 && b1 == 254) return true
                // 100.64.0.0/10 (Carrier-grade NAT)
                if (b0 == 100 && (b1 in 64..127)) return true
                // 0.0.0.0/8
                if (b0 == 0) return true
            }
            is Inet6Address -> {
                val bytes = addr.address
                val b0 = bytes[0].toInt() and 0xFF
                // Unique-local fc00::/7 (0xfc or 0xfd)
                if ((b0 and 0xFE) == 0xFC) return true
                // Link-local fe80::/10
                if (b0 == 0xFE && ((bytes[1].toInt() and 0xC0) == 0x80)) return true
                // IPv4-mapped IPv6 address ::ffff:x.x.x.x
                if (isIPv4MappedIPv6(bytes)) {
                    val ipv4Bytes = bytes.copyOfRange(12, 16)
                    val ipv4 = InetAddress.getByAddress(ipv4Bytes)
                    return isPrivateOrLocalAddress(ipv4)
                }
            }
        }

        return false
    }

    private fun isIPv4MappedIPv6(bytes: ByteArray): Boolean {
        if (bytes.size != 16) return false
        for (i in 0 until 10) {
            if (bytes[i] != 0.toByte()) return false
        }
        return bytes[10] == 0xFF.toByte() && bytes[11] == 0xFF.toByte()
    }

    private fun readStreamWithCap(inputStream: InputStream, cap: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var totalBytesRead = 0

        inputStream.use { stream ->
            var bytesRead: Int
            while (stream.read(buffer).also { bytesRead = it } != -1) {
                totalBytesRead += bytesRead
                if (totalBytesRead > cap) {
                    throw AiaPayloadTooLargeException("AIA response exceeded maximum allowed payload size ($cap bytes)")
                }
                output.write(buffer, 0, bytesRead)
            }
        }

        return output.toByteArray()
    }

    private fun parseCertificates(bytes: ByteArray): List<X509Certificate> {
        val certs = mutableListOf<X509Certificate>()
        val stream = ByteArrayInputStream(bytes)

        try {
            // CertificateFactory handles single DER, PEM, and PKCS#7 certificate collections
            val parsed = certFactory.generateCertificates(stream)
            for (c in parsed) {
                if (c is X509Certificate) {
                    certs.add(c)
                }
            }
        } catch (_: Exception) {
            // Fallback: try generateCertificate for single DER
            val singleStream = ByteArrayInputStream(bytes)
            try {
                val singleCert = certFactory.generateCertificate(singleStream)
                if (singleCert is X509Certificate) {
                    certs.add(singleCert)
                }
            } catch (e: Exception) {
                throw Exception("Failed to parse certificate from AIA response: ${e.message}", e)
            }
        }

        if (certs.isEmpty()) {
            throw Exception("No valid X.509 certificates found in AIA response")
        }

        return certs
    }
}
