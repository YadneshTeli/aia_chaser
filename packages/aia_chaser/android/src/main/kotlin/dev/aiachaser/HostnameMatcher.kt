package dev.aiachaser

import java.net.InetAddress
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * RFC 6125 compliant hostname verification against X.509 Subject Alternative Names (SANs).
 */
object HostnameMatcher {

    private const val SAN_DNS = 2
    private const val SAN_IP = 7

    /**
     * Verifies if the given [certificate] is valid for [hostnameOrIp].
     * Following RFC 6125:
     * - Checks SAN (DNS and IP) extensions.
     * - If SAN is present, Common Name (CN) is ignored.
     * - Wildcards are only accepted as the sole leftmost label (e.g. *.example.com).
     * - Partial wildcards (e.g. f*o.com) are rejected.
     */
    fun verify(hostnameOrIp: String, certificate: X509Certificate): Boolean {
        val normalizedTarget = hostnameOrIp.trim().lowercase(Locale.US)
        if (normalizedTarget.isEmpty()) return false

        val isIp = isIpAddress(normalizedTarget)
        val sans = getSubjectAlternativeNames(certificate)

        if (sans != null && sans.isNotEmpty()) {
            if (isIp) {
                // Match against IP SANs
                for (san in sans) {
                    if (san.type == SAN_IP) {
                        val sanIp = san.value.trim().lowercase(Locale.US)
                        if (matchIp(normalizedTarget, sanIp)) {
                            return true
                        }
                    }
                }
            } else {
                // Match against DNS SANs
                for (san in sans) {
                    if (san.type == SAN_DNS) {
                        val sanDns = san.value.trim().lowercase(Locale.US)
                        if (matchDns(normalizedTarget, sanDns)) {
                            return true
                        }
                    }
                }
            }
            return false
        }

        // Fallback to CN only if SAN is completely absent
        if (!isIp) {
            val cn = extractCommonName(certificate.subjectX500Principal.name)
            if (cn != null) {
                return matchDns(normalizedTarget, cn.lowercase(Locale.US))
            }
        }

        return false
    }

    fun getSans(certificate: X509Certificate): List<String> {
        val result = mutableListOf<String>()
        val sans = getSubjectAlternativeNames(certificate) ?: return result
        for (san in sans) {
            val prefix = if (san.type == SAN_IP) "IP:" else "DNS:"
            result.add("$prefix${san.value}")
        }
        return result
    }

    private fun matchDns(targetHost: String, pattern: String): Boolean {
        if (targetHost == pattern) {
            return true
        }

        // Wildcard match: e.g. *.example.com
        if (pattern.startsWith("*.")) {
            val wildcardSuffix = pattern.substring(1) // .example.com
            // Ensure target has a single leftmost label before suffix
            if (targetHost.endsWith(wildcardSuffix)) {
                val prefix = targetHost.substring(0, targetHost.length - wildcardSuffix.length)
                // Leftmost label must not contain '.' (only single level)
                if (prefix.isNotEmpty() && !prefix.contains('.')) {
                    return true
                }
            }
        }

        return false
    }

    private fun matchIp(targetIp: String, sanIp: String): Boolean {
        if (targetIp == sanIp) return true
        return try {
            val targetAddr = InetAddress.getByName(targetIp)
            val sanAddr = InetAddress.getByName(sanIp)
            targetAddr == sanAddr
        } catch (_: Exception) {
            false
        }
    }

    private fun isIpAddress(host: String): Boolean {
        return try {
            // Check IPv4 or IPv6
            val parts = host.split(".")
            if (parts.size == 4) {
                parts.all { it.toIntOrNull() in 0..255 }
            } else {
                host.contains(":")
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun extractCommonName(dn: String): String? {
        val parts = dn.split(",")
        for (part in parts) {
            val trimmed = part.trim()
            if (trimmed.startsWith("CN=", ignoreCase = true)) {
                return trimmed.substring(3).trim()
            }
        }
        return null
    }

    private data class SanEntry(val type: Int, val value: String)

    private fun getSubjectAlternativeNames(cert: X509Certificate): List<SanEntry>? {
        return try {
            val entries = cert.subjectAlternativeNames ?: return null
            val result = mutableListOf<SanEntry>()
            for (entry in entries) {
                if (entry.size >= 2) {
                    val type = (entry[0] as? Number)?.toInt() ?: continue
                    val value = entry[1]?.toString() ?: continue
                    result.add(SanEntry(type, value))
                }
            }
            result
        } catch (_: CertificateParsingException) {
            null
        }
    }
}
