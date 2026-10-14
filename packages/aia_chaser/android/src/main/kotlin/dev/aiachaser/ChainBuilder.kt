package dev.aiachaser

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Builds and completes X.509 certificate chains by chasing missing intermediate
 * certificates via Authority Information Access (AIA) caIssuers extensions.
 */
class ChainBuilder(
    private val fetcher: AiaFetcher,
    private val diskCache: DiskIssuerCache? = null,
    private val seedCertificates: List<X509Certificate> = emptyList(),
    private val trustValidator: TrustValidator? = null,
    private val maxDepth: Int = 4
) {

    companion object {
        // OID for Authority Information Access: 1.3.6.1.5.5.7.1.1
        const val OID_AIA = "1.3.6.1.5.5.7.1.1"

        // Encoded bytes of OID 1.3.6.1.5.5.7.48.2 (id-ad-caIssuers)
        // Tag (0x06), Length (0x08), 2B 06 01 05 05 07 30 02
        private val OID_CA_ISSUERS_BYTES = byteArrayOf(
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02
        )

        fun sha256Hex(cert: X509Certificate): String {
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert.encoded)
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    data class BuildResult(
        val chain: List<X509Certificate>,
        val fetchedUrls: List<String>,
        val isSelfSigned: Boolean,
        val hitMaxDepth: Boolean
    )

    /**
     * Extracts AIA caIssuers URLs from an X.509 certificate.
     */
    fun extractCaIssuersUrls(cert: X509Certificate): List<String> {
        val extensionBytes = cert.getExtensionValue(OID_AIA) ?: return emptyList()
        val urls = mutableListOf<String>()

        try {
            // The extension value is wrapped in an ASN.1 OCTET STRING
            var offset = 0
            if (extensionBytes.size > 2 && extensionBytes[0] == 0x04.toByte()) {
                // Read OCTET STRING length
                offset = 2
                if ((extensionBytes[1].toInt() and 0x80) != 0) {
                    val lenBytes = extensionBytes[1].toInt() and 0x7F
                    offset = 2 + lenBytes
                }
            }

            val data = if (offset < extensionBytes.size) {
                extensionBytes.copyOfRange(offset, extensionBytes.size)
            } else {
                extensionBytes
            }

            // Find id-ad-caIssuers OID occurrences
            var idx = 0
            while (idx <= data.size - OID_CA_ISSUERS_BYTES.size) {
                var match = true
                for (j in OID_CA_ISSUERS_BYTES.indices) {
                    if (data[idx + j] != OID_CA_ISSUERS_BYTES[j]) {
                        match = false
                        break
                    }
                }

                if (match) {
                    // Following the OID is GeneralName. For URI, GeneralName tag is [6] (0x86)
                    var uriTagIdx = idx + OID_CA_ISSUERS_BYTES.size
                    if (uriTagIdx < data.size && (data[uriTagIdx].toInt() and 0xFF) == 0x86) {
                        uriTagIdx++
                        // Read length
                        var uriLen = data[uriTagIdx].toInt() and 0xFF
                        uriTagIdx++
                        if ((uriLen and 0x80) != 0) {
                            val numBytes = uriLen and 0x7F
                            uriLen = 0
                            for (b in 0 until numBytes) {
                                uriLen = (uriLen shl 8) or (data[uriTagIdx].toInt() and 0xFF)
                                uriTagIdx++
                            }
                        }

                        if (uriTagIdx + uriLen <= data.size) {
                            val urlString = String(data, uriTagIdx, uriLen, Charsets.US_ASCII).trim()
                            if (urlString.startsWith("http://", ignoreCase = true) ||
                                urlString.startsWith("https://", ignoreCase = true)
                            ) {
                                urls.add(urlString)
                            }
                            idx = uriTagIdx + uriLen
                            continue
                        }
                    }
                }
                idx++
            }
        } catch (_: Exception) {
            // Safe fallback: non-conforming ASN.1 octets
        }

        // Fallback scanner if ASN.1 structure was unusual: scan for ASCII http:// or https://
        if (urls.isEmpty()) {
            val text = String(extensionBytes, Charsets.ISO_8859_1)
            val httpIdx = text.indexOf("http://")
            val httpsIdx = text.indexOf("https://")
            val startIdx = when {
                httpIdx != -1 && httpsIdx != -1 -> Math.min(httpIdx, httpsIdx)
                httpIdx != -1 -> httpIdx
                httpsIdx != -1 -> httpsIdx
                else -> -1
            }

            if (startIdx != -1) {
                val endIdx = text.indexOfAny(charArrayOf(' ', '\u0000', '\n', '\r', '\t', '"'), startIdx)
                val rawUrl = if (endIdx != -1) text.substring(startIdx, endIdx) else text.substring(startIdx)
                val cleaned = rawUrl.filter { it in ' '..'~' }.trim()
                if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
                    urls.add(cleaned)
                }
            }
        }

        return urls.distinct()
    }

    /**
     * Builds the certificate chain starting from [leaf], resolving missing issuers
     * from seeds, disk cache, and AIA network endpoints up to [maxDepth].
     *
     * Prioritizes paths that reach a trusted system anchor, exploring cross-certificates
     * before self-issued roots to handle modern CAs on legacy trust stores.
     */
    fun buildChain(leaf: X509Certificate, host: String? = null): BuildResult {
        val fetchedUrls = mutableListOf<String>()
        val visitedCertHashes = mutableSetOf<String>()

        // 1. Try path exploration to reach a verified system trust anchor
        val trustedChain = findTrustedPath(
            currentChain = listOf(leaf),
            host = host,
            fetchedUrls = fetchedUrls,
            visitedHashes = visitedCertHashes,
            depth = 0
        )

        if (trustedChain != null) {
            return BuildResult(
                chain = trustedChain,
                fetchedUrls = fetchedUrls.distinct(),
                isSelfSigned = isSelfIssued(trustedChain.last()),
                hitMaxDepth = false
            )
        }

        // 2. Fallback: linear accumulation so detailed diagnostics and reasons can be reported
        return buildLinearChain(leaf, fetchedUrls)
    }

    private fun findTrustedPath(
        currentChain: List<X509Certificate>,
        host: String?,
        fetchedUrls: MutableList<String>,
        visitedHashes: MutableSet<String>,
        depth: Int
    ): List<X509Certificate>? {
        val top = currentChain.last()
        visitedHashes.add(sha256Hex(top))

        // Check if current chain is trusted by system trust store
        if (trustValidator != null && !host.isNullOrEmpty()) {
            val check = trustValidator.validateSystemTrust(currentChain, host)
            if (check is TrustValidator.TrustResult.Trusted || check is TrustValidator.TrustResult.Pinned) {
                return currentChain
            }
        }

        if (depth >= maxDepth) {
            return null
        }

        if (isSelfIssued(top)) {
            // Self-signed certificate that failed trust validation; dead end
            return null
        }

        val candidates = mutableListOf<X509Certificate>()

        // 1. Check seeds
        for (seed in seedCertificates) {
            if (isValidIssuer(top, seed)) {
                candidates.add(seed)
            }
        }

        // 2. Check disk cache
        if (diskCache != null) {
            val cached = diskCache.findBySubject(top.issuerX500Principal.name)
            for (c in cached) {
                if (isValidIssuer(top, c)) {
                    candidates.add(c)
                }
            }
        }

        // 3. Fetch from AIA caIssuers URLs
        val aiaUrls = extractCaIssuersUrls(top)
        for (url in aiaUrls) {
            if (!fetchedUrls.contains(url)) {
                fetchedUrls.add(url)
            }
            try {
                val fetched = fetcher.fetchCertificates(url)
                for (c in fetched) {
                    if (isValidIssuer(top, c)) {
                        diskCache?.put(url, c)
                        candidates.add(c)
                    }
                }
            } catch (_: Exception) {}
        }

        // Deduplicate and filter out loop candidates
        val uniqueCandidates = candidates.distinctBy { sha256Hex(it) }
            .filter { !visitedHashes.contains(sha256Hex(it)) }

        // Prioritize cross-certificates (isSelfIssued == false) before self-issued roots (isSelfIssued == true)
        val sortedCandidates = uniqueCandidates.sortedBy { isSelfIssued(it) }

        for (candidate in sortedCandidates) {
            val path = findTrustedPath(
                currentChain = currentChain + candidate,
                host = host,
                fetchedUrls = fetchedUrls,
                visitedHashes = visitedHashes.toMutableSet(),
                depth = depth + 1
            )
            if (path != null) {
                return path
            }
        }

        return null
    }

    private fun buildLinearChain(leaf: X509Certificate, fetchedUrls: MutableList<String>): BuildResult {
        val currentChain = mutableListOf<X509Certificate>(leaf)
        val visitedCertHashes = mutableSetOf<String>()
        visitedCertHashes.add(sha256Hex(leaf))

        var depth = 0
        var hitMaxDepth = false

        while (depth < maxDepth) {
            val top = currentChain.last()

            if (isSelfIssued(top)) {
                return BuildResult(
                    chain = currentChain,
                    fetchedUrls = fetchedUrls.distinct(),
                    isSelfSigned = true,
                    hitMaxDepth = false
                )
            }

            val issuerFromPool = findIssuerInPool(top)
            if (issuerFromPool != null) {
                val hash = sha256Hex(issuerFromPool)
                if (visitedCertHashes.contains(hash)) {
                    break
                }
                visitedCertHashes.add(hash)
                currentChain.add(issuerFromPool)
                depth++
                continue
            }

            val aiaUrls = extractCaIssuersUrls(top)
            if (aiaUrls.isEmpty()) {
                break
            }

            var resolvedNewIssuer = false
            for (url in aiaUrls) {
                if (!fetchedUrls.contains(url)) {
                    fetchedUrls.add(url)
                }
                try {
                    val fetchedCerts = fetcher.fetchCertificates(url)
                    val sorted = fetchedCerts.sortedBy { isSelfIssued(it) }
                    for (candidate in sorted) {
                        if (isValidIssuer(top, candidate)) {
                            diskCache?.put(url, candidate)
                            val hash = sha256Hex(candidate)
                            if (!visitedCertHashes.contains(hash)) {
                                visitedCertHashes.add(hash)
                                currentChain.add(candidate)
                                resolvedNewIssuer = true
                                break
                            }
                        }
                    }
                    if (resolvedNewIssuer) break
                } catch (_: Exception) {}
            }

            if (!resolvedNewIssuer) {
                break
            }

            depth++
        }

        if (depth >= maxDepth) {
            hitMaxDepth = true
        }

        return BuildResult(
            chain = currentChain,
            fetchedUrls = fetchedUrls.distinct(),
            isSelfSigned = isSelfIssued(currentChain.last()),
            hitMaxDepth = hitMaxDepth
        )
    }

    private fun findIssuerInPool(child: X509Certificate): X509Certificate? {
        // Check seeds
        for (seed in seedCertificates) {
            if (isValidIssuer(child, seed)) {
                return seed
            }
        }

        // Check disk cache
        if (diskCache != null) {
            val cached = diskCache.findBySubject(child.issuerX500Principal.name)
            for (cand in cached) {
                if (isValidIssuer(child, cand)) {
                    return cand
                }
            }
        }

        return null
    }

    private fun isValidIssuer(child: X509Certificate, candidate: X509Certificate): Boolean {
        // 1. Subject of candidate must match Issuer of child
        if (child.issuerX500Principal != candidate.subjectX500Principal) {
            return false
        }

        // 2. Candidate must be a Certificate Authority (basicConstraints != -1)
        if (candidate.basicConstraints == -1) {
            return false
        }

        // 3. Candidate's public key must cryptographically verify child's signature
        return try {
            child.verify(candidate.publicKey)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun isSelfIssued(cert: X509Certificate): Boolean {
        return cert.subjectX500Principal == cert.issuerX500Principal
    }
}
