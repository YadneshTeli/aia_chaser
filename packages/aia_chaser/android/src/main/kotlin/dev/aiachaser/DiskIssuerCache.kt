package dev.aiachaser

import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Collections

/**
 * On-disk persistent cache for public intermediate certificates fetched via AIA.
 * Stores DER-encoded certificate files and an index.json under <cacheDir>/aia_chaser/v1/.
 * Maximum 64 entries and 2 MB disk footprint with LRU eviction.
 */
class DiskIssuerCache(private val cacheDir: File) {

    private val baseDir = File(cacheDir, "aia_chaser/v1")
    private val indexFile = File(baseDir, "index.json")
    private val certFactory = CertificateFactory.getInstance("X.509")

    data class CacheEntry(
        val urlHash: String,
        val url: String,
        val certSha256: String,
        val subjectDn: String,
        val issuerDn: String,
        val notAfter: Long,
        var fetchedAt: Long,
        val sizeBytes: Long
    )

    private val entries = Collections.synchronizedMap(LinkedHashMap<String, CacheEntry>())
    private val maxEntries = 64
    private val maxTotalBytes = 2L * 1024 * 1024 // 2 MB

    init {
        ensureDirs()
        loadIndex()
    }

    private fun ensureDirs() {
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }
    }

    @Synchronized
    fun put(url: String, cert: X509Certificate) {
        ensureDirs()
        val urlHash = sha256Hex(url.toByteArray(Charsets.UTF_8))
        val certBytes = cert.encoded
        val certSha256 = sha256Hex(certBytes)
        val derFile = File(baseDir, "$urlHash.der")

        // Atomic write to temp file then rename
        val tmpFile = File(baseDir, "$urlHash.der.tmp")
        try {
            FileOutputStream(tmpFile).use { fos ->
                fos.write(certBytes)
            }
            if (tmpFile.renameTo(derFile)) {
                val entry = CacheEntry(
                    urlHash = urlHash,
                    url = url,
                    certSha256 = certSha256,
                    subjectDn = cert.subjectX500Principal.name,
                    issuerDn = cert.issuerX500Principal.name,
                    notAfter = cert.notAfter.time,
                    fetchedAt = System.currentTimeMillis(),
                    sizeBytes = certBytes.size.toLong()
                )
                entries[urlHash] = entry
                enforceLimits()
                saveIndex()
            }
        } catch (_: Exception) {
            tmpFile.delete()
        }
    }

    @Synchronized
    fun findBySubject(subjectDn: String): List<X509Certificate> {
        val now = System.currentTimeMillis()
        val results = mutableListOf<X509Certificate>()

        for (entry in entries.values.toList()) {
            if (entry.subjectDn.equals(subjectDn, ignoreCase = true)) {
                if (entry.notAfter < now) {
                    // Skip expired entry
                    continue
                }
                val derFile = File(baseDir, "${entry.urlHash}.der")
                if (derFile.exists()) {
                    try {
                        derFile.inputStream().use { stream ->
                            val cert = certFactory.generateCertificate(stream) as? X509Certificate
                            if (cert != null) {
                                entry.fetchedAt = now // Update for LRU
                                results.add(cert)
                            }
                        }
                    } catch (_: Exception) {
                        derFile.delete()
                    }
                }
            }
        }
        return results
    }

    @Synchronized
    fun clear() {
        entries.clear()
        baseDir.listFiles()?.forEach { it.delete() }
    }

    @Synchronized
    fun getStats(): Pair<Int, Long> {
        var totalBytes = 0L
        for (e in entries.values) {
            totalBytes += e.sizeBytes
        }
        return Pair(entries.size, totalBytes)
    }

    private fun enforceLimits() {
        var totalBytes = entries.values.sumOf { it.sizeBytes }

        // Evict LRU while exceeding limits
        val iterator = entries.entries.iterator()
        while (iterator.hasNext() && (entries.size > maxEntries || totalBytes > maxTotalBytes)) {
            val next = iterator.next()
            val file = File(baseDir, "${next.value.urlHash}.der")
            file.delete()
            totalBytes -= next.value.sizeBytes
            iterator.remove()
        }
    }

    private fun loadIndex() {
        if (!indexFile.exists()) return

        try {
            val jsonText = indexFile.readText(Charsets.UTF_8)
            // Simple robust JSON parser without external dependencies
            val entryList = parseSimpleJsonEntries(jsonText)
            val now = System.currentTimeMillis()
            entries.clear()

            for (e in entryList) {
                val derFile = File(baseDir, "${e.urlHash}.der")
                if (derFile.exists() && e.notAfter > now) {
                    entries[e.urlHash] = e
                } else {
                    derFile.delete()
                }
            }
        } catch (_: Exception) {
            // Rebuild if index is corrupted
            entries.clear()
        }
    }

    private fun saveIndex() {
        try {
            val sb = java.lang.StringBuilder()
            sb.append("{\n  \"schema_version\": 1,\n  \"entries\": [\n")
            val list = entries.values.toList()
            for (i in list.indices) {
                val e = list[i]
                sb.append("    {\n")
                sb.append("      \"url_hash\": \"").append(escapeJson(e.urlHash)).append("\",\n")
                sb.append("      \"url\": \"").append(escapeJson(e.url)).append("\",\n")
                sb.append("      \"cert_sha256\": \"").append(escapeJson(e.certSha256)).append("\",\n")
                sb.append("      \"subject_dn\": \"").append(escapeJson(e.subjectDn)).append("\",\n")
                sb.append("      \"issuer_dn\": \"").append(escapeJson(e.issuerDn)).append("\",\n")
                sb.append("      \"not_after\": ").append(e.notAfter).append(",\n")
                sb.append("      \"fetched_at\": ").append(e.fetchedAt).append(",\n")
                sb.append("      \"size_bytes\": ").append(e.sizeBytes).append("\n")
                sb.append("    }")
                if (i < list.size - 1) sb.append(",")
                sb.append("\n")
            }
            sb.append("  ]\n}\n")

            val tmpIndex = File(baseDir, "index.json.tmp")
            tmpIndex.writeText(sb.toString(), Charsets.UTF_8)
            tmpIndex.renameTo(indexFile)
        } catch (_: Exception) {
            // Ignore index save failure
        }
    }

    private fun escapeJson(str: String): String {
        return str.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
    }

    private fun parseSimpleJsonEntries(json: String): List<CacheEntry> {
        val result = mutableListOf<CacheEntry>()
        val blocks = json.split("}")
        for (b in blocks) {
            val urlHash = extractJsonValue(b, "url_hash") ?: continue
            val url = extractJsonValue(b, "url") ?: ""
            val certSha256 = extractJsonValue(b, "cert_sha256") ?: ""
            val subjectDn = extractJsonValue(b, "subject_dn") ?: ""
            val issuerDn = extractJsonValue(b, "issuer_dn") ?: ""
            val notAfter = extractJsonValue(b, "not_after")?.toLongOrNull() ?: 0L
            val fetchedAt = extractJsonValue(b, "fetched_at")?.toLongOrNull() ?: 0L
            val sizeBytes = extractJsonValue(b, "size_bytes")?.toLongOrNull() ?: 0L

            result.add(
                CacheEntry(
                    urlHash = urlHash,
                    url = url,
                    certSha256 = certSha256,
                    subjectDn = subjectDn,
                    issuerDn = issuerDn,
                    notAfter = notAfter,
                    fetchedAt = fetchedAt,
                    sizeBytes = sizeBytes
                )
            )
        }
        return result
    }

    private fun extractJsonValue(block: String, key: String): String? {
        val target = "\"$key\""
        val idx = block.indexOf(target)
        if (idx == -1) return null
        val colonIdx = block.indexOf(":", idx + target.length)
        if (colonIdx == -1) return null

        val sub = block.substring(colonIdx + 1).trim()
        return if (sub.startsWith("\"")) {
            val endQuote = sub.indexOf("\"", 1)
            if (endQuote != -1) sub.substring(1, endQuote) else null
        } else {
            val endComma = sub.indexOfAny(charArrayOf(',', '\n', '\r', '}'))
            if (endComma != -1) sub.substring(0, endComma).trim() else sub.trim()
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
