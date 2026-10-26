package dev.aiachaser

import android.content.Context
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.BinaryMessenger
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future

class AiaChaserPlugin : FlutterPlugin, AiaChaserHostApi {

    private var context: Context? = null
    private var flutterApi: AiaChaserFlutterApi? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile
    private var executor = Executors.newFixedThreadPool(4)
    private val certFactory = CertificateFactory.getInstance("X.509")

    private var fetcher = AiaFetcher()
    private var diskCache: DiskIssuerCache? = null
    private var trustValidator = TrustValidator()
    private var chainBuilder = ChainBuilder(fetcher, null, emptyList(), trustValidator)
    private var prober = Prober(chainBuilder, trustValidator)

    private val seedCertificates = mutableListOf<X509Certificate>()

    // In-memory validation cache: "$host:$port:$leafSha256" -> CachedVerdict
    data class CachedVerdict(
        val outcome: ValidationOutcome,
        val chainSha256Hex: List<String>,
        val fetchedUrls: List<String>,
        val expiresAtMs: Long
    )

    private val validationCache = ConcurrentHashMap<String, CachedVerdict>()

    // Single-flight deduplication: key -> List of callbacks
    private val inFlightValidations = ConcurrentHashMap<String, MutableList<(Result<ValidationResult>) -> Unit>>()
    private val singleFlightLock = Any()

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        if (executor.isShutdown) {
            executor = Executors.newFixedThreadPool(4)
        }
        context = binding.applicationContext
        flutterApi = AiaChaserFlutterApi(binding.binaryMessenger)
        AiaChaserHostApi.setUp(binding.binaryMessenger, this)

        try {
            val cacheDir = binding.applicationContext.cacheDir
            val cache = DiskIssuerCache(cacheDir)
            diskCache = cache
            chainBuilder = ChainBuilder(fetcher, cache, seedCertificates, trustValidator)
            prober = Prober(chainBuilder, trustValidator)
        } catch (_: Exception) {
            chainBuilder = ChainBuilder(fetcher, null, seedCertificates, trustValidator)
            prober = Prober(chainBuilder, trustValidator)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        AiaChaserHostApi.setUp(binding.binaryMessenger, null)
        flutterApi = null
        context = null
        mainHandler.removeCallbacksAndMessages(null)
        executor.shutdown()
    }

    override fun configure(config: NativeConfig) {
        val fetchOpts = config.fetch
        fetcher = AiaFetcher(
            connectTimeoutMs = fetchOpts.connectTimeoutMs.toInt(),
            readTimeoutMs = fetchOpts.readTimeoutMs.toInt(),
            maxBytes = fetchOpts.maxBytes.toInt(),
            maxRedirects = fetchOpts.maxRedirects.toInt(),
            blockPrivateAddresses = fetchOpts.blockPrivateAddresses
        )

        trustValidator = TrustValidator(trustUserCaCerts = config.trustUserCaCerts)

        val ctx = context
        if (ctx != null && config.cache.issuerDiskCache) {
            diskCache = DiskIssuerCache(ctx.cacheDir)
        } else {
            diskCache = null
        }

        // Load seed certificates from paths if provided
        seedCertificates.clear()
        for (path in config.seedCertPaths) {
            try {
                val file = File(path)
                if (file.exists()) {
                    file.inputStream().use { stream ->
                        val certs = certFactory.generateCertificates(stream)
                        for (c in certs) {
                            if (c is X509Certificate) {
                                seedCertificates.add(c)
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        for (der in config.seedCertsDer) {
            try {
                val c = certFactory.generateCertificate(ByteArrayInputStream(der))
                if (c is X509Certificate) {
                    seedCertificates.add(c)
                }
            } catch (_: Exception) {}
        }

        chainBuilder = ChainBuilder(
            fetcher = fetcher,
            diskCache = diskCache,
            seedCertificates = seedCertificates,
            trustValidator = trustValidator,
            maxDepth = fetchOpts.maxDepth.toInt()
        )
        prober = Prober(chainBuilder, trustValidator)

        // Verdicts cached under the previous configuration must not be reused.
        validationCache.clear()
    }

    override fun validate(request: ValidationRequest, callback: (Result<ValidationResult>) -> Unit) {
        executor.execute {
            val startTime = System.currentTimeMillis()
            val host = request.host.trim().lowercase()
            val port = request.port.toInt()
            val leafDer = request.leafDer

            val leafSha256 = sha256Hex(leafDer)
            val cacheKey = "$host:$port:$leafSha256"

            // 1. In-memory cache check
            val now = System.currentTimeMillis()
            val cached = validationCache[cacheKey]
            if (cached != null && cached.expiresAtMs > now) {
                emitEvent("cache_hit", host, leafSha256, cached.outcome, 0, null)
                val res = ValidationResult(
                    outcome = cached.outcome,
                    chainSha256Hex = cached.chainSha256Hex,
                    fetchedUrls = cached.fetchedUrls,
                    durationMs = (System.currentTimeMillis() - startTime),
                    detail = "In-memory cache hit"
                )
                mainHandler.post {
                    callback(Result.success(res))
                }
                return@execute
            }

            // 2. Single-flight synchronization
            var isFirstRequest = false
            synchronized(singleFlightLock) {
                val existing = inFlightValidations[cacheKey]
                if (existing != null) {
                    existing.add(callback)
                    return@execute
                } else {
                    val callbacks = mutableListOf(callback)
                    inFlightValidations[cacheKey] = callbacks
                    isFirstRequest = true
                }
            }

            if (!isFirstRequest) return@execute

            try {
                val result = performValidation(host, leafDer, startTime)
                val duration = (System.currentTimeMillis() - startTime)

                // Cache verdict
                val ttlMs = if (result.outcome == ValidationOutcome.VALIDATED ||
                    result.outcome == ValidationOutcome.VALIDATED_BY_PIN
                ) {
                    24L * 60 * 60 * 1000 // 24 hours
                } else {
                    60L * 1000 // 60 seconds negative cache
                }

                validationCache[cacheKey] = CachedVerdict(
                    outcome = result.outcome,
                    chainSha256Hex = result.chainSha256Hex,
                    fetchedUrls = result.fetchedUrls,
                    expiresAtMs = System.currentTimeMillis() + ttlMs
                )

                emitEvent("chain_validated", host, leafSha256, result.outcome, duration, result.detail)
                dispatchSingleFlight(cacheKey, Result.success(result))
            } catch (e: Exception) {
                dispatchSingleFlight(cacheKey, Result.failure(e))
            }
        }
    }

    private fun performValidation(host: String, leafDer: ByteArray, startTime: Long): ValidationResult {
        // Parse leaf
        val cert = try {
            certFactory.generateCertificate(ByteArrayInputStream(leafDer)) as? X509Certificate
                ?: throw Exception("Not an X.509 certificate")
        } catch (_: Exception) {
            return ValidationResult(
                outcome = ValidationOutcome.NO_CERTIFICATE,
                chainSha256Hex = emptyList(),
                fetchedUrls = emptyList(),
                durationMs = (System.currentTimeMillis() - startTime),
                detail = "Failed to parse leaf certificate bytes"
            )
        }

        // Check if Dart passed an intermediate CA certificate rather than an end-entity leaf
        val isCaCert = cert.basicConstraints >= 0
        val targetLeaf: X509Certificate
        if (isCaCert) {
            // Dart passed an intermediate CA certificate (whose signature failed system trust).
            // Probe the host with SNI to obtain the true end-entity leaf certificate and complete server chain.
            val probe = try {
                prober.captureServerChain(host, 443, 5000)
            } catch (_: Exception) {
                null
            }
            targetLeaf = probe?.leafCert ?: cert
        } else {
            targetLeaf = cert
        }

        // Hostname check (SAN) on the actual end-entity leaf
        if (!HostnameMatcher.verify(host, targetLeaf)) {
            return ValidationResult(
                outcome = ValidationOutcome.REJECTED_HOSTNAME,
                chainSha256Hex = listOf(sha256Hex(leafDer)),
                fetchedUrls = emptyList(),
                durationMs = (System.currentTimeMillis() - startTime),
                detail = "Hostname '$host' does not match certificate SANs: ${HostnameMatcher.getSans(targetLeaf)}"
            )
        }

        // Validity check
        val now = Date()
        if (now.before(targetLeaf.notBefore) || now.after(targetLeaf.notAfter)) {
            return ValidationResult(
                outcome = ValidationOutcome.REJECTED_EXPIRED,
                chainSha256Hex = listOf(sha256Hex(leafDer)),
                fetchedUrls = emptyList(),
                durationMs = (System.currentTimeMillis() - startTime),
                detail = "Certificate validity error: valid from ${targetLeaf.notBefore} to ${targetLeaf.notAfter}"
            )
        }

        // Try system trust on targetLeaf alone first
        val directTrust = trustValidator.validateSystemTrust(listOf(targetLeaf), host)
        if (directTrust is TrustValidator.TrustResult.Trusted) {
            val hashes = (directTrust.fullChain.map { sha256Hex(it.encoded) } + sha256Hex(leafDer)).distinct()
            return ValidationResult(
                outcome = ValidationOutcome.VALIDATED,
                chainSha256Hex = hashes,
                fetchedUrls = emptyList(),
                durationMs = (System.currentTimeMillis() - startTime),
                detail = "Chain validated directly by system trust store"
            )
        }

        // Build chain via AIA
        val buildResult = chainBuilder.buildChain(targetLeaf, host)
        val fullChain = buildResult.chain
        val chainHashes = (fullChain.map { sha256Hex(it.encoded) } + sha256Hex(leafDer)).distinct()

        // Evaluate system trust on completed chain
        val trustCheck = trustValidator.validateSystemTrust(fullChain, host)
        return when (trustCheck) {
            is TrustValidator.TrustResult.Trusted -> {
                ValidationResult(
                    outcome = ValidationOutcome.VALIDATED,
                    chainSha256Hex = chainHashes,
                    fetchedUrls = buildResult.fetchedUrls,
                    durationMs = (System.currentTimeMillis() - startTime),
                    detail = "Completed chain validated via AIA chasing (${buildResult.fetchedUrls.size} certs fetched)"
                )
            }
            is TrustValidator.TrustResult.Pinned -> {
                ValidationResult(
                    outcome = ValidationOutcome.VALIDATED_BY_PIN,
                    chainSha256Hex = chainHashes,
                    fetchedUrls = buildResult.fetchedUrls,
                    durationMs = (System.currentTimeMillis() - startTime),
                    detail = "Validated via matching explicit pin"
                )
            }
            is TrustValidator.TrustResult.Untrusted -> {
                val outcome = if (buildResult.hitMaxDepth) {
                    ValidationOutcome.MAX_DEPTH_EXCEEDED
                } else if (buildResult.fetchedUrls.isEmpty()) {
                    ValidationOutcome.REJECTED_UNTRUSTED
                } else {
                    ValidationOutcome.REJECTED_UNTRUSTED
                }

                ValidationResult(
                    outcome = outcome,
                    chainSha256Hex = chainHashes,
                    fetchedUrls = buildResult.fetchedUrls,
                    durationMs = (System.currentTimeMillis() - startTime),
                    detail = trustCheck.reason
                )
            }
        }
    }

    private fun dispatchSingleFlight(cacheKey: String, result: Result<ValidationResult>) {
        val callbacks = synchronized(singleFlightLock) {
            inFlightValidations.remove(cacheKey)
        } ?: return

        mainHandler.post {
            for (cb in callbacks) {
                cb(result)
            }
        }
    }

    override fun prewarm(host: String, port: Long, callback: (Result<ValidationResult>) -> Unit) {
        executor.execute {
            val startTime = System.currentTimeMillis()
            try {
                val probe = prober.captureServerChain(host, port.toInt(), 5000)
                val leaf = probe.leafCert
                if (leaf == null) {
                    val res = ValidationResult(
                        outcome = ValidationOutcome.NO_CERTIFICATE,
                        chainSha256Hex = emptyList(),
                        fetchedUrls = emptyList(),
                        durationMs = (System.currentTimeMillis() - startTime),
                        detail = "Prewarm failed: no certificate presented by $host:$port"
                    )
                    mainHandler.post {
                        callback(Result.success(res))
                    }
                    return@execute
                }

                val req = ValidationRequest(
                    host = host,
                    port = port,
                    leafDer = leaf.encoded
                )
                validate(req, callback)
            } catch (e: Exception) {
                val res = ValidationResult(
                    outcome = ValidationOutcome.AIA_UNAVAILABLE,
                    chainSha256Hex = emptyList(),
                    fetchedUrls = emptyList(),
                    durationMs = (System.currentTimeMillis() - startTime),
                    detail = "Prewarm connection error: ${e.message}"
                )
                mainHandler.post {
                    callback(Result.success(res))
                }
            }
        }
    }

    override fun diagnose(host: String, port: Long, timeoutMs: Long, callback: (Result<ChainReport>) -> Unit) {
        executor.execute {
            try {
                val report = prober.diagnose(host, port.toInt(), timeoutMs.toInt())
                mainHandler.post {
                    callback(Result.success(report))
                }
            } catch (e: Exception) {
                mainHandler.post {
                    callback(Result.failure(e))
                }
            }
        }
    }

    override fun getCacheStats(): CacheStats {
        val (count, bytes) = diskCache?.getStats() ?: Pair(0, 0L)
        return CacheStats(
            issuerCacheCount = count.toLong(),
            issuerCacheBytes = bytes,
            memoryVerdictCount = validationCache.size.toLong()
        )
    }

    override fun clearCaches(scope: ClearScope) {
        when (scope) {
            ClearScope.VERDICTS_ONLY -> validationCache.clear()
            ClearScope.ISSUER_CACHE_ONLY -> diskCache?.clear()
            ClearScope.ALL -> {
                validationCache.clear()
                diskCache?.clear()
            }
        }
    }

    private fun emitEvent(
        type: String,
        host: String,
        leafSha256: String?,
        outcome: ValidationOutcome?,
        durationMs: Long,
        detail: String?
    ) {
        val event = NativeEvent(
            type = type,
            host = host,
            timestampMs = System.currentTimeMillis(),
            leafSha12 = leafSha256?.take(12),
            outcome = outcome,
            durationMs = durationMs,
            detailJson = detail
        )
        mainHandler.post {
            flutterApi?.onNativeEvent(event) {}
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
