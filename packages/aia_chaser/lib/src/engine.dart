import 'dart:async';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show rootBundle;

import 'config.dart';
import 'events.dart';
import 'pfn/aia_api.g.dart';
import 'store.dart';

class AiaEngine implements AiaChaserFlutterApi {
  AiaConfig _config = const AiaConfig(hosts: {});
  final ValidatedLeafStore store = ValidatedLeafStore();
  final AiaChaserHostApi _hostApi = AiaChaserHostApi();

  final StreamController<AiaEvent> _eventsController =
      StreamController<AiaEvent>.broadcast();

  final Map<String, Future<ValidationResult>> _inFlight = {};

  Stream<AiaEvent> get events => _eventsController.stream;

  bool _initialized = false;
  bool get isInitialized => _initialized;

  AiaEngine() {
    AiaChaserFlutterApi.setUp(this);
  }

  Future<void> initialize(AiaConfig config) async {
    config.validate();
    _config = config;
    _initialized = true;

    // Flutter asset keys are not filesystem paths, so load the bytes here.
    final seedCertsDer = <Uint8List>[];
    for (final asset in config.cache.seedAssets) {
      try {
        final data = await rootBundle.load(asset);
        seedCertsDer.add(data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes));
      } catch (e) {
        if (kDebugMode) {
          debugPrint('[AiaChaser] Could not load seed asset "$asset": $e');
        }
      }
    }

    // Send native configuration
    await _hostApi.configure(NativeConfig(
      fetch: NativeFetchOptions(
        connectTimeoutMs: config.fetch.connectTimeout.inMilliseconds,
        readTimeoutMs: config.fetch.readTimeout.inMilliseconds,
        maxDepth: config.fetch.maxDepth,
        maxBytes: config.fetch.maxBytes,
        maxRedirects: config.fetch.maxRedirects,
        blockPrivateAddresses: config.fetch.blockPrivateAddresses,
      ),
      cache: NativeCacheOptions(
        issuerDiskCache: config.cache.issuerDiskCache,
        issuerTtlMs: config.cache.issuerTtl.inMilliseconds,
        validationTtlMs: config.cache.validationTtl.inMilliseconds,
      ),
      trustUserCaCerts: config.trustUserCaCerts,
      seedCertPaths: const [],
      seedCertsDer: seedCertsDer,
    ));

    // Handle prewarm
    if (config.prewarm != PrewarmMode.none) {
      final future = _executePrewarm(config.prewarm == PrewarmMode.awaitCompletion);
      if (config.prewarm == PrewarmMode.awaitCompletion) {
        await future;
      }
    }
  }

  Future<void> _executePrewarm(bool awaitCompletion) async {
    final futures = <Future>[];
    for (final entry in _config.hosts.entries) {
      final hostPattern = entry.key;
      // Exact hosts only (wildcards cannot be prewarmed without a known subdomain)
      if (!hostPattern.startsWith('*.')) {
        final future = prewarm(hostPattern);
        futures.add(future);
      }
    }

    if (awaitCompletion && futures.isNotEmpty) {
      await Future.wait(futures);
    }
  }

  /// Resolves the applicable policy for [host].
  HostPolicy resolvePolicy(String host) {
    final normalized = host.trim().toLowerCase();

    // 1. Exact match
    if (_config.hosts.containsKey(normalized)) {
      return _config.hosts[normalized]!;
    }

    // 2. Wildcard suffix match (longest matching suffix wins)
    String? bestWildcardPattern;
    for (final pattern in _config.hosts.keys) {
      if (pattern.startsWith('*.')) {
        final suffix = pattern.substring(1); // .example.com
        if (normalized.endsWith(suffix) && normalized.length > suffix.length) {
          if (bestWildcardPattern == null ||
              pattern.length > bestWildcardPattern.length) {
            bestWildcardPattern = pattern;
          }
        }
      }
    }

    if (bestWildcardPattern != null) {
      return _config.hosts[bestWildcardPattern]!;
    }

    // 3. Fallback to unlisted hosts policy
    return _config.unlistedHosts;
  }

  /// Schedules a single-flight background validation task.
  Future<ValidationResult> scheduleValidation(
    String host,
    int port,
    Uint8List leafDer,
  ) {
    final leafSha256 = sha256.convert(leafDer).toString();
    final key = '${host.trim().toLowerCase()}:$leafSha256';

    if (_inFlight.containsKey(key)) {
      return _inFlight[key]!;
    }

    final completer = Completer<ValidationResult>();
    _inFlight[key] = completer.future;

    _hostApi
        .validate(ValidationRequest(
      host: host,
      port: port,
      leafDer: leafDer,
    ))
        .then((result) {
      // Store in memory cache
      if (result.outcome == ValidationOutcome.validated ||
          result.outcome == ValidationOutcome.validatedByPin) {
        store.put(
          host,
          leafSha256,
          result.outcome,
          ttl: _config.cache.validationTtl,
          detail: result.detail,
        );
        for (final certHash in result.chainSha256Hex) {
          store.put(
            host,
            certHash,
            result.outcome,
            ttl: _config.cache.validationTtl,
            detail: result.detail,
          );
        }
      }

      completer.complete(result);
      if (kDebugMode) {
        debugPrint('[AiaChaser] Validation completed for $host -> ${result.outcome} (${result.durationMs}ms - ${result.detail})');
      }
    }).catchError((error, stackTrace) {
      completer.completeError(error, stackTrace);
    }).whenComplete(() {
      _inFlight.remove(key);
    });

    return completer.future;
  }

  /// Checks if an active in-flight validation exists for this host.
  Future<ValidationResult>? getInFlight(String host, String leafSha256) {
    final key = '${host.trim().toLowerCase()}:$leafSha256';
    return _inFlight[key];
  }

  /// Checks if any active in-flight validation exists for this host.
  Future<ValidationResult>? getInFlightForHost(String host) {
    final prefix = '${host.trim().toLowerCase()}:';
    for (final entry in _inFlight.entries) {
      if (entry.key.startsWith(prefix)) {
        return entry.value;
      }
    }
    return null;
  }

  Future<ValidationResult> prewarm(String host, {int port = 443}) async {
    final result = await _hostApi.prewarm(host, port);
    if (result.chainSha256Hex.isNotEmpty) {
      if (result.outcome == ValidationOutcome.validated ||
          result.outcome == ValidationOutcome.validatedByPin) {
        for (final certHash in result.chainSha256Hex) {
          store.put(
            host,
            certHash,
            result.outcome,
            ttl: _config.cache.validationTtl,
            detail: result.detail,
          );
        }
      }
    }

    if (kDebugMode) {
      debugPrint('[AiaChaser] Prewarmed $host -> ${result.outcome} (${result.durationMs}ms - ${result.detail})');
    }

    _eventsController.add(AiaEvent(
      type: AiaEventType.prewarmCompleted,
      rawType: 'prewarm_completed',
      host: host,
      timestamp: DateTime.now(),
      outcome: result.outcome,
      duration: Duration(milliseconds: result.durationMs),
      detail: result.detail,
    ));

    return result;
  }

  Future<ChainReport> diagnose(
    String host, {
    int port = 443,
    Duration timeout = const Duration(seconds: 8),
  }) {
    return _hostApi.diagnose(host, port, timeout.inMilliseconds);
  }

  Future<CacheStats> getCacheStats() {
    return _hostApi.getCacheStats();
  }

  void clearCaches({ClearScope scope = ClearScope.all}) {
    if (scope == ClearScope.all || scope == ClearScope.verdictsOnly) {
      store.clear();
    }
    _hostApi.clearCaches(scope);
  }

  @override
  void onNativeEvent(NativeEvent event) {
    _eventsController.add(AiaEvent.fromNative(event));
  }

  void logUnsafeWarning(String host) {
    debugPrint(
        '[AiaChaser] WARNING: Request to "$host" accepted WITHOUT validation (unsafeAllow policy).');
    _eventsController.add(AiaEvent(
      type: AiaEventType.policyDecision,
      rawType: 'policy_decision',
      host: host,
      timestamp: DateTime.now(),
      outcome: ValidationOutcome.policyUnsafeAllowed,
      detail: 'Accepted without validation due to unsafeAllow policy',
    ));
  }

  /// Resets configuration and clears in-memory state.
  void reset() {
    _config = const AiaConfig(hosts: {});
    _initialized = false;
    store.clear();
    _inFlight.clear();
  }

  void dispose() {
    _eventsController.close();
  }
}
