import 'dart:async';
import 'package:flutter/services.dart';

import 'src/config.dart';
import 'src/engine.dart';
import 'src/events.dart';
import 'src/pfn/aia_api.g.dart';

export 'src/config.dart';
export 'src/diagnostics.dart';
export 'src/events.dart';
export 'src/overrides.dart';
export 'src/pfn/aia_api.g.dart'
    show
        ValidationOutcome,
        CertSource,
        ClearScope,
        CacheStats,
        ChainReport,
        CertInfo,
        ValidationResult;
export 'src/engine.dart' show AiaEngine;
export 'src/store.dart' show ValidatedLeafStore;
export 'src/ui/aia_diagnostics_view.dart'
    show AiaDiagnosticsView, AiaThemeColors;

/// Main entry point for the AIA Chaser plugin ecosystem.
class AiaChaser {
  static final AiaEngine _engine = AiaEngine();

  /// Access the internal engine instance.
  static AiaEngine get engine => _engine;

  /// Stream of real-time diagnostic and validation events.
  static Stream<AiaEvent> get events => _engine.events;

  /// Prepares a background isolate to communicate with the AIA Chaser native engine.
  ///
  /// Must be called with [RootIsolateToken.instance!] before calling [AiaChaser.initialize]
  /// or making requests in a spawned background isolate (e.g. compute() or background workers).
  static void registerBackgroundIsolate(RootIsolateToken rootIsolateToken) {
    BackgroundIsolateBinaryMessenger.ensureInitialized(rootIsolateToken);
  }

  /// Configures and initializes AIA Chaser.
  static Future<void> initialize(AiaConfig config) async {
    _engine.initialize(config);
  }

  /// Resets configuration, active validation state, and memory cache.
  ///
  /// Useful in testing and test isolation.
  static void reset() {
    _engine.reset();
  }

  /// Diagnoses the SSL/TLS certificate chain for [host] and returns a detailed [ChainReport].
  static Future<ChainReport> diagnose(
    String host, {
    int port = 443,
    Duration timeout = const Duration(seconds: 8),
  }) {
    return _engine.diagnose(host, port: port, timeout: timeout);
  }

  /// Proactively connects to [host] and prewarms its validated chain into memory cache.
  static Future<ValidationResult> prewarm(String host, {int port = 443}) {
    return _engine.prewarm(host, port: port);
  }

  /// Retrieves cache usage statistics from disk and memory.
  static Future<CacheStats> getCacheStats() {
    return _engine.getCacheStats();
  }

  /// Clears in-memory verdicts, persistent disk cache, or both.
  static void clearCaches({ClearScope scope = ClearScope.all}) {
    _engine.clearCaches(scope: scope);
  }
}
