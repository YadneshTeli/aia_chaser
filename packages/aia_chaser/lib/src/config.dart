import 'package:flutter/foundation.dart';

export 'pfn/aia_api.g.dart'
    show ValidationOutcome, CertSource, ClearScope, CacheStats;

enum PrewarmMode {
  none,
  background,
  awaitCompletion,
}

enum PinType {
  spkiSha256,
  certSha256,
}

class Pin {
  final PinType type;
  final String value;

  const Pin.spkiSha256(this.value) : type = PinType.spkiSha256;
  const Pin.certSha256(this.value) : type = PinType.certSha256;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Pin &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          value == other.value;

  @override
  int get hashCode => type.hashCode ^ value.hashCode;

  @override
  String toString() => '${type.name}:$value';
}

enum FailurePolicyType {
  reject,
  pinFallback,
  unsafeAllow,
}

class FailurePolicy {
  final FailurePolicyType type;
  final Set<Pin> pins;
  final bool allowInRelease;

  const FailurePolicy.reject()
      : type = FailurePolicyType.reject,
        pins = const {},
        allowInRelease = false;

  const FailurePolicy.pinFallback(this.pins)
      : type = FailurePolicyType.pinFallback,
        allowInRelease = false;

  const FailurePolicy.unsafeAllow({this.allowInRelease = false})
      : type = FailurePolicyType.unsafeAllow,
        pins = const {};

  @override
  String toString() => 'FailurePolicy.${type.name}';
}

class HostPolicy {
  final bool chase;
  final FailurePolicy onFailure;
  final Duration? connectTimeout;
  final Duration? readTimeout;
  final bool retryOnce;

  const HostPolicy({
    this.chase = true,
    this.onFailure = const FailurePolicy.reject(),
    this.connectTimeout,
    this.readTimeout,
    this.retryOnce = true,
  });

  const HostPolicy.chase({
    FailurePolicy onFailure = const FailurePolicy.reject(),
    Duration? connectTimeout,
    Duration? readTimeout,
    bool retryOnce = true,
  }) : this(
          chase: true,
          onFailure: onFailure,
          connectTimeout: connectTimeout,
          readTimeout: readTimeout,
          retryOnce: retryOnce,
        );

  HostPolicy.pinOnly(
    Set<Pin> pins, {
    Duration? connectTimeout,
    Duration? readTimeout,
    bool retryOnce = true,
  }) : this(
          chase: false,
          onFailure: FailurePolicy.pinFallback(pins),
          connectTimeout: connectTimeout,
          readTimeout: readTimeout,
          retryOnce: retryOnce,
        );

  static const HostPolicy passthrough = HostPolicy(
    chase: false,
    onFailure: FailurePolicy.reject(),
    retryOnce: false,
  );
}

class AiaFetchOptions {
  final Duration connectTimeout;
  final Duration readTimeout;
  final int maxDepth;
  final int maxBytes;
  final int maxRedirects;
  final bool blockPrivateAddresses;

  const AiaFetchOptions({
    this.connectTimeout = const Duration(seconds: 3),
    this.readTimeout = const Duration(seconds: 3),
    this.maxDepth = 4,
    this.maxBytes = 64 * 1024,
    this.maxRedirects = 3,
    this.blockPrivateAddresses = true,
  });
}

class AiaCacheOptions {
  final bool issuerDiskCache;
  final Duration issuerTtl;
  final Duration validationTtl;
  final List<String> seedAssets;

  const AiaCacheOptions({
    this.issuerDiskCache = true,
    this.issuerTtl = const Duration(days: 30),
    this.validationTtl = const Duration(hours: 24),
    this.seedAssets = const [],
  });
}

class AiaConfig {
  final Map<String, HostPolicy> hosts;
  final HostPolicy unlistedHosts;
  final AiaFetchOptions fetch;
  final AiaCacheOptions cache;
  final PrewarmMode prewarm;
  final bool trustUserCaCerts;

  const AiaConfig({
    required this.hosts,
    this.unlistedHosts = HostPolicy.passthrough,
    this.fetch = const AiaFetchOptions(),
    this.cache = const AiaCacheOptions(),
    this.prewarm = PrewarmMode.background,
    this.trustUserCaCerts = true,
  });

  /// Validates the configuration and throws [AiaConfigurationException] if invalid.
  void validate() {
    for (final entry in hosts.entries) {
      final host = entry.key;
      final policy = entry.value;

      // Host pattern validation
      if (host.trim().isEmpty) {
        throw AiaConfigurationException('Host pattern cannot be empty');
      }

      // Unsafe mode guard in release builds
      if (policy.onFailure.type == FailurePolicyType.unsafeAllow) {
        if (!policy.onFailure.allowInRelease && kReleaseMode) {
          throw AiaConfigurationException(
            'Host "$host" has FailurePolicy.unsafeAllow() which is prohibited in release builds '
            'unless allowInRelease: true is explicitly declared.',
          );
        }
      }
    }
  }
}

class AiaConfigurationException implements Exception {
  final String message;
  AiaConfigurationException(this.message);

  @override
  String toString() => '[AiaChaser] Configuration error: $message';
}
