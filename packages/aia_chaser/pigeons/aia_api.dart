import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/src/pfn/aia_api.g.dart',
  dartTestOut: 'test/pfn/test_aia_api.g.dart',
  kotlinOut: 'android/src/main/kotlin/dev/aiachaser/GeneratedApi.kt',
  kotlinOptions: KotlinOptions(package: 'dev.aiachaser'),
  swiftOut: 'ios/Classes/GeneratedApi.swift',
  swiftOptions: SwiftOptions(),
))
enum ValidationOutcome {
  validated,
  validatedByPin,
  rejectedUntrusted,
  rejectedHostname,
  rejectedExpired,
  aiaUnavailable,
  aiaFetchFailed,
  maxDepthExceeded,
  noCertificate,
  policyUnsafeAllowed,
  notConfigured,
}

enum CertSource {
  server,
  aia,
  seed,
  systemRoot,
}

enum ClearScope {
  verdictsOnly,
  issuerCacheOnly,
  all,
}

class NativeFetchOptions {
  late int connectTimeoutMs;
  late int readTimeoutMs;
  late int maxDepth;
  late int maxBytes;
  late int maxRedirects;
  late bool blockPrivateAddresses;
}

class NativeCacheOptions {
  late bool issuerDiskCache;
  late int issuerTtlMs;
  late int validationTtlMs;
}

class NativeConfig {
  late NativeFetchOptions fetch;
  late NativeCacheOptions cache;
  late bool trustUserCaCerts;
  late List<String> seedCertPaths;
}

class ValidationRequest {
  late String host;
  late int port;
  late Uint8List leafDer;
}

class ValidationResult {
  late ValidationOutcome outcome;
  late List<String> chainSha256Hex;
  late List<String> fetchedUrls;
  late int durationMs;
  String? detail;
}

class CertInfo {
  late String subjectDn;
  late String issuerDn;
  late String sha256Hex;
  late int notBeforeMs;
  late int notAfterMs;
  late String keyAlgorithm;
  late CertSource source;
  List<String>? sans;
  String? aiaUrl;
}

class ChainReport {
  late String host;
  late int port;
  late List<CertInfo> serverSentChain;
  late List<CertInfo> completedChain;
  late ValidationOutcome outcome;
  late String cause;
  late String suggestedFix;
  late int durationMs;
}

class CacheStats {
  late int issuerCacheCount;
  late int issuerCacheBytes;
  late int memoryVerdictCount;
}

class NativeEvent {
  late String type;
  late String host;
  late int timestampMs;
  String? leafSha12;
  ValidationOutcome? outcome;
  int? durationMs;
  String? detailJson;
}

@HostApi()
abstract class AiaChaserHostApi {
  void configure(NativeConfig config);
  @async
  ValidationResult validate(ValidationRequest request);
  @async
  ValidationResult prewarm(String host, int port);
  @async
  ChainReport diagnose(String host, int port, int timeoutMs);
  CacheStats getCacheStats();
  void clearCaches(ClearScope scope);
}

@FlutterApi()
abstract class AiaChaserFlutterApi {
  void onNativeEvent(NativeEvent event);
}
