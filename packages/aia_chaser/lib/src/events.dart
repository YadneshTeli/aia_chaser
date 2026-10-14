import 'pfn/aia_api.g.dart';

enum AiaEventType {
  chainValidated,
  aiaFetched,
  aiaFetchFailed,
  policyDecision,
  cacheHit,
  retryAttempted,
  prewarmCompleted,
  unknown,
}

class AiaEvent {
  final AiaEventType type;
  final String rawType;
  final String host;
  final DateTime timestamp;
  final String? leafSha12;
  final ValidationOutcome? outcome;
  final Duration? duration;
  final String? detail;

  AiaEvent({
    required this.type,
    required this.rawType,
    required this.host,
    required this.timestamp,
    this.leafSha12,
    this.outcome,
    this.duration,
    this.detail,
  });

  factory AiaEvent.fromNative(NativeEvent native) {
    AiaEventType eventType;
    switch (native.type) {
      case 'chain_validated':
        eventType = AiaEventType.chainValidated;
        break;
      case 'aia_fetched':
        eventType = AiaEventType.aiaFetched;
        break;
      case 'aia_fetch_failed':
        eventType = AiaEventType.aiaFetchFailed;
        break;
      case 'policy_decision':
        eventType = AiaEventType.policyDecision;
        break;
      case 'cache_hit':
        eventType = AiaEventType.cacheHit;
        break;
      case 'retry_attempted':
        eventType = AiaEventType.retryAttempted;
        break;
      case 'prewarm_completed':
        eventType = AiaEventType.prewarmCompleted;
        break;
      default:
        eventType = AiaEventType.unknown;
    }

    return AiaEvent(
      type: eventType,
      rawType: native.type,
      host: native.host,
      timestamp: DateTime.fromMillisecondsSinceEpoch(native.timestampMs),
      leafSha12: native.leafSha12,
      outcome: native.outcome,
      duration: native.durationMs != null
          ? Duration(milliseconds: native.durationMs!)
          : null,
      detail: native.detailJson,
    );
  }

  @override
  String toString() {
    final sb = StringBuffer('[AiaChaser Event: ${type.name}] $host');
    if (outcome != null) sb.write(' (${outcome!.name})');
    if (duration != null) sb.write(' in ${duration!.inMilliseconds}ms');
    if (detail != null && detail!.isNotEmpty) sb.write(' - $detail');
    return sb.toString();
  }
}
