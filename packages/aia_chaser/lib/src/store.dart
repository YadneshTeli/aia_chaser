import 'pfn/aia_api.g.dart';

class StoredVerdict {
  final ValidationOutcome outcome;
  final DateTime expiresAt;
  final String? detail;

  StoredVerdict({
    required this.outcome,
    required this.expiresAt,
    this.detail,
  });

  bool get isExpired => DateTime.now().isAfter(expiresAt);

  bool get isValidated =>
      (outcome == ValidationOutcome.validated ||
          outcome == ValidationOutcome.validatedByPin) &&
      !isExpired;
}

/// In-memory, thread-safe, microsecond O(1) store of validated leaf certificate fingerprints.
/// Used directly by synchronous badCertificateCallback.
class ValidatedLeafStore {
  final Map<String, StoredVerdict> _store = {};

  String _buildKey(String host, String leafSha256Hex) {
    return '${host.trim().toLowerCase()}:${leafSha256Hex.trim().toLowerCase()}';
  }

  /// Returns true if this (host, leafSha256) is recorded as trusted and unexpired.
  bool isValidated(String host, String leafSha256Hex) {
    final key = _buildKey(host, leafSha256Hex);
    final verdict = _store[key];
    if (verdict == null) return false;
    if (verdict.isExpired) {
      _store.remove(key);
      return false;
    }
    return verdict.isValidated;
  }

  /// Returns the stored outcome if present and fresh, or null.
  ValidationOutcome? getOutcome(String host, String leafSha256Hex) {
    final key = _buildKey(host, leafSha256Hex);
    final verdict = _store[key];
    if (verdict == null) return null;
    if (verdict.isExpired) {
      _store.remove(key);
      return null;
    }
    return verdict.outcome;
  }

  /// Records a validation outcome.
  void put(
    String host,
    String leafSha256Hex,
    ValidationOutcome outcome, {
    Duration ttl = const Duration(hours: 24),
    String? detail,
  }) {
    final key = _buildKey(host, leafSha256Hex);
    final expiresAt = DateTime.now().add(ttl);
    _store[key] = StoredVerdict(
      outcome: outcome,
      expiresAt: expiresAt,
      detail: detail,
    );
  }

  /// Evicts all cached verdicts for [host].
  void invalidateHost(String host) {
    final prefix = '${host.trim().toLowerCase()}:';
    _store.removeWhere((key, _) => key.startsWith(prefix));
  }

  /// Clears all stored verdicts.
  void clear() {
    _store.clear();
  }

  /// Returns the number of stored verdicts.
  int get count => _store.length;
}
