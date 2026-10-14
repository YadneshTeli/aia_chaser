import 'package:flutter_test/flutter_test.dart';
import 'package:aia_chaser/aia_chaser.dart';

void main() {
  group('ValidatedLeafStore', () {
    test('records and returns validated verdicts for exact host and leaf hash',
        () {
      final store = ValidatedLeafStore();
      const host = 'api.example.com';
      const leafHash = '4a2f8b1c9e3a7c5d';

      expect(store.isValidated(host, leafHash), isFalse);

      store.put(host, leafHash, ValidationOutcome.validated);

      expect(store.isValidated(host, leafHash), isTrue);
      expect(store.isValidated('other.com', leafHash), isFalse);
      expect(store.isValidated(host, 'differenthash'), isFalse);
    });

    test('treats expired verdicts as not validated', () {
      final store = ValidatedLeafStore();
      const host = 'api.example.com';
      const leafHash = '4a2f8b1c9e3a7c5d';

      // Insert verdict with negative TTL (already expired)
      store.put(
        host,
        leafHash,
        ValidationOutcome.validated,
        ttl: const Duration(seconds: -1),
      );

      expect(store.isValidated(host, leafHash), isFalse);
    });

    test('invalidates by host correctly', () {
      final store = ValidatedLeafStore();
      store.put('api.example.com', 'hash1', ValidationOutcome.validated);
      store.put('api.example.com', 'hash2', ValidationOutcome.validated);
      store.put('cdn.example.com', 'hash3', ValidationOutcome.validated);

      expect(store.count, equals(3));

      store.invalidateHost('api.example.com');
      expect(store.isValidated('api.example.com', 'hash1'), isFalse);
      expect(store.isValidated('api.example.com', 'hash2'), isFalse);
      expect(store.isValidated('cdn.example.com', 'hash3'), isTrue);
      expect(store.count, equals(1));
    });

    test('clears all verdicts', () {
      final store = ValidatedLeafStore();
      store.put('host1.com', 'hash1', ValidationOutcome.validated);
      store.put('host2.com', 'hash2', ValidationOutcome.validated);

      expect(store.count, equals(2));
      store.clear();
      expect(store.count, equals(0));
    });
  });
}
