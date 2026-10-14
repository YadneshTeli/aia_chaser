import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser/src/pfn/aia_api.g.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.configure',
      (ByteData? message) async {
        return AiaChaserHostApi.pigeonChannelCodec
            .encodeMessage(<Object?>[null]);
      },
    );
  });

  group('AiaConfig & HostPolicy Resolution', () {
    test('resolves exact match policy correctly', () {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'api.example.com': const HostPolicy.chase(),
          'other.example.com': const HostPolicy(chase: false),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final policy1 = engine.resolvePolicy('api.example.com');
      expect(policy1.chase, isTrue);

      final policy2 = engine.resolvePolicy('other.example.com');
      expect(policy2.chase, isFalse);
    });

    test('resolves wildcard subdomain policies by longest suffix match', () {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          '*.cdn.example.com': const HostPolicy.chase(),
          '*.example.com': const HostPolicy(chase: false),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      // Deep subdomain should match the more specific wildcard
      final cdnPolicy = engine.resolvePolicy('images.cdn.example.com');
      expect(cdnPolicy.chase, isTrue);

      // General subdomain should match *.example.com
      final generalPolicy = engine.resolvePolicy('login.example.com');
      expect(generalPolicy.chase, isFalse);
    });

    test('falls back to unlistedHosts policy when host is not configured', () {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'api.example.com': const HostPolicy.chase(),
        },
        unlistedHosts: const HostPolicy(chase: false),
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final policy = engine.resolvePolicy('unknown.org');
      expect(policy.chase, isFalse);
    });

    test('throws AiaConfigurationException on empty host pattern', () {
      final config = AiaConfig(
        hosts: {
          '': const HostPolicy.chase(),
        },
      );

      expect(
          () => config.validate(), throwsA(isA<AiaConfigurationException>()));
    });
  });
}
