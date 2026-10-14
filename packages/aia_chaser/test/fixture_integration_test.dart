import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser/src/pfn/aia_api.g.dart';
import 'package:mocktail/mocktail.dart';

class MockX509Certificate extends Mock implements X509Certificate {}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late MockX509Certificate mockLeaf;
  final fakeDer = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

  setUpAll(() {
    registerFallbackValue(ValidationRequest(
      host: 'fallback',
      port: 443,
      leafDer: Uint8List(0),
    ));
  });

  setUp(() {
    mockLeaf = MockX509Certificate();
    when(() => mockLeaf.der).thenReturn(fakeDer);
    when(() => mockLeaf.pem).thenReturn(
        '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----');

    // Mock native Pigeon configure and validate responses
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.configure',
      (ByteData? message) async {
        return AiaChaserHostApi.pigeonChannelCodec
            .encodeMessage(<Object?>[null]);
      },
    );

    final leafHash = sha256.convert(fakeDer).toString();

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.prewarm',
      (ByteData? message) async {
        final result = ValidationResult(
          outcome: ValidationOutcome.validated,
          chainSha256Hex: [leafHash, 'test_intermediate_hash'],
          fetchedUrls: ['http://127.0.0.1:8088/intermediate.der'],
          durationMs: 45,
          detail: 'Validated via mock AIA fetch',
        );
        return AiaChaserHostApi.pigeonChannelCodec
            .encodeMessage(<Object?>[result]);
      },
    );

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.validate',
      (ByteData? message) async {
        final result = ValidationResult(
          outcome: ValidationOutcome.validated,
          chainSha256Hex: [leafHash, 'test_intermediate_hash'],
          fetchedUrls: ['http://127.0.0.1:8088/intermediate.der'],
          durationMs: 30,
          detail: 'Validated via mock AIA fetch',
        );
        return AiaChaserHostApi.pigeonChannelCodec
            .encodeMessage(<Object?>[result]);
      },
    );
  });

  group('AiaHttpOverrides Validate-Ahead Integration', () {
    test(
        'rejects un-prewarmed request initially and schedules background validation',
        () async {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'api.brokenchain.test': const HostPolicy.chase(),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final overrides = AiaHttpOverrides(engine);

      // 1. Initial attempt: miss in ValidatedLeafStore
      final result1 =
          overrides.handleBadCertificate(mockLeaf, 'api.brokenchain.test', 443);
      expect(result1, isFalse,
          reason:
              'Initial request must fail while validation runs in background');

      // Allow scheduled background validation to complete
      await Future.delayed(const Duration(milliseconds: 50));

      // 2. Second attempt: hit in ValidatedLeafStore
      final result2 =
          overrides.handleBadCertificate(mockLeaf, 'api.brokenchain.test', 443);
      expect(result2, isTrue,
          reason: 'Once validated, badCertificateCallback returns true');
    });

    test('immediately approves prewarmed hosts', () async {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'prewarmed.test': const HostPolicy.chase(),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      // Prewarm the host
      await engine.prewarm('prewarmed.test');

      final overrides = AiaHttpOverrides(engine);
      final result =
          overrides.handleBadCertificate(mockLeaf, 'prewarmed.test', 443);
      expect(result, isTrue,
          reason:
              'Prewarmed hosts must pass badCertificateCallback immediately');
    });

    test('unlisted host is rejected and never chased', () {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'api.brokenchain.test': const HostPolicy.chase(),
        },
        unlistedHosts: HostPolicy.passthrough,
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final overrides = AiaHttpOverrides(engine);
      final result =
          overrides.handleBadCertificate(mockLeaf, 'unlisted-host.com', 443);
      expect(result, isFalse,
          reason: 'Unlisted host should pass through to platform rejection');
    });

    test('unsafeAllow policy immediately permits connection with warning log',
        () {
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'staging.internal': const HostPolicy(
            onFailure: FailurePolicy.unsafeAllow(allowInRelease: true),
          ),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final overrides = AiaHttpOverrides(engine);
      final result =
          overrides.handleBadCertificate(mockLeaf, 'staging.internal', 443);
      expect(result, isTrue, reason: 'unsafeAllow permits connection');
    });

    test('pinFallback matches certificate fingerprint and permits connection',
        () {
      final leafHash = sha256.convert(fakeDer).toString();
      final config = AiaConfig(
        prewarm: PrewarmMode.none,
        hosts: {
          'pinned.test': HostPolicy.pinOnly({
            Pin.certSha256(leafHash),
          }),
        },
      );

      final engine = AiaEngine();
      engine.initialize(config);

      final overrides = AiaHttpOverrides(engine);
      final result =
          overrides.handleBadCertificate(mockLeaf, 'pinned.test', 443);
      expect(result, isTrue, reason: 'Matching pin must permit connection');
    });
  });
}
