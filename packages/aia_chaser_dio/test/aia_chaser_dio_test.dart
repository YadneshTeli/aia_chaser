import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_dio/aia_chaser_dio.dart';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.configure',
      (ByteData? message) async {
        return const StandardMessageCodec().encodeMessage(<Object?>[null]);
      },
    );

    AiaChaser.initialize(const AiaConfig(
      prewarm: PrewarmMode.none,
      hosts: {
        'api.example.com': HostPolicy(
          chase: true,
          retryOnce: true,
        ),
        'no-retry.example.com': HostPolicy(
          chase: true,
          retryOnce: false,
        ),
      },
    ));
  });

  tearDown(() {
    AiaChaser.reset();
  });

  test('AiaDioAdapter initializes cleanly and respects close', () {
    final adapter = AiaDioAdapter();
    expect(adapter, isNotNull);
    adapter.close(force: true);
  });

  test('AiaDioAdapter passes through non-handshake DioException without retry',
      () async {
    final dio = Dio();
    dio.httpClientAdapter = AiaDioAdapter();

    expect(
      () => dio.get('http://nonexistent.invalid.local-test/data'),
      throwsA(isA<DioException>()),
    );
  });
}
