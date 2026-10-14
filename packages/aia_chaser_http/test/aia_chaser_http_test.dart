import 'dart:io';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_http/aia_chaser_http.dart';
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
      },
    ));
  });

  tearDown(() {
    AiaChaser.reset();
  });

  test('AiaHttpClient initializes cleanly and closes without error', () {
    final client = AiaHttpClient();
    expect(client, isNotNull);
    client.close();
  });

  test('AiaHttpClient passes through regular requests or non-handshake errors',
      () async {
    final client = AiaHttpClient();
    expect(
      () => client.get(Uri.parse('http://nonexistent.invalid.local-test')),
      throwsA(isA<SocketException>()),
    );
    client.close();
  });
}
