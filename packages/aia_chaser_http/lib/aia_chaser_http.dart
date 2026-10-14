import 'dart:io';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

/// A drop-in replacement for [http.Client] that integrates with AIA Chaser.
///
/// Automatically chases missing intermediate certificates and retries failed
/// requests once upon validation.
class AiaHttpClient extends http.BaseClient {
  final http.Client _inner;

  AiaHttpClient([http.Client? inner])
      : _inner = inner ?? IOClient(AiaHttpClientFactory.create());

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final host = request.url.host;
    final policy = AiaChaser.engine.resolvePolicy(host);

    // Buffer body bytes for retry if request is a Request with body
    List<int>? bodyBytes;
    if (request is http.Request) {
      bodyBytes = request.bodyBytes;
    }

    try {
      return await _inner.send(request);
    } catch (e) {
      final isHandshakeError = e is HandshakeException ||
          e is http.ClientException && e.message.contains('CERTIFICATE_VERIFY_FAILED') ||
          e.toString().contains('CERTIFICATE_VERIFY_FAILED');

      if (!isHandshakeError || !policy.retryOnce) {
        rethrow;
      }

      // Check if we can validate via AIA prewarm
      final result = await AiaChaser.prewarm(host, port: request.url.port);

      if (result.outcome == ValidationOutcome.validated ||
          result.outcome == ValidationOutcome.validatedByPin) {
        // Re-create replayable request
        final retryRequest = _recreateRequest(request, bodyBytes);
        return await _inner.send(retryRequest);
      }

      rethrow;
    }
  }

  http.BaseRequest _recreateRequest(http.BaseRequest original, List<int>? bodyBytes) {
    if (original is http.Request) {
      final req = http.Request(original.method, original.url)
        ..headers.addAll(original.headers)
        ..followRedirects = original.followRedirects
        ..maxRedirects = original.maxRedirects
        ..persistentConnection = original.persistentConnection;
      if (bodyBytes != null) {
        req.bodyBytes = bodyBytes;
      }
      return req;
    }

    // For general StreamedRequest, if it has already been finalized, it cannot be safely re-read
    throw http.ClientException(
      'Certificate completed via AIA, but streaming request body cannot be replayed for retry.',
      original.url,
    );
  }

  @override
  void close() {
    _inner.close();
  }
}
