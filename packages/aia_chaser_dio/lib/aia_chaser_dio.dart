import 'dart:io';
import 'dart:typed_data';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';

/// A custom [HttpClientAdapter] for Dio that integrates with AIA Chaser.
///
/// Automatically wires [AiaHttpOverrides] and transparently retries requests
/// once when an incomplete certificate chain is chased and validated.
class AiaDioAdapter implements HttpClientAdapter {
  final IOHttpClientAdapter _inner;

  AiaDioAdapter({
    CreateHttpClient? createHttpClient,
    ValidateCertificate? validateCertificate,
  }) : _inner = IOHttpClientAdapter(
          createHttpClient: createHttpClient ?? AiaHttpClientFactory.create,
          validateCertificate: validateCertificate,
        );

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    final host = options.uri.host;
    final policy = AiaChaser.engine.resolvePolicy(host);

    try {
      return await _inner.fetch(options, requestStream, cancelFuture);
    } on DioException catch (e) {
      final errStr = '${e.error} ${e.message}';
      final isHandshakeError = e.error is HandshakeException ||
          e.error is TlsException ||
          e.type == DioExceptionType.badCertificate ||
          e.type == DioExceptionType.connectionError ||
          errStr.contains('CERTIFICATE_VERIFY_FAILED') ||
          errStr.contains('HandshakeException') ||
          errStr.contains('Handshake error') ||
          errStr.contains('certificate');

      if (!isHandshakeError || !policy.retryOnce) {
        rethrow;
      }

      // Check if we can validate the host via prewarm
      final port = options.uri.hasPort ? options.uri.port : 443;
      final result = await AiaChaser.prewarm(host, port: port);

      if (result.outcome == ValidationOutcome.validated ||
          result.outcome == ValidationOutcome.validatedByPin) {
        // Re-attempt request once
        // Note: streaming request bodies that are already consumed cannot be retried
        if (requestStream != null && options.data is Stream) {
          throw DioException(
            requestOptions: options,
            error:
                'Certificate validated via AIA, but request stream cannot be replayed for retry.',
            type: DioExceptionType.unknown,
          );
        }

        // Retry with a fresh stream if data was buffered
        Stream<Uint8List>? retryStream;
        if (options.data is List<int>) {
          retryStream =
              Stream.value(Uint8List.fromList(options.data as List<int>));
        }

        return await _inner.fetch(options, retryStream, cancelFuture);
      }

      rethrow;
    }
  }

  @override
  void close({bool force = false}) {
    _inner.close(force: force);
  }
}
