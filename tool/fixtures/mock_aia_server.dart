import 'dart:io';

/// Mock HTTP server serving AIA intermediate certificates and failure scenarios.
void main(List<String> args) async {
  final port = args.isNotEmpty ? int.parse(args[0]) : 8088;
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
  print('[MockAiaServer] Listening on http://127.0.0.1:$port');

  await for (HttpRequest request in server) {
    final path = request.uri.path;
    print('[MockAiaServer] Received request for $path');

    if (path == '/intermediate.der') {
      // Serves mock intermediate certificate DER
      request.response.headers.contentType =
          ContentType('application', 'pkix-cert');
      final file = File('tool/fixtures/certs/intermediate.der');
      if (await file.exists()) {
        await request.response.addStream(file.openRead());
      } else {
        request.response.write('MOCK_DER_CERTIFICATE_BYTES');
      }
      await request.response.close();
    } else if (path == '/slow.der') {
      // Simulates slow / hanging endpoint
      await Future.delayed(const Duration(seconds: 10));
      request.response.statusCode = HttpStatus.ok;
      request.response.write('DELAYED_DATA');
      await request.response.close();
    } else if (path == '/oversized.der') {
      // Simulates payload bomb > 64 KiB
      request.response.headers.contentType =
          ContentType('application', 'pkix-cert');
      final largeBytes = List<int>.filled(128 * 1024, 0x41); // 128 KiB
      request.response.add(largeBytes);
      await request.response.close();
    } else if (path == '/loop.der') {
      // Points back in a cycle
      request.response.headers.contentType =
          ContentType('application', 'pkix-cert');
      request.response.write('LOOP_CERT_DATA');
      await request.response.close();
    } else if (path == '/redirect_private') {
      // Attempt SSRF redirect to internal link-local / AWS metadata
      request.response
          .redirect(Uri.parse('http://169.254.169.254/latest/meta-data/'));
    } else {
      request.response.statusCode = HttpStatus.notFound;
      request.response.write('Not found');
      await request.response.close();
    }
  }
}
