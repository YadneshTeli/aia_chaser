import 'dart:io';

/// Mock HTTPS server that serves deliberately incomplete certificate chains
/// (only the leaf certificate is sent during the TLS handshake).
void main(List<String> args) async {
  final port = args.isNotEmpty ? int.parse(args[0]) : 8443;

  final leafCertFile = File('tool/fixtures/certs/leaf.pem');
  final keyFile = File('tool/fixtures/certs/leaf_key.pem');

  if (!await leafCertFile.exists() || !await keyFile.exists()) {
    print('[BrokenChainServer] Certificate files not found at tool/fixtures/certs/.');
    print('[BrokenChainServer] Run generate_certs script to produce fixtures.');
    return;
  }

  final securityContext = SecurityContext()
    ..useCertificateChain(leafCertFile.path)
    ..usePrivateKey(keyFile.path);

  final server = await SecureServerSocket.bind(
    InternetAddress.loopbackIPv4,
    port,
    securityContext,
  );

  print('[BrokenChainServer] TLS server listening on https://127.0.0.1:$port');
  print('[BrokenChainServer] Serving incomplete certificate chain (leaf only).');

  await for (SecureSocket client in server) {
    client.listen(
      (data) {
        final response =
            'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\nAIA Chaser Test OK';
        client.write(response);
        client.close();
      },
      onError: (e) {
        print('[BrokenChainServer] Handshake/Client error: $e');
        client.destroy();
      },
      cancelOnError: true,
    );
  }
}
