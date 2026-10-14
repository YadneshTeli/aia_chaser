import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_http/aia_chaser_http.dart';
import 'package:http/http.dart' as http;

void main() async {
  // 1. Initialize AIA Chaser with hosts requiring chain completion
  await AiaChaser.initialize(
    const AiaConfig(
      hosts: {
        'register.acrex.in': HostPolicy.chase(retryOnce: true),
      },
      prewarm: PrewarmMode.background,
    ),
  );

  // 2. Wrap standard http.Client with AiaHttpClient
  final client = AiaHttpClient(http.Client());

  // 3. Make requests - transparently retries once if intermediate CA needs to be chased
  try {
    final response = await client.get(
      Uri.parse('https://register.acrex.in/ACREXService.svc/GetSliderList'),
    );
    print('HTTP Status: ${response.statusCode}');
    print('Response: ${response.body}');
  } finally {
    client.close();
  }
}
