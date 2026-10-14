import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_dio/aia_chaser_dio.dart';
import 'package:dio/dio.dart';

void main() async {
  // 1. Initialize AIA Chaser with hosts that omit intermediate certificates
  await AiaChaser.initialize(
    const AiaConfig(
      hosts: {
        'register.acrex.in': HostPolicy.chase(retryOnce: true),
      },
      prewarm: PrewarmMode.background,
    ),
  );

  // 2. Configure Dio with AiaDioAdapter
  final dio = Dio();
  dio.httpClientAdapter = AiaDioAdapter();

  // 3. Make requests as normal - handshake failures trigger AIA chasing and transparent retry
  try {
    final response = await dio.get(
      'https://register.acrex.in/ACREXService.svc/GetSliderList',
    );
    print('Success: HTTP ${response.statusCode}');
    print('Data: ${response.data}');
  } on DioException catch (e) {
    print('DioException: ${e.message}');
  }
}
