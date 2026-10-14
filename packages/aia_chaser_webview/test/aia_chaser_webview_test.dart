import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_webview/aia_chaser_webview.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import 'package:webview_flutter_platform_interface/webview_flutter_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    AiaChaser.initialize(AiaConfig(
      hosts: {
        'trusted.com': const HostPolicy(chase: true),
        'unsafe.com': const HostPolicy(
          chase: false,
          onFailure: FailurePolicy.unsafeAllow(),
        ),
      },
    ));
  });

  tearDown(() {
    AiaChaser.reset();
  });

  test('AiaWebViewHandler.install attaches handler to delegate', () {
    final delegate = AndroidNavigationDelegate(
      AndroidNavigationDelegateCreationParams
          .fromPlatformNavigationDelegateCreationParams(
        const PlatformNavigationDelegateCreationParams(),
      ),
    );

    // Should install without throwing
    expect(() => AiaWebViewHandler.install(delegate), returnsNormally);
  });
}
