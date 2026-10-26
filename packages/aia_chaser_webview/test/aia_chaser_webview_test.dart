import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_webview/aia_chaser_webview.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:webview_flutter_android/src/android_webkit.g.dart'
    as android_webview;
import 'package:webview_flutter_android/webview_flutter_android.dart';
import 'package:webview_flutter_platform_interface/webview_flutter_platform_interface.dart';

class _TestWebViewClient extends android_webview.WebViewClient {
  _TestWebViewClient({
    super.onPageFinished,
    super.onPageStarted,
    super.onReceivedHttpError,
    super.onReceivedHttpAuthRequest,
    super.onReceivedRequestErrorCompat,
    super.doUpdateVisitedHistory,
    super.onReceivedRequestError,
    super.requestLoading,
    super.urlLoading,
    super.onFormResubmission,
    super.onLoadResource,
    super.onPageCommitVisible,
    super.onReceivedClientCertRequest,
    super.onReceivedLoginRequest,
    super.onReceivedSslError,
    super.onScaleChanged,
  }) : super.pigeon_detached();
}

class _TestWebChromeClient extends android_webview.WebChromeClient {
  _TestWebChromeClient({
    super.onProgressChanged,
    required super.onShowFileChooser,
    super.onGeolocationPermissionsShowPrompt,
    super.onGeolocationPermissionsHidePrompt,
    super.onShowCustomView,
    super.onHideCustomView,
    super.onPermissionRequest,
    super.onConsoleMessage,
    super.onJsAlert,
    required super.onJsConfirm,
    super.onJsPrompt,
  }) : super.pigeon_detached();
}

class _TestDownloadListener extends android_webview.DownloadListener {
  _TestDownloadListener({required super.onDownloadStart})
      : super.pigeon_detached();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    android_webview.PigeonOverrides.webViewClient_new = _TestWebViewClient.new;
    android_webview.PigeonOverrides.webChromeClient_new =
        _TestWebChromeClient.new;
    android_webview.PigeonOverrides.downloadListener_new =
        _TestDownloadListener.new;

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(
      'dev.flutter.pigeon.aia_chaser.AiaChaserHostApi.configure',
      (message) async =>
          const StandardMessageCodec().encodeMessage(<Object?>[null]),
    );

    await AiaChaser.initialize(AiaConfig(
      prewarm: PrewarmMode.none,
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
    android_webview.PigeonOverrides.webViewClient_new = null;
    android_webview.PigeonOverrides.webChromeClient_new = null;
    android_webview.PigeonOverrides.downloadListener_new = null;
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
