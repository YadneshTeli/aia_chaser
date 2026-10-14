import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:aia_chaser/aia_chaser.dart';
import 'package:aia_chaser_webview/aia_chaser_webview.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Initialize AIA Chaser
  await AiaChaser.initialize(
    const AiaConfig(
      hosts: {
        'register.acrex.in': HostPolicy.chase(),
      },
      prewarm: PrewarmMode.background,
    ),
  );

  runApp(const MaterialApp(home: WebViewExampleScreen()));
}

class WebViewExampleScreen extends StatefulWidget {
  const WebViewExampleScreen({super.key});

  @override
  State<WebViewExampleScreen> createState() => _WebViewExampleScreenState();
}

class _WebViewExampleScreenState extends State<WebViewExampleScreen> {
  late final WebViewController _controller;

  @override
  void initState() {
    super.initState();

    final delegate = NavigationDelegate(
      onPageFinished: (url) => debugPrint('Loaded: $url'),
    );

    // 2. Install AIA SSL error handler on AndroidNavigationDelegate
    // Safely intercepts SSL_UNTRUSTED, downloads intermediate CA, and continues
    if (defaultTargetPlatform == TargetPlatform.android) {
      AiaWebViewHandler.install(delegate.platform as AndroidNavigationDelegate);
    }

    // 3. Load HTTPS URL that has an incomplete intermediate chain
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(delegate)
      ..loadRequest(
        Uri.parse(
          'https://register.acrex.in/hallLayout/ViewhallLayout.html?HallId=7&hallName=HALL+9',
        ),
      );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('AIA WebView Example')),
      body: WebViewWidget(controller: _controller),
    );
  }
}
