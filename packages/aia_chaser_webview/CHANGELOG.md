## 0.1.0-alpha.1

* Initial alpha release of `aia_chaser_webview`.
* Native Android WebView SSL error integration (`AiaWebViewHandler.install`).
* Safely intercepts `onReceivedSslError` (`SSL_UNTRUSTED`), completes the chain via AIA chasing, and calls `proceed()` ONLY when cryptographic trust is confirmed.
