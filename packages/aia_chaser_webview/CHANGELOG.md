## 0.1.0

* First stable release of `aia_chaser_webview`.
* Updated dependency to stable `aia_chaser: ^0.1.0`.
* Android WebView SSL error integration (`AiaWebViewHandler.install`) for safe AIA validation.

## 0.1.0-alpha.1

* Initial alpha release of `aia_chaser_webview`.
* Native Android WebView SSL error integration (`AiaWebViewHandler.install`).
* Safely intercepts `onReceivedSslError` (`SSL_UNTRUSTED`), completes the chain via AIA chasing, and calls `proceed()` ONLY when cryptographic trust is confirmed.
