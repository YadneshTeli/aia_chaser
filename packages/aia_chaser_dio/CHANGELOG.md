## 0.1.1

* Updated example code to use `incomplete-chain.badssl.com`.
* Bumped dependency to `aia_chaser: ^0.1.2`.

## 0.1.0

* First stable release of `aia_chaser_dio`.
* Updated dependency to stable `aia_chaser: ^0.1.0`.
* Automatic retry-once on incomplete SSL certificate chains with Dio.

## 0.1.0-alpha.1

* Initial alpha release of `aia_chaser_dio`.
* Transparent `Dio` HTTP adapter (`AiaDioAdapter`) with automatic retry-once on incomplete SSL certificate chains.
* Wires `badCertificateCallback` directly to the `aia_chaser` leaf store.
