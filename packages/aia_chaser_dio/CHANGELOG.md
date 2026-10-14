## 0.1.0-alpha.1

* Initial alpha release of `aia_chaser_dio`.
* Transparent `Dio` HTTP adapter (`AiaDioAdapter`) with automatic retry-once on incomplete SSL certificate chains.
* Wires `badCertificateCallback` directly to the `aia_chaser` leaf store.
