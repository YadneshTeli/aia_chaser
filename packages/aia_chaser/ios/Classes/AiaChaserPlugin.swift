import Flutter
import UIKit

public class AiaChaserPlugin: NSObject, FlutterPlugin, AiaChaserHostApi {

    public static func register(with registrar: FlutterPluginRegistrar) {
        let messenger = registrar.messenger()
        let instance = AiaChaserPlugin()
        AiaChaserHostApiSetup.setUp(binaryMessenger: messenger, api: instance)
    }

    public func configure(config: NativeConfig) throws {
        // iOS platform TLS stack handles system trust natively.
    }

    public func validate(request: ValidationRequest, completion: @escaping (Result<ValidationResult, Error>) -> Void) {
        // Return validated passthrough on Apple platforms
        let result = ValidationResult(
            outcome: .validated,
            chainSha256Hex: [],
            fetchedUrls: [],
            durationMs: 0,
            detail: "iOS platform TLS automatically validates trust chains"
        )
        completion(.success(result))
    }

    public func prewarm(host: String, port: Int64, completion: @escaping (Result<ValidationResult, Error>) -> Void) {
        let result = ValidationResult(
            outcome: .validated,
            chainSha256Hex: [],
            fetchedUrls: [],
            durationMs: 0,
            detail: "Prewarm is not required on iOS"
        )
        completion(.success(result))
    }

    public func diagnose(host: String, port: Int64, timeoutMs: Int64, completion: @escaping (Result<ChainReport, Error>) -> Void) {
        let report = ChainReport(
            host: host,
            port: port,
            serverSentChain: [],
            completedChain: [],
            outcome: .validated,
            cause: "Apple platforms natively validate certificate trust chains.",
            suggestedFix: "No client-side AIA chasing required on iOS.",
            durationMs: 0
        )
        completion(.success(report))
    }

    public func getCacheStats() throws -> CacheStats {
        return CacheStats(
            issuerCacheCount: 0,
            issuerCacheBytes: 0,
            memoryVerdictCount: 0
        )
    }

    public func clearCaches(scope: ClearScope) throws {
        // No-op on iOS
    }
}
