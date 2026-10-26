import 'dart:io';
import 'package:flutter/material.dart';
import 'package:aia_chaser/aia_chaser.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Initialize AIA Chaser with validate-ahead policies
  await AiaChaser.initialize(
    const AiaConfig(
      hosts: {
        'register.acrex.in': HostPolicy.chase(retryOnce: true),
        'acrex.in': HostPolicy.chase(retryOnce: true),
        '*.acrex.in': HostPolicy.chase(retryOnce: true),
      },
      prewarm: PrewarmMode.background,
    ),
  );

  // 2. Install HttpOverrides for dart:io HttpClient
  HttpOverrides.global = AiaHttpOverrides();

  runApp(const AiaChaserExampleApp());
}

class AiaChaserExampleApp extends StatelessWidget {
  const AiaChaserExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AIA Chaser Example',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2563EB),
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF60A5FA),
          brightness: Brightness.dark,
        ),
      ),
      home: const AiaChaserHomeScreen(),
    );
  }
}

class AiaChaserHomeScreen extends StatefulWidget {
  const AiaChaserHomeScreen({super.key});

  @override
  State<AiaChaserHomeScreen> createState() => _AiaChaserHomeScreenState();
}

class _AiaChaserHomeScreenState extends State<AiaChaserHomeScreen> {
  final TextEditingController _hostController =
      TextEditingController(text: 'register.acrex.in');
  ChainReport? _diagnosticReport;
  bool _isLoading = false;
  String? _httpStatus;
  CacheStats? _cacheStats;

  @override
  void initState() {
    super.initState();
    _refreshStats();
  }

  Future<void> _refreshStats() async {
    try {
      final stats = await AiaChaser.getCacheStats();
      if (mounted) setState(() => _cacheStats = stats);
    } catch (_) {}
  }

  Future<void> _runDiagnostics() async {
    final host = _hostController.text.trim();
    if (host.isEmpty) return;

    setState(() {
      _isLoading = true;
      _httpStatus = null;
    });

    try {
      final report = await AiaChaser.diagnose(host);
      if (mounted) {
        setState(() {
          _diagnosticReport = report;
          _isLoading = false;
        });
      }
      _refreshStats();
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _httpStatus = 'Error running diagnostics: $e';
        });
      }
    }
  }

  Future<void> _testHttpRequest() async {
    final host = _hostController.text.trim();
    if (host.isEmpty) return;

    setState(() {
      _isLoading = true;
      _httpStatus = null;
    });

    final stopwatch = Stopwatch()..start();
    try {
      final client = HttpClient();
      final uri = Uri.parse('https://$host/');
      final request = await client.getUrl(uri);
      final response = await request.close();
      stopwatch.stop();

      if (mounted) {
        setState(() {
          _isLoading = false;
          _httpStatus =
              'SUCCESS: HTTP ${response.statusCode} (${response.reasonPhrase}) in ${stopwatch.elapsedMilliseconds}ms\n'
              'TLS Handshake validated via AIA Chaser.';
        });
      }
      _refreshStats();
    } catch (e) {
      stopwatch.stop();
      if (mounted) {
        setState(() {
          _isLoading = false;
          _httpStatus = 'FAILED (${stopwatch.elapsedMilliseconds}ms): $e';
        });
      }
    }
  }

  Future<void> _prewarm() async {
    final host = _hostController.text.trim();
    if (host.isEmpty) return;

    setState(() => _isLoading = true);
    final stopwatch = Stopwatch()..start();
    try {
      final result = await AiaChaser.prewarm(host);
      stopwatch.stop();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Prewarmed $host -> ${result.outcome.name} (${stopwatch.elapsedMilliseconds}ms)',
            ),
          ),
        );
        setState(() => _isLoading = false);
      }
      _refreshStats();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Prewarm failed: $e')),
        );
        setState(() => _isLoading = false);
      }
    }
  }

  void _clearCache() {
    AiaChaser.clearCaches(scope: ClearScope.all);
    _refreshStats();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
          content: Text('AIA Chaser memory and disk cache cleared.')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AIA Chaser Example'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined),
            tooltip: 'Clear Cache',
            onPressed: _clearCache,
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh Stats',
            onPressed: _refreshStats,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Controls Card
            Card(
              elevation: 0,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(color: Theme.of(context).dividerColor),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Target Host',
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _hostController,
                      decoration: const InputDecoration(
                        hintText: 'e.g. register.acrex.in',
                        border: OutlineInputBorder(),
                        isDense: true,
                        prefixIcon: Icon(Icons.language),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 8,
                      children: [
                        ActionChip(
                          label: const Text('register.acrex.in'),
                          onPressed: () => setState(
                              () => _hostController.text = 'register.acrex.in'),
                        ),
                        ActionChip(
                          label: const Text('acrex.in'),
                          onPressed: () =>
                              setState(() => _hostController.text = 'acrex.in'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Wrap(
                      spacing: 12,
                      runSpacing: 8,
                      children: [
                        FilledButton.icon(
                          onPressed: _isLoading ? null : _runDiagnostics,
                          icon: const Icon(Icons.analytics_outlined),
                          label: const Text('Diagnose Chain'),
                        ),
                        OutlinedButton.icon(
                          onPressed: _isLoading ? null : _testHttpRequest,
                          icon: const Icon(Icons.http),
                          label: const Text('Test HTTPS Request'),
                        ),
                        OutlinedButton.icon(
                          onPressed: _isLoading ? null : _prewarm,
                          icon: const Icon(Icons.bolt),
                          label: const Text('Prewarm Host'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Cache Stats Bar
            if (_cacheStats != null)
              Card(
                elevation: 0,
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 16.0, vertical: 12.0),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      Text(
                        'Memory: ${_cacheStats!.memoryVerdictCount} entries',
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      Text(
                        'Disk: ${_cacheStats!.issuerCacheCount} certs (${_cacheStats!.issuerCacheBytes} B)',
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                    ],
                  ),
                ),
              ),

            // Loading indicator
            if (_isLoading)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 24.0),
                child: Center(child: CircularProgressIndicator()),
              ),

            // HTTP Status message
            if (_httpStatus != null) ...[
              const SizedBox(height: 16),
              Card(
                color: _httpStatus!.startsWith('SUCCESS')
                    ? Colors.green.withValues(alpha: 0.1)
                    : Colors.red.withValues(alpha: 0.1),
                elevation: 0,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                  side: BorderSide(
                    color: _httpStatus!.startsWith('SUCCESS')
                        ? Colors.green
                        : Colors.red,
                  ),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        _httpStatus!.startsWith('SUCCESS')
                            ? Icons.check_circle
                            : Icons.error_outline,
                        color: _httpStatus!.startsWith('SUCCESS')
                            ? Colors.green
                            : Colors.red,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          _httpStatus!,
                          style: TextStyle(
                            fontFamily: 'monospace',
                            color: _httpStatus!.startsWith('SUCCESS')
                                ? Colors.green.shade900
                                : Colors.red.shade900,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],

            // Diagnostic View
            if (_diagnosticReport != null) ...[
              const SizedBox(height: 16),
              AiaDiagnosticsView(
                report: _diagnosticReport!,
                onRefresh: _runDiagnostics,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
