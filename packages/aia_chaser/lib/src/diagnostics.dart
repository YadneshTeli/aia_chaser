import 'dart:convert';
import 'pfn/aia_api.g.dart';

extension ChainReportFormatting on ChainReport {
  /// Formats the report as a clean, human-readable terminal/log string.
  String toFormattedString({bool redact = true}) {
    final buffer = StringBuffer();
    buffer.writeln(
        '================================================================================');
    buffer.writeln('[AiaChaser] Diagnostic Report for $host:$port');
    buffer.writeln(
        '--------------------------------------------------------------------------------');
    buffer.writeln('Outcome:      ${outcome.name.toUpperCase()}');
    buffer.writeln('Duration:     ${durationMs}ms');
    buffer.writeln('Server Sent:  ${serverSentChain.length} certificate(s)');
    buffer.writeln('Completed:    ${completedChain.length} certificate(s)');
    buffer.writeln(
        '--------------------------------------------------------------------------------');

    buffer.writeln('Server Presented Chain:');
    if (serverSentChain.isEmpty) {
      buffer.writeln('  (none)');
    } else {
      for (var i = 0; i < serverSentChain.length; i++) {
        final cert = serverSentChain[i];
        final fp = redact ? cert.sha256Hex.substring(0, 12) : cert.sha256Hex;
        buffer.writeln('  [${i + 1}] Subject: ${cert.subjectDn}');
        buffer.writeln('      Issuer:  ${cert.issuerDn}');
        buffer.writeln('      SHA-256: $fp...');
        if (cert.aiaUrl != null) {
          buffer.writeln('      AIA:     ${cert.aiaUrl}');
        }
      }
    }

    buffer.writeln(
        '--------------------------------------------------------------------------------');
    buffer.writeln('Resolved Trust Chain:');
    if (completedChain.isEmpty) {
      buffer.writeln('  (chain incomplete)');
    } else {
      for (var i = 0; i < completedChain.length; i++) {
        final cert = completedChain[i];
        final fp = redact ? cert.sha256Hex.substring(0, 12) : cert.sha256Hex;
        final src = cert.source.name.toUpperCase();
        buffer.writeln('  [${i + 1}] ($src) ${cert.subjectDn}');
        buffer.writeln('      SHA-256: $fp...');
      }
    }

    buffer.writeln(
        '--------------------------------------------------------------------------------');
    buffer.writeln('Root Cause:');
    buffer.writeln('  $cause');
    buffer.writeln('');
    buffer.writeln('Suggested Fix:');
    buffer.writeln('  $suggestedFix');
    buffer.writeln(
        '================================================================================');

    return buffer.toString();
  }

  /// Exports the report as redacted JSON suitable for bug reports.
  Map<String, dynamic> toRedactedJson() {
    return {
      'host': host,
      'port': port,
      'outcome': outcome.name,
      'durationMs': durationMs,
      'serverSentCount': serverSentChain.length,
      'completedCount': completedChain.length,
      'serverSent': serverSentChain
          .map((c) => {
                'subjectDn': c.subjectDn,
                'issuerDn': c.issuerDn,
                'sha12': c.sha256Hex.substring(0, 12),
                'source': c.source.name,
              })
          .toList(),
      'completed': completedChain
          .map((c) => {
                'subjectDn': c.subjectDn,
                'issuerDn': c.issuerDn,
                'sha12': c.sha256Hex.substring(0, 12),
                'source': c.source.name,
              })
          .toList(),
      'cause': cause,
      'suggestedFix': suggestedFix,
    };
  }

  String toJsonString({bool pretty = true}) {
    final encoder = pretty ? const JsonEncoder.withIndent('  ') : const JsonEncoder();
    return encoder.convert(toRedactedJson());
  }
}
