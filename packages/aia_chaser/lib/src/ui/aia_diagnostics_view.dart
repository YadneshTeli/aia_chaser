import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../diagnostics.dart';
import '../pfn/aia_api.g.dart';

/// Semantic colors for AIA Chaser UI components per the UI/UX design brief.
class AiaThemeColors {
  final Color signalBlue;
  final Color chainGreen;
  final Color amber;
  final Color alarmRed;
  final Color dashedGray;

  const AiaThemeColors({
    required this.signalBlue,
    required this.chainGreen,
    required this.amber,
    required this.alarmRed,
    required this.dashedGray,
  });

  factory AiaThemeColors.light() => const AiaThemeColors(
        signalBlue: Color(0xFF2563EB),
        chainGreen: Color(0xFF16A34A),
        amber: Color(0xFFD97706),
        alarmRed: Color(0xFFDC2626),
        dashedGray: Color(0xFF94A3B8),
      );

  factory AiaThemeColors.dark() => const AiaThemeColors(
        signalBlue: Color(0xFF60A5FA),
        chainGreen: Color(0xFF4ADE80),
        amber: Color(0xFFFBBF24),
        alarmRed: Color(0xFFF87171),
        dashedGray: Color(0xFF64748B),
      );
}

/// A drop-in inspector widget for visualizing certificate chains, AIA chasing,
/// and automated root-cause diagnostics.
class AiaDiagnosticsView extends StatelessWidget {
  final ChainReport report;
  final VoidCallback? onRefresh;

  const AiaDiagnosticsView({
    super.key,
    required this.report,
    this.onRefresh,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final colors = isDark ? AiaThemeColors.dark() : AiaThemeColors.light();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildHeaderCard(context, colors),
              const SizedBox(height: 16),
              _buildChainSection(context, colors),
              const SizedBox(height: 16),
              _buildDiagnosticCard(context, colors),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeaderCard(BuildContext context, AiaThemeColors colors) {
    final statusColor = _getOutcomeColor(report.outcome, colors);
    final statusIcon = _getOutcomeIcon(report.outcome);

    return Card(
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
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Expanded(
                  child: Text(
                    report.host,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: statusColor.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(statusIcon, size: 16, color: statusColor),
                      const SizedBox(width: 6),
                      Text(
                        _formatOutcome(report.outcome),
                        style: TextStyle(
                          color: statusColor,
                          fontWeight: FontWeight.w600,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              'Port: ${report.port}  •  Duration: ${report.durationMs}ms',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).textTheme.bodySmall?.color,
                  ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildChainSection(BuildContext context, AiaThemeColors colors) {
    final certs = report.completedChain.isNotEmpty
        ? report.completedChain
        : report.serverSentChain;

    if (certs.isEmpty) {
      return Card(
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: Theme.of(context).dividerColor),
        ),
        child: const Padding(
          padding: EdgeInsets.all(24.0),
          child: Center(
            child: Text('No certificate chain presented by the remote server.'),
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4.0, vertical: 8.0),
          child: Text(
            'Certificate Trust Path (${certs.length})',
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
          ),
        ),
        ListView.separated(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          itemCount: certs.length,
          separatorBuilder: (context, index) => _buildConnector(colors),
          itemBuilder: (context, index) {
            final cert = certs[index];
            final isLeaf = index == 0;
            return _buildCertNode(context, cert, isLeaf, colors);
          },
        ),
      ],
    );
  }

  Widget _buildConnector(AiaThemeColors colors) {
    return Center(
      child: Container(
        width: 2,
        height: 24,
        color: colors.dashedGray,
      ),
    );
  }

  Widget _buildCertNode(
    BuildContext context,
    CertInfo cert,
    bool isLeaf,
    AiaThemeColors colors,
  ) {
    final isAia = cert.source == CertSource.aia;
    final badgeColor = isAia ? colors.amber : colors.signalBlue;
    final badgeLabel = _getSourceBadgeLabel(cert.source);

    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: isAia ? colors.amber : Theme.of(context).dividerColor,
          width: isAia ? 1.5 : 1.0,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Expanded(
                  child: Text(
                    _extractCn(cert.subjectDn),
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: badgeColor.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    badgeLabel,
                    style: TextStyle(
                      color: badgeColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              'Issuer: ${_extractCn(cert.issuerDn)}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                const Icon(Icons.fingerprint, size: 14),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    'SHA-256: ${cert.sha256Hex.substring(0, 16)}...',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.copy, size: 14),
                  tooltip: 'Copy full fingerprint',
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: cert.sha256Hex));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Fingerprint copied to clipboard'),
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                ),
              ],
            ),
            if (cert.aiaUrl != null) ...[
              const SizedBox(height: 6),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.link, size: 14),
                  const SizedBox(width: 4),
                  Expanded(
                    child: Text(
                      'AIA: ${cert.aiaUrl}',
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildDiagnosticCard(BuildContext context, AiaThemeColors colors) {
    return Card(
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
            Row(
              children: [
                const Icon(Icons.assessment_outlined, size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Diagnosis & Suggested Fix',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const Spacer(),
                TextButton.icon(
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('Copy Report'),
                  onPressed: () {
                    Clipboard.setData(
                        ClipboardData(text: report.toFormattedString()));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Report copied to clipboard'),
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                ),
              ],
            ),
            const Divider(),
            const SizedBox(height: 8),
            const Text(
              'Root Cause',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
            ),
            const SizedBox(height: 4),
            Text(report.cause, style: Theme.of(context).textTheme.bodyMedium),
            const SizedBox(height: 12),
            const Text(
              'Recommended Server Fix',
              style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
            ),
            const SizedBox(height: 4),
            Text(report.suggestedFix,
                style: Theme.of(context).textTheme.bodyMedium),
          ],
        ),
      ),
    );
  }

  Color _getOutcomeColor(ValidationOutcome outcome, AiaThemeColors colors) {
    switch (outcome) {
      case ValidationOutcome.validated:
      case ValidationOutcome.validatedByPin:
        return colors.chainGreen;
      case ValidationOutcome.policyUnsafeAllowed:
      case ValidationOutcome.maxDepthExceeded:
        return colors.amber;
      default:
        return colors.alarmRed;
    }
  }

  IconData _getOutcomeIcon(ValidationOutcome outcome) {
    switch (outcome) {
      case ValidationOutcome.validated:
      case ValidationOutcome.validatedByPin:
        return Icons.verified_user_outlined;
      case ValidationOutcome.policyUnsafeAllowed:
        return Icons.warning_amber_rounded;
      default:
        return Icons.gpp_bad_outlined;
    }
  }

  String _formatOutcome(ValidationOutcome outcome) {
    switch (outcome) {
      case ValidationOutcome.validated:
        return 'Validated';
      case ValidationOutcome.validatedByPin:
        return 'Pinned';
      case ValidationOutcome.rejectedUntrusted:
        return 'Untrusted';
      case ValidationOutcome.rejectedHostname:
        return 'Host Mismatch';
      case ValidationOutcome.rejectedExpired:
        return 'Expired';
      case ValidationOutcome.aiaUnavailable:
        return 'AIA Down';
      case ValidationOutcome.aiaFetchFailed:
        return 'Fetch Failed';
      case ValidationOutcome.maxDepthExceeded:
        return 'Depth Exceeded';
      case ValidationOutcome.noCertificate:
        return 'No Cert';
      case ValidationOutcome.policyUnsafeAllowed:
        return 'Unsafe Allowed';
      case ValidationOutcome.notConfigured:
        return 'Not Configured';
    }
  }

  String _getSourceBadgeLabel(CertSource source) {
    switch (source) {
      case CertSource.server:
        return 'Sent by server';
      case CertSource.aia:
        return 'Fetched via AIA';
      case CertSource.seed:
        return 'Seed certificate';
      case CertSource.systemRoot:
        return 'System Root';
    }
  }

  String _extractCn(String dn) {
    final parts = dn.split(',');
    for (final part in parts) {
      final trimmed = part.trim();
      if (trimmed.toUpperCase().startsWith('CN=')) {
        return trimmed.substring(3);
      }
    }
    return dn;
  }
}
