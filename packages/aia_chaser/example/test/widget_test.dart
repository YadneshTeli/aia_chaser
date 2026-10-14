import 'package:flutter_test/flutter_test.dart';
import 'package:aia_chaser_example/main.dart';

void main() {
  testWidgets('AiaChaserExampleApp smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const AiaChaserExampleApp());
    expect(find.text('AIA Chaser Example'), findsOneWidget);
    expect(find.text('Diagnose Chain'), findsOneWidget);
  });
}
