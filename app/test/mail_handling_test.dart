import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

// Settings → Mail handling: the Spam screen (model status, thresholds, DNSBL,
// folder, allow / block lists) and the Filters screen (enable, reorder, add /
// edit / remove, dry run), against FakeCore (acct-1 holds two seeded rules).

FakeCore fake() => FakeCore(latency: Duration.zero);

Future<void> pumpAt(
  WidgetTester tester,
  FakeCore core,
  String location, {
  Size size = desktop,
}) async {
  setSurface(tester, size);
  await tester.pumpWidget(buildApp(core: core, initialLocation: location));
  await tester.pumpAndSettle();
}

Future<void> scrollTo(WidgetTester tester, Finder f) async {
  await tester.scrollUntilVisible(f, 200, scrollable: find.byType(Scrollable).first);
  await tester.pumpAndSettle();
}

void main() {
  group('Settings → Mail handling', () {
    testWidgets('the section lists signature, out of office, spam and filters per account', (
      tester,
    ) async {
      await pumpAt(tester, fake(), '/settings');
      final spam = find.byKey(const ValueKey('settings-spam-acct-1'));
      await scrollTo(tester, spam);
      expect(find.byKey(const Key('settings-mail-handling')), findsOneWidget);
      expect(find.text('Signature & out of office'), findsNothing);
      expect(find.byKey(const ValueKey('settings-filters-acct-1')), findsOneWidget);
      expect(find.text('alice.rivera@gmail.com · 2 rules'), findsOneWidget);
      expect(find.text('alice.rivera@gmail.com · on'), findsOneWidget);
      await tester.tap(spam);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('spam-model')), findsOneWidget);
    });
  });

  group('Spam screen', () {
    testWidgets('model status and the account settings as the engine reports them', (tester) async {
      await pumpAt(tester, fake(), '/settings/spam?account=acct-1');
      expect(find.text('trusted 62 %'), findsOneWidget);
      expect(
        find.textContaining('Learned from 12 spam and 31 not-spam messages (2417 words)'),
        findsOneWidget,
      );
      expect(find.text('Possibly spam from 50 %'), findsOneWidget);
      expect(find.text('Spam from 90 %'), findsOneWidget);
      expect(find.textContaining('moved to [Gmail]/Spam'), findsOneWidget);
      expect(
        find.text('Off by default: reveals sender IPs and link domains to your DNS resolver.'),
        findsOneWidget,
      );
      expect(tester.widget<SwitchListTile>(find.byKey(const Key('spam-dnsbl'))).value, isFalse);
      expect(
        find.byKey(const Key('spam-account')),
        findsOneWidget,
        reason: 'two accounts: a picker',
      );
    });

    testWidgets('thresholds, DNSBL and folder are saved and normalised by the engine', (
      tester,
    ) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/spam?account=acct-1');
      // Drag the spam threshold all the way left: the unsure one follows (never above it).
      await tester.drag(find.byKey(const Key('spam-spam-threshold')), const Offset(-2000, 0));
      await tester.pumpAndSettle();
      expect(find.text('Spam from 0 %'), findsOneWidget);
      expect(find.text('Possibly spam from 0 %'), findsOneWidget);
      await tester.drag(find.byKey(const Key('spam-spam-threshold')), const Offset(2000, 0));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('spam-dnsbl')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('spam-save')));
      await tester.pumpAndSettle();
      expect(find.text('Spam settings saved'), findsOneWidget);
      final s = await core.spamSettings('acct-1');
      expect((s.spamThreshold, s.unsureThreshold, s.dnsblEnabled), (1.0, 0.0, true));
    });

    testWidgets('an invalid folder is refused inline with the engine\'s words', (tester) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/spam?account=acct-1');
      await tester.enterText(find.byKey(const Key('spam-folder')), 'INBOX');
      await tester.tap(find.byKey(const Key('spam-save')));
      await tester.pumpAndSettle();
      expect(find.text('move_to_folder cannot be INBOX'), findsOneWidget);
      expect((await core.spamSettings('acct-1')).moveToFolder, 'Spam', reason: 'nothing changed');
    });

    testWidgets('allow and block lists: add, move between them, remove', (tester) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/spam?account=acct-1');
      final allowInput = find.byKey(const Key('spam-allow-input'));
      await scrollTo(tester, allowInput);
      await tester.enterText(allowInput, '@Friend.Example');
      await tester.tap(find.byKey(const Key('spam-allow-add')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('spam-allow-friend.example')),
        findsOneWidget,
        reason: 'normalised',
      );
      final blockInput = find.byKey(const Key('spam-block-input'));
      await scrollTo(tester, blockInput);
      await tester.enterText(blockInput, 'friend.example');
      await tester.tap(find.byKey(const Key('spam-block-add')));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('spam-block-friend.example')), findsOneWidget);
      expect(
        find.byKey(const ValueKey('spam-allow-friend.example')),
        findsNothing,
        reason: 'moved over',
      );
      await tester.tap(find.byTooltip('Remove friend.example'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('spam-block-friend.example')), findsNothing);
      final s = await core.spamSettings('acct-1');
      expect(s.allowlist, isEmpty);
      expect(s.blocklist, isEmpty);
    });

    testWidgets('switching the account in the picker opens that account\'s settings', (
      tester,
    ) async {
      final core = fake();
      await core.setSpamSettings('acct-2', const SpamSettings(enabled: false));
      await pumpAt(tester, core, '/settings/spam?account=acct-1');
      expect(tester.widget<SwitchListTile>(find.byKey(const Key('spam-enabled'))).value, isTrue);
      await tester.tap(find.byKey(const Key('spam-account')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('alice@fastmail.com').last);
      await tester.pumpAndSettle();
      expect(tester.widget<SwitchListTile>(find.byKey(const Key('spam-enabled'))).value, isFalse);
      expect(find.textContaining('Off: nothing is classified'), findsOneWidget);
    });
  });

  group('Filters screen', () {
    testWidgets('lists the rules in order with readable conditions; a switch disables one', (
      tester,
    ) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/filters?account=acct-1');
      expect(find.text('Newsletters'), findsOneWidget);
      expect(find.text('Subject contains "[newsletter]": move to Newsletters'), findsOneWidget);
      expect(find.text('From domain is "sealbox.test": star'), findsOneWidget);
      expect(
        tester.getTopLeft(find.text('Newsletters')).dy,
        lessThan(tester.getTopLeft(find.text('Finance')).dy),
      );
      await tester.tap(find.byKey(const ValueKey('filter-enabled-2')));
      await tester.pumpAndSettle();
      expect((await core.filterRules('acct-1')).firstWhere((r) => r.id == 2).enabled, isFalse);
    });

    testWidgets('drag to reorder saves the new order (setFilterRules)', (tester) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/filters?account=acct-1');
      final handle = find.descendant(
        of: find.byKey(const ValueKey('filter-rule-2')),
        matching: find.byIcon(Icons.drag_indicator),
      );
      final gesture = await tester.startGesture(tester.getCenter(handle));
      await tester.pump(const Duration(milliseconds: 50));
      await gesture.moveBy(const Offset(0, -200));
      await tester.pump();
      await gesture.up();
      await tester.pumpAndSettle();
      final rules = await core.filterRules('acct-1');
      expect(rules.map((r) => r.name), ['Finance', 'Newsletters']);
      expect(rules.map((r) => r.order), [10, 20]);
      expect(
        tester.getTopLeft(find.text('Finance')).dy,
        lessThan(tester.getTopLeft(find.text('Newsletters')).dy),
      );
    });

    testWidgets('add a rule with a flag; an invalid flag is refused inline', (tester) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/filters?account=acct-2');
      expect(find.byKey(const Key('filters-empty')), findsOneWidget);
      await tester.tap(find.byKey(const Key('filters-add')));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('filter-name')), 'Lists');
      await tester.enterText(find.byKey(const Key('filter-value')), 'list');
      await tester.ensureVisible(find.byKey(const Key('filter-action')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-action')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Add a flag').last);
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('filter-flag')), 'two words');
      await tester.ensureVisible(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('filter-error')), findsOneWidget);
      expect(find.textContaining('is not a valid IMAP flag'), findsOneWidget);
      await tester.enterText(find.byKey(const Key('filter-flag')), r'$List');
      await tester.ensureVisible(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('filter-editor')), findsNothing);
      expect(find.text(r'Subject contains "list": flag $List'), findsOneWidget);
      final rules = await core.filterRules('acct-2');
      expect(rules.single.action.code, r'flag:$List');
    });

    testWidgets('edit a rule, then remove it after confirming', (tester) async {
      final core = fake();
      await pumpAt(tester, core, '/settings/filters?account=acct-1');
      await tester.tap(find.text('Newsletters'));
      await tester.pumpAndSettle();
      expect(find.text('Edit rule'), findsOneWidget);
      await tester.ensureVisible(find.byKey(const Key('filter-stop')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-stop')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-save')));
      await tester.pumpAndSettle();
      expect(
        find.text('Subject contains "[newsletter]": move to Newsletters, then stop'),
        findsOneWidget,
      );
      expect((await core.filterRules('acct-1')).first.stop, isTrue);

      await tester.tap(find.text('Newsletters'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('filter-remove')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('filter-remove')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('filter-remove-dialog')), findsOneWidget);
      await tester.tap(find.byKey(const Key('filter-remove-confirm')));
      await tester.pumpAndSettle();
      expect(find.text('Newsletters'), findsNothing);
      expect((await core.filterRules('acct-1')).map((r) => r.name), ['Finance']);
    });

    testWidgets('test against a message: one row per enabled rule and the combined effect', (
      tester,
    ) async {
      await pumpAt(tester, fake(), '/settings/filters?account=acct-1');
      await tester.tap(find.byKey(const Key('filters-test')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('filters-test-picker')), findsOneWidget);
      await tester.tap(find.byKey(const ValueKey('filter-test-pick-m-1')));
      await tester.pumpAndSettle();
      final report = find.byKey(const Key('filters-test-report'));
      await scrollTo(tester, report);
      expect(find.text('Test: "Q4 budget — final numbers"'), findsOneWidget);
      expect(find.text('Would star it (rule: Finance).'), findsOneWidget);
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('filter-test-rule-2')),
          matching: find.text('matches'),
        ),
        findsOneWidget,
      );
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('filter-test-rule-1')),
          matching: find.text('no match'),
        ),
        findsOneWidget,
      );
    });
  });
}
