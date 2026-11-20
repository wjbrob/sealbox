import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sealbox_app/src/core/fake_core.dart';
import 'package:sealbox_app/src/core/models.dart';

import 'helpers.dart';

// Settings → My key → key directory (publish / verify / states), Settings →
// Server (runtime URL), and the account pickers for My key and Security.

class _Core extends FakeCore {
  _Core({this.publishError}) : super(latency: Duration.zero);

  final Object? publishError;
  DirectoryStatus? forced;
  int statusCalls = 0;

  @override
  Future<DirectoryStatus> directoryStatus(String accountId) async {
    statusCalls++;
    return forced ?? await super.directoryStatus(accountId);
  }

  @override
  Future<PublishResult> publishKey(String accountId) async {
    if (publishError != null) throw publishError!;
    return super.publishKey(accountId);
  }
}

/// Like the real engine: the directory answers only what it serves (nothing until the
/// address is verified); "awaiting" comes only from completing the verification.
class _EngineLike extends FakeCore {
  _EngineLike() : super(latency: Duration.zero);

  bool _uploaded = false;
  bool _verified = false;
  bool mailArrived = false;

  DirectoryStatus _status(String id) => DirectoryStatus(
    accountId: id,
    state: _verified ? DirectoryState.published : DirectoryState.unpublished,
    serverUrl: 'https://sealbox.example',
    published: _verified,
    fingerprintMatches: _verified ? true : null,
  );

  @override
  Future<DirectoryStatus> directoryStatus(String accountId) async => _status(accountId);

  @override
  Future<PublishResult> publishKey(String accountId) async {
    _uploaded = true;
    return PublishResult(
      accountId: accountId,
      fingerprint: 'F',
      serverUrl: 'https://sealbox.example',
      tokenIssued: !_verified,
    );
  }

  @override
  Future<DirectoryStatus> completeDirectoryVerification(String accountId) async {
    if (_uploaded && mailArrived) _verified = true;
    final s = _status(accountId);
    return _verified
        ? s
        : DirectoryStatus(
            accountId: accountId,
            state: DirectoryState.awaitingVerification,
            serverUrl: s.serverUrl,
          );
  }
}

Future<void> pumpSettings(
  WidgetTester tester,
  FakeCore core, {
  String location = '/settings',
}) async {
  setSurface(tester, desktop);
  await tester.pumpWidget(buildApp(core: core, initialLocation: location));
  await tester.pumpAndSettle();
}

/// Scrolls the settings list from the top until [f] is on screen, then centres it
/// (so the panel's chip above a button stays in view when the button is tapped).
Future<void> reveal(WidgetTester tester, Finder f) async {
  final list = find.byType(Scrollable).first;
  tester.state<ScrollableState>(list).position.jumpTo(0);
  await tester.pumpAndSettle();
  await tester.scrollUntilVisible(f, 200, scrollable: list);
  await tester.pumpAndSettle();
  await Scrollable.ensureVisible(tester.element(f), alignment: 0.5);
  await tester.pumpAndSettle();
}

Finder chip(DirectoryState s) => find.byKey(ValueKey('directory-state-${s.name}'));

void main() {
  group('publish to the key directory', () {
    testWidgets('unpublished → Publish → check your inbox → Complete verification → published', (
      tester,
    ) async {
      final core = _Core();
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-publish')));
      expect(chip(DirectoryState.unpublished), findsOneWidget);
      expect(find.text('Publish to directory (soon)'), findsNothing);
      await tester.tap(find.byKey(const Key('directory-publish')));
      await tester.pumpAndSettle();
      expect(
        find.text(
          'Key uploaded. The directory mailed a verification link to alice.rivera@gmail.com.',
        ),
        findsOneWidget,
      );
      expect(chip(DirectoryState.awaitingVerification), findsOneWidget);
      expect(find.textContaining("Check your inbox for the directory's mail"), findsOneWidget);
      await tester.tap(find.byKey(const Key('directory-complete')));
      await tester.pumpAndSettle();
      expect(find.text('Verified: your key is published.'), findsOneWidget);
      // The panel shrank (no buttons any more): scroll back up to its chip.
      await tester.scrollUntilVisible(
        chip(DirectoryState.published),
        -150,
        scrollable: find.byType(Scrollable).first,
      );
      expect(chip(DirectoryState.published), findsOneWidget);
      expect(find.text('Published on sealbox.example'), findsOneWidget);
      expect(find.byKey(const Key('directory-publish')), findsNothing);
    });

    testWidgets('engine semantics: the panel remembers the mailed challenge until it is verified', (
      tester,
    ) async {
      final core = _EngineLike();
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-publish')));
      await tester.tap(find.byKey(const Key('directory-publish')));
      await tester.pumpAndSettle();
      expect(
        chip(DirectoryState.awaitingVerification),
        findsOneWidget,
        reason: 'status says unpublished',
      );
      await tester.tap(find.byKey(const Key('directory-complete')));
      await tester.pumpAndSettle();
      expect(find.textContaining('has not arrived yet'), findsOneWidget);
      expect(chip(DirectoryState.awaitingVerification), findsOneWidget);
      core.mailArrived = true;
      await tester.tap(find.byKey(const Key('directory-complete')));
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        chip(DirectoryState.published),
        -150,
        scrollable: find.byType(Scrollable).first,
      );
      expect(chip(DirectoryState.published), findsOneWidget);
    });

    testWidgets('no server: Publish is disabled and "Set a server URL first" leads to Server', (
      tester,
    ) async {
      final core = _Core()
        ..configuredServer = null
        ..environmentServer = null;
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-set-server')));
      expect(chip(DirectoryState.noServer), findsOneWidget);
      expect(
        tester.widget<FilledButton>(find.byKey(const Key('directory-publish'))).onPressed,
        isNull,
      );
      await tester.tap(find.byKey(const Key('directory-set-server')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('server-url-field')).hitTestable(), findsOneWidget);
      // Setting a server there makes the directory reachable for publishing.
      await tester.enterText(find.byKey(const Key('server-url-field')), 'https://keys.example.org');
      await tester.tap(find.byKey(const Key('server-url-save')));
      await tester.pumpAndSettle();
      await reveal(tester, find.byKey(const Key('directory-publish')));
      expect(chip(DirectoryState.unpublished), findsOneWidget);
      expect(find.textContaining('keys.example.org'), findsWidgets);
    });

    testWidgets('another key is published: offers to publish this one', (tester) async {
      final core = _Core()..directoryProgression = const [DirectoryState.otherKey];
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-publish')));
      expect(chip(DirectoryState.otherKey), findsOneWidget);
      expect(find.textContaining('holds another key for this address'), findsOneWidget);
      expect(find.text('Publish this key'), findsOneWidget);
    });

    testWidgets('verification failed: Publish again', (tester) async {
      final core = _Core()..directoryProgression = const [DirectoryState.verificationFailed];
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-publish')));
      expect(chip(DirectoryState.verificationFailed), findsOneWidget);
      expect(find.text('Publish again'), findsOneWidget);
    });

    testWidgets('unreachable: the error and Retry, which asks the directory again', (tester) async {
      final core = _Core()
        ..forced = const DirectoryStatus(
          accountId: 'acct-1',
          state: DirectoryState.unreachable,
          serverUrl: 'https://sealbox.example',
          error: 'connection: https://sealbox.example: connection refused',
        );
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-retry')));
      expect(chip(DirectoryState.unreachable), findsOneWidget);
      expect(find.text('connection: https://sealbox.example: connection refused'), findsOneWidget);
      final before = core.statusCalls;
      await tester.tap(find.byKey(const Key('directory-retry')));
      await tester.pumpAndSettle();
      expect(core.statusCalls, before + 1);
    });

    testWidgets('a refused publish shows the engine error inline (friendlyError)', (tester) async {
      final core = _Core(
        publishError: Exception(
          'key directory: HTTP 503 from https://sealbox.example (os error 104)',
        ),
      );
      await pumpSettings(tester, core);
      await reveal(tester, find.byKey(const Key('directory-publish')));
      await tester.tap(find.byKey(const Key('directory-publish')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('directory-error')), findsOneWidget);
      expect(find.text('key directory: HTTP 503 from https://sealbox.example'), findsOneWidget);
    });
  });

  group('server URL', () {
    testWidgets('set, shown with its source, cleared back to the environment', (tester) async {
      final core = _Core();
      await pumpSettings(tester, core, location: '/settings?section=server');
      expect(
        find.byKey(const Key('server-url-field')).hitTestable(),
        findsOneWidget,
        reason: 'deep link',
      );
      expect(find.text('Source: environment (SEALBOX_SERVER_URL)'), findsOneWidget);
      expect(find.byKey(const Key('server-url-clear')), findsNothing);
      await tester.enterText(
        find.byKey(const Key('server-url-field')),
        'https://keys.example.org/',
      );
      await tester.tap(find.byKey(const Key('server-url-save')));
      await tester.pumpAndSettle();
      expect(find.text('Sealbox server set to https://keys.example.org.'), findsOneWidget);
      expect(find.text('Source: settings (wins over SEALBOX_SERVER_URL)'), findsOneWidget);
      expect(await core.serverUrl(), 'https://keys.example.org');
      await tester.tap(find.byKey(const Key('server-url-clear')));
      await tester.pumpAndSettle();
      expect(
        find.text('Server setting cleared; using https://sealbox.example from the environment.'),
        findsOneWidget,
      );
      expect(find.text('Source: environment (SEALBOX_SERVER_URL)'), findsOneWidget);
    });

    testWidgets('N3: without a server the line under the title names the source, not the title', (
      tester,
    ) async {
      final core = _Core()..configuredServer = null;
      await pumpSettings(tester, core, location: '/settings?section=server');
      expect(find.text('No Sealbox server configured'), findsOneWidget);
      expect(
        find.descendant(
          of: find.byKey(const Key('server-url-source')),
          matching: find.text('Source: none — set a URL below'),
        ),
        findsOneWidget,
      );
      expect(
        find.text('No server configured'),
        findsNothing,
        reason: 'the old subtitle repeated the title',
      );
      expect(await core.serverUrlSource(), ServerUrlSource.none);
    });

    testWidgets('an invalid URL is refused inline and nothing changes', (tester) async {
      final core = _Core();
      await pumpSettings(tester, core, location: '/settings?section=server');
      await tester.enterText(find.byKey(const Key('server-url-field')), 'ftp://keys.example.org');
      await tester.tap(find.byKey(const Key('server-url-save')));
      await tester.pumpAndSettle();
      expect(
        find.text('server URL must be http(s)://host[:port], got `ftp://keys.example.org`'),
        findsOneWidget,
      );
      expect(await core.serverUrlSource(), ServerUrlSource.environment);
    });
  });

  group('account pickers', () {
    testWidgets('My key and Security follow the selected account', (tester) async {
      await pumpSettings(tester, _Core());
      expect(find.text('OpenPGP fingerprint · alice.rivera@gmail.com'), findsOneWidget);
      await tester.tap(find.byKey(const Key('my-key-account')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('alice@fastmail.com').last);
      await tester.pumpAndSettle();
      expect(find.text('OpenPGP fingerprint · alice@fastmail.com'), findsOneWidget);
      final recovery = find.byKey(const Key('settings-recovery-phrase'));
      await reveal(tester, recovery);
      // The Security card shows the same account in its own picker.
      final picker = tester.widget<DropdownMenu<String>>(
        find.descendant(
          of: find.byKey(const Key('identity-account')),
          matching: find.byType(DropdownMenu<String>),
        ),
      );
      expect(picker.initialSelection, 'acct-2');
      await tester.tap(recovery);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('recovery-create')), findsOneWidget);
    });

    testWidgets('one account: no picker', (tester) async {
      final core = FakeCore(latency: Duration.zero);
      await core.removeAccount('acct-2');
      await pumpSettings(tester, core);
      expect(find.byKey(const Key('my-key-account')), findsNothing);
      expect(find.byKey(const Key('identity-account')), findsNothing);
    });
  });
}
