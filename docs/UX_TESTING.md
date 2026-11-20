# UI/UX testing — goldens, accessibility, end-to-end flow (gate G20)

`scripts/gate_g20.sh` is the gate (docs/GATES.md). It runs three suites against the Flutter app
in `app/` and prints the counts it saw: goldens compared, accessibility assertions (passed and
skipped-for-a-finding), flow steps. PASS means every one of them passed under the gate runner.

| Suite | Files | What it proves |
|---|---|---|
| Goldens | `app/test/golden_*_test.dart`, images in `app/test/goldens/` | Every screen and major state renders pixel-identically to the reviewed reference, at phone and desktop size, light and dark |
| Accessibility | `app/test/a11y_test.dart` | Text contrast, tap-target size, labelled controls on every screen in both themes; lock badges and recipient pills read sensibly to a screen reader |
| Flow | `app/integration_test/ux_flow_test.dart` (Linux desktop under Xvfb) | Onboarding → inbox → encrypted thread → reply → send → receipt → settings works end to end, in a desktop and a phone-sized window |

Shared helpers live in `app/test/support/`:

- `golden_core.dart` — `GoldenCore`, a `FakeCore` subclass whose output never depends on the
  wall clock (dates re-based onto 15 Jun 2026, fixed key/backup times, seeded passphrase) and
  which can simulate a first sync and a sent copy for the flow test.
- `harness.dart` — the device × theme matrix (`GoldenDevice`, `GoldenTheme`, `Variant`,
  `fullMatrix`, `reducedA/B`), `pumpSealbox()` (configures window, pixel ratio, platform,
  brightness; pumps the real app through the same provider overrides `main.dart` uses) and
  `expectGolden()`.
- `fonts.dart` — loads Roboto, a monospace face and the icon fonts so text renders (the test
  engine otherwise draws every glyph as a box). golden_toolkit's `loadAppFonts()` is
  discontinued upstream; this is the local equivalent. Fonts and licences: `support/fonts/`.
- `golden_comparator.dart` — pixel-exact comparator; `SEALBOX_GOLDEN_MAX_DIFF_PERCENT` can
  tolerate anti-aliasing drift on another machine (never set it in the gate).
- `app/test/flutter_test_config.dart` wires the fonts, a deterministic text cursor and the
  comparator into every test in `app/test/` (harmless for the plain widget tests).

## Goldens

### What is covered (150 images, regenerated from `app/test/goldens/` on 2026-10-29)

Naming: `app/test/goldens/<screen>_<state>_<size>_<theme>.png`, sizes `phone` (390×844 logical,
rendered at 3× → 1170×2532 px, `TargetPlatform.android`, bottom bar) and `desktop` (1280×800 at
1×, `TargetPlatform.linux`, navigation rail, list + detail). A screen's primary state is captured
in all four cells; secondary states in one cell per size with the themes crossed, so every state
is seen on both sizes and every size in both themes while the total stays small.

| Screen | Full matrix (4) | Reduced (2 each) |
|---|---|---|
| compose | `mixed`, `suggestions`, `cc_bcc` | `empty`, `encrypted`, `guest_sent`, `plaintext_dialog`, `reply_preview` |
| filters | `list` | `editor` |
| identity | `thread_key_changed`, `verify` | `compose_key_changed`, `contact_key_changed`, `settings_kt_alert`, `thread_key_accepted`, `thread_verified` |
| inbox | `loaded`, `drafts`, `syncing` | `backfill`, `empty`, `no_threads`, `spam_folder` |
| onboarding | `detected_gmail`, `email` | `app_password_yahoo`, `connecting`, `detecting`, `done`, `error`, `manual_unknown`, `oauth_google` |
| recovery | `phrase_revealed`, `restore_form` | `inbox_reminder`, `phrase_blurred`, `phrase_confirm`, `restore_credential`, `restore_error`, `transfer_code` |
| search | `results` | |
| settings | `loaded` | `backup_on`, `no_accounts`, `publish_awaiting` |
| spam | `settings` | `explain` |
| thread | `encrypted_verified`, `html`, `html_inline_image` | `encrypted_unknown_signer`, `plaintext`, `signed_only`, `signer_mismatch`, `undecryptable` |

Search (`search_results`: "Q4" typed after the inbox's search action, matched words in bold in
the snippets; phone: the search screen, desktop: the results in the list pane), the Drafts chip
(`inbox_drafts`: three saved drafts) and compose with Cc and Bcc recipients (`compose_cc_bcc`:
Dana in Cc, Erik in Bcc with the field's note, the draft saved: "Draft saved 14:05" under the
title; it replaced `compose_cc` when the Bcc field arrived) arrived on 2026-10-29. Not
golden-tested: the search's hint / no-results / error states and the drafts list's empty state
(widget tests in `test/search_test.dart` and `test/drafts_test.dart` cover them), the drafts list
after a sync with drafts from another device — the "From another device" and "N files on the other
device" tags, the "could not sync" line, pull to refresh — and compose's note about those files
(`test/drafts_server_test.dart`; no golden: FakeCore's seeded drafts are this device's), the draft
save-failure and partial-send snackbars (`test/draft_leave_failure_test.dart`,
`test/compose_bcc_test.dart`; a group send that fails midway — who got it, Send again to the
rest only — in `test/compose_partial_send_test.dart`), the lock screen before the engine opens
in the stored theme (`test/theme_preference_test.dart`), and a Starred chip (not in the app). The end-to-end flow
(`integration_test/ux_flow_test.dart`) has 34 steps (17 per variant); the a11y suite asserts 344
guideline checks across the fixtures in `test/a11y_test.dart` (`search_results`,
`inbox_drafts`, `compose_cc` and `compose_cc_bcc` among them; plus text contrast and labelled /
Android tap targets over the open recipient suggestions, light and dark, in
`test/recipient_suggestions_test.dart`, and over search results, the drafts list and compose
with Cc in `test/search_test.dart` / `test/drafts_test.dart`).

The inbox app bar carries the live-updates status (`Key('live-status')`), so every capture that shows
the inbox list — inbox, spam folder, recovery reminder and the desktop two-pane thread and identity
states, 24 images — renders its state for `kLiveUpdatesDefault` (off today: no watcher runs).
Flipping that default changes those 24 images on purpose: regenerate `golden_inbox_test.dart`,
`golden_thread_test.dart`, `golden_identity_test.dart`, `golden_recovery_test.dart` and
`golden_mail_handling_test.dart` in the same commit. `GoldenCore` keeps its IDLE stream armed like
the engine does, so the flipped captures show a steady "on". The same app bar carries the search
action and its chip row the Drafts chip (after Sent, no count, so no chip's position depends on the
number of drafts); changing either re-records those captures plus `spam_explain_desktop_dark` and
`thread_html_desktop_*` (26 images). On a phone-width window (< 480 dp) compose shows Attach and
Discard in an overflow menu, so its title ("Compose") and the labelled Send button fit.

The To field ends with the "Cc" and "Bcc" links (each until its field is open); changing them
re-records every compose capture that shows the To field (`compose_{empty, encrypted,
guest_sent, mixed, plaintext_dialog, suggestions}`, `identity_compose_key_changed`: 18 images)
plus `compose_cc_bcc`. Below 600 dp a thread card gives the sender's address and "to …" a line
each, "to …" exactly one (review P9: a name never wraps in the middle); changing that re-records
the 14 phone captures that show a thread card (`thread_*`, `identity_thread_*`,
`spam_explain_phone_light`). Under the body a card has a chip per attachment except an image the
HTML shows inline (review N4: `thread_html_inline_image_*` has the logo and no `logo.png` chip;
`thread_html_*` keeps it, that sample's part names no Content-ID); "Show as text" lists every part
again (`test/message_body_test.dart`). The empty inbox's copy is one line per sentence (review P8:
`inbox_no_threads_*`), pinned on the laid-out paragraph at 360, 390 and 411 dp and on the desktop
pane by `test/inbox_empty_copy_test.dart`.

### Determinism

Goldens are only useful if a re-run produces the same bytes. Everything that could vary is pinned:

- data: `GoldenCore` (no `DateTime.now()` reaches a pixel; local-time anchors, so time zones do
  not matter either);
- fonts: loaded from the repo, never from the host;
- text cursor: `EditableText.debugDeterministicCursor = true` (no blink timer);
- animation: every capture follows `pumpAndSettle()`, except the two spinner states, which pump
  a fixed 250 ms after the transition and hold the fake core open with a `Completer` (no timer is
  left pending);
- platform: `debugDefaultTargetPlatformOverride` per device, reset at tear-down.

If a golden flickers between runs, the cause is a new wall-clock or random dependency in the
app; fix the fixture (`GoldenCore`) rather than loosening the comparator.

Known harness limitation: the test engine has no system-font fallback, so a glyph outside
Roboto's coverage (the "→" in the app-password instructions, emoji) renders as a tofu box in
goldens. The real app falls back to system fonts on every platform; the flow screenshots
(taken from the real Linux build) show the arrow correctly. Recorded as a copy finding
(FINDING-6), not a rendering bug.

### Update policy

1. A golden failure writes `app/test/failures/<name>_masterImage.png` (what is committed),
   `_testImage.png` (what rendered now), `_maskedDiff.png` and `_isolatedDiff.png`.
   **Look at the diff first.** The Read tool renders PNGs; so does any image viewer.
2. If the change is intended (a deliberate UI change), regenerate only the affected files:
   `cd app && flutter test --update-goldens test/golden_<screen>_test.dart`, review the new PNGs
   once more, and commit them **in the same commit as the UI change** with a one-line reason.
3. If the change is not intended, it is a regression: fix the app, do not update the golden.
4. Never run `--update-goldens` across the whole suite to "make it green"; never commit goldens
   generated with `SEALBOX_GOLDEN_MAX_DIFF_PERCENT` set.
5. Keep the count near 60: when adding a state, prefer the reduced pair (alternate `reducedA` /
   `reducedB` with the neighbouring state) and only give a screen's primary state the full matrix.

### Adding a golden

```dart
// app/test/golden_<screen>_test.dart
for (final v in reducedA) {                       // or fullMatrix / reducedB
  testWidgets('golden <screen>_<state> $v', (tester) async {
    await pumpSealbox(tester, core: GoldenCore(), variant: v, initialLocation: '/<route>');
    // drive the UI to the state with tester.tap / enterText + pumpAndSettle
    expect(find.byKey(const Key('<something that proves the state>')), findsOneWidget);
    await expectGolden(tester, '<screen>', '<state>', v);
  });
}
```

Then `flutter test --update-goldens test/golden_<screen>_test.dart`, open the PNGs, add the
state to the table above, commit test + images together.

## Accessibility

`app/test/a11y_test.dart` pumps eight screen states (onboarding: email, detected Gmail, Yahoo
app-password, manual; inbox; thread; compose with mixed recipients; settings) in light and dark
and asserts, on the phone size, `textContrastGuideline`, `androidTapTargetGuideline`,
`iOSTapTargetGuideline`, `labeledTapTargetGuideline`, and on the desktop size
`textContrastGuideline` and `labeledTapTargetGuideline` (tap-target minimums are a touch rule:
Material deliberately shrinks targets on desktop) — 96 guideline assertions. Four semantics tests
check that lock badges announce "Encrypted / Signed / Not encrypted" (with the explanatory tooltip
in the thread view) and that recipient pills announce the address, the status and a labelled menu,
and 16 `lock colours` tests measure the badge/pill label contrast directly (below). First run on
2026-10-27: 52 tests, 116 assertions — 90 pass, 26 are recorded findings (FINDING-1…5).

Each assertion prints `A11Y_ASSERT <id> PASS`. All guidelines of a screen are evaluated before
the test fails, so one violation never hides another. A guideline that fails because of app code
the suite may not change is **not** silently skipped: its id is listed in `_knownFindings` with a
`FINDING-n` number and a *signature* (a substring every failing node must contain); the guideline
still runs, and the test fails if the violation has disappeared or if any failure does not match
the signature — so the skip expires with the defect and cannot mask a new one. Every `FINDING-n`
is a row in `review/ux-findings-<date>.md` with file, line and proposed fix. Closing one means:
fix the app, remove the map entry, re-run the gate, mark the row closed with the commit.

Blind spot of `textContrastGuideline`: it looks text up by its semantics label, and texts that
merge into a container node (a `Card`, a tooltip-wrapped pill) are never found. The `lock colours`
group therefore measures the WCAG ratio of the `LockColors` labels directly (badge label on its
12 % tint, pill status on its 10 % tint, both themes) — the same arithmetic, without the
semantics dependency. Its known failures are `_knownColourFindings` (FINDING-3).

## End-to-end flow

`app/integration_test/ux_flow_test.dart` runs on the Linux desktop embedder:

```
cd app && flutter test -d linux integration_test/ux_flow_test.dart          # needs a DISPLAY
scripts/gate_g20.sh                                                          # starts its own Xvfb
```

Fourteen steps per variant (each verified and printed as `FLOW_STEP <variant> <n>: …`): fresh
start shows onboarding → `alice@gmail.com` → "Detecting provider…" → Gmail detected with OAuth and
the app-password fallback → app-password instructions → "Connecting to imap.gmail.com…" → ready →
inbox after the simulated first sync (layout check, mixed badges) → the encrypted thread
(decrypted body, verified signature) → Reply pre-fills the recipient (pill shows **encrypted ·
Autocrypt**), subject and quote → send → the inbox shows "Sent: encrypted to 1" → the thread row
previews the sent reply (no manual refresh needed) → the re-opened thread shows the Sent copy as
its newest, encrypted card → a manual fetch reports its outcome → Settings shows the account and
the key fingerprint. It runs twice: `desktop` (1280×720, the real window) and `narrow` (480×900
logical: bottom bar, stacked list/detail, back button — the phone layout exercised on desktop),
28 steps in all.

Injection: the test builds the same tree `main.dart` builds, overriding `coreApiProvider` with
`GoldenCore(seeded: false, syncOnAddAccount: true)` and `initialLocationProvider` with
`/onboarding`. No `--dart-define` and no test hook in `lib/` is needed. In a live binding the
fake core's latency is real time, so transitions are awaited with `waitFor(finder)` (poll, then
`pumpAndSettle`) rather than a bare `pumpAndSettle`, which returns as soon as no frame is
scheduled.

Screenshots: with `SEALBOX_FLOW_SHOTS_DIR=<absolute dir>` every step writes
`<dir>/<variant>/<nn>_<slug>.png` (the gate uses `review/ux-flow/<date>/`). They are review
evidence, not goldens.

## Review loop

Findings from the goldens, the a11y suite, the flow screenshots and the daily visual loops
(`review/desktop/<date>/`, `review/android/<date>/`) are tracked with `review/REVIEW_TEMPLATE.md`
(issue · screen · severity · evidence png · fix · status). The current list for the app owner is
`review/ux-findings-<date>.md`.
