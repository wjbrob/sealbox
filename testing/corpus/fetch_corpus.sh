#!/usr/bin/env bash
# Download the SpamAssassin public corpus (https://spamassassin.apache.org/old/publiccorpus/)
# into testing/corpus/.cache/ (gitignored) and lay it out as
#   .cache/corpus/ham/<set>/<file>   .cache/corpus/spam/<set>/<file>
# which is what `sealbox spam eval --corpus testing/corpus/.cache/corpus` expects
# (one RFC 5322 message per file, label = first path component).
#
# Idempotent: tarballs whose size matches the server's Content-Length are not re-downloaded;
# extraction is skipped when the marker file exists. Sizes are verified after download
# (Content-Length + a sanity floor + `tar -t`). Set CORPUS_BASE to use a mirror.
#
# Sets used (the 2003-02-28 release, plus the 2005-03-11 re-release of spam_2 which supersedes
# 20030228_spam_2 — the two are the same 1,397 messages, so only one is taken):
#   easy_ham (2500) + easy_ham_2 (1400) + hard_ham (250) = 4150 ham
#   spam (500) + spam_2 (1397)                            = 1897 spam
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="$HERE/.cache"
BASE="${CORPUS_BASE:-https://spamassassin.apache.org/old/publiccorpus}"
mkdir -p "$CACHE/tarballs" "$CACHE/corpus/ham" "$CACHE/corpus/spam"

# name|label|expected-top-level-dir|minimum bytes
SETS=(
  "20030228_easy_ham.tar.bz2|ham|easy_ham|1400000"
  "20030228_easy_ham_2.tar.bz2|ham|easy_ham_2|900000"
  "20030228_hard_ham.tar.bz2|ham|hard_ham|900000"
  "20030228_spam.tar.bz2|spam|spam|1000000"
  "20050311_spam_2.tar.bz2|spam|spam_2|1900000"
)

fetch() {
  local name="$1" min="$2" out="$CACHE/tarballs/$1"
  local remote
  remote="$(curl -sIL --max-time 30 "$BASE/$name" | tr -d '\r' | awk 'tolower($1)=="content-length:"{v=$2} END{print v}')"
  if [ -s "$out" ] && [ -n "${remote:-}" ] && [ "$(stat -c %s "$out")" = "$remote" ]; then
    echo "cached   $name ($remote bytes)"
    return 0
  fi
  echo "fetching $name"
  curl -fsSL --retry 3 --max-time 600 -o "$out.part" "$BASE/$name"
  local got; got="$(stat -c %s "$out.part")"
  if [ -n "${remote:-}" ] && [ "$got" != "$remote" ]; then
    echo "size mismatch for $name: got $got, server says $remote" >&2; rm -f "$out.part"; return 1
  fi
  if [ "$got" -lt "$min" ]; then
    echo "$name is only $got bytes (< $min): truncated or an error page" >&2; rm -f "$out.part"; return 1
  fi
  tar -tjf "$out.part" >/dev/null || { echo "$name is not a valid tar.bz2" >&2; rm -f "$out.part"; return 1; }
  mv "$out.part" "$out"
  echo "verified $name ($got bytes)"
}

extract() {
  local name="$1" label="$2" top="$3" dest="$CACHE/corpus/$2/$3"
  if [ -f "$dest/.extracted" ]; then return 0; fi
  rm -rf "$dest"; mkdir -p "$dest"
  # Strip the leading directory; drop the `cmds` helper file the corpus ships.
  tar -xjf "$CACHE/tarballs/$name" -C "$dest" --strip-components=1
  rm -f "$dest/cmds"
  find "$dest" -type f -size 0 -delete
  touch "$dest/.extracted"
}

fail=0
for row in "${SETS[@]}"; do
  IFS='|' read -r name label top min <<<"$row"
  fetch "$name" "$min" || { fail=1; continue; }
  extract "$name" "$label" "$top"
done
ham=$(find "$CACHE/corpus/ham" -type f ! -name .extracted | wc -l)
spam=$(find "$CACHE/corpus/spam" -type f ! -name .extracted | wc -l)
echo "corpus: $ham ham, $spam spam at $CACHE/corpus"
if [ "$fail" != 0 ]; then echo "some sets failed to download" >&2; exit 1; fi
if [ "$ham" -lt 4000 ] || [ "$spam" -lt 1800 ]; then echo "corpus incomplete" >&2; exit 1; fi
