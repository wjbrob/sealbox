# Sealbox patch to mail-builder 2.0.0

Used **only** by `extension/wasm` (via `[patch.crates-io]`); the native workspace keeps the
crates.io release. Reason: on `wasm32-unknown-unknown`, `std::time::SystemTime::now()` panics
("time not implemented on this platform"), and mail-builder reads the clock for every MIME
boundary and for an implicit `Date:`. The patch is `cfg(target_arch = "wasm32")`-only:

* `src/mime.rs` `unix_nanos()` → `js_sys::Date::now()` (+ `Math.random()` sub-ms spread).
* `src/headers/date.rs` `Date::now()` → `js_sys::Date::now()`.
* `src/lib.rs` / `Cargo.toml`: `gethostname` is not compiled on wasm32 (Message-ID fallback
  host becomes `localhost`; Sealbox always sets its own Message-ID anyway).

Native behaviour is byte-identical to upstream. Drop this directory once upstream gains a
wasm clock (track: stalwartlabs/mail-builder).
