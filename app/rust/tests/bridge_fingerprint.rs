//! Structural fingerprint of the flutter_rust_bridge surface.
//!
//! Why this exists. `frb_generated.dart` carries a `rustContentHash` (758121173 at the time of
//! writing) which reads as if it pins the Rust side. It does not pin the *shape* of the bridged
//! data: editing a field of a DTO — renaming `display_name`, changing `i64` to `String`, adding a
//! field — leaves that hash where it was, so a stale generated bundle keeps marshalling the old
//! layout against the new library and mis-decodes at run time instead of failing to build.
//!
//! So this test derives the shape itself, from the source, and pins it:
//!
//!   1. parse `src/api/*.rs`, canonicalise every bridged item (each `pub struct`'s fields with
//!      their types in declaration order, each `pub enum`'s variants, every bridged `pub fn`
//!      signature), SHA-256 the list, and assert it equals the committed `bridge.fingerprint`.
//!      Any edit to the bridged surface fails here until a human looks at it.
//!   2. cross-check the *generated Dart* against those same structs and enums: a field present in
//!      Rust and absent from `app/lib/src/rust/api/<module>.dart` means codegen was not re-run.
//!      This is the check `rustContentHash` cannot do.
//!
//! The fingerprint is a tripwire, not a spec: when it fires legitimately, re-run
//! `flutter_rust_bridge_codegen generate` (from `app/`) and write the new hash into
//! `app/rust/bridge.fingerprint` in the same commit. `cargo test -p rust_lib_sealbox_app -- --nocapture`
//! prints the canonical list, and it is also written to `target/bridge_api.txt` for diffing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A bridged aggregate, kept so the Dart cross-check can look for its members.
struct Aggregate {
    module: String,
    kind: &'static str,
    name: String,
    /// Rust member names in declaration order (struct fields, or unit-enum variants).
    members: Vec<String>,
}

/// Bridged types that deliberately have no mirrored Dart class. `Engine` is the engine handle:
/// flutter_rust_bridge carries it across as an opaque `RustOpaque`, so Dart sees methods on it and
/// never its fields. Anything else appearing here would be a codegen that was not re-run.
const OPAQUE_IN_DART: &[&str] = &["Engine"];

fn api_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api")
}

fn render_type(ty: &syn::Type) -> String {
    // Token-stream rendering, then collapse the spacing `quote` inserts so that `Option < String >`
    // and `Option<String>` cannot produce two different fingerprints for the same type.
    let raw = quote::ToTokens::to_token_stream(ty).to_string();
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == ' ' {
            continue;
        }
        out.push(ch);
    }
    out
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// `#[cfg(test)]` items are not part of the bridge and must not move the fingerprint.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && quote::ToTokens::to_token_stream(&a.meta)
                .to_string()
                .contains("test")
    })
}

fn signature_of(sig: &syn::Signature) -> String {
    let mut s = String::new();
    let _ = write!(s, "{}(", sig.ident);
    let mut first = true;
    for arg in &sig.inputs {
        if !first {
            s.push_str(", ");
        }
        first = false;
        match arg {
            syn::FnArg::Receiver(r) => {
                // `&self` / `&mut self` / `self` — the receiver is part of the call shape.
                s.push_str(if r.mutability.is_some() {
                    "&mut self"
                } else if r.reference.is_some() {
                    "&self"
                } else {
                    "self"
                });
            }
            syn::FnArg::Typed(t) => {
                let name = quote::ToTokens::to_token_stream(&t.pat).to_string();
                let _ = write!(s, "{}: {}", name.trim(), render_type(&t.ty));
            }
        }
    }
    s.push(')');
    if let syn::ReturnType::Type(_, ty) = &sig.output {
        let _ = write!(s, " -> {}", render_type(ty));
    }
    if sig.asyncness.is_some() {
        s.insert_str(0, "async ");
    }
    s
}

/// Canonicalises one module's bridged surface into one line per item, and collects the aggregates.
fn canonicalise(module: &str, src: &str, lines: &mut Vec<String>, aggs: &mut Vec<Aggregate>) {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("{module}.rs does not parse: {e}"));
    for item in &file.items {
        match item {
            syn::Item::Struct(s) if is_pub(&s.vis) && !is_cfg_test(&s.attrs) => {
                lines.push(format!("{module} struct {}", s.ident));
                let mut members = Vec::new();
                match &s.fields {
                    syn::Fields::Named(named) => {
                        for f in &named.named {
                            let Some(ident) = &f.ident else { continue };
                            if !is_pub(&f.vis) {
                                // A private field is not bridged, but its presence changes nothing
                                // on the Dart side, so record it as private and move on.
                                lines.push(format!("  (private) {ident}"));
                                continue;
                            }
                            lines.push(format!("  {}: {}", ident, render_type(&f.ty)));
                            members.push(ident.to_string());
                        }
                    }
                    syn::Fields::Unnamed(un) => {
                        for (i, f) in un.unnamed.iter().enumerate() {
                            lines.push(format!("  {}: {}", i, render_type(&f.ty)));
                        }
                    }
                    syn::Fields::Unit => lines.push("  (unit)".to_string()),
                }
                aggs.push(Aggregate {
                    module: module.to_string(),
                    kind: "struct",
                    name: s.ident.to_string(),
                    members,
                });
            }
            syn::Item::Enum(e) if is_pub(&e.vis) && !is_cfg_test(&e.attrs) => {
                lines.push(format!("{module} enum {}", e.ident));
                let mut members = Vec::new();
                let mut all_unit = true;
                for v in &e.variants {
                    match &v.fields {
                        syn::Fields::Unit => lines.push(format!("  {}", v.ident)),
                        syn::Fields::Named(named) => {
                            all_unit = false;
                            let body: Vec<String> = named
                                .named
                                .iter()
                                .map(|f| {
                                    format!(
                                        "{}: {}",
                                        f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default(),
                                        render_type(&f.ty)
                                    )
                                })
                                .collect();
                            lines.push(format!("  {} {{ {} }}", v.ident, body.join(", ")));
                        }
                        syn::Fields::Unnamed(un) => {
                            all_unit = false;
                            let body: Vec<String> =
                                un.unnamed.iter().map(|f| render_type(&f.ty)).collect();
                            lines.push(format!("  {}({})", v.ident, body.join(", ")));
                        }
                    }
                    members.push(v.ident.to_string());
                }
                aggs.push(Aggregate {
                    module: module.to_string(),
                    kind: if all_unit { "enum" } else { "data-enum" },
                    name: e.ident.to_string(),
                    members,
                });
            }
            syn::Item::Fn(f) if is_pub(&f.vis) && !is_cfg_test(&f.attrs) => {
                lines.push(format!("{module} fn {}", signature_of(&f.sig)));
            }
            syn::Item::Impl(im) if im.trait_.is_none() && !is_cfg_test(&im.attrs) => {
                // Inherent impls are bridged (`Engine::add_account` and friends). Trait impls are
                // not — every `impl From<sc::X> for X` in this tree is internal conversion glue,
                // and including them would make the fingerprint move for edits Dart never sees.
                let self_ty = render_type(&im.self_ty);
                for sub in &im.items {
                    if let syn::ImplItem::Fn(m) = sub {
                        if is_pub(&m.vis) && !is_cfg_test(&m.attrs) {
                            lines.push(format!(
                                "{module} method {self_ty}::{}",
                                signature_of(&m.sig)
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// snake_case → lowerCamelCase, the name flutter_rust_bridge gives a field in Dart.
fn lower_camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper_next = false;
    for ch in name.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The body of `class <name> {` / `enum <name> {` in a generated Dart file, if it is there at all.
fn dart_body<'a>(dart: &'a str, keyword: &str, name: &str) -> Option<&'a str> {
    let needle = format!("\n{keyword} {name} {{");
    let start = dart.find(&needle)? + needle.len();
    let rest = &dart[start..];
    // Brace-match to the end of the declaration rather than guessing at a blank line: Dart class
    // bodies here contain `=>` expressions with their own braces.
    let mut depth = 1usize;
    for (i, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&rest[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn bridged_api_shape_is_unchanged_and_dart_is_regenerated() {
    let modules = ["engine", "sealbox"];
    let mut lines: Vec<String> = Vec::new();
    let mut aggs: Vec<Aggregate> = Vec::new();

    for m in modules {
        let path = api_dir().join(format!("{m}.rs"));
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        canonicalise(m, &src, &mut lines, &mut aggs);
    }

    assert!(
        lines.len() > 200,
        "only {} canonical lines — the parser is not seeing the api modules",
        lines.len()
    );

    let canonical = lines.join("\n");
    let digest = format!("{:x}", Sha256::digest(canonical.as_bytes()));

    // Written unconditionally so a failure can be diffed against the previous run.
    let dump = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/bridge_api.txt");
    if let Some(dir) = dump.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&dump, format!("{canonical}\n"));
    println!("{canonical}");
    println!("\n{} items, sha256 = {digest}", lines.len());

    // --- 1. the fingerprint itself -------------------------------------------------------------
    let fp_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("bridge.fingerprint");
    let committed = std::fs::read_to_string(&fp_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", fp_path.display()));
    let committed = committed.trim();
    assert_eq!(
        committed,
        digest,
        "\nthe bridged API shape changed.\n\
         committed {committed}\n\
         computed  {digest}\n\
         The canonical list is in {} — diff it to see what moved. If the change is intended,\n\
         re-run codegen (cd app && flutter_rust_bridge_codegen generate) and write the computed\n\
         hash into app/rust/bridge.fingerprint in the same commit.\n",
        dump.display()
    );

    // --- 2. the generated Dart actually has these members ---------------------------------------
    let dart_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/src/rust/api");
    let mut missing: Vec<String> = Vec::new();
    let mut no_class: Vec<String> = Vec::new();

    for agg in &aggs {
        let dart_path = dart_root.join(format!("{}.dart", agg.module));
        let dart = std::fs::read_to_string(&dart_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dart_path.display()));

        let keyword = if agg.kind == "enum" { "enum" } else { "class" };
        let Some(body) = dart_body(&dart, keyword, &agg.name) else {
            if !OPAQUE_IN_DART.contains(&agg.name.as_str()) {
                no_class.push(format!("{} {} {}", agg.module, agg.kind, agg.name));
            }
            continue;
        };
        for member in &agg.members {
            let dart_name = if keyword == "enum" {
                // frb lowerCamelCases variant names: `AppPassword` -> `appPassword`.
                let mut it = member.chars();
                match it.next() {
                    Some(c) => c.to_lowercase().collect::<String>() + it.as_str(),
                    None => continue,
                }
            } else {
                lower_camel(member)
            };
            // A name that collides with a Dart keyword is emitted with a trailing underscore
            // (`pub new: u32` becomes `final int new_;`, `ComposeKind::New` becomes `new_`), so
            // accept either spelling rather than carrying a copy of Dart's keyword list.
            let escaped = format!("{dart_name}_");
            let present = if keyword == "enum" {
                body.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|t| t == dart_name || t == escaped)
            } else {
                // A field declaration, not a mention inside `==`/`hashCode`.
                body.lines().map(str::trim).any(|l| {
                    l.starts_with("final ")
                        && (l.ends_with(&format!(" {dart_name};"))
                            || l.ends_with(&format!(" {escaped};")))
                })
            };
            if !present {
                missing.push(format!(
                    "{} {} {}.{} (Dart: {})",
                    agg.module, agg.kind, agg.name, member, dart_name
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "\nthe generated Dart is stale — these members exist in Rust and not in \
         app/lib/src/rust/api/:\n  {}\n\nRun: cd app && flutter_rust_bridge_codegen generate\n",
        missing.join("\n  ")
    );
    assert!(
        no_class.is_empty(),
        "\nthese bridged types have no declaration in app/lib/src/rust/api/ at all:\n  {}\n\n\
         Either codegen was not re-run, or the type is meant to stay an opaque handle — in which\n\
         case add it to OPAQUE_IN_DART in this test, with a reason.\n",
        no_class.join("\n  ")
    );

    // --- 3. and nothing in the generated Dart that Rust no longer has -------------------------
    // The mirror has to hold in both directions: reverting a Rust type without re-running codegen
    // leaves a Dart class the library cannot produce, which fails at run time, not at build.
    let known: Vec<&str> = aggs.iter().map(|a| a.name.as_str()).collect();
    let mut orphans: Vec<String> = Vec::new();
    for m in modules {
        let dart = std::fs::read_to_string(dart_root.join(format!("{m}.dart"))).unwrap();
        for line in dart.lines() {
            let Some(rest) = line
                .strip_prefix("class ")
                .or_else(|| line.strip_prefix("enum "))
            else {
                continue;
            };
            let name = rest
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("");
            if !name.is_empty() && !known.contains(&name) {
                orphans.push(format!("{m}.dart: {name}"));
            }
        }
    }
    assert!(
        orphans.is_empty(),
        "\nthese declarations exist in the generated Dart and have no counterpart in \
         src/api/*.rs:\n  {}\n\nRun: cd app && flutter_rust_bridge_codegen generate\n",
        orphans.join("\n  ")
    );
}
