//! `sealbox profile …` and the global `--profile-key` / `--profile-passphrase-env` flags
//! (gate G27, secrets at rest). See `docs/SECRETS_AT_REST.md`.

use std::io::Write;
use std::path::Path;

use clap::{Args, Subcommand, ValueEnum};
use sealbox_core::vault::{env_passphrase, PASSPHRASE_ENV};
use sealbox_core::{Engine, Error, ProfileKeySource, ProfileKeyStatus};

/// Default variable for the new passphrase of `profile rewrap --to passphrase`.
pub const NEW_PASSPHRASE_ENV: &str = "SEALBOX_PROFILE_NEW_PASSPHRASE";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyKind {
    /// OS keyring (Secret Service / Keychain / Credential Manager); the default
    Keyring,
    /// Argon2id passphrase from $SEALBOX_PROFILE_PASSPHRASE (or --profile-passphrase-env)
    Passphrase,
    /// Plaintext profile; also needs SEALBOX_ALLOW_PLAINTEXT_PROFILE=1
    None,
}

/// Global key-source flags.
#[derive(Args, Debug, Default)]
pub struct KeyArgs {
    /// Where the profile's at-rest key comes from (default: keyring; headless fallback to
    /// $SEALBOX_PROFILE_PASSPHRASE)
    #[arg(long, global = true, value_enum, env = "SEALBOX_PROFILE_KEY")]
    pub profile_key: Option<KeyKind>,
    /// Read the profile passphrase from this environment variable (implies
    /// --profile-key passphrase)
    #[arg(long, global = true, value_name = "VAR")]
    pub profile_passphrase_env: Option<String>,
}

#[derive(Args, Debug)]
pub struct ProfileArgs {
    #[command(subcommand)]
    cmd: ProfileCmd,
}

#[derive(Subcommand, Debug)]
enum ProfileCmd {
    /// Key source, KDF and how many sensitive values are wrapped / plaintext
    Status,
    /// Re-encrypt everything under a new key source (the old key stops working)
    Rewrap {
        #[arg(long, value_enum)]
        to: KeyKind,
        /// Variable holding the new passphrase (for --to passphrase)
        #[arg(long, value_name = "VAR", default_value = NEW_PASSPHRASE_ENV)]
        new_passphrase_env: String,
    },
}

fn read_var(var: &str) -> Result<String, Error> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::InvalidInput(format!("environment variable {var} is not set")))
}

/// Turn the global flags into the process-wide key source used by every `Engine::open`.
pub fn apply(args: &KeyArgs) -> Result<(), Error> {
    let src = if let Some(var) = &args.profile_passphrase_env {
        if matches!(
            args.profile_key,
            Some(KeyKind::Keyring) | Some(KeyKind::None)
        ) {
            return Err(Error::InvalidInput(
                "--profile-passphrase-env needs --profile-key passphrase (or none given)".into(),
            ));
        }
        ProfileKeySource::Passphrase(read_var(var)?)
    } else {
        match args.profile_key {
            None => return Ok(()),
            Some(KeyKind::Keyring) => ProfileKeySource::Keyring,
            Some(KeyKind::None) => ProfileKeySource::None,
            Some(KeyKind::Passphrase) => ProfileKeySource::Passphrase(
                env_passphrase().ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "--profile-key passphrase: set {PASSPHRASE_ENV} or use --profile-passphrase-env VAR"
                    ))
                })?,
            ),
        }
    };
    ProfileKeySource::set_process_default(src);
    Ok(())
}

fn print(json: bool, st: &ProfileKeyStatus) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, st)?;
        out.write_all(b"\n")?;
    } else {
        writeln!(out, "source:         {}", st.source)?;
        writeln!(out, "kdf:            {}", st.kdf.as_deref().unwrap_or("-"))?;
        writeln!(out, "wrapped rows:   {}", st.wrapped_rows)?;
        writeln!(out, "plaintext rows: {}", st.plaintext_rows)?;
        if let Some(f) = &st.fallback {
            writeln!(out, "note:           {f}")?;
        }
    }
    Ok(())
}

pub async fn run(profile: &Path, json: bool, args: ProfileArgs) -> anyhow::Result<()> {
    let engine = Engine::open(profile)?;
    let st = match args.cmd {
        ProfileCmd::Status => engine.profile_key_status()?,
        ProfileCmd::Rewrap {
            to,
            new_passphrase_env,
        } => {
            let new = match to {
                KeyKind::Keyring => ProfileKeySource::Keyring,
                KeyKind::None => ProfileKeySource::None,
                KeyKind::Passphrase => ProfileKeySource::Passphrase(read_var(&new_passphrase_env)?),
            };
            engine.rewrap_profile(new)?
        }
    };
    print(json, &st)
}
