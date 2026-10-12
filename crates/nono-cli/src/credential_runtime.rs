use crate::cli::SandboxArgs;
use colored::Colorize;
use nono::{LoadedSecret, NonoError, Result};
use std::collections::HashMap;
use tracing::info;

fn parse_env_credential_map_args(values: &[String]) -> Result<Vec<(String, String)>> {
    if !values.len().is_multiple_of(2) {
        return Err(NonoError::ConfigParse(
            "--env-credential-map expects pairs: <CREDENTIAL_REF> <ENV_VAR>".to_string(),
        ));
    }

    let mut pairs = Vec::with_capacity(values.len() / 2);
    for chunk in values.as_chunks::<2>().0 {
        let credential_ref = chunk[0].trim();
        let env_var = chunk[1].trim();

        if credential_ref.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty credential reference".to_string(),
            ));
        }

        if env_var.is_empty() {
            return Err(NonoError::ConfigParse(
                "--env-credential-map has an empty destination env var".to_string(),
            ));
        }

        pairs.push((credential_ref.to_string(), env_var.to_string()));
    }

    Ok(pairs)
}

/// Set once by `nono run --dry-run --json`, before it builds the plan: from
/// then on this process reads no credential source. No keystore or password
/// manager is asked, no credential command runs, nothing prompts; each
/// credential is planned as declared, with an empty value that never leaves
/// the dry run (it launches nothing).
static CREDENTIAL_SOURCES_SKIPPED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn skip_credential_sources() {
    CREDENTIAL_SOURCES_SKIPPED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn credential_sources_skipped() -> bool {
    CREDENTIAL_SOURCES_SKIPPED.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn load_env_credentials(
    args: &SandboxArgs,
    profile_secrets: &HashMap<String, String>,
    silent: bool,
    outer_caps: &nono::CapabilitySet,
) -> Result<Vec<LoadedSecret>> {
    let cli_secret_mappings = parse_env_credential_map_args(&args.env_credential_map)?;

    let secret_mappings = nono::keystore::build_secret_mappings(
        args.env_credential.as_deref(),
        &cli_secret_mappings,
        profile_secrets,
    )?;

    if secret_mappings.is_empty() {
        return Ok(Vec::new());
    }
    // (A dry run plans each as declared: its destination, never its value.)
    if credential_sources_skipped() {
        return Ok(secret_mappings
            .values()
            .map(|env_var| LoadedSecret {
                env_var: env_var.clone(),
                value: zeroize::Zeroizing::new(String::new()),
            })
            .collect());
    }

    let op_count = secret_mappings
        .keys()
        .filter(|credential| nono::keystore::is_op_uri(credential))
        .count();
    let bw_count = secret_mappings
        .keys()
        .filter(|credential| nono::keystore::is_bw_uri(credential))
        .count();
    let apple_password_count = secret_mappings
        .keys()
        .filter(|credential| nono::keystore::is_apple_password_uri(credential))
        .count();
    let keyring_count = secret_mappings.len() - op_count - bw_count - apple_password_count;

    info!(
        "Loading {} credential(s) (keyring: {}, 1Password: {}, Bitwarden: {}, Apple Passwords: {})",
        secret_mappings.len(),
        keyring_count,
        op_count,
        bw_count,
        apple_password_count
    );
    if !silent {
        let mut source_parts: Vec<String> = Vec::new();
        if keyring_count > 0 {
            source_parts.push(format!("{} from keystore", keyring_count));
        }
        if op_count > 0 {
            source_parts.push(format!("{} from 1Password", op_count));
        }
        if bw_count > 0 {
            source_parts.push(format!("{} from Bitwarden", bw_count));
        }
        if apple_password_count > 0 {
            source_parts.push(format!("{} from Apple Passwords", apple_password_count));
        }

        eprintln!(
            "  Loading {} credential(s) ({})...",
            secret_mappings.len(),
            source_parts.join(", ")
        );

        for account in secret_mappings.keys() {
            let display_account = if nono::keystore::is_op_uri(account) {
                nono::keystore::redact_op_uri(account)
            } else if nono::keystore::is_bw_uri(account) {
                nono::keystore::redact_bw_uri(account)
            } else if nono::keystore::is_apple_password_uri(account) {
                nono::keystore::redact_apple_password_uri(account)
            } else {
                account.to_string()
            };
            eprintln!(
                "  {}: env credential '{}' exposes the secret directly to the sandboxed process.\n\
                 {}  For network API keys, use a profile with credentials for credential isolation.",
                "warning".yellow(),
                display_account,
                " ".repeat(11),
            );
        }
    }

    nono::keystore::load_secrets(
        nono::keystore::DEFAULT_SERVICE,
        &secret_mappings,
        Some(outer_caps),
    )
}
