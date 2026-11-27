use omawarden_engine::clipboard::ClipboardGuard;
use omawarden_engine::config::Config;
use serde_json::json;
use std::process::ExitCode;

use super::client::totp_output;

pub(crate) fn run(query: Option<String>, stdin: bool, copy: bool, cfg: &Config) -> ExitCode {
    let query = if stdin { None } else { query.as_deref() };
    if query.is_some_and(|q| q.starts_with("otpauth://") || q.starts_with("otpauth-migration://")) {
        eprintln!(
            "Error: Passing otpauth URIs or secrets in CLI arguments is forbidden (violates Zero-Argv security policy).\nPipe secret via STDIN instead: echo '<otpauth_uri>' | omawarden totp --stdin"
        );
        return ExitCode::FAILURE;
    }

    let output = match totp_output(cfg, query, copy) {
        Ok(Some(output)) => output,
        result => {
            let error = result.err().unwrap_or_else(|| {
                "Failed to generate TOTP: item not found or secret is invalid".into()
            });
            println!("{}", json!({ "ok": false, "error": error }));
            return ExitCode::FAILURE;
        }
    };
    let res = output.result;
    if copy {
        let clipboard = ClipboardGuard::default();
        let copied = match output.scope {
            Some(scope) => clipboard.copy_vault_output(&res.code, true, 30, &scope),
            None => clipboard.copy(&res.code, true, 30),
        };
        if !copied {
            println!(
                "{}",
                json!({
                    "ok": false, "error": "Could not copy TOTP. Verify the vault session and retry."
                })
            );
            return ExitCode::FAILURE;
        }
    }

    let mut response =
        json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period });
    if let Some((id, name)) = output.item {
        response["id"] = json!(id);
        response["name"] = json!(name);
    }
    if copy {
        response["copied"] = json!(true);
    }
    println!("{}", serde_json::to_string_pretty(&response).unwrap());
    ExitCode::SUCCESS
}
