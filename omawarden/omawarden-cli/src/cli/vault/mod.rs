mod collections;
mod create;
mod edit;
mod editor;
mod export;
mod get;
mod import;
mod lifecycle;
mod read;

use clap::Subcommand;
use omawarden_engine::config::Config;
use omawarden_engine::vault::VaultManager;
use std::path::PathBuf;
use std::process::ExitCode;

use super::io::parse_cli_bool;
pub(crate) use create::CreateItemAction;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum VaultAction {
    #[command(about = "Sync vault from Bitwarden server")]
    Sync,
    #[command(about = "List all vault items")]
    List {
        #[arg(long = "filter")]
        category: Option<String>,
        #[arg(long, help = "List only soft-deleted items in the Trash")]
        trash: bool,
    },
    #[command(about = "Search vault items")]
    Search {
        #[arg(value_name = "QUERY", default_value = "")]
        query: String,
        #[arg(
            long = "query",
            help = "Search query string (alternative to positional argument)"
        )]
        query_flag: Option<String>,
        #[arg(long = "filter")]
        category: Option<String>,
        #[arg(long, help = "Search only soft-deleted items in the Trash")]
        trash: bool,
    },
    #[command(about = "Retrieve a single cipher or field to stdout")]
    Get {
        #[arg(
            value_name = "TARGET",
            help = "Target cipher ID, name, or unique prefix/substring"
        )]
        target: String,
        #[arg(
            short = 'f',
            long = "field",
            value_name = "SELECTOR",
            conflicts_with_all = ["password", "username", "totp", "notes", "uri"],
            help = "Extract a single field by selector (e.g. password, card.number, identity.email, ssh.private_key, custom.<name>)"
        )]
        field: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["field", "username", "totp", "notes", "uri"],
            help = "Shorthand for --field password"
        )]
        password: bool,
        #[arg(
            long,
            conflicts_with_all = ["field", "password", "totp", "notes", "uri"],
            help = "Shorthand for --field username"
        )]
        username: bool,
        #[arg(
            long,
            conflicts_with_all = ["field", "password", "username", "notes", "uri"],
            help = "Shorthand for --field totp"
        )]
        totp: bool,
        #[arg(
            long,
            conflicts_with_all = ["field", "password", "username", "totp", "uri"],
            help = "Shorthand for --field notes"
        )]
        notes: bool,
        #[arg(
            long,
            conflicts_with_all = ["field", "password", "username", "totp", "notes"],
            help = "Shorthand for --field uri"
        )]
        uri: bool,
        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Narrow target resolution by cipher type (login|note|card|identity|ssh_key)"
        )]
        cipher_type: Option<String>,
        #[arg(long, help = "Resolve target against soft-deleted items in the Trash")]
        trash: bool,
        #[arg(long, help = "Output structured JSON")]
        json: bool,
        #[arg(
            long,
            help = "Reveal sensitive fields or JSON output in an interactive terminal"
        )]
        reveal: bool,
    },
    #[command(about = "Create a new vault cipher")]
    Create {
        #[command(subcommand)]
        item: Option<CreateItemAction>,
        #[arg(
            long,
            conflicts_with = "stdin",
            help = "Path to JSON file containing cipher payload"
        )]
        from_json: Option<PathBuf>,
        #[arg(
            long,
            conflicts_with = "from_json",
            help = "Read cipher payload JSON from standard input"
        )]
        stdin: bool,
        #[arg(long, global = true, help = "Output structured JSON")]
        json: bool,
    },
    #[command(
        about = "Delete a cipher from the vault",
        alias = "remove",
        alias = "rm"
    )]
    Delete {
        #[arg(
            value_name = "TARGET",
            help = "Target cipher name or 32-character / UUID ID to delete"
        )]
        target: String,
        #[arg(
            long,
            help = "Permanently delete the cipher instead of soft-deleting (moving to trash)"
        )]
        permanent: bool,
        #[arg(long, help = "Permanently delete a soft-deleted cipher from the Trash")]
        trash: bool,
        #[arg(
            short = 'y',
            long = "yes",
            help = "Skip confirmation prompt in interactive terminals"
        )]
        yes: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Restore a soft-deleted cipher from the Trash")]
    Restore {
        #[arg(
            value_name = "TARGET",
            help = "Target trashed cipher name or 32-character / UUID ID to restore"
        )]
        target: String,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Share (transfer) a personal cipher into an Organization")]
    Share {
        #[arg(
            value_name = "TARGET",
            help = "Target personal cipher name or 32-character / UUID ID to share"
        )]
        target: String,
        #[arg(
            long = "organization-id",
            value_name = "ORG_ID",
            required = true,
            help = "Target Organization ID"
        )]
        organization_id: String,
        #[arg(
            long = "collection-id",
            value_name = "COL_ID",
            required = true,
            action = clap::ArgAction::Append,
            help = "Target writable Collection ID (repeatable)"
        )]
        collection_ids: Vec<String>,
        #[arg(
            short = 'y',
            long = "yes",
            help = "Confirm irreversible ownership transfer without interactive prompt (required in --json mode)"
        )]
        yes: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Reassign collections on an Organization cipher")]
    Collections {
        #[arg(
            value_name = "TARGET",
            help = "Target Organization cipher name or 32-character / UUID ID"
        )]
        target: String,
        #[arg(
            long = "collection-id",
            value_name = "COL_ID",
            action = clap::ArgAction::Append,
            conflicts_with_all = ["add", "remove"],
            help = "Replace assigned collections with the specified Collection ID(s) (repeatable)"
        )]
        collection_ids: Vec<String>,
        #[arg(
            long = "add",
            value_name = "COL_ID",
            action = clap::ArgAction::Append,
            conflicts_with = "collection_ids",
            help = "Add a writable Collection ID to the cipher (repeatable)"
        )]
        add: Vec<String>,
        #[arg(
            long = "remove",
            value_name = "COL_ID",
            action = clap::ArgAction::Append,
            conflicts_with = "collection_ids",
            help = "Remove a writable Collection ID from the cipher (repeatable)"
        )]
        remove: Vec<String>,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Edit an existing vault cipher")]
    Edit {
        #[arg(
            value_name = "TARGET",
            help = "Target cipher name or 32-character / UUID ID to edit"
        )]
        target: String,
        #[arg(long, help = "New name for the cipher")]
        name: Option<String>,
        #[arg(long, help = "New username for login cipher")]
        username: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password_stdin", "generate_password", "generate_passphrase"],
            help = "New password for login cipher"
        )]
        password: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password", "generate_password", "generate_passphrase"],
            help = "Read new password from standard input"
        )]
        password_stdin: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_passphrase"],
            help = "Automatically generate a new 16-character high-entropy password"
        )]
        generate_password: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_password"],
            help = "Automatically generate a new 4-word Diceware passphrase"
        )]
        generate_passphrase: bool,
        #[arg(
            long,
            conflicts_with_all = ["password_stdin", "notes_stdin", "clear_totp"],
            help = "Read TOTP seed or otpauth:// URI from standard input (Zero-Argv compliant)"
        )]
        totp_stdin: bool,
        #[arg(
            long,
            conflicts_with = "totp_stdin",
            help = "Clear the TOTP seed from login cipher"
        )]
        clear_totp: bool,
        #[arg(
            long,
            conflicts_with = "notes_stdin",
            help = "New notes for the cipher"
        )]
        notes: Option<String>,
        #[arg(
            long,
            conflicts_with = "notes",
            help = "Read new notes from standard input"
        )]
        notes_stdin: bool,
        #[arg(
            long = "uri",
            action = clap::ArgAction::Append,
            help = "New URI for login cipher (repeatable to replace URI list)"
        )]
        uris: Vec<String>,
        #[arg(
            long = "add-uri",
            action = clap::ArgAction::Append,
            conflicts_with = "clear_uris",
            help = "Append an additional URI to existing URIs"
        )]
        add_uris: Vec<String>,
        #[arg(
            long,
            conflicts_with_all = ["uris", "add_uris"],
            help = "Clear all URIs from login cipher"
        )]
        clear_uris: bool,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Upsert a text custom field (NAME=VALUE; repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Upsert a hidden custom field (NAME=VALUE; repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Upsert a boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(
            long = "remove-field",
            action = clap::ArgAction::Append,
            value_name = "NAME",
            help = "Remove a custom field by name (repeatable)"
        )]
        remove_fields: Vec<String>,
        #[arg(long, alias = "folder", help = "Folder ID for the cipher")]
        folder_id: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Favorite status (true/false)"
        )]
        favorite: Option<bool>,
        #[arg(
            long,
            conflicts_with_all = [
                "from_json",
                "name",
                "username",
                "password",
                "password_stdin",
                "generate_password",
                "generate_passphrase",
                "totp_stdin",
                "clear_totp",
                "notes",
                "notes_stdin",
                "uris",
                "add_uris",
                "clear_uris",
                "fields",
                "hidden_fields",
                "bool_fields",
                "remove_fields",
                "folder_id",
                "favorite"
            ],
            help = "Read cipher update payload JSON from standard input"
        )]
        stdin: bool,
        #[arg(
            long,
            conflicts_with_all = [
                "stdin",
                "name",
                "username",
                "password",
                "password_stdin",
                "generate_password",
                "generate_passphrase",
                "totp_stdin",
                "clear_totp",
                "notes",
                "notes_stdin",
                "uris",
                "add_uris",
                "clear_uris",
                "fields",
                "hidden_fields",
                "bool_fields",
                "remove_fields",
                "folder_id",
                "favorite"
            ],
            help = "Path to JSON file containing cipher update payload"
        )]
        from_json: Option<PathBuf>,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Export personal Vault items and folders")]
    Export {
        #[arg(
            long,
            default_value = "encrypted_json",
            value_name = "FORMAT",
            help = "Export format (encrypted_json, account_encrypted_json, json, csv)"
        )]
        format: String,
        #[arg(
            short = 'o',
            long = "output",
            value_name = "PATH",
            help = "Destination file path, directory, or '-' for stdout"
        )]
        output: Option<PathBuf>,
        #[arg(
            long,
            conflicts_with = "password_file",
            help = "Read export password from standard input (Zero-Argv compliant)"
        )]
        password_stdin: bool,
        #[arg(
            long,
            value_name = "PATH",
            conflicts_with = "password_stdin",
            help = "Read export password from a file (Zero-Argv compliant)"
        )]
        password_file: Option<PathBuf>,
        #[arg(
            long,
            help = "Confirm unencrypted plaintext export without interactive prompt"
        )]
        allow_plaintext: bool,
        #[arg(
            long,
            help = "Overwrite an existing file or allow plaintext stdout on an interactive terminal"
        )]
        force: bool,
        #[arg(long, help = "Output structured JSON status envelope")]
        json: bool,
    },
    #[command(about = "Import personal Vault items and folders from a Bitwarden export file")]
    Import {
        #[arg(value_name = "FILE", help = "Path to Bitwarden export file")]
        file: PathBuf,
        #[arg(
            long,
            default_value = "auto",
            value_name = "FORMAT",
            help = "Import format (auto, encrypted_json, account_encrypted_json, json, csv)"
        )]
        format: String,
        #[arg(
            long,
            value_name = "NAME_OR_ID",
            help = "Route all imported items into a single Folder (existing UUID/name or new name)"
        )]
        folder: Option<String>,
        #[arg(
            long,
            help = "Validate, normalize, and preview import plan without modifying the Vault"
        )]
        dry_run: bool,
        #[arg(
            short = 'y',
            long = "yes",
            help = "Skip interactive confirmation prompt (required in non-interactive or --json mode)"
        )]
        yes: bool,
        #[arg(long, help = "Output structured JSON status envelope")]
        json: bool,
    },
}

pub(crate) fn run(action: VaultAction, cfg: &Config) -> ExitCode {
    let vault_mgr =
        VaultManager::with_identity_url(&cfg.server_url, cfg.identity_url.as_deref(), None, None);
    match action {
        VaultAction::Sync => read::run_sync(),
        VaultAction::List { category, trash } => read::run_list(&vault_mgr, category, trash),
        VaultAction::Search {
            query,
            query_flag,
            category,
            trash,
        } => read::run_search(&vault_mgr, query, query_flag, category, trash),
        VaultAction::Get {
            target,
            field,
            password,
            username,
            totp,
            notes,
            uri,
            cipher_type,
            trash,
            json: json_mode,
            reveal,
        } => {
            let selector = if let Some(f) = field {
                Some(f)
            } else if password {
                Some("password".to_string())
            } else if username {
                Some("username".to_string())
            } else if totp {
                Some("totp".to_string())
            } else if notes {
                Some("notes".to_string())
            } else if uri {
                Some("uri".to_string())
            } else {
                None
            };
            get::handle_vault_get(
                &target,
                selector.as_deref(),
                cipher_type.as_deref(),
                trash,
                json_mode,
                reveal,
            )
        }
        VaultAction::Create {
            item,
            from_json,
            stdin,
            json,
        } => create::run(item, from_json, stdin, json),
        VaultAction::Delete {
            target,
            permanent,
            trash,
            yes,
            json,
        } => lifecycle::run_delete(target, permanent, trash, yes, json),
        VaultAction::Restore { target, json } => lifecycle::run_restore(target, json),
        VaultAction::Share {
            target,
            organization_id,
            collection_ids,
            yes,
            json,
        } => lifecycle::run_share(target, organization_id, collection_ids, yes, json),
        VaultAction::Collections {
            target,
            collection_ids,
            add,
            remove,
            json,
        } => collections::run(target, collection_ids, add, remove, json),
        VaultAction::Edit {
            target,
            name,
            username,
            password,
            password_stdin,
            generate_password,
            generate_passphrase,
            totp_stdin,
            clear_totp,
            notes,
            notes_stdin,
            uris,
            add_uris,
            clear_uris,
            fields,
            hidden_fields,
            bool_fields,
            remove_fields,
            folder_id,
            favorite,
            stdin,
            from_json,
            json,
        } => edit::run(
            edit::EditArgs {
                target,
                name,
                username,
                password,
                password_stdin,
                generate_password,
                generate_passphrase,
                totp_stdin,
                clear_totp,
                notes,
                notes_stdin,
                uris,
                add_uris,
                clear_uris,
                fields,
                hidden_fields,
                bool_fields,
                remove_fields,
                folder_id,
                favorite,
                stdin,
                from_json,
                json,
            },
            cfg,
        ),
        VaultAction::Export {
            format,
            output,
            password_stdin,
            password_file,
            allow_plaintext,
            force,
            json,
        } => export::handle_vault_export(
            &format,
            output.as_deref(),
            password_stdin,
            password_file.as_deref(),
            allow_plaintext,
            force,
            json,
        ),
        VaultAction::Import {
            file,
            format,
            folder,
            dry_run,
            yes,
            json,
        } => import::handle_vault_import(&file, &format, folder.as_deref(), dry_run, yes, json),
    }
}
