use omawarden_engine::clipboard::ClipboardScope;
use std::path::PathBuf;
use std::process::ExitCode;

pub(crate) struct HolderArgs {
    pub(crate) seconds: u64,
    pub(crate) provider: Option<String>,
    pub(crate) binary_path: Option<PathBuf>,
    pub(crate) public: bool,
    pub(crate) expected_lock_generation: Option<u64>,
    pub(crate) cache_path: Option<PathBuf>,
    pub(crate) expected_credential_id: Option<String>,
    pub(crate) expected_lock_epoch: Option<u64>,
    pub(crate) legacy_path: Option<PathBuf>,
}

pub(crate) fn run_holder(args: HolderArgs) -> ExitCode {
    let active_path = args.binary_path.as_deref().or(args.legacy_path.as_deref());
    let resolved_provider =
        omawarden_engine::clipboard::resolve_provider(args.provider.as_deref(), active_path);
    let scope = match (
        args.expected_lock_generation,
        args.cache_path,
        args.expected_credential_id,
        args.expected_lock_epoch,
    ) {
        (Some(generation), None, None, None) => Some(ClipboardScope::Session(generation)),
        (None, Some(path), Some(credential_id), Some(lock_epoch)) => {
            Some(ClipboardScope::Cache { path, credential_id, lock_epoch })
        }
        (None, None, None, None) => None,
        _ => {
            eprintln!("Invalid clipboard holder scope");
            return ExitCode::FAILURE;
        }
    };
    match crate::clipboard_holder::hold_selection(
        resolved_provider,
        std::time::Duration::from_secs(args.seconds),
        !args.public,
        scope.as_ref(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
