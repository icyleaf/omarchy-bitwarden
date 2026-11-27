mod cli;
mod clipboard_holder;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Disable process tracing (ptrace) and core dump generation for memory
    // defense. Fail-open is accepted (a desktop helper should not refuse to
    // run over prctl), but never silently: without this the whole process
    // stays ptraceable and core-dumpable.
    if let Err(e) = omawarden_engine::locked::disable_dumpable() {
        omawarden_engine::log_error!(
            "omawarden:locked",
            "Could not disable ptrace/core dumps (prctl PR_SET_DUMPABLE: {e}); tracing protections are INACTIVE for this process"
        );
    }

    cli::run()
}
