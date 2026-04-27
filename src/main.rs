//! `pwm` — Rust port of the Python CLI password manager. See `lib.rs` for
//! the module-level docs and `cli` for the actual command implementation.

fn main() {
    // Cleanly handle SIGINT (Ctrl+C) at the top level: print a friendly
    // message and exit 0, mirroring the Python reference. We do NOT
    // install a global handler — the read primitives already surface
    // SIGINT as an `io::Error`, and the interactive layer prints
    // "Перервано." via the error path. For non-interactive mode the
    // default Ctrl+C behaviour (terminate) is fine.
    let code = passwordmanagerrs::cli::run();
    std::process::exit(code);
}
