#![forbid(unsafe_code)]
mod constants;
mod evaluation;

fn main() -> std::process::ExitCode {
    evaluation::run()
}
