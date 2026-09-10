/*
 * Tkach Security
 *
 * Copyright 2026 ECD5A
 * Licensed under the Apache License, Version 2.0.
 *
 * Repository: https://github.com/ECD5A/Tkach-Security
 *
 * See LICENSE and SECURITY.md.
 */

//! Minimal onboarding CLI around the stable Tkach Gateway boundary.

use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
use tkach_core::krosna::{Krosna, Policy};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, ExternalMessage, ExternalRequest, ExternalRole, FakeToolBroker, Gateway,
    MAX_REQUEST_BODY_BYTES, ProviderStep, ScriptedStep,
};

const VERSION: &str = "0.1.0";
const STARTER_REQUEST: &str = r#"{
  "messages": [
    {"role": "user", "content": "Return a bounded response"}
  ],
  "metadata": [],
  "tool_declarations": []
}
"#;
const USAGE: &str = "Usage:\n  tkach init [DIRECTORY]\n  tkach check [REQUEST_JSON]\n  tkach run --demo\n  tkach --help\n  tkach --version";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliError {
    Usage,
    UnknownCommand,
    Io,
    AlreadyInitialized,
    InvalidRequest,
    DemoFailed,
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Usage => USAGE,
            Self::UnknownCommand => "unknown command; run `tkach --help`",
            Self::Io => "could not read or create the requested local file",
            Self::AlreadyInitialized => "starter request already exists; refusing to overwrite it",
            Self::InvalidRequest => "request is invalid or exceeds the bounded schema",
            Self::DemoFailed => "local demo failed closed",
        })
    }
}

impl Error for CliError {}

#[derive(Debug)]
enum Command {
    Help,
    Version,
    Init(PathBuf),
    Check(PathBuf),
    Demo,
}

fn main() {
    match parse_args(env::args().skip(1)).and_then(execute) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    }
}

fn parse_args<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    match args.as_slice() {
        [] => Ok(Command::Help),
        [arg] if arg == "--help" || arg == "-h" => Ok(Command::Help),
        [arg] if arg == "--version" || arg == "-V" => Ok(Command::Version),
        [command] if command == "init" => Ok(Command::Init(PathBuf::from("."))),
        [command, root] if command == "init" => Ok(Command::Init(PathBuf::from(root))),
        [command] if command == "check" => Ok(Command::Check(PathBuf::from(".tkach/request.json"))),
        [command, request] if command == "check" => Ok(Command::Check(PathBuf::from(request))),
        [command, flag] if command == "run" && flag == "--demo" => Ok(Command::Demo),
        [command] if command == "run" => Err(CliError::Usage),
        [command] if command == "help" => Ok(Command::Help),
        _ => Err(CliError::UnknownCommand),
    }
}

fn execute(command: Command) -> Result<String, CliError> {
    match command {
        Command::Help => Ok(USAGE.to_owned()),
        Command::Version => Ok(format!("tkach {VERSION}")),
        Command::Init(root) => initialize(&root),
        Command::Check(path) => check_request(&path),
        Command::Demo => run_demo(),
    }
}

fn initialize(root: &Path) -> Result<String, CliError> {
    fs::create_dir_all(root).map_err(|_| CliError::Io)?;
    let directory = root.join(".tkach");
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if is_directory_link(&metadata) || !metadata.is_dir() => {
            return Err(CliError::Io);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&directory).map_err(|_| CliError::Io)?;
        }
        Err(_) => return Err(CliError::Io),
    }
    let request_path = directory.join("request.json");
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&request_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CliError::AlreadyInitialized);
        }
        Err(_) => return Err(CliError::Io),
    };
    if file
        .write_all(STARTER_REQUEST.as_bytes())
        .and_then(|()| file.flush())
        .is_err()
    {
        let _ = fs::remove_file(&request_path);
        return Err(CliError::Io);
    }
    Ok(format!(
        "initialized {}\nnext: tkach check {}\nthen: tkach run --demo",
        directory.display(),
        request_path.display()
    ))
}

fn is_directory_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn check_request(path: &Path) -> Result<String, CliError> {
    let file = File::open(path).map_err(|_| CliError::Io)?;
    let mut bytes = Vec::new();
    file.take((MAX_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::Io)?;
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(CliError::InvalidRequest);
    }
    let request = ExternalRequest::from_json(&bytes).map_err(|_| CliError::InvalidRequest)?;
    Ok(format!(
        "valid bounded request: {} message(s), {} metadata entr(y/ies), {} tool declaration(s)",
        request.messages().len(),
        request.metadata().len(),
        request.tool_declarations().len()
    ))
}

fn run_demo() -> Result<String, CliError> {
    let client = Destination::Internal(Identity::new("client").map_err(|_| CliError::DemoFailed)?);
    let flow = FlowRule::allow(
        RuleId::new("allow-cli-demo-release").map_err(|_| CliError::DemoFailed)?,
        FlowMatcher::any()
            .principal(Principal::Model)
            .source(FlowSource::Model)
            .destination(client.clone())
            .operation(FlowOperation::Export),
    );
    let ruslo = Ruslo::new(vec![flow]).map_err(|_| CliError::DemoFailed)?;
    let policy = Policy::new(
        PolicyId::new("cli-demo-policy").map_err(|_| CliError::DemoFailed)?,
        Vec::new(),
    )
    .map_err(|_| CliError::DemoFailed)?;
    let kernel = Krosna::with_zaslon_and_ruslo(policy, Zaslon::empty(), ruslo);
    let mut gateway = Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        FakeToolBroker::new(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["bounded response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let request = ExternalRequest::new(
        vec![
            ExternalMessage::new(ExternalRole::User, "return a bounded response".to_owned())
                .map_err(|_| CliError::DemoFailed)?,
        ],
        Vec::new(),
        Vec::new(),
    )
    .map_err(|_| CliError::DemoFailed)?;
    let result = gateway
        .run(&mut provider, &request)
        .map_err(|_| CliError::DemoFailed)?;
    if result.output() != Some("bounded response") {
        return Err(CliError::DemoFailed);
    }
    Ok("demo passed: bounded Gateway response released after final gates".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parser_keeps_the_onboarding_surface_small_and_explicit() {
        assert!(matches!(parse_args(["--help"]), Ok(Command::Help)));
        assert!(matches!(parse_args(["--version"]), Ok(Command::Version)));
        assert!(matches!(parse_args(["init"]), Ok(Command::Init(_))));
        assert!(matches!(parse_args(["check"]), Ok(Command::Check(_))));
        assert!(matches!(parse_args(["run", "--demo"]), Ok(Command::Demo)));
        assert_eq!(parse_args(["run"]).unwrap_err(), CliError::Usage);
        assert_eq!(
            parse_args(["help", "unexpected"]).unwrap_err(),
            CliError::UnknownCommand
        );
        assert_eq!(parse_args(["shell"]).unwrap_err(), CliError::UnknownCommand);
    }

    #[test]
    fn init_is_no_overwrite_and_starter_is_accepted_by_gateway_parser() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("tkach-cli-{suffix}"));
        let initialized = initialize(&root).expect("starter initialization succeeds");
        assert!(initialized.contains("tkach check"));
        let path = root.join(".tkach/request.json");
        assert!(check_request(&path).is_ok());
        assert_eq!(initialize(&root).unwrap_err(), CliError::AlreadyInitialized);
        fs::remove_dir_all(root).expect("test directory cleanup succeeds");
    }

    #[test]
    fn oversized_check_fails_before_request_deserialization() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!("tkach-cli-oversized-{suffix}.json"));
        fs::write(&path, vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]).expect("test file write succeeds");
        assert_eq!(check_request(&path).unwrap_err(), CliError::InvalidRequest);
        fs::remove_file(path).expect("test file cleanup succeeds");
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_a_preexisting_directory_symlink() {
        use std::os::unix::fs::symlink;

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("tkach-cli-link-{suffix}"));
        let outside = env::temp_dir().join(format!("tkach-cli-outside-{suffix}"));
        fs::create_dir_all(&root).expect("test root creation succeeds");
        fs::create_dir_all(&outside).expect("test outside directory creation succeeds");
        symlink(&outside, root.join(".tkach")).expect("test symlink creation succeeds");

        assert_eq!(initialize(&root).unwrap_err(), CliError::Io);
        assert!(!outside.join("request.json").exists());

        fs::remove_dir_all(root).expect("test root cleanup succeeds");
        fs::remove_dir_all(outside).expect("test outside directory cleanup succeeds");
    }

    #[test]
    fn demo_runs_through_the_existing_gateway_authority_path() {
        assert_eq!(
            run_demo().unwrap(),
            "demo passed: bounded Gateway response released after final gates"
        );
    }
}
