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
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

mod ui;
use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
use tkach_core::krosna::{Krosna, Policy};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, ExternalMessage, ExternalRequest, ExternalRole, FakeToolBroker, Gateway,
    MAX_REQUEST_BODY_BYTES, ProviderStep, RuntimeAuthenticator, RuntimeLimits, RuntimeService,
    ScriptedStep,
};
use tkach_http::{HttpListener, HttpTransportError};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_UI_INPUT_BYTES: usize = 256;
const STARTER_REQUEST: &str = r#"{
  "messages": [
    {"role": "user", "content": "Return a bounded response"}
  ],
  "metadata": [],
  "tool_declarations": []
}
"#;
const USAGE_EN: &str = "Commands:\n  tkach init [DIRECTORY]       -> create a safe starter request\n  tkach check [REQUEST_JSON]   -> validate one bounded request\n  tkach doctor                 -> inspect local readiness without secrets\n  tkach run --demo             -> run the local deterministic proof\n  tkach serve --demo           -> serve the local authenticated HTTP demo\n  tkach --help                 -> show this guide\n  tkach --version              -> print the version\n\nFlow:\n  init -> check -> trusted runtime -> Gateway -> bounded result\n\nOptions:\n  --lang en|ru                 -> choose the interface language\n  TKACH_LANG=en|ru             -> choose the default language";
const USAGE_RU: &str = "Команды:\n  tkach init [DIRECTORY]       -> создать безопасный starter request\n  tkach check [REQUEST_JSON]   -> проверить один ограниченный request\n  tkach doctor                 -> проверить локальную готовность без секретов\n  tkach run --demo             -> запустить локальное deterministic proof\n  tkach serve --demo           -> запустить локальный аутентифицированный HTTP demo\n  tkach --help                 -> показать эту справку\n  tkach --version              -> показать версию\n\nПуть:\n  init -> check -> trusted runtime -> Gateway -> ограниченный результат\n\nНастройки:\n  --lang en|ru                 -> выбрать язык интерфейса\n  TKACH_LANG=en|ru             -> язык по умолчанию";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Language {
    English,
    Russian,
}

impl Language {
    fn parse(value: &str) -> Result<Self, CliError> {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "en" | "eng" | "english" | "англ" | "английский" => Ok(Self::English),
            "ru" | "rus" | "russian" | "рус" | "русский" => Ok(Self::Russian),
            _ => Err(CliError::Language),
        }
    }

    fn from_env() -> Result<Self, CliError> {
        match env::var("TKACH_LANG") {
            Ok(value) => Self::parse(&value),
            Err(env::VarError::NotPresent) => Ok(Self::English),
            Err(env::VarError::NotUnicode(_)) => Err(CliError::Language),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Russian => "ru",
        }
    }
}

fn localized(language: Language, en: &'static str, ru: &'static str) -> &'static str {
    match language {
        Language::English => en,
        Language::Russian => ru,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliError {
    Usage,
    UnknownCommand,
    Language,
    Io,
    AlreadyInitialized,
    InvalidRequest,
    DemoFailed,
    ServerConfiguration,
    ServerFailed,
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message(Language::English))
    }
}

impl CliError {
    fn message(self, language: Language) -> &'static str {
        match (self, language) {
            (Self::Usage, Language::English) => "invalid usage; run `tkach --help`",
            (Self::UnknownCommand, Language::English) => "unknown command; run `tkach --help`",
            (Self::Language, Language::English) => {
                "unsupported language; use `--lang en|ru` or TKACH_LANG=en|ru"
            }
            (Self::Io, Language::English) => "could not read or create the requested local file",
            (Self::AlreadyInitialized, Language::English) => {
                "starter request already exists; refusing to overwrite it"
            }
            (Self::InvalidRequest, Language::English) => {
                "request is invalid or exceeds the bounded schema"
            }
            (Self::DemoFailed, Language::English) => "local demo failed closed",
            (Self::ServerConfiguration, Language::English) => {
                "server configuration is invalid or TKACH_BEARER_TOKEN is missing"
            }
            (Self::ServerFailed, Language::English) => "local HTTP server stopped unexpectedly",
            (Self::Usage, Language::Russian) => "неверное использование; запустите `tkach --help`",
            (Self::UnknownCommand, Language::Russian) => {
                "неизвестная команда; запустите `tkach --help`"
            }
            (Self::Language, Language::Russian) => {
                "неподдерживаемый язык; используйте `--lang en|ru` или TKACH_LANG=en|ru"
            }
            (Self::Io, Language::Russian) => "не удалось прочитать или создать локальный файл",
            (Self::AlreadyInitialized, Language::Russian) => {
                "starter request уже существует; перезапись запрещена"
            }
            (Self::InvalidRequest, Language::Russian) => {
                "request недействителен или превышает ограниченную схему"
            }
            (Self::DemoFailed, Language::Russian) => "локальное демо завершилось с отказом",
            (Self::ServerConfiguration, Language::Russian) => {
                "неверная настройка server или отсутствует TKACH_BEARER_TOKEN"
            }
            (Self::ServerFailed, Language::Russian) => {
                "локальный HTTP server остановился неожиданно"
            }
        }
    }
}

impl Error for CliError {}

#[derive(Debug)]
enum Command {
    Help,
    Version,
    Init(PathBuf),
    Check(PathBuf),
    Doctor,
    Demo,
    ServeDemo,
    Ui,
}

#[derive(Debug)]
struct ParsedArgs {
    language: Language,
    command: Command,
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() && io::stdin().is_terminal() && io::stdout().is_terminal() {
        args.push("ui".to_owned());
    }
    let default_language = if explicit_language_option(&args) {
        // An explicit CLI selection must remain usable even when the environment
        // contains a stale or invalid value.
        Language::English
    } else {
        match Language::from_env() {
            Ok(language) => language,
            Err(error) => {
                eprintln!("error: {}", error.message(Language::English));
                std::process::exit(2);
            }
        }
    };
    match parse_args_with_default(args, default_language) {
        Ok(parsed) => match parsed.command {
            Command::Ui => {
                if let Err(error) = run_ui(parsed.language) {
                    eprintln!("error: {}", error.message(parsed.language));
                    std::process::exit(2);
                }
            }
            command => match execute(command, parsed.language) {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("error: {}", error.message(parsed.language));
                    std::process::exit(2);
                }
            },
        },
        Err(error) => {
            eprintln!("error: {}", error.message(default_language));
            std::process::exit(2);
        }
    }
}

fn explicit_language_option(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg == "--lang" || arg.starts_with("--lang="))
}

fn parse_language_options(args: &[String]) -> Result<(Option<Language>, Vec<String>), CliError> {
    let mut language = None;
    let mut command_args = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--lang" {
            if language.is_some() || index + 1 == args.len() {
                return Err(CliError::Usage);
            }
            language = Some(Language::parse(&args[index + 1])?);
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--lang=") {
            if language.is_some() {
                return Err(CliError::Usage);
            }
            language = Some(Language::parse(value)?);
            index += 1;
            continue;
        }
        command_args.push(arg.clone());
        index += 1;
    }
    Ok((language, command_args))
}

#[cfg(test)]
fn parse_args<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    parse_args_with_default(args, Language::English).map(|parsed| parsed.command)
}

fn parse_args_with_default<I, S>(
    args: I,
    default_language: Language,
) -> Result<ParsedArgs, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let (explicit_language, command_args) = parse_language_options(&args)?;
    let language = explicit_language.unwrap_or(default_language);
    let command = match command_args.as_slice() {
        [] => Command::Help,
        [arg] if arg == "--help" || arg == "-h" => Command::Help,
        [arg] if arg == "--version" || arg == "-V" => Command::Version,
        [command] if command == "init" => Command::Init(PathBuf::from(".")),
        [command, root] if command == "init" => Command::Init(PathBuf::from(root)),
        [command] if command == "check" => Command::Check(PathBuf::from(".tkach/request.json")),
        [command, request] if command == "check" => Command::Check(PathBuf::from(request)),
        [command] if command == "doctor" => Command::Doctor,
        [command, flag] if command == "run" && flag == "--demo" => Command::Demo,
        [command, flag] if command == "serve" && flag == "--demo" => Command::ServeDemo,
        [command] if command == "ui" || command == "menu" => Command::Ui,
        [command] if command == "run" || command == "serve" => return Err(CliError::Usage),
        [command] if command == "help" => Command::Help,
        _ => return Err(CliError::UnknownCommand),
    };
    Ok(ParsedArgs { language, command })
}

fn execute(command: Command, language: Language) -> Result<String, CliError> {
    match command {
        Command::Help => Ok(help(language)),
        Command::Version => Ok(format!("tkach {VERSION}")),
        Command::Init(root) => initialize(&root, language),
        Command::Check(path) => check_request(&path, language),
        Command::Doctor => Ok(doctor(language)),
        Command::Demo => run_demo(language),
        Command::ServeDemo => {
            run_server()?;
            Ok(String::new())
        }
        Command::Ui => Err(CliError::Usage),
    }
}

fn help(language: Language) -> String {
    let intro = match language {
        Language::English => "A fail-closed boundary for AI agents and untrusted model output.",
        Language::Russian => {
            "Отказоустойчивая граница для AI-агентов и недоверенного вывода модели."
        }
    };
    let usage = match language {
        Language::English => USAGE_EN,
        Language::Russian => USAGE_RU,
    };
    let ui_hint = match language {
        Language::English => {
            "Interactive UI: `tkach ui` | Up/Down + Enter | F1 or L/Д switches language"
        }
        Language::Russian => {
            "Интерактивный UI: `tkach ui` | Стрелки + Enter | F1 или L/Д меняет язык"
        }
    };
    format!("Tkach Security {VERSION}\n{intro}\n\n{usage}\n\n{ui_hint}\n")
}

#[derive(Debug, PartialEq, Eq)]
enum UiAction {
    ToggleLanguage,
    SetLanguage(Language),
    Help,
    Init(PathBuf),
    Check(PathBuf),
    Doctor,
    Integration,
    Demo,
    Quit,
}

enum UiInput {
    End,
    Line(String),
    TooLong,
    InvalidUtf8,
}

fn run_ui(language: Language) -> Result<(), CliError> {
    let stdin = io::stdin();
    let terminal_input = stdin.is_terminal() && io::stdout().is_terminal();
    let mut output = io::stdout();
    if terminal_input {
        match ui::run(&mut output, language) {
            Ok(()) => return Ok(()),
            Err(CliError::Io) => {
                writeln!(
                    output,
                    "{}",
                    localized(
                        language,
                        "Interactive terminal mode is unavailable; using line mode.",
                        "Интерактивный режим терминала недоступен; включён строковый режим.",
                    )
                )
                .map_err(|_| CliError::Io)?;
            }
            Err(error) => return Err(error),
        }
    }

    let mut input = stdin.lock();
    run_line_ui(&mut input, &mut output, language)
}

fn run_line_ui(
    input: &mut impl BufRead,
    output: &mut impl Write,
    mut language: Language,
) -> Result<(), CliError> {
    loop {
        write_ui_menu(output, language).map_err(|_| CliError::Io)?;
        output.flush().map_err(|_| CliError::Io)?;
        match read_ui_input(input).map_err(|_| CliError::Io)? {
            UiInput::End => break,
            UiInput::TooLong | UiInput::InvalidUtf8 => {
                writeln!(output, "error: {}", CliError::Usage.message(language))
                    .map_err(|_| CliError::Io)?;
                break;
            }
            UiInput::Line(line) => match parse_ui_action(&line) {
                Ok(action) => {
                    if !apply_ui_action(action, &mut language, output)? {
                        break;
                    }
                }
                Err(error) => {
                    writeln!(output, "error: {}", error.message(language))
                        .map_err(|_| CliError::Io)?;
                }
            },
        }
    }
    Ok(())
}

fn apply_ui_action(
    action: UiAction,
    language: &mut Language,
    output: &mut impl Write,
) -> Result<bool, CliError> {
    match action {
        UiAction::Quit => Ok(false),
        UiAction::ToggleLanguage => {
            *language = match *language {
                Language::English => Language::Russian,
                Language::Russian => Language::English,
            };
            writeln!(output, "language: {}", language.label()).map_err(|_| CliError::Io)?;
            Ok(true)
        }
        UiAction::SetLanguage(selected) => {
            *language = selected;
            writeln!(output, "language: {}", language.label()).map_err(|_| CliError::Io)?;
            Ok(true)
        }
        UiAction::Help => {
            write!(output, "{}", help(*language)).map_err(|_| CliError::Io)?;
            Ok(true)
        }
        UiAction::Init(path) => {
            write_ui_result(output, initialize(&path, *language), *language)?;
            Ok(true)
        }
        UiAction::Check(path) => {
            write_ui_result(output, check_request(&path, *language), *language)?;
            Ok(true)
        }
        UiAction::Doctor => {
            writeln!(output, "{}", doctor(*language)).map_err(|_| CliError::Io)?;
            Ok(true)
        }
        UiAction::Integration => {
            writeln!(output, "{}", ui::integration_text(*language)).map_err(|_| CliError::Io)?;
            Ok(true)
        }
        UiAction::Demo => {
            write_ui_result(output, run_demo(*language), *language)?;
            Ok(true)
        }
    }
}

fn write_ui_result(
    output: &mut impl Write,
    result: Result<String, CliError>,
    language: Language,
) -> Result<(), CliError> {
    match result {
        Ok(value) => writeln!(output, "{value}").map_err(|_| CliError::Io),
        Err(error) => {
            writeln!(output, "error: {}", error.message(language)).map_err(|_| CliError::Io)
        }
    }
}

fn write_ui_menu(output: &mut impl Write, language: Language) -> io::Result<()> {
    for line in ui::menu_lines(language, None) {
        writeln!(output, "{line}")?;
    }
    writeln!(
        output,
        "{}",
        localized(
            language,
            "F1 or /l: switch language | q: quit",
            "F1 или /l: сменить язык | q: выйти",
        )
    )?;
    write!(output, "tkach[{}]> ", language.label())
}

fn parse_ui_action(line: &str) -> Result<UiAction, CliError> {
    let trimmed = line.trim();
    let normalized = trimmed.to_lowercase();
    if matches!(
        normalized.as_str(),
        "f1" | "l" | "\u{0434}" | "\u{1b}op" | "\u{1b}[11~" | "\u{1b}[[a"
    ) {
        return Ok(UiAction::ToggleLanguage);
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let command = parts.next().unwrap_or("").to_lowercase();
    let argument = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match command.as_str() {
        "" => Err(CliError::Usage),
        "/l" | "/lang" | "language" | "язык" => match argument {
            Some(value) => Ok(UiAction::SetLanguage(Language::parse(value)?)),
            None => Ok(UiAction::ToggleLanguage),
        },
        "1" | "init" => Ok(UiAction::Init(PathBuf::from(argument.unwrap_or(".")))),
        "2" | "check" => Ok(UiAction::Check(PathBuf::from(
            argument.unwrap_or(".tkach/request.json"),
        ))),
        "3" | "demo" => Ok(UiAction::Demo),
        "4" | "doctor" => Ok(UiAction::Doctor),
        "5" | "guide" | "integration" => Ok(UiAction::Integration),
        "run" if argument == Some("--demo") => Ok(UiAction::Demo),
        "h" | "help" | "?" => Ok(UiAction::Help),
        "6" | "q" | "quit" | "exit" => Ok(UiAction::Quit),
        _ => Err(CliError::UnknownCommand),
    }
}

fn read_ui_input(reader: &mut impl BufRead) -> io::Result<UiInput> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if reader.read(&mut byte)? == 0 {
            if bytes.is_empty() {
                return Ok(UiInput::End);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        if bytes.len() >= MAX_UI_INPUT_BYTES {
            // Do not drain an unbounded pipe. The line-mode UI terminates after
            // an oversized command, so unread bytes cannot become later commands.
            return Ok(UiInput::TooLong);
        }
        bytes.push(byte[0]);
    }
    Ok(match String::from_utf8(bytes) {
        Ok(line) => UiInput::Line(line),
        Err(_) => UiInput::InvalidUtf8,
    })
}

fn reject_link_components(path: &Path) -> Result<(), CliError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        let should_check = match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
                false
            }
            Component::RootDir => {
                current.push(component.as_os_str());
                true
            }
            Component::CurDir => {
                if current.as_os_str().is_empty() {
                    current.push(component.as_os_str());
                }
                true
            }
            Component::ParentDir => return Err(CliError::Io),
            Component::Normal(name) => {
                current.push(name);
                true
            }
        };
        if !should_check {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_directory_link(&metadata) || !metadata.is_dir() => {
                return Err(CliError::Io);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CliError::Io),
        }
    }
    Ok(())
}

fn safe_path(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii() && !character.is_ascii_control() {
                character.to_string()
            } else {
                format!("\\u{{{:04X}}}", character as u32)
            }
        })
        .collect()
}

fn initialize(root: &Path, language: Language) -> Result<String, CliError> {
    reject_link_components(root)?;
    fs::create_dir_all(root).map_err(|_| CliError::Io)?;
    reject_link_components(root)?;
    let directory = root.join(".tkach");
    reject_link_components(&directory)?;
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if is_directory_link(&metadata) || !metadata.is_dir() => {
            return Err(CliError::Io);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&directory).map_err(|_| CliError::Io)?;
            reject_link_components(&directory)?;
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
    Ok(match language {
        Language::English => format!(
            "initialized {}\n  -> next: tkach check {}\n  -> demo: tkach run --demo",
            safe_path(&directory),
            safe_path(&request_path)
        ),
        Language::Russian => format!(
            "инициализировано {}\n  -> дальше: tkach check {}\n  -> демо: tkach run --demo",
            safe_path(&directory),
            safe_path(&request_path)
        ),
    })
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

fn check_request(path: &Path, language: Language) -> Result<String, CliError> {
    if !fs::metadata(path).map_err(|_| CliError::Io)?.is_file() {
        return Err(CliError::InvalidRequest);
    }
    let file = File::open(path).map_err(|_| CliError::Io)?;
    if !file.metadata().map_err(|_| CliError::Io)?.is_file() {
        return Err(CliError::InvalidRequest);
    }
    let mut bytes = Vec::new();
    file.take((MAX_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::Io)?;
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(CliError::InvalidRequest);
    }
    let request = ExternalRequest::from_json(&bytes).map_err(|_| CliError::InvalidRequest)?;
    Ok(match language {
        Language::English => format!(
            "valid bounded request: {} message(s), {} metadata entr(y/ies), {} tool declaration(s)",
            request.messages().len(),
            request.metadata().len(),
            request.tool_declarations().len()
        ),
        Language::Russian => format!(
            "валидный ограниченный request: {} сообщ., {} metadata, {} tool declaration(s)",
            request.messages().len(),
            request.metadata().len(),
            request.tool_declarations().len()
        ),
    })
}

fn doctor(language: Language) -> String {
    let cwd =
        env::current_dir().map_or_else(|_| "<unavailable>".to_owned(), |path| safe_path(&path));
    let request_path = Path::new(".tkach/request.json");
    let request_status = match fs::metadata(request_path) {
        Ok(metadata) if metadata.is_file() => match check_request(request_path, language) {
            Ok(message) => message,
            Err(_) => match language {
                Language::English => "present but invalid".to_owned(),
                Language::Russian => "есть, но недействителен".to_owned(),
            },
        },
        Ok(_) => match language {
            Language::English => "path exists but is not a file".to_owned(),
            Language::Russian => "путь существует, но это не файл".to_owned(),
        },
        Err(_) => match language {
            Language::English => "not found; run `tkach init`".to_owned(),
            Language::Russian => "не найден; запустите `tkach init`".to_owned(),
        },
    };
    let configured_address = match env::var("TKACH_HTTP_ADDR") {
        Ok(value) => value.parse::<SocketAddr>().ok(),
        Err(env::VarError::NotPresent) => "127.0.0.1:8080".parse::<SocketAddr>().ok(),
        Err(env::VarError::NotUnicode(_)) => None,
    };
    let address_status = match configured_address {
        Some(address) if address.ip().is_loopback() => format!("OK: loopback {address}"),
        Some(_) => match language {
            Language::English => "FAIL: non-loopback address is rejected".to_owned(),
            Language::Russian => "ОШИБКА: внешний адрес запрещён".to_owned(),
        },
        None => match language {
            Language::English => "FAIL: TKACH_HTTP_ADDR is invalid".to_owned(),
            Language::Russian => "ОШИБКА: TKACH_HTTP_ADDR недействителен".to_owned(),
        },
    };
    let token_status = match env::var("TKACH_BEARER_TOKEN") {
        Ok(value) if !value.is_empty() => localized(
            language,
            "configured (value hidden)",
            "настроен (значение скрыто)",
        )
        .to_owned(),
        Ok(_) | Err(env::VarError::NotPresent) => localized(
            language,
            "not set; required only for `serve --demo`",
            "не задан; нужен только для `serve --demo`",
        )
        .to_owned(),
        Err(env::VarError::NotUnicode(_)) => localized(
            language,
            "invalid environment encoding",
            "недействительная кодировка окружения",
        )
        .to_owned(),
    };
    let title = match language {
        Language::English => "TKACH LOCAL READINESS",
        Language::Russian => "ЛОКАЛЬНАЯ ГОТОВНОСТЬ TKACH",
    };
    let next = match language {
        Language::English => "Next: tkach init <directory> → tkach check → tkach run --demo",
        Language::Russian => "Дальше: tkach init <каталог> → tkach check → tkach run --demo",
    };
    format!(
        "{title}\n\n{} {VERSION}\n{} {cwd}\n{} {request_status}\n{} {address_status}\n{} {token_status}\n{} {}\n\n{}",
        localized(language, "Version:", "Версия:"),
        localized(language, "Directory:", "Каталог:"),
        localized(language, "Starter request:", "Starter request:"),
        localized(language, "Demo HTTP:", "Demo HTTP:"),
        localized(language, "Bearer:", "Bearer:"),
        localized(language, "Core:", "Core:"),
        localized(
            language,
            "provider-independent, deterministic, no model connection",
            "независимое от провайдера, детерминированное, без подключения модели",
        ),
        next
    )
}

fn demo_gateway() -> Result<Gateway, CliError> {
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
    Ok(Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        FakeToolBroker::new(),
    ))
}

fn demo_provider() -> DeterministicProvider {
    DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["bounded response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }])
}

fn run_server() -> Result<(), CliError> {
    let token = env::var("TKACH_BEARER_TOKEN")
        .map_err(|_| CliError::ServerConfiguration)?
        .into_bytes();
    let address = env::var("TKACH_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()
        .map_err(|_| CliError::ServerConfiguration)?;
    let authenticator =
        RuntimeAuthenticator::new(token).map_err(|_| CliError::ServerConfiguration)?;
    let service = RuntimeService::new(
        demo_gateway()?,
        demo_provider(),
        authenticator,
        RuntimeLimits::default(),
    );
    let mut listener = HttpListener::bind(address, service).map_err(|error| match error {
        HttpTransportError::NonLoopbackBind => CliError::ServerConfiguration,
        HttpTransportError::Io | HttpTransportError::ResponseTooLarge => CliError::ServerFailed,
    })?;
    let local_address = listener.local_addr().map_err(|_| CliError::ServerFailed)?;
    eprintln!(
        "tkach demo runtime listening at http://{local_address}; /healthz is public, /v1/run requires TKACH_BEARER_TOKEN; press Ctrl-C to stop"
    );
    listener.serve_forever().map_err(|_| CliError::ServerFailed)
}

fn run_demo(language: Language) -> Result<String, CliError> {
    let mut gateway = demo_gateway()?;
    let mut provider = demo_provider();
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
    Ok(match language {
        Language::English => {
            "demo passed: bounded Gateway response released after final gates".to_owned()
        }
        Language::Russian => {
            "демо пройдено: ограниченный ответ прошёл финальные проверки Gateway".to_owned()
        }
    })
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
        assert!(matches!(parse_args(["doctor"]), Ok(Command::Doctor)));
        assert!(matches!(parse_args(["run", "--demo"]), Ok(Command::Demo)));
        assert!(matches!(
            parse_args(["serve", "--demo"]),
            Ok(Command::ServeDemo)
        ));
        assert_eq!(parse_args(["run"]).unwrap_err(), CliError::Usage);
        assert_eq!(parse_args(["serve"]).unwrap_err(), CliError::Usage);
        assert_eq!(
            parse_args(["help", "unexpected"]).unwrap_err(),
            CliError::UnknownCommand
        );
        assert_eq!(parse_args(["shell"]).unwrap_err(), CliError::UnknownCommand);
    }

    #[test]
    fn language_selection_is_explicit_and_does_not_change_command_surface() {
        let parsed = parse_args_with_default(["--lang", "ru", "--help"], Language::English)
            .expect("Russian language flag is accepted");
        assert_eq!(parsed.language, Language::Russian);
        assert!(help(parsed.language).contains("Команды"));

        let parsed = parse_args_with_default(["--lang=ru", "run", "--demo"], Language::English)
            .expect("equals language flag is accepted");
        assert_eq!(parsed.language, Language::Russian);
        assert!(matches!(parsed.command, Command::Demo));

        let parsed = parse_args_with_default(["run", "--demo", "--lang", "ru"], Language::English)
            .expect("language option is accepted after the command");
        assert_eq!(parsed.language, Language::Russian);
        assert!(matches!(parsed.command, Command::Demo));
        assert_eq!(
            parse_args_with_default(["--lang", "ru", "--lang", "en"], Language::English)
                .unwrap_err(),
            CliError::Usage
        );
        assert_eq!(Language::parse("fr").unwrap_err(), CliError::Language);
    }

    #[test]
    fn interactive_shortcuts_accept_case_and_language_aliases() {
        for shortcut in ["l", "L", "д", "Д"] {
            assert_eq!(parse_ui_action(shortcut), Ok(UiAction::ToggleLanguage));
        }
        assert_eq!(parse_ui_action("F1"), Ok(UiAction::ToggleLanguage));
        assert_eq!(
            parse_ui_action("/L РУССКИЙ"),
            Ok(UiAction::SetLanguage(Language::Russian))
        );
        assert_eq!(
            parse_ui_action("/l ENGLISH"),
            Ok(UiAction::SetLanguage(Language::English))
        );
        assert_eq!(parse_ui_action("язык"), Ok(UiAction::ToggleLanguage));
        assert_eq!(parse_ui_action("3"), Ok(UiAction::Demo));
        assert_eq!(parse_ui_action("4"), Ok(UiAction::Doctor));
        assert_eq!(parse_ui_action("5"), Ok(UiAction::Integration));
        assert_eq!(parse_ui_action("6"), Ok(UiAction::Quit));
        assert_eq!(parse_ui_action("q"), Ok(UiAction::Quit));
    }

    #[test]
    fn line_menu_stays_logo_free_and_functional() {
        for language in [Language::English, Language::Russian] {
            let mut output = Vec::new();
            write_ui_menu(&mut output, language).expect("line menu renders");
            let output = String::from_utf8(output).expect("menu output is UTF-8");
            for line in ui::menu_lines(language, None) {
                assert!(
                    output.contains(&line),
                    "line menu drifted from TTY menu: {line}"
                );
            }
            assert!(!output.contains("TKACH SECURITY"));
            assert!(!output.contains("Architected defense"));
            assert!(output.contains("01"));
            assert!(output.contains("06"));
        }
    }

    #[test]
    fn interactive_input_is_bounded_and_handles_invalid_utf8() {
        let mut input = std::io::Cursor::new(vec![b'x'; MAX_UI_INPUT_BYTES + 1]);
        assert!(matches!(
            read_ui_input(&mut input).expect("bounded input read succeeds"),
            UiInput::TooLong
        ));

        let mut input = std::io::Cursor::new(vec![0xff, b'\n']);
        assert!(matches!(
            read_ui_input(&mut input).expect("invalid UTF-8 read succeeds"),
            UiInput::InvalidUtf8
        ));
    }

    #[test]
    fn safe_path_escapes_terminal_controls_and_non_ascii() {
        let path = Path::new("safe\u{1b}[31m\n\u{2603}");
        assert_eq!(safe_path(path), "safe\\u{001B}[31m\\u{000A}\\u{2603}");
    }

    #[test]
    fn cli_version_is_sourced_from_package_metadata() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn init_is_no_overwrite_and_starter_is_accepted_by_gateway_parser() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("tkach-cli-{suffix}"));
        let initialized =
            initialize(&root, Language::English).expect("starter initialization succeeds");
        assert!(initialized.contains("tkach check"));
        let path = root.join(".tkach/request.json");
        assert!(check_request(&path, Language::English).is_ok());
        assert_eq!(
            initialize(&root, Language::English).unwrap_err(),
            CliError::AlreadyInitialized
        );
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
        assert_eq!(
            check_request(&path, Language::English).unwrap_err(),
            CliError::InvalidRequest
        );
        fs::remove_file(path).expect("test file cleanup succeeds");
    }

    #[test]
    fn check_rejects_directories() {
        assert_eq!(
            check_request(Path::new("."), Language::English),
            Err(CliError::InvalidRequest)
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_rejects_special_devices() {
        assert_eq!(
            check_request(Path::new("/dev/null"), Language::English),
            Err(CliError::InvalidRequest)
        );
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

        assert_eq!(
            initialize(&root, Language::English).unwrap_err(),
            CliError::Io
        );
        assert!(!outside.join("request.json").exists());

        fs::remove_dir_all(root).expect("test root cleanup succeeds");
        fs::remove_dir_all(outside).expect("test outside directory cleanup succeeds");
    }

    #[cfg(unix)]
    #[test]
    fn init_rejects_a_symlink_in_an_existing_parent_component() {
        use std::os::unix::fs::symlink;

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let base = env::temp_dir().join(format!("tkach-cli-parent-{suffix}"));
        let outside = env::temp_dir().join(format!("tkach-cli-parent-outside-{suffix}"));
        let linked_root = base.join("linked").join("nested");
        fs::create_dir_all(&base).expect("test base creation succeeds");
        fs::create_dir_all(&outside).expect("test outside creation succeeds");
        symlink(&outside, base.join("linked")).expect("test parent symlink creation succeeds");

        assert_eq!(
            initialize(&linked_root, Language::English).unwrap_err(),
            CliError::Io
        );
        assert!(!outside.join("nested/.tkach/request.json").exists());

        fs::remove_dir_all(base).expect("test base cleanup succeeds");
        fs::remove_dir_all(outside).expect("test outside cleanup succeeds");
    }

    #[test]
    fn demo_runs_through_the_existing_gateway_authority_path() {
        assert_eq!(
            run_demo(Language::English).unwrap(),
            "demo passed: bounded Gateway response released after final gates"
        );
    }

    #[test]
    fn doctor_is_local_and_does_not_claim_model_authority() {
        let report = doctor(Language::English);
        assert!(report.contains("TKACH LOCAL READINESS"));
        assert!(report.contains("provider-independent, deterministic"));
        assert!(!report.contains("local-development-secret"));
    }
}
