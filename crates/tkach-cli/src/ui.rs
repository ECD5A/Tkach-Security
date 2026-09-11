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

//! Interactive onboarding; all effects use the existing CLI boundary.
use super::{
    CliError, Language, MAX_UI_INPUT_BYTES, VERSION, check_request, doctor, initialize, run_demo,
};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, Write},
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::Duration,
};

const MIN_UI_WIDTH: u16 = 44;
const MIN_UI_HEIGHT: u16 = 14;

fn tr(l: Language, en: &'static str, ru: &'static str) -> &'static str {
    match l {
        Language::English => en,
        Language::Russian => ru,
    }
}

fn menu_items(l: Language) -> [(&'static str, &'static str); 6] {
    match l {
        Language::English => [
            ("init", "create starter"),
            ("check", "validate request"),
            ("demo", "run offline demo"),
            ("doctor", "local diagnostics"),
            ("guide", "integration guide"),
            ("quit", "exit"),
        ],
        Language::Russian => [
            ("init", "создать запрос"),
            ("check", "проверить запрос"),
            ("demo", "запустить демо"),
            ("doctor", "локальная диагностика"),
            ("guide", "руководство"),
            ("quit", "выход"),
        ],
    }
}

pub(super) fn menu_lines(l: Language, selected: Option<usize>) -> Vec<String> {
    let mut lines = vec![
        format!("Tkach local panel  |  v{VERSION}  |  {}", l.label()),
        tr(
            l,
            "The model proposes. Tkach authorizes.",
            "Модель предлагает. Ткач авторизует.",
        )
        .into(),
        String::new(),
    ];
    for (index, (command, description)) in menu_items(l).iter().enumerate() {
        let marker = if selected == Some(index) { ">" } else { " " };
        lines.push(format!(
            "{marker} {:02}  {command:<7} {description}",
            index + 1
        ));
    }
    lines
}

#[derive(Debug, PartialEq, Eq)]
enum Screen {
    Menu,
    Path(bool, String),
    Result(String),
    Integration,
    Checking,
}
struct App {
    language: Language,
    selected: usize,
    screen: Screen,
    scroll: usize,
    pending: Option<Receiver<Result<String, CliError>>>,
}
impl App {
    fn new(language: Language) -> Self {
        Self {
            language,
            selected: 0,
            screen: Screen::Menu,
            scroll: 0,
            pending: None,
        }
    }
    fn key(&mut self, k: KeyEvent) -> bool {
        if k.kind != KeyEventKind::Press {
            return true;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(k.code, KeyCode::Char('c' | 'C' | 'с' | 'С'))
        {
            return false;
        }
        if k.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
        {
            return true;
        }
        if k.code == KeyCode::F(1)
            || (!matches!(self.screen, Screen::Path(..))
                && matches!(k.code, KeyCode::Char('l' | 'L' | 'д' | 'Д')))
        {
            self.language = match self.language {
                Language::English => Language::Russian,
                Language::Russian => Language::English,
            };
            return true;
        }
        match &mut self.screen {
            Screen::Menu => match k.code {
                KeyCode::Up => self.selected = (self.selected + 5) % 6,
                KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % 6,
                KeyCode::Char(c @ '1'..='6') => self.selected = c as usize - '1' as usize,
                KeyCode::Enter => match self.selected {
                    0 => self.screen = Screen::Path(true, String::new()),
                    1 => self.screen = Screen::Path(false, String::new()),
                    2 => {
                        self.screen =
                            Screen::Result(outcome(run_demo(self.language), self.language));
                    }
                    3 => self.screen = Screen::Result(doctor(self.language)),
                    4 => self.screen = Screen::Integration,
                    _ => return false,
                },
                KeyCode::Esc | KeyCode::Char('q' | 'Q' | 'й' | 'Й') => return false,
                _ => {}
            },
            Screen::Path(create, value) => match k.code {
                KeyCode::Esc => self.screen = Screen::Menu,
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c)
                    if !c.is_control() && value.len() + c.len_utf8() <= MAX_UI_INPUT_BYTES =>
                {
                    value.push(c);
                }
                KeyCode::Char(c) if !c.is_control() => {
                    // Reject the entire input instead of accepting a truncated path.
                    self.screen = Screen::Result(
                        tr(
                            self.language,
                            "Path exceeds 256 UTF-8 bytes. Nothing was created or checked.",
                            "Путь длиннее 256 байт UTF-8. Создание и проверка не выполнялись.",
                        )
                        .into(),
                    );
                }
                KeyCode::Enter => {
                    let path = if value.is_empty() {
                        if *create { "." } else { ".tkach/request.json" }
                    } else {
                        value.as_str()
                    };
                    if *create {
                        self.screen = Screen::Result(outcome(
                            initialize(Path::new(path), self.language),
                            self.language,
                        ));
                    } else {
                        let path = path.to_owned();
                        self.start_check(path);
                    }
                    self.scroll = 0;
                }
                _ => {}
            },
            _ => match k.code {
                KeyCode::Enter | KeyCode::Esc => {
                    self.screen = Screen::Menu;
                    self.scroll = 0;
                }
                KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
                KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
                _ => {}
            },
        }
        true
    }
    // Keep the localized screen copy together so the terminal contract is easy to audit.
    #[allow(clippy::too_many_lines)]
    fn lines(&self) -> Vec<String> {
        let l = self.language;
        match &self.screen {
            Screen::Checking => {
                vec![tr(l, "Checking... Esc: cancel.", "Проверка... Esc: отмена.").into()]
            }
            Screen::Menu => menu_lines(l, Some(self.selected)),
            Screen::Path(create, value) => path_lines(l, *create, value),
            Screen::Result(value) => value.lines().map(str::to_owned).collect(),
            Screen::Integration => integration_lines(l),
        }
    }
}
impl App {
    fn start_check(&mut self, path: String) {
        if self.pending.is_some() {
            self.screen = Screen::Result(
                tr(
                    self.language,
                    "A previous file read is still pending. Wait or exit the CLI.",
                    "Предыдущее чтение ещё не завершено. Подождите или выйдите из CLI.",
                )
                .into(),
            );
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let language = self.language;
        // At most one reader per UI, even after cancelling. A stalled OS read
        // cannot consume the UI thread or accumulate unbounded worker threads.
        match std::thread::Builder::new()
            .name("tkach-file-check".into())
            .spawn(move || {
                let _ = sender.send(check_request(Path::new(&path), language));
            }) {
            Ok(_) => {
                self.pending = Some(receiver);
                self.screen = Screen::Checking;
            }
            Err(_) => self.screen = Screen::Result(outcome(Err(CliError::Io), language)),
        }
    }
    fn poll_check(&mut self) -> bool {
        let Some(receiver) = &self.pending else {
            return false;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => Err(CliError::Io),
        };
        self.pending = None;
        if self.screen == Screen::Checking {
            self.screen = Screen::Result(outcome(result, self.language));
            self.scroll = 0;
            return true;
        }
        false
    }
}

fn resize_key(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Esc | KeyCode::F(1))
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C' | 'с' | 'С')))
}

fn path_lines(l: Language, create: bool, value: &str) -> Vec<String> {
    vec![
        tr(
            l,
            if create {
                "CREATE STARTER REQUEST"
            } else {
                "VALIDATE REQUEST"
            },
            if create {
                "СОЗДАТЬ СТАРТОВЫЙ ЗАПРОС"
            } else {
                "ПРОВЕРИТЬ ЗАПРОС"
            },
        )
        .into(),
        String::new(),
        tr(
            l,
            if create {
                "Project directory (Enter confirms creation):"
            } else {
                "JSON request path (Enter validates):"
            },
            if create {
                "Папка проекта (Enter подтверждает создание):"
            } else {
                "Путь к JSON-запросу (Enter проверяет):"
            },
        )
        .into(),
        tr(
            l,
            if create {
                "Creates .tkach/request.json; never overwrites."
            } else {
                "Checks schema and limits; does not authorize execution."
            },
            if create {
                "Создаст .tkach/request.json без перезаписи."
            } else {
                "Проверяет формат и лимиты, не разрешает выполнение."
            },
        )
        .into(),
        format!(
            "{} {}",
            tr(l, "Default:", "По умолчанию:"),
            if create { "." } else { ".tkach/request.json" }
        ),
        String::new(),
        format!("> {}_", visible(value)),
        String::new(),
        tr(
            l,
            "Path without quotes. F1: language. Esc: cancel.",
            "Путь без кавычек. F1: язык. Esc: отмена.",
        )
        .into(),
        tr(
            l,
            "In paths, l/L and д/Д remain ordinary letters.",
            "В пути l/L и д/Д остаются обычными буквами.",
        )
        .into(),
    ]
}

fn integration_lines(l: Language) -> Vec<String> {
    [
        tr(l, "HOW TO INTEGRATE", "КАК ПОДКЛЮЧИТЬ"),
        "",
        tr(
            l,
            "CLI: local setup, request validation and offline demo.",
            "CLI: настройка, проверка запросов и офлайн-демо.",
        ),
        tr(
            l,
            "Rust: embed tkach-gateway with trusted policy and brokers.",
            "Rust: встройте tkach-gateway с политикой и брокерами.",
        ),
        tr(
            l,
            "Other languages: HTTP JSON through a trusted runtime.",
            "Другие языки: HTTP JSON через доверенный runtime.",
        ),
        tr(
            l,
            "MCP: tkach-mcp is a stdio adapter to that HTTP runtime.",
            "MCP: tkach-mcp — stdio-адаптер к HTTP runtime.",
        ),
        "",
        tr(
            l,
            "The menu does not launch a server or connect a model.",
            "Меню не запускает сервер и не подключает модель.",
        ),
        tr(
            l,
            "init creates an example request, not a deployed policy.",
            "init создаёт пример запроса, а не политику защиты.",
        ),
        tr(
            l,
            "Route every protected effect through the Gateway.",
            "Проводите каждое защищённое действие через Gateway.",
        ),
        "",
        "docs/INTEGRATION.md",
        "docs/PRODUCT_CONTRACT.md",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

pub(super) fn integration_text(l: Language) -> String {
    integration_lines(l).join("\n")
}

fn outcome(result: Result<String, CliError>, l: Language) -> String {
    match result {
        Ok(message) => format!("{}\n\n{message}", tr(l, "COMPLETED", "ГОТОВО")),
        Err(error) => format!(
            "{}\n\n{}",
            tr(l, "NOT COMPLETED", "НЕ ВЫПОЛНЕНО"),
            error.message(l)
        ),
    }
}
fn visible(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic()
                || c == ' '
                || ('А'..='я').contains(&c)
                || matches!(c, 'ё' | 'Ё')
            {
                c.to_string()
            } else {
                format!("\\u{{{:04X}}}", c as u32)
            }
        })
        .collect()
}
struct Guard;
impl Guard {
    fn enter(out: &mut impl Write) -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(out, EnterAlternateScreen, Hide) {
            let _ = execute!(out, Show, LeaveAlternateScreen);
            let _ = terminal::disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), ResetColor, Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}
fn fit_lines(lines: Vec<String>, width: usize, editing: bool) -> Vec<String> {
    let width = width.max(1);
    lines
        .into_iter()
        .flat_map(|line| {
            let chars: Vec<char> = line.chars().collect();
            if chars.is_empty() {
                return vec![String::new()];
            }
            if editing && line.starts_with("> ") && chars.len() > width {
                return vec![format!(
                    "<{}",
                    chars[chars.len() - width.saturating_sub(1)..]
                        .iter()
                        .collect::<String>()
                )];
            }
            chars
                .chunks(width)
                .map(|chunk| chunk.iter().collect())
                .collect()
        })
        .collect()
}

fn draw(out: &mut impl Write, app: &mut App) -> io::Result<()> {
    let (w, h) = terminal::size()?;
    queue!(out, ResetColor, Clear(ClearType::All))?;
    let mut lines = app.lines();
    if w < MIN_UI_WIDTH || h < MIN_UI_HEIGHT {
        lines = vec![
            tr(
                app.language,
                "Resize terminal to at least 44 x 14.",
                "Увеличьте окно до 44 x 14.",
            )
            .into(),
        ];
    }
    let lines = fit_lines(
        lines,
        usize::from(w.saturating_sub(1)),
        matches!(app.screen, Screen::Path(..)),
    );
    let available = usize::from(h.saturating_sub(2));
    app.scroll = app.scroll.min(lines.len().saturating_sub(available));
    for (row, line) in lines.iter().skip(app.scroll).take(available).enumerate() {
        queue!(out, MoveTo(0, u16::try_from(row).unwrap_or(0)))?;
        if std::env::var_os("NO_COLOR").is_none() && line.starts_with('>') {
            queue!(
                out,
                SetForegroundColor(Color::Cyan),
                SetAttribute(Attribute::Bold)
            )?;
        }
        queue!(
            out,
            Print(
                line.chars()
                    .take(usize::from(w.saturating_sub(1)))
                    .collect::<String>()
            ),
            ResetColor,
            SetAttribute(Attribute::Reset)
        )?;
    }
    if h > 0 {
        let footer = match app.screen {
            Screen::Menu => tr(
                app.language,
                "Up/Down  Enter  F1/L/Д: EN-RU  Esc: exit",
                "Стрелки  Enter  F1/L/Д: EN-RU  Esc: выход",
            ),
            Screen::Path(..) => tr(
                app.language,
                "F1: EN-RU  Enter: confirm  Esc: cancel",
                "F1: EN-RU  Enter: подтвердить  Esc: отмена",
            ),
            _ => tr(
                app.language,
                "F1/L/Д: EN-RU  Up/Down: scroll  Enter/Esc: back",
                "F1/L/Д: EN-RU  Стрелки: прокрутка  Enter/Esc: назад",
            ),
        };
        queue!(
            out,
            MoveTo(0, h - 1),
            Print(
                footer
                    .chars()
                    .take(usize::from(w.saturating_sub(1)))
                    .collect::<String>()
            )
        )?;
    }
    out.flush()
}
pub(super) fn run(out: &mut impl Write, language: Language) -> Result<(), CliError> {
    let _guard = Guard::enter(out).map_err(|_| CliError::Io)?;
    let mut app = App::new(language);
    draw(out, &mut app).map_err(|_| CliError::Io)?;
    loop {
        if app.poll_check() {
            draw(out, &mut app).map_err(|_| CliError::Io)?;
        }
        if !event::poll(Duration::from_millis(50)).map_err(|_| CliError::Io)? {
            continue;
        }
        match event::read().map_err(|_| CliError::Io)? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                let (width, height) = terminal::size().map_err(|_| CliError::Io)?;
                // Do not execute an invisible selection while the window is too small.
                if (width < MIN_UI_WIDTH || height < MIN_UI_HEIGHT) && !resize_key(key) {
                    continue;
                }
                if !app.key(key) {
                    return Ok(());
                }
            }
            Event::Resize(..) => {}
            _ => continue,
        }
        draw(out, &mut app).map_err(|_| CliError::Io)?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    #[test]
    fn both_layouts_and_caps_toggle_immediately() {
        for code in [
            KeyCode::F(1),
            KeyCode::Char('l'),
            KeyCode::Char('L'),
            KeyCode::Char('д'),
            KeyCode::Char('Д'),
        ] {
            let mut app = App::new(Language::English);
            assert!(app.key(key(code)));
            assert_eq!(app.language, Language::Russian);
            app.key(key(code));
            assert_eq!(app.language, Language::English);
        }
    }

    #[test]
    fn menu_contract_is_shared_by_the_tty_renderer() {
        let app = App::new(Language::English);
        assert_eq!(app.lines(), menu_lines(Language::English, Some(0)));
    }

    #[test]
    fn selection_does_not_execute_and_escape_cancels() {
        let mut app = App::new(Language::English);
        app.key(key(KeyCode::Char('2')));
        assert_eq!(app.screen, Screen::Menu);
        app.key(key(KeyCode::Up));
        app.key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Path(true, String::new()));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Menu);
        app.key(key(KeyCode::Up));
        assert_eq!(app.selected, 5);
        assert!(!app.key(key(KeyCode::Enter)));
    }
    #[test]
    fn paths_preserve_letters_and_bound_utf8() {
        let mut app = App::new(Language::English);
        app.key(key(KeyCode::Enter));
        for c in "lLдД".chars() {
            app.key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.screen, Screen::Path(true, "lLдД".into()));
        for _ in 0..300 {
            app.key(key(KeyCode::Char('я')));
        }
        let Screen::Result(message) = &app.screen else {
            panic!("oversized input must be rejected")
        };
        assert!(message.contains("Nothing was created"));
        app.key(key(KeyCode::F(1)));
        assert_eq!(app.language, Language::Russian);
    }
    #[test]
    fn repeat_release_and_modified_keys_do_not_submit() {
        let mut app = App::new(Language::English);
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            app.key(KeyEvent::new_with_kind(
                KeyCode::Enter,
                KeyModifiers::NONE,
                kind,
            ));
            assert_eq!(app.screen, Screen::Menu);
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
        assert_eq!(app.screen, Screen::Menu);
    }
    #[test]
    fn display_escapes_terminal_and_bidi_controls() {
        let text = visible("normal\u{1b}[2J\n\u{202e}");
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains('\u{202e}'));
    }

    #[test]
    fn narrow_results_wrap_and_path_tail_stays_visible() {
        assert_eq!(fit_lines(vec!["абвгд".into()], 3, false), vec!["абв", "гд"]);
        assert_eq!(fit_lines(vec!["> abcdef_".into()], 5, true), vec!["<def_"]);
        assert_eq!(fit_lines(vec!["ab".into()], 0, false), vec!["a", "b"]);
    }

    #[test]
    fn undersized_window_only_accepts_cancel_language_and_interrupt() {
        for c in "lLдДcCсС".chars() {
            assert!(!resize_key(key(KeyCode::Char(c))));
        }
        assert!(!resize_key(key(KeyCode::Enter)));
        assert!(resize_key(key(KeyCode::F(1))));
        assert!(resize_key(key(KeyCode::Esc)));
        assert!(resize_key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
    }

    #[test]
    fn cancelled_reader_cannot_publish_or_spawn_more_readers() {
        let mut app = App::new(Language::English);
        let (sender, receiver) = mpsc::channel();
        app.pending = Some(receiver);
        app.screen = Screen::Checking;
        assert!(!app.poll_check());
        app.key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Menu);
        app.start_check("not-read.json".into());
        assert!(matches!(&app.screen, Screen::Result(message) if message.contains("previous")));
        sender.send(Ok("stale result".into())).unwrap();
        assert!(!app.poll_check());
        assert!(app.pending.is_none());
        assert!(matches!(&app.screen, Screen::Result(message) if !message.contains("stale")));
    }

    #[test]
    fn reader_errors_finish_without_authorizing_anything() {
        let mut app = App::new(Language::English);
        let (sender, receiver) = mpsc::channel();
        app.pending = Some(receiver);
        app.screen = Screen::Checking;
        drop(sender);
        assert!(app.poll_check());
        assert!(
            matches!(&app.screen, Screen::Result(message) if message.contains("NOT COMPLETED"))
        );
    }
}
