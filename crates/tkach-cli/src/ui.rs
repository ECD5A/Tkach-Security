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
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    style::ResetColor,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Padding, Paragraph, Wrap},
};
use std::{
    io::{self, Cursor, Write},
    path::Path,
    sync::{
        OnceLock,
        mpsc::{self, Receiver, TryRecvError},
    },
    time::Duration,
};

const MIN_UI_WIDTH: u16 = 44;
const MIN_UI_HEIGHT: u16 = 18;
const DASHBOARD_WIDTH: u16 = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BannerMode {
    Compact,
    Raster { width: u16, rows: u16 },
}

const BANNER_PNG: &[u8] = include_bytes!("../../../assets/tkach-banner.png");
const BANNER_MIN_WIDTH: u16 = 92;
const BANNER_MAX_WIDTH: u16 = 124;

struct RasterBanner {
    width: u32,
    height: u32,
    pixels: Vec<[u8; 4]>,
}

fn tr(l: Language, en: &'static str, ru: &'static str) -> &'static str {
    match l {
        Language::English => en,
        Language::Russian => ru,
    }
}

fn menu_items(l: Language) -> [(&'static str, &'static str); 8] {
    match l {
        Language::English => [
            ("init", "create starter"),
            ("check", "validate request"),
            ("demo", "run offline demo"),
            ("doctor", "local diagnostics"),
            ("guide", "integration guide"),
            ("settings", "UI preferences"),
            ("help", "controls and safety"),
            ("quit", "exit"),
        ],
        Language::Russian => [
            ("init", "создать запрос"),
            ("check", "проверить запрос"),
            ("demo", "запустить демо"),
            ("doctor", "локальная диагностика"),
            ("guide", "руководство"),
            ("settings", "настройки UI"),
            ("help", "управление и безопасность"),
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
    Diagnostics(String),
    Integration,
    Settings,
    Help,
    Checking,
}
struct App {
    language: Language,
    selected: usize,
    settings_selected: usize,
    monochrome: bool,
    screen: Screen,
    scroll: usize,
    pending: Option<Receiver<Result<String, CliError>>>,
}
impl App {
    fn new(language: Language) -> Self {
        Self {
            language,
            selected: 0,
            settings_selected: 0,
            monochrome: false,
            screen: Screen::Menu,
            scroll: 0,
            pending: None,
        }
    }

    fn menu_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up => self.selected = (self.selected + 7) % 8,
            KeyCode::Down | KeyCode::Tab => self.selected = (self.selected + 1) % 8,
            KeyCode::Char(c @ '1'..='8') => self.selected = c as usize - '1' as usize,
            KeyCode::Enter => match self.selected {
                0 => self.screen = Screen::Path(true, String::new()),
                1 => self.screen = Screen::Path(false, String::new()),
                2 => {
                    self.screen = Screen::Result(outcome(run_demo(self.language), self.language));
                }
                3 => self.screen = Screen::Diagnostics(doctor(self.language)),
                4 => self.screen = Screen::Integration,
                5 => self.screen = Screen::Settings,
                6 => self.screen = Screen::Help,
                _ => return false,
            },
            KeyCode::Esc | KeyCode::Char('q' | 'Q' | 'й' | 'Й') => return false,
            _ => {}
        }
        true
    }

    fn settings_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up | KeyCode::Down | KeyCode::Tab => {
                self.settings_selected = (self.settings_selected + 1) % 2;
            }
            KeyCode::Char(c @ '1'..='2') => {
                self.settings_selected = c as usize - '1' as usize;
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Enter => {
                if self.settings_selected == 0 {
                    self.language = match self.language {
                        Language::English => Language::Russian,
                        Language::Russian => Language::English,
                    };
                } else {
                    self.monochrome = !self.monochrome;
                }
            }
            KeyCode::Esc | KeyCode::Char('q' | 'Q' | 'й' | 'Й') => {
                self.screen = Screen::Menu;
            }
            _ => {}
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
        if matches!(self.screen, Screen::Menu) {
            return self.menu_key(k.code);
        }
        if matches!(self.screen, Screen::Settings) {
            self.settings_key(k.code);
            return true;
        }
        match &mut self.screen {
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
            Screen::Result(value) | Screen::Diagnostics(value) => {
                value.lines().map(str::to_owned).collect()
            }
            Screen::Integration => integration_lines(l),
            Screen::Settings => settings_lines(l, self.settings_selected, self.monochrome),
            Screen::Help => help_lines(l),
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

fn settings_lines(l: Language, selected: usize, monochrome: bool) -> Vec<String> {
    let language = match l {
        Language::English => "English",
        Language::Russian => "Русский",
    };
    let color = if std::env::var_os("NO_COLOR").is_some() {
        tr(l, "MONO (NO_COLOR)", "МОНО (NO_COLOR)")
    } else if monochrome {
        tr(l, "MONO", "МОНО")
    } else {
        tr(l, "CYAN", "ГОЛУБОЙ")
    };
    vec![
        format!(
            "{} 01  {}: {language}",
            if selected == 0 { ">" } else { " " },
            tr(l, "Language", "Язык")
        ),
        format!(
            "{} 02  {}: {color}",
            if selected == 1 { ">" } else { " " },
            tr(l, "Theme", "Тема")
        ),
        String::new(),
        tr(
            l,
            "Left/Right or Enter changes the selected preference.",
            "Left/Right или Enter меняет выбранную настройку.",
        )
        .into(),
        tr(
            l,
            "Preferences apply only to this CLI session.",
            "Настройки действуют только в текущей сессии CLI.",
        )
        .into(),
        tr(
            l,
            "Banner: embedded PNG pixels; compact when color is unavailable.",
            "Баннер: встроенные PNG-пиксели; компактный без поддержки цвета.",
        )
        .into(),
        String::new(),
        tr(
            l,
            "Policy, secrets, endpoints and authority are not editable here.",
            "Policy, секреты, endpoints и полномочия здесь не изменяются.",
        )
        .into(),
    ]
}

pub(super) fn settings_text(l: Language) -> String {
    [
        tr(l, "LINE-MODE SETTINGS", "НАСТРОЙКИ СТРОКОВОГО РЕЖИМА"),
        "",
        tr(l, "Language: /l en | /l ru", "Язык: /l en | /l ru"),
        tr(
            l,
            "Color: set NO_COLOR=1 before launch",
            "Цвет: задайте NO_COLOR=1 перед запуском",
        ),
        tr(
            l,
            "Banner: TKACH_BANNER=compact hides the image",
            "Баннер: TKACH_BANNER=compact скрывает картинку",
        ),
        tr(
            l,
            "Interactive session settings are available in TTY mode.",
            "Интерактивные настройки сессии доступны в TTY-режиме.",
        ),
        "",
        tr(
            l,
            "Policy, secrets, endpoints and authority are not editable here.",
            "Policy, секреты, endpoints и полномочия здесь не изменяются.",
        ),
    ]
    .join("\n")
}

fn help_lines(l: Language) -> Vec<String> {
    [
        tr(l, "QUICK CONTROLS", "БЫСТРОЕ УПРАВЛЕНИЕ"),
        "",
        tr(
            l,
            "Up/Down or Tab  move selection",
            "Up/Down или Tab  выбор",
        ),
        tr(
            l,
            "Enter           open or confirm",
            "Enter           открыть или подтвердить",
        ),
        tr(
            l,
            "1-8             quick action",
            "1-8             быстрое действие",
        ),
        tr(
            l,
            "F1 / L / Д      switch language",
            "F1 / L / Д      сменить язык",
        ),
        tr(
            l,
            "Esc             back or exit",
            "Esc             назад или выход",
        ),
        tr(
            l,
            "The image uses color cells, not font-dependent Braille glyphs.",
            "Картинка использует цветные ячейки, а не Braille-шрифт.",
        ),
        "",
        tr(l, "SAFETY", "БЕЗОПАСНОСТЬ"),
        tr(
            l,
            "The UI never grants model authority or reveals bearer values.",
            "UI не выдаёт модели полномочия и не показывает bearer-значения.",
        ),
        tr(
            l,
            "Init never overwrites; validation never executes the request.",
            "Init не перезаписывает; проверка не выполняет request.",
        ),
        tr(
            l,
            "Demo is deterministic, local and provider-independent.",
            "Демо детерминированное, локальное и независимое от провайдера.",
        ),
    ]
    .iter()
    .map(|line| (*line).to_owned())
    .collect()
}

pub(super) fn help_text(l: Language) -> String {
    help_lines(l).join("\n")
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

fn accent_style(no_color: bool) -> Style {
    if no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }
}

fn muted_style(no_color: bool) -> Style {
    if no_color {
        Style::default()
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn selected_style(no_color: bool) -> Style {
    if no_color {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }
}

fn success_style(no_color: bool) -> Style {
    if no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn error_style(no_color: bool) -> Style {
    if no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD)
    }
}

fn panel_block<'a>(title: impl Into<Line<'a>>, no_color: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(accent_style(no_color))
        .padding(Padding::horizontal(1))
        .title(title)
}

fn screen_title(l: Language, screen: &Screen) -> &'static str {
    match screen {
        Screen::Menu => tr(l, "STATUS", "СОСТОЯНИЕ"),
        Screen::Path(true, _) => tr(l, "INITIALIZE", "ИНИЦИАЛИЗАЦИЯ"),
        Screen::Path(false, _) => tr(l, "VALIDATE", "ПРОВЕРКА"),
        Screen::Result(_) => tr(l, "RESULT", "РЕЗУЛЬТАТ"),
        Screen::Diagnostics(_) => tr(l, "DIAGNOSTICS", "ДИАГНОСТИКА"),
        Screen::Integration => tr(l, "INTEGRATION", "ИНТЕГРАЦИЯ"),
        Screen::Settings => tr(l, "SETTINGS", "НАСТРОЙКИ"),
        Screen::Help => tr(l, "HELP", "СПРАВКА"),
        Screen::Checking => tr(l, "CHECKING", "ПРОВЕРКА"),
    }
}

fn decode_banner() -> Option<RasterBanner> {
    let decoder = png::Decoder::new(Cursor::new(BANNER_PNG));
    let mut reader = decoder.read_info().ok()?;
    let mut bytes = vec![0; reader.output_buffer_size()?];
    let output = reader.next_frame(&mut bytes).ok()?;
    if output.color_type != png::ColorType::Rgba || output.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let pixels = bytes[..output.buffer_size()]
        .chunks_exact(4)
        .map(|pixel| [pixel[0], pixel[1], pixel[2], pixel[3]])
        .collect();
    Some(RasterBanner {
        width: output.width,
        height: output.height,
        pixels,
    })
}

fn banner_image() -> Option<&'static RasterBanner> {
    static IMAGE: OnceLock<Option<RasterBanner>> = OnceLock::new();
    IMAGE.get_or_init(decode_banner).as_ref()
}

fn banner_rows(image: &RasterBanner, width: u16) -> u16 {
    let target_width = u32::from(width);
    let numerator = target_width.saturating_mul(image.height);
    let denominator = image.width.saturating_mul(2);
    numerator
        .saturating_add(denominator.saturating_sub(1))
        .checked_div(denominator)
        .and_then(|rows| u16::try_from(rows).ok())
        .unwrap_or(u16::MAX)
}

fn choose_banner(
    preference: Option<&str>,
    no_color: bool,
    area: Rect,
    image: Option<&RasterBanner>,
) -> BannerMode {
    if no_color || preference.is_some_and(|value| value.eq_ignore_ascii_case("compact")) {
        return BannerMode::Compact;
    }
    let Some(image) = image else {
        return BannerMode::Compact;
    };
    let width = area.width.saturating_sub(4).min(BANNER_MAX_WIDTH);
    if width < BANNER_MIN_WIDTH {
        return BannerMode::Compact;
    }
    let rows = banner_rows(image, width);
    if u32::from(rows) + 9 > u32::from(area.height) {
        return BannerMode::Compact;
    }
    BannerMode::Raster { width, rows }
}

fn banner_mode(area: Rect, no_color: bool) -> BannerMode {
    let preference = std::env::var("TKACH_BANNER").ok();
    choose_banner(preference.as_deref(), no_color, area, banner_image())
}

fn banner_title(app: &App, no_color: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" v{VERSION} "), muted_style(no_color)),
        Span::styled(" CORE: FAIL-CLOSED ", success_style(no_color)),
        Span::styled(" LOCAL ", accent_style(no_color)),
        Span::styled(
            format!(" {} ", app.language.label().to_ascii_uppercase()),
            muted_style(no_color),
        ),
    ])
}

fn scaled_channel(channel: u8, alpha: u8) -> u8 {
    u8::try_from(u16::from(channel) * u16::from(alpha) / 255)
        .expect("alpha scaling of an 8-bit channel stays within range")
}

fn average_channel(first: u8, second: u8) -> u8 {
    let value =
        u16::from(first) / 2 + u16::from(second) / 2 + u16::from((first & 1) + (second & 1)) / 2;
    u8::try_from(value).expect("average of two 8-bit channels stays within range")
}

fn pixel_color(pixel: [u8; 4]) -> Color {
    Color::Rgb(
        scaled_channel(pixel[0], pixel[3]),
        scaled_channel(pixel[1], pixel[3]),
        scaled_channel(pixel[2], pixel[3]),
    )
}

fn raster_banner_lines(image: &RasterBanner, width: u16, rows: u16) -> Vec<Line<'static>> {
    let width = usize::from(width);
    let rows = usize::from(rows);
    let mut lines = Vec::with_capacity(rows);
    for row in 0..rows {
        let mut spans = Vec::with_capacity(width);
        for column in 0..width {
            let source_x = column * image.width as usize / width;
            let source_y = row * 2 * image.height as usize / (rows * 2);
            let next_y =
                ((row * 2 + 1) * image.height as usize / (rows * 2)).min(image.height as usize - 1);
            let first = pixel_color(image.pixels[source_y * image.width as usize + source_x]);
            let second = pixel_color(image.pixels[next_y * image.width as usize + source_x]);
            let Color::Rgb(first_red, first_green, first_blue) = first else {
                unreachable!()
            };
            let Color::Rgb(second_red, second_green, second_blue) = second else {
                unreachable!()
            };
            let color = Color::Rgb(
                average_channel(first_red, second_red),
                average_channel(first_green, second_green),
                average_channel(first_blue, second_blue),
            );
            spans.push(Span::styled(" ", Style::default().bg(color)));
        }
        lines.push(Line::from(spans));
    }
    lines
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App, no_color: bool, mode: BannerMode) {
    if let BannerMode::Raster { width, rows } = mode {
        if let Some(image) = banner_image() {
            let lines = raster_banner_lines(image, width, rows);
            frame.render_widget(
                Paragraph::new(lines).block(panel_block(banner_title(app, no_color), no_color)),
                area,
            );
            return;
        }
    }
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("T K A C H", accent_style(no_color)),
            Span::styled("  /  SECURITY CONTROL", muted_style(no_color)),
        ]),
        Line::from(vec![
            Span::styled(format!("v{VERSION}"), muted_style(no_color)),
            Span::raw("  |  "),
            Span::styled("[ CORE: FAIL-CLOSED ]", success_style(no_color)),
            Span::raw("  |  "),
            Span::styled("[ LOCAL ]", accent_style(no_color)),
            Span::raw("  |  "),
            Span::styled(
                format!("[ {} ]", app.language.label().to_ascii_uppercase()),
                muted_style(no_color),
            ),
        ]),
    ])
    .block(panel_block(" CONTROL ", no_color));
    frame.render_widget(header, area);
}

fn render_menu_panel(frame: &mut Frame<'_>, area: Rect, app: &App, no_color: bool) {
    let items = menu_items(app.language)
        .iter()
        .enumerate()
        .map(|(index, (command, description))| {
            let style = if index == app.selected {
                selected_style(no_color)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(
                format!(" {:02}  {command:<7} {description} ", index + 1),
                style,
            )))
        })
        .collect::<Vec<_>>();
    let menu = List::new(items).block(panel_block(
        tr(app.language, " ACTIONS ", " ДЕЙСТВИЯ "),
        no_color,
    ));
    frame.render_widget(menu, area);
}

fn render_status_panel(frame: &mut Frame<'_>, area: Rect, app: &App, no_color: bool) {
    let lines = vec![
        Line::from(Span::styled(
            tr(
                app.language,
                "The model proposes. Tkach authorizes.",
                "Модель предлагает. Ткач авторизует.",
            ),
            accent_style(no_color),
        )),
        Line::from(""),
        Line::from(tr(
            app.language,
            "• model output stays data",
            "• вывод модели остаётся данными",
        )),
        Line::from(tr(
            app.language,
            "• no provider or network is started",
            "• провайдер и сеть не запускаются",
        )),
        Line::from(tr(
            app.language,
            "• protected effects stay behind Gateway",
            "• защищённые действия идут через Gateway",
        )),
        Line::from(""),
        Line::from(Span::styled(
            tr(
                app.language,
                "LOCAL ONBOARDING / SAFE BY DEFAULT",
                "ЛОКАЛЬНАЯ НАСТРОЙКА / БЕЗОПАСНО ПО УМОЛЧАНИЮ",
            ),
            muted_style(no_color),
        )),
    ];
    let panel = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .block(panel_block(
            screen_title(app.language, &app.screen),
            no_color,
        ));
    frame.render_widget(panel, area);
}

fn render_text_screen(frame: &mut Frame<'_>, area: Rect, app: &App, no_color: bool) {
    let lines = fit_lines(
        app.lines(),
        usize::from(area.width.saturating_sub(2)),
        matches!(app.screen, Screen::Path(..)),
    )
    .into_iter()
    .skip(app.scroll)
    .map(|line| {
        let style = if line.starts_with('>') {
            selected_style(no_color)
        } else if line.contains("FAIL:")
            || line.contains("ОШИБКА")
            || matches!(line.as_str(), "NOT COMPLETED" | "НЕ ВЫПОЛНЕНО")
        {
            error_style(no_color)
        } else if line.contains("OK:") || matches!(line.as_str(), "COMPLETED" | "ГОТОВО") {
            success_style(no_color)
        } else {
            Style::default()
        };
        Line::from(Span::styled(visible(&line), style))
    })
    .collect::<Vec<_>>();
    let panel = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(panel_block(
            screen_title(app.language, &app.screen),
            no_color,
        ));
    frame.render_widget(panel, area);
}

fn footer_text(l: Language, screen: &Screen) -> &'static str {
    match screen {
        Screen::Menu => tr(
            l,
            "↑↓/Tab move   Enter select   1-8 quick action   F1/L/Д language   Esc quit",
            "↑↓/Tab выбор   Enter открыть   1-8 быстро   F1/L/Д язык   Esc выход",
        ),
        Screen::Path(..) => tr(
            l,
            "Type path   Enter confirm   F1 language   Esc cancel",
            "Введите путь   Enter подтвердить   F1 язык   Esc отмена",
        ),
        Screen::Settings => tr(
            l,
            "Up/Down select   Left/Right/Enter change   F1 language   Esc back",
            "Up/Down выбор   Left/Right/Enter изменить   F1 язык   Esc назад",
        ),
        _ => tr(
            l,
            "↑↓ scroll   Enter/Esc back   F1/L/Д language",
            "↑↓ прокрутка   Enter/Esc назад   F1/L/Д язык",
        ),
    }
}

fn draw_frame(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let no_color = app.monochrome || std::env::var_os("NO_COLOR").is_some();
    let outer = panel_block(" SECURITY BOUNDARY ", no_color);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if area.width < MIN_UI_WIDTH || area.height < MIN_UI_HEIGHT {
        let message = Paragraph::new(vec![
            Line::from(Span::styled(
                tr(app.language, "WINDOW TOO SMALL", "ОКНО СЛИШКОМ МАЛО"),
                accent_style(no_color),
            )),
            Line::from(""),
            Line::from(tr(
                app.language,
                "Resize terminal to at least 44 x 18.",
                "Увеличьте окно до 44 x 18.",
            )),
        ])
        .alignment(Alignment::Center)
        .block(panel_block(" UI ", no_color));
        frame.render_widget(message, inner);
        return;
    }

    let mode = banner_mode(inner, no_color);
    let header_height = match mode {
        BannerMode::Raster { rows, .. } => rows + 2,
        BannerMode::Compact => 4,
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);
    render_header(frame, layout[0], app, no_color, mode);
    if app.screen == Screen::Menu && area.width >= DASHBOARD_WIDTH {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(layout[1]);
        render_menu_panel(frame, body[0], app, no_color);
        render_status_panel(frame, body[1], app, no_color);
    } else if app.screen == Screen::Menu {
        render_menu_panel(frame, layout[1], app, no_color);
    } else {
        render_text_screen(frame, layout[1], app, no_color);
    }
    let status = Paragraph::new(Line::from(vec![
        Span::styled("[ READY ]", success_style(no_color)),
        Span::raw("  "),
        Span::styled(
            tr(
                app.language,
                "local-only / no model connection",
                "только локально / без подключения к модели",
            ),
            muted_style(no_color),
        ),
    ]));
    frame.render_widget(status, layout[2]);
    let footer = Paragraph::new(Line::from(Span::styled(
        footer_text(app.language, &app.screen),
        muted_style(no_color),
    )));
    frame.render_widget(footer, layout[3]);
}

fn draw_terminal<W: Write>(
    terminal: &mut Terminal<CrosstermBackend<W>>,
    app: &App,
) -> io::Result<()> {
    terminal.draw(|frame| draw_frame(frame, app)).map(|_| ())
}
pub(super) fn run(out: &mut impl Write, language: Language) -> Result<(), CliError> {
    let _guard = Guard::enter(out).map_err(|_| CliError::Io)?;
    let mut app = App::new(language);
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).map_err(|_| CliError::Io)?;
    terminal.clear().map_err(|_| CliError::Io)?;
    draw_terminal(&mut terminal, &app).map_err(|_| CliError::Io)?;
    loop {
        if app.poll_check() {
            draw_terminal(&mut terminal, &app).map_err(|_| CliError::Io)?;
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
        draw_terminal(&mut terminal, &app).map_err(|_| CliError::Io)?;
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
    fn embedded_banner_decodes_and_scales_without_font_glyphs() {
        let image = banner_image().expect("bundled banner PNG decodes");
        assert_eq!((image.width, image.height), (819, 161));
        assert_eq!(image.pixels.len(), (image.width * image.height) as usize);
        assert_eq!(banner_rows(image, BANNER_MAX_WIDTH), 13);
        let lines = raster_banner_lines(image, BANNER_MAX_WIDTH, 13);
        assert_eq!(lines.len(), 13);
        assert!(lines.iter().all(|line| line.spans.len() == 124));
        assert!(
            lines
                .iter()
                .flat_map(|line| &line.spans)
                .any(|span| span.style.bg.is_some())
        );
        assert_eq!(
            choose_banner(None, false, Rect::new(0, 0, 128, 38), Some(image)),
            BannerMode::Raster {
                width: 124,
                rows: 13
            }
        );
        assert_eq!(
            choose_banner(
                Some("compact"),
                false,
                Rect::new(0, 0, 128, 38),
                Some(image)
            ),
            BannerMode::Compact
        );
        assert_eq!(
            choose_banner(None, true, Rect::new(0, 0, 128, 38), Some(image)),
            BannerMode::Compact
        );
        assert_eq!(
            choose_banner(None, false, Rect::new(0, 0, 44, 18), Some(image)),
            BannerMode::Compact
        );
        assert_eq!(
            choose_banner(None, false, Rect::new(0, 0, 128, 38), None),
            BannerMode::Compact
        );
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
        assert_eq!(app.selected, 7);
        assert!(!app.key(key(KeyCode::Enter)));
    }

    #[test]
    fn settings_change_only_session_ui_preferences() {
        let mut app = App::new(Language::English);
        app.selected = 5;
        app.key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Settings);
        app.key(key(KeyCode::Enter));
        assert_eq!(app.language, Language::Russian);
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Enter));
        assert!(app.monochrome);
        app.key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Menu);
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
