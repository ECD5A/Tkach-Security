<p align="right">
  <a href="README.md">English version</a>
</p>

<p align="center">
  <img src="assets/tkach-preview.png" alt="Tkach Security preview — Krosna, Zaslon, Propusk and Sled">
</p>

<div align="center">

**Граница безопасности с fail-closed поведением для AI-агентов и скомпрометированного вывода модели.**

<a href="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml"><img src="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
<img src="https://img.shields.io/badge/MSRV-1.85-orange?logo=rust" alt="MSRV 1.85">
<img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Лицензия Apache 2.0">
<img src="https://img.shields.io/badge/status-Strong%20Core%20release%20candidate-5b6ee1" alt="Кандидат Strong Core release">

</div>

Tkach Security — детерминированная типизированная граница безопасности для
систем, использующих вероятностные или скомпрометированные модели.

> Модель предлагает. Tkach авторизует.

Если модель скомпрометирована, её вывод остаётся недоверенными ДАННЫМИ
(DATA). Tkach ограничивает действия, информационные потоки и операции с
секретами через брокер, которые могут пересечь защищённую границу. Tkach не
пытается сделать модель доверенной.

## Зачем нужен Tkach

- Текст модели и предложения инструментов не могут самостоятельно создать
  полномочия на выполнение.
- Защищённые эффекты требуют выданный ядром `Propusk` с точной областью
  действия.
- `READ`, `EXPORT` и другие направления являются отдельными решениями
  `Ruslo`.
- `Gnezdo`, `Niti` и `Metka` сохраняют консервативное состояние данных и
  происхождения.
- `Zaslon` и финальные проверки выпуска блокируют некорректные, слишком большие,
  запрещённые, повторные, отменённые и неопределённые состояния.
- `Klyuchnik` удерживает значения секретов у брокера вне обычного контекста
  модели, а `Sled` записывает ограниченные свидетельства без содержимого.

Это защищает путь контроля, даже если модель ведёт себя враждебно. Tkach не
защищает интегратора, который намеренно обходит границу.

## Локальный старт за пять минут

Из checkout с Rust 1.85 или новее:

```console
cargo install --path crates/tkach-cli --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`init` создаёт ограниченный стартовый запрос и отказывается перезаписывать
существующий. `check` использует ту же строгую форму запроса, что и Gateway.
`run --demo` запускает детерминированную локальную проверку Gateway без сетевого
вызова провайдера и реального побочного эффекта.

Текущий CLI устанавливается локально из исходников. Публикации в crates.io,
готовых бинарников и публичного production-сервиса пока нет.

## Превью CLI

Поверхность onboarding намеренно небольшая и читаемая:

```text
$ tkach --version
Tkach Security 0.1.0

$ tkach init my-agent
initialized my-agent/.tkach/request.json
  -> next: tkach check my-agent/.tkach/request.json
  -> demo: tkach run --demo

$ tkach check my-agent/.tkach/request.json
valid bounded request: 1 message(s), 0 metadata entr(y/ies), 0 tool declaration(s)

$ tkach run --demo
demo passed: bounded Gateway response released after final gates
```

Для локальной проверки HTTP запустите отдельный детерминированный reference
runtime; bearer-токен передаётся не в аргументе команды, а через окружение:

```console
TKACH_BEARER_TOKEN=local-development-secret TKACH_HTTP_ADDR=127.0.0.1:8080 tkach serve --demo
```

Он открывает только loopback `/healthz` и аутентифицированный `/v1/run`, не
вызывает настоящую модель и не выполняет защищённых побочных эффектов. Это не
production gateway.

Запустите `tkach` без аргументов в терминале или `tkach ui`, чтобы открыть меню.
**Стрелки вверх/вниз** (или **1–8**) выбирают пункт, **Enter** открывает действие,
**Esc** возвращает назад или закрывает меню. **F1**, **l/L** и **д/Д** сразу
переключают русский и английский. При вводе пути используйте **F1**:
буквы остаются частью пути.
Меню помогает создать стартовый запрос, проверить файл, проверить локальную
готовность, запустить офлайн-демо, настроить UI текущей сессии и разобраться с
подключением. Оно не
развёртывает политику защиты и не
подключает модель. `serve --demo` — отдельная неинтерактивная reference-команда.
При вводе через pipe сохраняются ограниченные строковые команды
(`/l en`, `/l ru`, `q`); скрипты и CI используют `init`, `check` и `run --demo` напрямую.

Для русской справки используйте `tkach --lang ru --help` или задайте
`TKACH_LANG=ru` как язык интерфейса по умолчанию. `--lang en|ru` меняет только
язык интерфейса, но не policy, полномочия, лимиты или поведение выполнения.

Интерактивное меню — адаптивная кроссплатформенная панель Ratatui с выбранным
действием, локальным статусом, подсказками управления и присланным PNG-баннером,
который выводится цветными пиксельными ячейками (пресет 132 x 40 показывает его
без обрезки). Этот путь не зависит от Braille-шрифтов и одинаково проходит
через Ratatui/crossterm в Windows CMD и WSL. Баннер можно скрыть через
`TKACH_BANNER=compact`; `NO_COLOR=1` намеренно оставляет компактную панель,
потому что пиксельный режим требует поддержки цветов. CLI управляет раскладкой
и цветами, а настоящий шрифт и его размер задаются эмулятором терминала.

## Архитектура

```text
недоверенный вывод модели/провайдера
                 |
                 v
      Gnezdo DATA + Niti/Metka
                 |
                 v
       Zaslon: формальные запреты
                 |
                 v
       Krosna: авторизация
            |             |
         Ruslo         Propusk
       flow gates         |
            |             v
            +----> защищённый executor
                              |
                              v
                    финальный выпуск Zaslon/Ruslo
                              |
                              v
                    ограниченная запись Sled
```

`tkach-core` не зависит от провайдера, протокола и runtime. Адаптеры проводят
запросы к границе; они не создают второй движок политики и не выдают полномочия
в обход ядра.

## Что входит в этот release candidate

| Пакет | Назначение |
| --- | --- |
| `tkach-core` | Strong Core: Krosna, Zaslon, Gnezdo, Propusk, Ruslo, Niti, Metka, Klyuchnik и Sled |
| `tkach-gateway` | Ограниченный lifecycle, orchestration провайдера, граница защищённого выполнения и финальный выпуск |
| `tkach-provider-openai` | Необязательный ограниченный non-streaming адаптер OpenAI Responses; вывод провайдера остаётся враждебными DATA |
| `tkach-cli` | Локальный onboarding: `init`, `check`, детерминированный `run --demo` и loopback reference runtime `serve --demo` |
| `tkach-http` | Только loopback HTTP/1.1 carrier вокруг существующего runtime service |
| `tkach-client` | Ограниченный Rust-клиент для проверенного локального HTTP-контракта |
| `tkach-mcp` | Отдельный MCP stdio-адаптер с одним делегированным инструментом `tkach_run` |

### Граница интеграции

Доступно сейчас:

- интеграция внутри Rust через `tkach-core` и `tkach-gateway`;
- loopback-only HTTP-контракт для host-приложения, которое подключает runtime
  service;
- типизированный Rust HTTP-клиент;
- source-level Python HTTP-адаптер только на стандартной библиотеке;
- dependency-free Node.js-адаптер с TypeScript declarations;
- dependency-free Go-адаптер;
- MCP stdio-адаптер поверх локального HTTP runtime;
- небольшой CLI для безопасного onboarding и детерминированной проверки.
- отдельный loopback-only `serve --demo` для smoke-проверки HTTP-интеграции.

Пока не заявляется:

- публикация в crates.io или другом публичном package registry;
- подписанные публичные бинарники GitHub Release;
- Docker/OCI-образы;
- готовый публичный HTTP gateway или TLS termination;
- Streamable HTTP, streaming release или публичный network service;
- опубликованные multi-language SDK-пакеты для Python, JavaScript/TypeScript,
  Go и других языков;
- UI, cloud control plane, generic executor или регистрация в MCP Registry.

Это факты текущего scope, а не скрытые обещания. HTTP JSON-контракт является
языконезависимой точкой интеграции для будущих клиентов, а security-логика
должна оставаться в Rust-границе.

## Security non-goals

Tkach не обнаруживает каждую prompt injection, смысловой перефраз, галлюцинацию
или плохое намерение. Он не делает LLM правдивой или aligned, не защищает
полностью скомпрометированный host/OS, не останавливает out-of-band executor и
не возвращает секреты, которые интегратор сам поместил в контекст модели. Tkach
не предоставляет распределённые exactly-once эффекты, TLS, изоляцию процессов
или универсальную защиту от конкурентных гонок файловой системы.

Гарантии действуют только тогда, когда каждый защищённый эффект и выпуск
проходят через настроенные Gateway и типизированную executor-границу, без
обходного пути к привилегиям или исходным credentials.

## Документация

- [Контракт продукта](docs/PRODUCT_CONTRACT.md) — гарантии и условия deployment.
- [Архитектура](docs/ARCHITECTURE.md) — реализованные границы и trusted computing base.
- [Модель безопасности](docs/SECURITY_MODEL.md) — роли примитивов, допущения и non-goals.
- [Модель угроз](docs/THREAT_MODEL.md) — возможности атакующего и цели containment.
- [Руководство по интеграции](docs/INTEGRATION.md) — CLI, Rust, HTTP, MCP и deployment profiles.
- [Контракт распространения](docs/DISTRIBUTION.md) — статус пакетов и релиза.
- [Политика безопасности](SECURITY.md) — scope для сообщений и responsible disclosure.
- [История изменений](CHANGELOG.md) — версии проекта.

## Локальная проверка

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo audit --no-fetch
cargo deny check
```

Проект распространяется под Apache-2.0. Текущий статус — Strong Core release
candidate, а не публичный production release.

## Участие в разработке

Делайте изменения небольшими, проверяемыми и явно описывайте границу
безопасности. Не добавляйте в commits полномочия, provider-specific policy,
credentials, generated artifacts, локальные результаты сканирования или
внутренние инженерные инструкции. Перед предложением изменения запускайте
релевантные format, lint, tests и security checks и описывайте остаточные
ограничения. Изменения Core допустимы при доказанном security или product
дефекте; адаптеры должны оставаться тонкими и не дублировать логику ядра.

## Поддержка

Если Tkach Security полезен в вашей работе, поддержите его дальнейшее развитие:

- TON: `pointoncurve.ton`
- Bitcoin (BTC): `1ECDSA1b4d5TcZHtqNpcxmY8pBH1GgHntN`
- USDT (TRC20): `TUF4vPdB6QkjCvZq18rBL4Qj4dK5ihCN75`

## Контакты

Вопросы о Tkach Security, интеграции, security research или сотрудничестве:

<p>
  <a href="mailto:stelmak159@gmail.com" aria-label="Email"><img alt="Email" height="24" src="https://cdn.simpleicons.org/gmail/EA4335"></a>
  &nbsp;
  <a href="https://t.me/ECDS4" aria-label="Telegram"><img alt="Telegram" height="24" src="https://cdn.simpleicons.org/telegram/26A5E4"></a>
  &nbsp;
  <a href="https://github.com/ECD5A/Tkach-Security" aria-label="GitHub repository"><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/github/FFFFFF"><img alt="GitHub repository" height="24" src="https://cdn.simpleicons.org/github/181717"></picture></a>
</p>
