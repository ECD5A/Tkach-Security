<p align="right">
  <a href="README.md">English version</a>
</p>

<p align="center">
  <img src="assets/tkach-preview.png" alt="Tkach Security — Krosna, Zaslon, Propusk и Sled">
</p>

<div align="center">

**Fail-closed граница безопасности для AI-агентов и скомпрометированного вывода модели.**

<a href="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml"><img src="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
<a href="https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.2"><img src="https://img.shields.io/github/v/release/ECD5A/Tkach-Security?display_name=tag&sort=semver" alt="GitHub release"></a>
<a href="https://www.npmjs.com/package/tkach-security-client"><img src="https://img.shields.io/npm/v/tkach-security-client?logo=npm" alt="npm package"></a>
<a href="https://pypi.org/project/tkach-security-client/"><img src="https://img.shields.io/pypi/v/tkach-security-client?logo=pypi&amp;cacheSeconds=300" alt="PyPI package"></a>
<a href="https://crates.io/crates/tkach-cli"><img src="https://img.shields.io/crates/v/tkach-cli?logo=rust" alt="tkach-cli на crates.io"></a>
<img src="https://img.shields.io/badge/MSRV-1.85-orange?logo=rust" alt="MSRV 1.85">
<img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Лицензия Apache 2.0">

</div>

> Модель предлагает. Ткач авторизует.

Разместите Tkach между предложениями модели и защищёнными действиями. Ядро на
Rust проверяет полномочия и потоки данных перед действием или выдачей ответа.
Вывод модели остаётся недоверенными данными, даже если модель скомпрометирована.

## Зачем нужен Tkach

- **Явные полномочия:** защищённому действию нужен выданный ядром `Propusk`
  с точной областью разрешения; текст модели не может его создать.
- **Контроль потоков данных:** право прочитать не означает право экспортировать.
  Проверки происхождения и выдачи данных остаются внутри границы.
- **Запрет по умолчанию:** некорректные, запрещённые, повторные, отменённые
  или неопределённые состояния не превращаются в разрешение.
- **Изоляция секретов и ограниченный аудит:** секреты брокера не попадают
  в обычный контекст модели; квитанции `Sled` не содержат полезную нагрузку.

Гарантии действуют для путей, проходящих через Tkach. Он не делает модель
доверенной, не распознаёт все prompt injection и не защищает взломанный хост.

## Старт за несколько минут

Установите из crates.io с Rust 1.85 или новее:

```console
cargo install tkach-cli --version 0.1.2 --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`init` создаёт пример запроса без перезаписи файлов; `check` проверяет схему,
а не разрешение на исполнение; `run --demo` демонстрирует офлайн-проверки без
подключения к модели. Интерактивная панель открывается командой `tkach ui`.

Не хотите устанавливать Rust? Скачайте готовый бинарник ниже и начните с `tkach init`.

## Пакеты и загрузки · v0.1.2

| Канал | Что доступно | Установка / следующий шаг |
| --- | --- | --- |
| [GitHub Releases](https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.2) | `tkach` + `tkach-mcp`; Linux x86_64, macOS x86_64/arm64, Windows x86_64 | [Проверка архивов](docs/DISTRIBUTION.md#verify-a-v012-archive) |
| [crates.io](https://crates.io/crates/tkach-cli) | Семь Rust-крейтов `0.1.2`: Core, Gateway, HTTP, клиент, MCP, CLI, адаптер провайдера | [Список пакетов](docs/DISTRIBUTION.md#version-and-package-contract) |
| [npm](https://www.npmjs.com/package/tkach-security-client) | Тонкий HTTP-клиент для JavaScript / TypeScript | `npm install tkach-security-client@0.1.2` |
| [PyPI](https://pypi.org/project/tkach-security-client/) | Тонкий HTTP-клиент для Python | `python -m pip install tkach-security-client==0.1.2` |
| [Official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.ECD5A%2Ftkach-security) | `io.github.ECD5A/tkach-security@0.1.2`, локальный stdio | [Настройка MCP](docs/INTEGRATION.md#mcp-stdio-adapter--v01) |
| [GHCR](https://github.com/ECD5A/Tkach-Security/pkgs/container/tkach-security) | OCI-образ для Linux amd64 / arm64 | [Digest и развёртывание](docs/DISTRIBUTION.md#oci-image) |

К бинарным архивам приложены SHA-256, keyless Sigstore bundles и подтверждения
сборки GitHub. Для развёртывания OCI закрепляйте digest; подробности проверки —
в [руководстве по распространению](docs/DISTRIBUTION.md).

## Интеграция без переноса политик из Rust

Используйте [HTTP-контракт](docs/INTEGRATION.md#http-adapter-contract--v01)
из своего приложения, [Rust-клиент](docs/INTEGRATION.md#rust-client-adapter--v01),
[клиент Python/JS/TS/Go](docs/INTEGRATION.md#language-sdks--v01)
или stdio-адаптер из MCP-клиента.
Клиентам и MCP нужен отдельно запущенный локальный `tkach serve` и его bearer
token; установка пакета сама по себе не включает фоновую защиту.

`tkach-core` независим от провайдера, протокола и языка. Адаптеры передают
запросы; политики и полномочия остаются в Rust. Следуйте
[руководству по интеграции](docs/INTEGRATION.md) или возьмите рабочий сценарий
из [`examples/`](examples/). Go-клиент доступен как исходный модуль, а не
отдельный пакет в registry.

Runtime по умолчанию слушает только loopback. Публичный интернет-сервис,
TLS termination, Streamable HTTP, облачная панель управления и универсальный
исполнитель **не входят в поставку**; см. [контракт развёртывания](docs/PRODUCT_CONTRACT.md).

<details>
<summary>Показать окно кросс-платформенного CLI</summary>

<p align="center">
  <img src="assets/tkach-cli-ru.png" width="100%" alt="Tkach CLI на русском в WSL Ubuntu">
</p>
</details>

## Проверить границу на практике

В каталоге клонированного репозитория запустите офлайн-сценарий Golden Case.
Ему не нужны сервис модели или учётные данные. Пример выполняет одну
create-only запись во временный sandbox, а затем показывает отказ для
соседнего пути и предложения скомпрометированной модели:

```console
cargo run -p tkach-gateway --example golden_case --locked
```

Ожидаемый результат:

```text
GOLDEN_CASE|safe_output=released|allowed_write=committed|out_of_scope=denied|compromised_action=denied|compromised_executor_calls=0
```

Позитивный путь использует доверенную настройку политики, назначения и
executor; провайдер передаёт только недоверенное предложение. Путь проверок
описан в [архитектуре](docs/ARCHITECTURE.md), проверки релиза и оставшиеся ограничения —
в [заметках к v0.1.2](docs/releases/v0.1.2.md).

## Документация

- **Использование:** [интеграция](docs/INTEGRATION.md), [примеры](examples/), [распространение](docs/DISTRIBUTION.md).
- **Технический обзор:** [контракт](docs/PRODUCT_CONTRACT.md), [архитектура](docs/ARCHITECTURE.md), [модель безопасности](docs/SECURITY_MODEL.md), [модель угроз](docs/THREAT_MODEL.md).
- **Развитие:** [история изменений](CHANGELOG.md), [roadmap](docs/ROADMAP.md). Сообщения об уязвимостях — через [SECURITY.md](SECURITY.md).

## Участие в разработке

Делайте изменения небольшими и явно описывайте security boundary. Изменение
Core требует доказанного security- или product-defect; адаптеры должны
оставаться тонкими и не дублировать логику Core. В
[CONTRIBUTING.md](CONTRIBUTING.md) описаны обязательные проверки, правила
публичных заявлений и файлы, которые должны оставаться локальными.

## Поддержка

Если Tkach Security приносит пользу вашей работе, вы можете поддержать его
развитие:

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
