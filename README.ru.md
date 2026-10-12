[English](README.md) | [فارسی](README.fa.md) | **Русский**

# ffvpn — Неофициальный Go-клиент встроенного VPN Firefox

`ffvpn` — автономный Go-клиент для **IP Protection** (встроенного VPN Firefox,
работающего на базе Mozilla VPN). Он входит в сервис Guardian с помощью вашей
учётной записи Firefox, получает краткоживущие токены «ProxyPass» и
предоставляет тот же прокси-данный узел (edge), который использует Firefox, в
виде **локального SOCKS5 / HTTP CONNECT прокси** для любого приложения.

> 🔻 **Отказ от ответственности:** `ffvpn` — **неофициальный независимый**
> проект сообщества. Он **никак не связан с Mozilla или Firefox, не одобрен,
> не спонсируется и не поддерживается** ими. «Firefox», «Mozilla» и
> «Mozilla VPN» — товарные знаки их владельцев; этот проект не является
> официальным продуктом Mozilla и не получает от Mozilla никакой поддержки.
> Используйте на свой страх и риск.

> ⚠️ **Серверное ограничение (не обходится):** Guardian обслуживает только
> учётные записи с подпиской Mozilla VPN (иначе `403`) и из разрешённых
> регионов (`451` для запрещённых регионов). Эти проверки выполняются
> исключительно на сервере; этот клиент лишь выполняет те же запросы, которые
> выполняет сам Firefox. Использование неофициального клиента может
> нарушать Условия использования Mozilla VPN и влечь риск ограничения или
> блокировки учётной записи.

## Архитектура (по исходникам Firefox 157)

```
Ваше приложение ──► локальный SOCKS5/HTTP прокси (127.0.0.1)
                          │
                          ▼
                 TLS + HTTP CONNECT с заголовком
                 Proxy-Authorization: Bearer <JWT>   ──►  *.m1.fastly-masque.net:2499
                          │
                          ▼
                   Интернет (выход из выбранной страны)
```

- **Список серверов**: публичная коллекция Remote Settings с именем
  `vpn-serverlist` (без аутентификации).
- **Аутентификация**: `sessionToken` учётной записи Firefox → OAuth-токен со
  scope'ами `profile` и `https://identity.mozilla.com/apps/vpn` (тот же
  client_id десктопного Firefox: `5882386c6d801776`) → API Guardian на
  `https://vpn.mozilla.org` (реальное значение pref в Firefox; домен `.com`
  в JS-фолбэке вообще никогда не резолвится):
  - `POST /api/v1/fpn/activate` — активация и получение entitlement
  - `GET  /api/v1/fpn/token` — получение краткоживущего JWT (ротация за
    2 минуты до истечения)
  - заголовки `X-Quota-*` — использование пропускной способности
- **Туннель**: в текущих записях поле `protocols` не указано, поэтому согласно
  логике самого Firefox (`IPPChannelFilter.sys.mjs`) протоколом по умолчанию
  является CONNECT поверх TLS, а имя хоста разрешается на стороне дата-центра
  (edge) — эквивалент `TRANSPARENT_PROXY_RESOLVES_HOST`.

## Сборка

Требование: [Go](https://go.dev) 1.24+ (клиент написан на чистом Go без CGO;
кроме самого Go никаких зависимостей не нужно).

Сборка прямо на целевой ОС:

```sh
# Linux
go build -o ffvpn .

# Windows (PowerShell или cmd)
go build -o ffvpn.exe .
```

Кросс-компиляция из Linux — поскольку зависимостей от платформы и CGO нет,
дополнительная настройка не нужна:

```sh
GOOS=linux   GOARCH=amd64 go build -o ffvpn .               # Linux x86-64
GOOS=windows GOARCH=amd64 go build -o ffvpn.exe .           # Windows x86-64
GOOS=windows GOARCH=arm64 go build -o ffvpn-arm64.exe .     # Windows для ARM
GOOS=darwin  GOARCH=arm64 go build -o ffvpn-macos .         # Mac (Apple Silicon)
```

## Платформы (Windows и Mac)

После удаления режима профиля в клиенте нет вообще никакого кода,
зависящего от ОС; поведение на Windows и Mac полностью одинаково (команды
сборки — в разделе «Сборка»). Практические отличия на Windows:

- Путь к `signedInUser.json`:
  `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\signedInUser.json`
  (на Mac: `~/Library/Application Support/Firefox/Profiles/<profile>/`).
  Извлечение токена в PowerShell без jq:

  ```powershell
  (Get-Content "$env:APPDATA\Mozilla\Firefox\Profiles\xxxx.default-release\signedInUser.json" |
    ConvertFrom-Json).accountData.sessionToken
  ```

- Остановка программы — по Ctrl+C (`SIGTERM` в Windows отсутствует).
- Слушать на `127.0.0.1`, как правило, не вызывает срабатывания Windows
  Firewall; но если слушать на всех интерфейсах через
  `--socks 0.0.0.0:PORT`, скорее всего, один раз увидите запрос фейрвола.

## Запуск

Единственный способ аутентификации — передать `sessionToken` учётной записи
Firefox: 64-символьную hex-строку, которую Firefox хранит в открытом виде в
`signedInUser.json` активного профиля (поле `accountData.sessionToken`).
Извлеките его:

```sh
jq -r '.accountData.sessionToken' ~/.mozilla/firefox/xxxxxxxx.default-release/signedInUser.json
```

и передайте программе:

```sh
./ffvpn --session-token <64 hex>
```

Порт прослушивания по умолчанию — `127.0.0.1:1080`; чтобы изменить:

```sh
./ffvpn --session-token <64 hex> --socks 127.0.0.1:2080
```

Или HTTP CONNECT прокси вместо SOCKS5 — передача только `--http` отключает
прокси SOCKS по умолчанию (передача обоих = оба):

```sh
./ffvpn --session-token <64 hex> --http 127.0.0.1:9088
```

Без `--session-token` (и если не указан `--email`) программа не запустится.

> ⚠️ **Вход по email/паролю (`--email`) обычно не работает**: дата-центр
> api.accounts.firefox.com блокирует запросы `/account/login` от
> не браузерных клиентов кодом HTTP 406 (подтверждено живым тестом; с любым
> User-Agent, включая curl и PyFxA). Если вы видите `fxa: HTTP 406` — вы
> попали под этот фильтр; используйте `--session-token`. Остальная цепочка
> (session/status, OAuth, Guardian) из Go работает без проблем.

Успешный вывод должен выглядеть примерно так:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Using proxy edge: faor73.m1.fastly-masque.net:2499
Proxy pass valid until 2026-10-06T18:44:12Z
SOCKS5 proxy listening on 127.0.0.1:1080
```

Затем подключите любое приложение к `socks5://127.0.0.1:1080` (например, curl):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

> 💡 Путь к папке активного профиля Firefox (чтобы найти `signedInUser.json`
> и извлечь токен) виден в `about:profiles` (корень «Default Profile»). Если
> вы не вошли в аккаунт — сначала войдите в Firefox, чтобы создался
> `signedInUser.json`.

### Просмотр квоты (без запуска прокси)

Чтобы просто посмотреть, сколько из квоты пропускной способности израсходовано
— без поднятия локального прокси:

```sh
./ffvpn --usage --session-token <64 hex>
```

Вывод:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Bandwidth: 1.8 GiB of 10.0 GiB used (18%), 8.2 GiB left resets 2026-11-01
```

Эти данные берутся из заголовков `X-Quota-*` ответа Guardian (те же
заголовки, которые читает сам Firefox); дата «resets» — это когда
сбрасывается месячная квота.

### Список стран выхода

Список серверов берётся из публичной коллекции Remote Settings; для просмотра
доступных стран токен и аутентификация не нужны:

```sh
./ffvpn --list-countries
```

Только страны без премиум-блокировки (те, которые Firefox показывает
бесплатным пользователям):

```sh
./ffvpn --list-countries --free-only
```

Вывод:

```
Available exit countries (select with --country CODE):
  US   United States        4 servers, 2 cities
  CA   Canada               2 servers, 1 city
```

Затем выберите страну выхода через `--country CODE` (по умолчанию:
серверный anycast-подсказка). Число серверов учитывает только
некарантинные серверы; страна с «0 servers» недоступна для выбора, а при
недопустимом коде сообщение об ошибке перечислит разрешённые коды.

О флаге `(locked)`: это поле из самих данных списка серверов, и в исходниках
Firefox оно описано так: «эта страна заперта за набором предусловий». Панель
Firefox показывает locked-страны только премиум-пользователям — премиум
означает подписку Mozilla VPN, либо неограниченную пропускную способность,
либо Firefox в качестве браузера по умолчанию в системе — а для остальных
скрывает эти страны из списка выбора. Ядро прокси самого Firefox
(`getLocation`) не проверяет этот флаг при выборе сервера; ffvpn лишь
отображает его и ничего не блокирует на стороне клиента — последнее слово за
дата-центром (edge).

### Основные флаги

| Флаг | Описание |
|---|---|
| `--session-token HEX` | Токен сессии FxA — из `signedInUser.json` профиля Firefox (см. выше) |
| `--email` / `--password` | Интерактивный вход — обычно упирается в фильтр 406 (см. выше) |
| `--socks HOST:PORT` | Адрес локального SOCKS5 прокси (по умолчанию `127.0.0.1:1080`; пустая строка = отключено) |
| `--http HOST:PORT` | Локальный HTTP CONNECT прокси (по умолчанию выключен; передача только его отключает SOCKS по умолчанию) |
| `--usage` | Только показать использование квоты и выйти; локальный прокси не запускается |
| `--country XX` | Выбор страны выхода (по умолчанию: серверная anycast-подсказка; список: `--list-countries`) |
| `--server HOST:PORT` | Обход списка серверов и подключение к конкретному дата-центру |
| `--dial-proxy socks5://[user:pass@]H:P` | Доступ до дата-центра через другой SOCKS5 прокси (bootstrap-прокси; необязательный user/pass по RFC 1929) |
| `--sni NAME` | Имя SNI, отправляемое в ClientHello дата-центру (по умолчанию: имя домена дата-центра). Сертификат дата-центра всё равно проверяется по реальному имени дата-центра, а не NAME |
| `--guardian URL` | Другой сервер Guardian (для тестов) |
| `--list-countries` | Только показать страны выхода и выйти; аутентификация не нужна |
| `--free-only` | Вместе с `--list-countries`: скрыть премиум-locked страны |
| `--verbose` | Подробное логирование |

## Предупреждения по безопасности

- `sessionToken` эквивалентен «ключу аккаунта»: любой, у кого он есть, может
  получать OAuth-токены от вашего имени. Никогда никуда его не отправляйте, а
  после использования сбросить сессии можно выходом/входом в Firefox.
- Ваш трафик проходит через дата-центр Fastly/Mozilla; как и в самом Firefox,
  назначение (hostname) видно дата-центру в запросе CONNECT, но ваш локальный
  провайдер видит только TLS-соединение с `*.fastly-masque.net`.

## Тесты

```sh
go test ./...                                   # полный набор с мок-серверами
FFVPN_LIVE_TEST=1 go test -run TestLiveFetch -v ./internal/servers/   # живая загрузка списка серверов
```

Покрытие тестами:

- Криптография FxA (quickStretch v1/v2, authPW, вывод Bearer-ключа сессии)
  против независимо сгенерированных векторов (Python) плюс векторы RFC 5869
  и RFC 7914
- Полный поток OAuth (PKCE) и вход/TOTP против мок-сервера FxA
- Клиент Guardian (activate/token/ошибки 401/403/429/451 и заголовки квот)
- Разбор списка серверов (connect по умолчанию, карантин, явный протокол) +
  живой тест
- Туннель (TLS + CONNECT + Bearer) и локальные прокси + ротация токена в
  end-to-end тесте всего бинарника + режим `--usage`

Что здесь протестировать нельзя: реальные ответы FxA/Guardian с премиум
аккаунтом (подписка/регион). Логика обоих взята точно из исходников Firefox.

## Структура кода

```
main.go                     связывает всё вместе, ротация токена, флаги
internal/fxa/               вход FxA (v1/v2), TOTP, вывод ключей, OAuth/PKCE
internal/guardian/          клиент Guardian и ProxyPass/Usage
internal/servers/           список серверов из Remote Settings
internal/tunnel/            TLS + CONNECT с Bearer; опциональный socks5 dialer
internal/localproxy/        локальные SOCKS5 (RFC 1928) и HTTP CONNECT серверы
```

Референс реализации: модули `toolkit/components/ipprotection/` в исходниках
Firefox и эталонная библиотека PyFxA (Bearer-поток без Hawk согласно
ADR-0022).
