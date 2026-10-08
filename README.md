# ffvpn — کلاینت گو برای وی‌پی‌ان داخلی فایرفاکس

`ffvpn` یک کلاینت مستقل به زبان Go برای **IP Protection** (وی‌پی‌ان داخلی مرورگر
فایرفاکس، مبتنی بر Mozilla VPN) است. با حساب Firefox Account شما وارد سرویس
Guardian می‌شود، توکن‌های کوتاه‌عمر «ProxyPass» می‌گیرد و تونل همان لبه‌ی
پروکسی که فایرفاکس استفاده می‌کند را به‌صورت یک **پروکسی محلی SOCKS5 / HTTP
CONNECT** در اختیار هر برنامه‌ای می‌گذارد.

> ⚠️ **پیش‌نیاز سمت سرور (دور زدنی نیست):** Guardian سرویس را فقط به حساب‌هایی
> که اشتراک Mozilla VPN دارند (`403` در غیر این صورت) و در منطقه‌ی مجاز هستند
> (`451` برای مناطق غیرمجاز) سرویس می‌دهد. این چک‌ها همه سروری‌اند؛ این کلاینت
> فقط همان درخواست‌هایی را می‌زند که خود فایرفاکس می‌زند. استفاده با کلاینت
> غیررسمی می‌تواند مغایر شرایط استفاده از Mozilla VPN باشد و ریسک محدود شدن
> حساب دارد.

## معماری (برگرفته از سورس فایرفاکس 157)

```
برنامه شما ──► پروکسی محلی SOCKS5/HTTP (127.0.0.1)
                    │
                    ▼
        TLS + HTTP CONNECT با هدر
        Proxy-Authorization: Bearer <JWT>     ──►  *.m1.fastly-masque.net:2499
                    │
                    ▼
            اینترنت (خروجی از کشور انتخابی)
```

- **لیست سرورها**: کالکشن عمومی Remote Settings با نام `vpn-serverlist`
  (بدون احراز هویت).
- **احراز هویت**: `sessionToken` حساب Firefox Account → توکن OAuth با
  scopeهای `profile` و
  `https://identity.mozilla.com/apps/vpn` (همان client_id دسکتاپ فایرفاکس:
  `5882386c6d801776`) → API های Guardian روی `https://vpn.mozilla.org`
  (مقدار pref واقعی فایرفاکس؛ دامنهٔ `.com` که در فال‌بک JS هست اصلاً رزولو
  نمی‌شود):
  - `POST /api/v1/fpn/activate` — فعال‌سازی و دریافت entitlement
  - `GET  /api/v1/fpn/token` — دریافت JWT کوتاه‌عمر (چرخش ۲ دقیقه قبل از انقضا)
  - هدرهای `X-Quota-*` — مصرف پهنای باند
- **تونل**: در رکوردهای فعلی هیچ `protocols` ثبت نشده، پس طبق منطق
  `IPPChannelFilter.sys.mjs` فایرفاکس، پروتکل پیش‌فرض همان CONNECT روی TLS است
  و نام میزبان توسط لبه حل می‌شود (معادل `TRANSPARENT_PROXY_RESOLVES_HOST`).

## بیلد

نیازمندی: [Go](https://go.dev) 1.24+ (کلاینت Go خالص و بدون CGO است؛ هیچ
وابستگی خارجی به‌جز خود Go لازم نیست).

بیلد روی خود سیستم‌عامل هدف:

```sh
# لینوکس
go build -o ffvpn .

# ویندوز (PowerShell یا cmd)
go build -o ffvpn.exe .
```

کراس‌کامپایل از لینوکس — چون هیچ وابستگی پلتفرمی و CGO در کار نیست، بدون
هیچ تنظیم اضافه‌ای کار می‌کند:

```sh
GOOS=linux   GOARCH=amd64 go build -o ffvpn .               # لینوکس x86-64
GOOS=windows GOARCH=amd64 go build -o ffvpn.exe .           # ویندوز x86-64
GOOS=windows GOARCH=arm64 go build -o ffvpn-arm64.exe .     # ویندوز on ARM
GOOS=darwin  GOARCH=arm64 go build -o ffvpn-macos .         # مک (Apple Silicon)
```

## پلتفرم‌ها (ویندوز و مک)

این کلاینت بعد از حذف حالت پروفایل، هیچ کد وابسته به سیستم‌عامل ندارد؛ روی
ویندوز و مک هم دقیقاً همین رفتار را دارد (دستورهای بیلد در بخش «بیلد»).
تفاوت‌های عملی در ویندوز:

- مسیر `signedInUser.json`:
  `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\signedInUser.json`
  (در مک: `~/Library/Application Support/Firefox/Profiles/<profile>/`). استخراج
  توکن در PowerShell، بدون نیاز به jq:

  ```powershell
  (Get-Content "$env:APPDATA\Mozilla\Firefox\Profiles\xxxx.default-release\signedInUser.json" |
    ConvertFrom-Json).accountData.sessionToken
  ```

- توقف برنامه با Ctrl+C است (`SIGTERM` در ویندوز وجود ندارد).
- گوش دادن روی `127.0.0.1` معمولاً Windows Firewall را درگیر نمی‌کند؛ ولی اگر
  با `--socks 0.0.0.0:PORT` روی همهٔ اینترفیس‌ها گوش دهید، احتمالاً یک بار
  پرامپت فایروال می‌بینید.

## اجرا

تنها راه احراز هویت پاس دادن `sessionToken` حساب Firefox Account است — رشتهٔ
۶۴ کاراکتری هگز که فایرفاکس به‌صورت متن ساده در `signedInUser.json` پروفایلِ
فعال ذخیره می‌کند (فیلد `accountData.sessionToken`). آن را استخراج کنید:

```sh
jq -r '.accountData.sessionToken' ~/.mozilla/firefox/xxxxxxxx.default-release/signedInUser.json
```

و به برنامه بدهید:

```sh
./ffvpn --session-token <64 hex>
```

پورت گوش دادن پیش‌فرض `127.0.0.1:1080` است؛ برای تغییر:

```sh
./ffvpn --session-token <64 hex> --socks 127.0.0.1:2080
```

یا پروکسی HTTP CONNECT به‌جای SOCKS5 — دادن `--http` به‌تنهایی، پیش‌فرض
SOCKS را غیرفعال می‌کند (هر دو با هم = هر دو):

```sh
./ffvpn --session-token <64 hex> --http 127.0.0.1:9088
```

بدون `--session-token` (و مگر با `--email`) برنامه اجرا نمی‌شود.

> ⚠️ **ورود با ایمیل/پسورد (`--email`) معمولاً کار نمی‌کند**: لبه‌ی
> api.accounts.firefox.com درخواست‌های `/account/login` کلاینت‌های
> غیرمرورگر را با HTTP 406 بلاک می‌کند (تأییدشده با تست زنده؛ با هر
> User-Agent‌ای، حتی curl و PyFxA). اگر خطای `fxa: HTTP 406` دیدید یعنی به
> این فیلتر خورده‌اید؛ از `--session-token` استفاده کنید. بقیه‌ی زنجیره
> (session/status، OAuth، Guardian) بدون مشکل از Go کار می‌کنند.

خروجی موفق باید چیزی شبیه این باشد:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Using proxy edge: faor73.m1.fastly-masque.net:2499
Proxy pass valid until 2026-10-06T18:44:12Z
SOCKS5 proxy listening on 127.0.0.1:1080
```

سپس هر برنامه‌ای را به `socks5://127.0.0.1:1080` وصل کنید (مثلاً curl):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

> 💡 مسیر پوشهٔ پروفایل فعال فایرفاکس (برای پیدا کردن `signedInUser.json` و
> استخراج توکن) را می‌توانید در `about:profiles` (ریشهٔ «Default Profile»)
> ببینید. اگر لاگین نباید، اول در خود فایرفاکس وارد حساب شوید تا
> `signedInUser.json` ساخته شود.

### مشاهدهٔ مصرف سهمیه (بدون اجرای پروکسی)

برای اینکه فقط ببینید چقدر از سهمیهٔ پهنای باند مصرف شده — بدون بالا آمدن
پروکسی محلی:

```sh
./ffvpn --usage --session-token <64 hex>
```

خروجی:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Bandwidth: 1.8 GiB of 10.0 GiB used (18%), 8.2 GiB left resets 2026-11-01
```

این اطلاعات از هدرهای `X-Quota-*` پاسخ Guardian می‌آید (همان هدرهایی که خود
فایرفاکس هم می‌خواند)؛ تاریخ «resets» مُدِ ریست شدن سهمیهٔ ماهانه است.

### فهرست کشورهای خروجی

لیست سرورها از یک کالکشن عمومی Remote Settings می‌آید؛ برای دیدن کشورهای
موجود نیازی به توکن و احراز هویت نیست:

```sh
./ffvpn --list-countries
```

فقط کشورهای بدون قفل premium (همان‌هایی که فایرفاکس به کاربران رایگان نشان
می‌دهد):

```sh
./ffvpn --list-countries --free-only
```

خروجی:

```
Available exit countries (select with --country CODE):
  US   United States        4 servers, 2 cities
  CA   Canada               2 servers, 1 city
```

سپس کشور خروجی را با `--country CODE` انتخاب کنید (پیش‌فرض: anycast
پیشنهادی سمت سرور). تعداد سرورها فقط موارد غیرقرنطینه را می‌شمارد؛ کشوری
که «0 servers» نشان می‌دهد قابل انتخاب نیست و اگر کد نامعتبری بدهید، فهرست
کدهای مجاز در پیام خطا می‌آید.

دربارهٔ پرچم `(locked)`: این فیلد از خود داده‌های لیست سرور می‌آید و در سورس
فایرفاکس چنین توضیح داده شده: «این کشور پشت مجموعه‌ای از پیش‌شرط‌ها قفل
است». پنل فایرفاکس کشورهای locked را فقط به کاربران premium نشان می‌دهد —
premium یعنی اشتراک Mozilla VPN دارد، یا پهنای باندش نامحدود است، یا
فایرفاکس مرورگر پیش‌فرض سیستم است — و برای بقیه، این کشورها را از فهرست
انتخاب حذف می‌کند. هستهٔ پروکسی فایرفاکس (`getLocation`) این پرچم را هنگام
انتخاب سرور چک نمی‌کند؛ ffvpn هم فقط نمایشش می‌دهد و سمت کلاینت چیزی را
بلاک نمی‌کند — حرف آخر را لبهٔ سرور می‌زند.

### فلگ‌های مهم

| فلگ | توضیح |
|---|---|
| `--session-token HEX` | توکن نشست FxA — از `signedInUser.json` پروفایل فایرفاکس (بالا را ببینید) |
| `--email` / `--password` | ورود تعاملی — معمولاً با فیلتر لبه‌ای 406 مواجه می‌شود (بالا را ببینید) |
| `--socks HOST:PORT` | آدرس پروکسی SOCKS5 محلی (پیش‌فرض `127.0.0.1:1080`؛ رشتهٔ خالی = غیرفعال) |
| `--http HOST:PORT` | پروکسی HTTP CONNECT محلی (پیش‌فرض غیرفعال؛ دادن تنها آن، پیش‌فرض SOCKS را غیرفعال می‌کند) |
| `--usage` | فقط نمایش مصرف سهمیه و خروج؛ پروکسی محلی بالا نمی‌آید |
| `--country XX` | انتخاب کشور خروجی (پیش‌فرض: anycast پیشنهادی؛ فهرست: `--list-countries`) |
| `--server HOST:PORT` | رد شدن از لیست سرور و اتصال به یک لبه مشخص |
| `--dial-proxy socks5://[user:pass@]H:P` | رسیدن به لبه از طریق یک SOCKS5 دیگر (پروکسی بوت‌استرپ؛ با نام کاربر/گذرواژهٔ اختیاری RFC 1929) |
| `--sni NAME` | نام SNI ارسالی در ClientHello به لبه (پیش‌فرض: نام دامنهٔ لبه). گواهی لبه همچنان بر اساس نام واقعی لبه اعتبارسنجی می‌شود، نه NAME |
| `--guardian URL` | تغییر سرور Guardian (برای تست) |
| `--list-countries` | فقط نمایش کشورهای خروجی و خروج؛ بدون نیاز به احراز هویت |
| `--free-only` | همراه با `--list-countries`: حذف کشورهای قفل‌شدهٔ premium |
| `--verbose` | لاگ پرجزئیات |

## هشدار امنیتی

- `sessionToken` معادل «کلید حساب» است: هرکس آن را داشته باشد می‌تواند به نام
  شما توکن OAuth بسازد. آن را به هیچ‌جا نفرستید و بعد از استفاده، با
  خروج/ورود مجدد در فایرفاکس می‌توانید نشست‌ها را بازنشانی کنید.
- ترافیک شما از لبه‌ی Fastly/Mozilla عبور می‌کند؛ مشابه خود فایرفاکس، مقصد
  (hostname) در درخواست CONNECT برای لبه قابل مشاهده است ولی برای ISP محلی فقط
  یک TLS به `*.fastly-masque.net` دیده می‌شود.

## تست‌ها

```sh
go test ./...                                   # تست کامل با سرورهای جعلی
FFVPN_LIVE_TEST=1 go test -run TestLiveFetch -v ./internal/servers/   # دریافت زندهٔ لیست سرورها
```

پوشش تست:

- رمزنگاری FxA (quickStretch v1/v2، authPW، مشتق Bearer session) در برابر
  وکتورهای مستقل تولیدشده با Python + وکتورهای RFC 5869 و RFC 7914
- جریان کامل OAuth (PKCE) و ورود/TOTP در برابر سرور جعلی FxA
- کلاینت Guardian (activate/token/خطاهای 401/403/429/451 و هدرهای سهمیه)
- تجزیهٔ لیست سرور (پیش‌فرض connect، قرنطینه، پروتکل صریح) + تست زنده
- تونل (TLS + CONNECT + Bearer) و پروکسی‌های محلی + چرخش توکن در تست
  انتها-به-انتهای کل باینری + حالت `--usage`

آنچه اینجا قابل تست نیست: پاسخ‌های واقعی FxA/Guardian با حساب پریمیوم
(اشتراک/منطقه). منطق هر دو دقیقاً از سورس فایرفاکس برداشت شده است.

## ساختار کد

```
main.go                     اتصال همه اجزا، چرخش توکن، فلگ‌ها
internal/fxa/               ورود FxA (v1/v2)، TOTP، مشتق کلیدها، OAuth/PKCE
internal/guardian/          کلاینت Guardian و ProxyPass/Usage
internal/servers/           لیست سرورها از Remote Settings
internal/tunnel/            TLS + CONNECT با Bearer؛ dialer اختیاری socks5
internal/localproxy/        سرور SOCKS5 (RFC 1928) و HTTP CONNECT محلی
```

مرجع پیاده‌سازی: ماژول‌های `toolkit/components/ipprotection/` در سورس
فایرفاکس و کتابخانهٔ مرجع PyFxA (جریان Bearer بدون Hawk مطابق ADR-0022).
