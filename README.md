# نصب سریع GRE-TUN v10.0.0

```bash
bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh)
```

> فایل `GRETUN.sh` داخل مخزن باید با نسخه v10.0.0 جایگزین شود تا همین دستور، نسخه جدید را نصب کند.

# GRE-TUN Manager v10.0.0 — Vira Hybrid

این نسخه شامل مدیریت تونل‌های زیر است:

- GRE
- WireGuard
- Vira Hybrid جدید
- HAProxy Port Forward

بخش GRE دست‌نخورده باقی مانده است. موتور قبلی Vira حذف و از ابتدا بازنویسی شده است.

## مهم‌ترین تغییر Vira

Vira قبلی فقط از UDP استفاده می‌کرد. در بعضی سرورها ممکن بود سرویس و رابط TUN بالا باشند، اما handshake به دلایل زیر کامل نشود:

- محدودیت یا فیلتر UDP در دیتاسنتر
- NAT یا تغییر پورت مبدأ
- مسدود بودن UDP برگشتی
- وجود DROP قبل از قانون ACCEPT در iptables
- قفل شدن سرور روی یک نشست UDP نیمه‌کاره
- اشغال بودن پورت یا اشتباه بودن جهت Client و Server

Vira Hybrid جدید در حالت `auto` ابتدا UDP را امتحان می‌کند و در صورت برقرار نشدن handshake، به‌صورت خودکار روی همان شماره پورت از TCP استفاده می‌کند.

## معماری Vira Hybrid

- جهت پیشنهادی: `Iran Client -> Kharej Server`
- UDP مبدأ سمت Client: پورت آزاد و موقت سیستم
- UDP مقصد سمت Server: پورت انتخابی شما
- TCP fallback: همان شماره پورت، ولی پروتکل TCP
- CRC32 برای تشخیص فریم خراب
- شناسه Tunnel و Cookie برای جلوگیری از قاطی شدن تونل‌ها
- HELLO / ACK / PING / PONG اختصاصی
- بازیابی خودکار بعد از timeout
- جایگزینی نشست UDP نیمه‌کاره با TCP
- آمار جداگانه UDP و TCP
- تست داخلی موتور قبل از نصب باینری

Vira Hybrid رمزنگاری انجام نمی‌دهد. `auth_key` موجود در فایل کانفیگ برای تطبیق نشست و جلوگیری از اتصال تصادفی تونل‌های دیگر است، نه رمزنگاری ترافیک.

## راه‌اندازی پیشنهادی

بهتر است ابتدا سرور خارج و سپس سرور ایران را تنظیم کنید.

روی هر دو سرور دستور نصب را اجرا کنید:

```bash
bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh)
```

سپس از منوی اصلی وارد شوید:

```text
1) create/update tunnel
3) Vira Hybrid auto UDP/TCP tunnel
```

### تنظیم سرور خارج

```text
Server role: Kharej
Direction: Recommended
Transport: Auto Hybrid
```

در حالت پیشنهادی، سرور خارج نقش Server را دارد و روی پورت انتخابی، UDP و TCP را هم‌زمان گوش می‌دهد.

### تنظیم سرور ایران

```text
Server role: Iran
Direction: Recommended
Transport: Auto Hybrid
```

سرور ایران نقش Client را دارد. ابتدا UDP را امتحان می‌کند و اگر پاسخ نگیرد، خودکار به TCP می‌رود.

## مقادیر لازم در دو سمت

این موارد باید در هر دو سرور یکسان باشند:

- شماره Tunnel
- شماره Port
- Direction
- Transport Profile

IP عمومی Local و Remote باید متناسب با هر سرور برعکس یکدیگر وارد شوند.

مثال:

```text
Tunnel number: 1
Port: 5572
MTU: 1280
Direction: Recommended
Transport: Auto Hybrid
```

آدرس‌های داخلی به‌صورت خودکار ساخته می‌شوند:

```text
Iran:   10.71.1.1
Kharej: 10.71.1.2
```

## انتخاب پورت

در سرور سمت Server، شماره انتخابی باید برای هر دو مورد آزاد باشد:

```text
UDP <port>
TCP <port>
```

TCP و UDP می‌توانند یک شماره یکسان داشته باشند، چون دو پروتکل جدا هستند؛ اما اگر برنامه دیگری قبلاً TCP همان پورت را گرفته باشد، fallback قابل اجرا نیست.

برای بررسی پورت، مثال پورت `5572`:

```bash
ss -lunp | grep ':5572 '
ss -ltnp | grep ':5572 '
```

پورت‌های عمومی مانند `443` فقط زمانی قابل استفاده‌اند که سرویس دیگری مثل Xray، Nginx یا HAProxy روی TCP آن پورت فعال نباشد.

## حالت‌های Transport

### Auto Hybrid

حالت پیشنهادی:

```text
UDP preferred -> TCP fallback
```

### UDP only

برای سرورهایی که UDP بدون محدودیت کار می‌کند و کمترین سربار مدنظر است.

### TCP only

برای مسیرهایی که UDP به‌طور کامل فیلتر است یا پاسخ UDP برگشتی وجود ندارد.

از منوی زیر می‌توان حالت تونل موجود را تغییر داد:

```text
6) change Vira transport profile
```

## دستورات سرویس

برای Tunnel شماره 1:

```bash
systemctl status vira7-tunnel@1.service --no-pager -l
systemctl restart vira7-tunnel@1.service
systemctl stop vira7-tunnel@1.service
systemctl start vira7-tunnel@1.service
journalctl -u vira7-tunnel@1.service -n 100 --no-pager
```

## مشاهده آمار اتصال

```bash
cat /run/vira7-vira71.stats
```

نمونه خروجی:

```text
engine=10.0.0
mode=client
transport_mode=auto
active_transport=udp
connected=1
peer=203.0.113.20:5572
fallback_count=0
udp_handshakes=1
tcp_handshakes=0
```

اگر UDP برقرار نشود و TCP جایگزین شود:

```text
active_transport=tcp
fallback_count=1
tcp_handshakes=1
```

## عیب‌یابی از منو

```text
7) Vira Hybrid diagnostics / logs
```

این بخش موارد زیر را نمایش می‌دهد:

- نسخه Engine
- وضعیت systemd
- رابط TUN
- حالت Transport
- TCP listener یا connection
- UDP listener یا socket
- آخرین زمان دریافت بسته
- تعداد handshakeهای UDP و TCP
- تعداد fallback و reconnect
- لاگ‌های اخیر سرویس
- Ping آدرس داخلی طرف مقابل

## تست دستی تونل

از ایران، برای Tunnel شماره 1:

```bash
ping -c 4 10.71.1.2
```

از خارج:

```bash
ping -c 4 10.71.1.1
```

## فایل‌های Vira

```text
/etc/vira7-tunnels/tunnel-1.conf
/etc/vira7-tunnels/vira7_engine.c
/usr/local/bin/vira7-engine
/etc/systemd/system/vira7-tunnel@.service
/run/vira7-vira71.stats
```

## مهاجرت از Vira قبلی

نسخه جدید با فایل‌های قدیمی سازگار است، اما برای ساخت کامل کانفیگ v10 بهتر است روی هر دو سرور مجدداً از مسیر زیر همان Tunnel را Update کنید:

```text
1) create/update tunnel
3) Vira Hybrid auto UDP/TCP tunnel
```

پیشنهاد:

1. ابتدا سرور خارج را Update کنید.
2. سپس سرور ایران را Update کنید.
3. روی هر دو سمت `Recommended` و `Auto Hybrid` را انتخاب کنید.
4. شماره Tunnel و Port دقیقاً یکسان باشد.
5. MTU را روی `1280` بگذارید.

## بررسی مستقیم موتور

```bash
/usr/local/bin/vira7-engine --version
/usr/local/bin/vira7-engine --self-test
/usr/local/bin/vira7-engine --check-config /etc/vira7-tunnels/tunnel-1.conf
```

## فایروال

اسکریپت قوانین UDP و TCP را برای پورت Vira در ابتدای chain قرار می‌دهد تا قوانین DROP قبلی مانع آن نشوند.

برای مشاهده قوانین:

```bash
iptables -S INPUT
iptables -S OUTPUT
iptables -S FORWARD
```

اگر فایروال خود دیتاسنتر یا پنل VPS فعال است، پورت انتخابی را در آنجا نیز برای هر دو پروتکل باز کنید:

```text
TCP
UDP
```

## محدودیت واقعی

هیچ پروتکلی نمی‌تواند اتصال را در حالتی تضمین کند که هر دو مسیر UDP و TCP، پورت انتخابی، یا ترافیک بین دو IP در سطح دیتاسنتر مسدود شده باشد. حالت Auto Hybrid بیشترین پوشش را برای مشکلات رایج UDP، NAT و مسیر یک‌طرفه ایجاد می‌کند؛ اگر هر دو پروتکل بسته باشند باید پورت یا دیتاسنتر تغییر کند.

## بروزرسانی فایل مخزن

فایل‌های زیر را در شاخه `main` جایگزین کنید:

```text
GRETUN.sh
README.md
CHANGELOG.md
```

بعد از جایگزینی، همان دستور ابتدای README نسخه جدید را اجرا می‌کند.
