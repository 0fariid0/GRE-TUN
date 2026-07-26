# GRE-TUN — Tunnel Manager v9.1.0 Vira Stable

## نصب یا بروزرسانی مستقیم

```bash
bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh)
```

این نسخه مدیریت تونل‌های **Normal GRE**، **WireGuard**، **Vira7 Stable UDP-TUN** و فوروارد پورت با **HAProxy** را در یک فایل انجام می‌دهد.

> برای اجرای صحیح، دستور را با کاربر `root` روی هر دو سرور اجرا کنید.

---

## تغییرات مهم Vira در نسخه 9.1.0

مشکل اصلی نسخه قبلی این بود که Vira به‌صورت پیش‌فرض سمت ایران را `Server` و سمت خارج را `Client` می‌ساخت. روی بعضی سرورها یا دیتاسنترهای ایران، UDP ورودی محدود یا فیلتر می‌شود و در نتیجه Vira وصل نمی‌شد، در حالی که GRE همچنان کار می‌کرد.

در نسخه جدید:

- جهت پیشنهادی اتصال به `Iran Client → Kharej Server` تغییر کرده است.
- حالت قدیمی `Iran Server ← Kharej Client` همچنان برای سازگاری وجود دارد.
- پورت Vira هنگام بروزرسانی دیگر به‌صورت خودکار و ناخواسته تغییر نمی‌کند.
- پورت باید در هر دو سرور دقیقاً یکسان وارد شود.
- MTU پیش‌فرض از `1400` به `1280` کاهش یافته تا Fragment شدن بسته‌های UDP کمتر شود.
- Keepalive از 5 ثانیه به 3 ثانیه کاهش یافته است.
- در صورت نگرفتن پاسخ، سمت Client سوکت UDP را خودکار بازسازی می‌کند.
- Peer سمت Server بعد از Timeout پاک می‌شود و اتصال تازه را دوباره می‌پذیرد.
- Peer به IP عمومی تعریف‌شده قفل می‌شود تا بسته ناشناس جای Peer اصلی را نگیرد.
- بافرهای UDP، صف شبکه و `rp_filter` به‌صورت خودکار برای Vira تنظیم می‌شوند.
- فایل کانفیگ قبلی قبل از آپدیت با پسوند `.last-good` نگه داشته می‌شود.
- اگر سرویس جدید بالا نیاید، اسکریپت تلاش می‌کند کانفیگ قبلی را بازیابی کند.
- آمار TX/RX/Drop/Reconnect و زمان آخرین دریافت در `/run` ثبت می‌شود.
- گزینه تشخیص وضعیت، سوکت، Ping و لاگ Vira به منوی اصلی اضافه شده است.

---

## روش صحیح ساخت یا بروزرسانی Vira

روی هر دو سرور دستور نصب بالای صفحه را اجرا کنید و سپس وارد مسیر زیر شوید:

```text
1) create/update tunnel
3) Vira7 Stable UDP-TUN tunnel
```

### سرور ایران

```text
Server role: 1) Iran
Connection direction: 1) Recommended
Mode نهایی: Client
Tunnel IP: 10.71.N.1
```

### سرور خارج

```text
Server role: 2) Kharej
Connection direction: 1) Recommended
Mode نهایی: Server
Tunnel IP: 10.71.N.2
```

در هر دو سمت موارد زیر باید یکسان باشند:

- شماره تونل `N`
- پورت UDP
- MTU
- گزینه Connection direction

IP عمومی Remote در هر سمت باید IP عمومی سرور مقابل باشد.

### نمونه تونل شماره 8

| مورد | ایران | خارج |
|---|---|---|
| Role | `1` | `2` |
| Direction | `1 - Recommended` | `1 - Recommended` |
| Mode | `client` | `server` |
| Interface | `vira78` | `vira78` |
| Tunnel IP | `10.71.8.1` | `10.71.8.2` |
| Remote tunnel IP | `10.71.8.2` | `10.71.8.1` |
| UDP port | مثلاً `5579` | دقیقاً `5579` |
| MTU | `1280` | `1280` |

---

## انتخاب پورت Vira

پورت پیش‌فرض از فرمول زیر ساخته می‌شود:

```text
5571 + Tunnel Number
```

برای مثال:

```text
Tunnel 1  -> UDP 5572
Tunnel 8  -> UDP 5579
Tunnel 79 -> UDP 5650
```

اگر پورت پیش‌فرض روی یک دیتاسنتر فیلتر بود، می‌توانید در هر دو سمت یک پورت دیگر مانند موارد زیر را امتحان کنید:

```text
443/UDP
53/UDP
8443/UDP
2087/UDP
```

پورت انتخابی باید در هر دو سرور یکسان باشد و توسط سرویس دیگری استفاده نشود. پورت `443/UDP` ممکن است با QUIC، پنل یا سرویس‌های دیگر تداخل داشته باشد؛ قبل از انتخاب آن وضعیت پورت را بررسی کنید.

```bash
ss -lunp | grep ':443 '
```

---

## بروزرسانی Viraهای قدیمی

برای تغییر Vira قدیمی به حالت پایدار جدید، این کار را روی **هر دو سرور** انجام دهید:

1. دستور نصب بالای README را اجرا کنید.
2. گزینه `create/update tunnel` را انتخاب کنید.
3. نوع `Vira7 Stable UDP-TUN` را انتخاب کنید.
4. همان شماره تونل قبلی را وارد کنید.
5. در هر دو سمت گزینه Direction شماره `1` را انتخاب کنید.
6. در هر دو سمت دقیقاً یک پورت یکسان وارد کنید.
7. MTU را روی `1280` قرار دهید.
8. ابتدا سمت خارج و بعد سمت ایران را بروزرسانی کنید.
9. از منوی `Vira7 diagnostics / logs` اتصال را بررسی کنید.

هنگام تغییر Direction، تا زمانی که هر دو سمت بروزرسانی نشده باشند تونل ممکن است موقتاً قطع باشد.

---

## منوی اصلی

```text
1) create/update tunnel
2) remove tunnel
3) reset all tunnels
4) ping test tunnels
5) haproxy port manager
6) optimize Vira7 CPU
7) Vira7 diagnostics / logs
0) Exit
```

---

## بررسی وضعیت Vira

از داخل اسکریپت گزینه زیر را انتخاب کنید:

```text
7) Vira7 diagnostics / logs
```

این بخش موارد زیر را نمایش می‌دهد:

- وضعیت سرویس systemd
- فعال یا غیرفعال بودن Interface
- IP و پورت Public
- IP داخلی تونل
- UDP Listener
- Peer شناسایی‌شده
- زمان آخرین بسته دریافتی
- تعداد TX، RX، Drop و Reconnect
- Ping سمت مقابل
- آخرین لاگ‌های سرویس

دستورات دستی:

```bash
systemctl status vira7-tunnel@1 --no-pager -l
journalctl -u vira7-tunnel@1 -n 100 --no-pager
ip -br addr show vira71
ss -lunp | grep vira7-engine
cat /run/vira7-vira71.stats
ping -c 4 10.71.1.2
```

عدد `1` را با شماره تونل خودتان عوض کنید.

---

## فایل‌ها و سرویس‌های Vira

```text
Config directory : /etc/vira7-tunnels
Engine source    : /etc/vira7-tunnels/vira7_engine.c
Engine binary    : /usr/local/bin/vira7-engine
Manager binary   : /usr/local/bin/gretun-manager.sh
Service template : /etc/systemd/system/vira7-tunnel@.service
Kernel tuning    : /etc/sysctl.d/99-vira7-stable.conf
Runtime stats    : /run/vira7-vira7N.stats
```

نمونه برای تونل شماره 8:

```text
/etc/vira7-tunnels/tunnel-8.conf
vira7-tunnel@8.service
vira78
/run/vira7-vira78.stats
```

---

## دستورات مدیریت سرویس

برای تونل شماره 8:

```bash
systemctl restart vira7-tunnel@8
systemctl stop vira7-tunnel@8
systemctl start vira7-tunnel@8
systemctl status vira7-tunnel@8 --no-pager -l
journalctl -u vira7-tunnel@8 -f
```

---

## رنج IP تونل‌ها

| نوع تونل | Interface | رنج IP |
|---|---|---|
| Normal GRE | `greN` | `10.10.N.1/30` و `10.10.N.2/30` |
| WireGuard | `wgtunN` | `10.20.N.1/30` و `10.20.N.2/30` |
| Vira7 Stable | `vira7N` | `10.71.N.1` و `10.71.N.2` |

شماره تونل باید بین `1` تا `254` باشد.

---

## استفاده از Vira برای HAProxy

بعد از وصل شدن Vira، در سمت ایران می‌توانید IP داخلی سمت خارج را به‌عنوان Target قرار دهید.

برای تونل شماره 8:

```text
Target IP سمت ایران: 10.71.8.2
```

در سمت خارج، IP داخلی ایران:

```text
10.71.8.1
```

قبل از افزودن پورت به HAProxy، Ping را بررسی کنید:

```bash
ping -c 4 10.71.8.2
```

---

## حالت Optimize CPU

گزینه 6 دو حالت دارد:

```text
1) Safe low CPU mode
2) Fast low CPU mode
```

حالت Safe پیشنهاد می‌شود. حالت Fast تولید checksum داخلی Vira را خاموش می‌کند و باید روی هر دو سرور یک تونل اعمال شود. UDP checksum سیستم‌عامل همچنان وجود دارد، اما برای بیشترین سازگاری ابتدا حالت Safe را استفاده کنید.

---

## نکات رفع مشکل

### Interface ساخته شده ولی Ping ندارید

موارد زیر را بررسی کنید:

```bash
systemctl status vira7-tunnel@N --no-pager -l
journalctl -u vira7-tunnel@N -n 100 --no-pager
ss -lunp | grep ':PORT '
cat /run/vira7-vira7N.stats
```

سپس مطمئن شوید:

- شماره تونل دو سمت یکی است.
- پورت UDP دو سمت یکی است.
- Direction دو سمت روی گزینه 1 است.
- ایران نقش 1 و خارج نقش 2 دارد.
- Remote Public IP اشتباه وارد نشده است.
- پورت UDP در فایروال دیتاسنتر یا پنل VPS باز است.
- سرویس دیگری پورت را نگرفته است.

### سرویس فعال است ولی RX صفر می‌ماند

اگر `tx_packets` افزایش دارد ولی `rx_packets` صفر است، معمولاً UDP بین دو سرور عبور نمی‌کند یا IP/Port سمت مقابل اشتباه است. یک پورت دیگر را در هر دو سمت امتحان کنید.

### GRE کار می‌کند ولی Vira نه

GRE از پروتکل IP شماره 47 استفاده می‌کند، اما Vira روی UDP اجرا می‌شود. ممکن است دیتاسنتر GRE را عبور دهد ولی UDP ورودی یا یک پورت خاص را محدود کند. جهت پیشنهادی جدید باعث می‌شود اتصال از ایران به‌صورت UDP خروجی آغاز شود؛ با این حال اگر کل UDP در مسیر مسدود باشد، Vira روی آن مسیر قابل استفاده نخواهد بود و باید از GRE یا روش جایگزین استفاده شود.

---

## بکاپ دستی قبل از تغییرات

```bash
BACKUP="/root/gre-tun-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a /etc/gre-tunnels "$BACKUP/" 2>/dev/null || true
cp -a /etc/wgtun-tunnels "$BACKUP/" 2>/dev/null || true
cp -a /etc/wireguard "$BACKUP/" 2>/dev/null || true
cp -a /etc/vira7-tunnels "$BACKUP/" 2>/dev/null || true
cp -a /usr/local/bin/gretun-manager.sh "$BACKUP/" 2>/dev/null || true
```

---

## تست‌های انجام‌شده روی فایل تحویلی

- بررسی Syntax اسکریپت با `bash -n`
- استخراج و کامپایل موتور C با `-Wall -Wextra -Werror`
- تست ذخیره و بارگذاری مجدد کانفیگ Vira
- تست جلوگیری از باقی‌ماندن متغیرهای تونل قبلی در تونل بعدی
- تست نگاشت Role و Direction در حالت Recommended و Legacy
- بررسی یکسان بودن فرمول IP و پورت در هر دو سمت

تست نهایی عبور ترافیک واقعی باید روی دو VPS انجام شود، چون وضعیت UDP و فایروال هر دیتاسنتر متفاوت است.
