# GRE-TUN Multi Tunnel Manager

اسکریپت مدیریت چندتونله برای ساخت، بررسی و حذف دو نوع تونل روی لینوکس:

1. **Normal GRE Tunnel**، همان نسخه قبلی/فعلی با پشتیبانی چندتونله
2. **WireGuard Tunnel**، نسخه امن‌تر با رمزنگاری و فایل‌ها/نام‌ها/IP جدا

این نسخه طوری طراحی شده که GRE و WireGuard هیچ تداخلی با هم نداشته باشند؛ نه در اسم اینترفیس، نه در رنج IP، نه در فایل کانفیگ، نه در سرویس systemd.

---

## نصب و اجرا

```bash
chmod +x GRETUN.sh
sudo ./GRETUN.sh
```

یا اگر فایل را روی سرور آپلود کرده‌اید:

```bash
sudo bash GRETUN.sh
```

> اسکریپت باید با دسترسی root اجرا شود.

---

## قابلیت‌های اصلی

- نمایش IP پابلیک همین سرور بالای تمام منوهای مهم
- ساخت چند تونل GRE روی یک سرور
- ساخت چند تونل WireGuard روی یک سرور
- قابلیت v5/v6: اگر GRE همین شماره فعال و قابل ping باشد، WireGuard به‌صورت خودکار از داخل GRE عبور می‌کند تا در صورت بسته بودن UDP/WireGuard روی اینترنت شانس اتصال بیشتر شود
- جدا بودن کامل GRE و WireGuard از نظر نام و IP و فایل
- پشتیبانی از سناریوی چند سرور به یک سرور یا برعکس
- ساخت سرویس systemd جدا برای هر GRE tunnel و فعال‌سازی خودکار برای بوت
- استفاده از سرویس استاندارد `wg-quick@...` برای هر WireGuard tunnel بدون اجرای دوباره و تداخل با `wg-quick up`
- اصلاح حالت pending برای WireGuard: اگر کلید طرف مقابل آماده نباشد، تونل fail نمی‌شود؛ فقط ذخیره می‌شود تا بعداً کامل شود
- پاک‌سازی خودکار public key هنگام کپی‌پیست: فاصله، Enter، و حتی خط کامل `PublicKey = ...` قابل قبول است
- حذف مرحله‌ای: اول انتخاب نوع تونل، بعد نمایش لیست، بعد زدن شماره تونل برای حذف
- عدم تغییر default route
- عدم دستکاری SSH
- فعال‌سازی IP forwarding
- باز کردن rule فایروال برای همان تونل
- سوال‌های کمتر هنگام ساخت: پورت WireGuard، endpoint در حالت GRE، AllowedIPs، ذخیره کانفیگ و فعال‌سازی سرویس به‌صورت خودکار انجام می‌شود
- قابلیت v6: اگر سرور چند IPv4 داشته باشد، هنگام نصب از شما Local IPv4 می‌پرسد تا GRE با همان IP bind شود و WireGuard هم همان IP را به‌عنوان endpoint صحیح این سرور ذخیره/نمایش دهد

---

## جداسازی کامل GRE و WireGuard

| نوع تونل | اینترفیس | رنج IP داخلی | فایل کانفیگ | سرویس |
|---|---|---|---|---|
| Normal GRE | `greN` | `10.10.N.0/30` | `/etc/gre-tunnels/tunnel-N.conf` | `gre-tunnel@N.service` |
| WireGuard | `wgtunN` | `10.20.N.0/30` | `/etc/wireguard/wgtunN.conf` | `wg-quick@wgtunN.service` |

مثلاً تونل شماره 1:

| نوع | ایران | خارج |
|---|---|---|
| GRE | `10.10.1.1/30` | `10.10.1.2/30` |
| WireGuard | `10.20.1.1/30` | `10.20.1.2/30` |

مثلاً تونل شماره 2:

| نوع | ایران | خارج |
|---|---|---|
| GRE | `10.10.2.1/30` | `10.10.2.2/30` |
| WireGuard | `10.20.2.1/30` | `10.20.2.2/30` |

---

## روش استفاده برای ساخت تونل GRE معمولی

روی هر دو سرور اسکریپت را اجرا کنید:

```bash
sudo ./GRETUN.sh
```

بعد:

```text
1) create/update tunnel
1) Normal GRE tunnel
```

سپس:

- روی سرور ایران گزینه نقش `Iran / local-side role` را بزنید.
- روی سرور خارج گزینه نقش `Kharej / remote-side role` را بزنید.
- روی هر دو طرف **شماره تونل یکسان** وارد کنید.
- Local IPv4 همین سرور را انتخاب/وارد کنید؛ اگر چند IP دارید، همان IP که می‌خواهید تونل از آن خارج شود را بزنید.
- IP پابلیک سرور مقابل را وارد کنید.
- کانفیگ ذخیره می‌شود و سرویس بوت به‌صورت خودکار فعال می‌شود.

نمونه تونل شماره 1:

```text
Iran server:
  tunnel number: 1
  local GRE IP : 10.10.1.1/30
  remote GRE IP: 10.10.1.2

Kharej server:
  tunnel number: 1
  local GRE IP : 10.10.1.2/30
  remote GRE IP: 10.10.1.1
```

---

## روش استفاده برای ساخت WireGuard

WireGuard امن‌تر از GRE خام است، چون رمزنگاری دارد. برای ساخت WireGuard روی هر دو سرور:

```bash
sudo ./GRETUN.sh
```

بعد:

```text
1) create/update tunnel
2) WireGuard tunnel
```

### نکته مهم درباره Public Key

WireGuard برای راه‌اندازی کامل، public key هر دو طرف را لازم دارد. در نسخه جدید، اسکریپت اول کلید همین سرور را می‌سازد و نشان می‌دهد، بعد کلید طرف مقابل را می‌پرسد.

روند پیشنهادی:

1. روی سرور اول WireGuard tunnel را بسازید.
2. وقتی public key همین سرور نمایش داده شد، آن را کپی کنید.
3. اگر هنوز public key سرور دوم را ندارید، فیلد `REMOTE WireGuard public key` را خالی بگذارید. تونل به حالت `PENDING` ذخیره می‌شود و start نمی‌شود.
4. روی سرور دوم همان شماره تونل را بسازید و public key سرور اول را به‌عنوان remote وارد کنید.
5. public key سرور دوم را بردارید و دوباره روی سرور اول همان شماره تونل را اجرا کنید و public key سرور دوم را وارد کنید.
6. بعد از اینکه هر دو طرف public key همدیگر را داشتند، سرویس `wg-quick@wgtunN.service` بالا می‌آید و ping باید از IP داخلی طرف مقابل تست شود.

اسکریپت موقع وارد کردن کلید، این حالت‌ها را هم قبول می‌کند:

```text
U8hufc17Tkm8ZZxfkdtunDQsB3L8zQE8kZ/fGglJoTI=
PublicKey = U8hufc17Tkm8ZZxfkdtunDQsB3L8zQE8kZ/fGglJoTI=
```

اگر اشتباهی public key همین سرور را به‌جای طرف مقابل وارد کنید، اسکریپت آن را تشخیص می‌دهد و تونل را pending ذخیره می‌کند.

### مثال WireGuard تونل شماره 1

روی ایران:

```text
Role: Iran
Tunnel number: 1
Local WG IP: 10.20.1.1/30
Remote WG IP: 10.20.1.2
Interface: wgtun1
Default UDP port: 51801
```

روی خارج:

```text
Role: Kharej
Tunnel number: 1
Local WG IP: 10.20.1.2/30
Remote WG IP: 10.20.1.1
Interface: wgtun1
Default UDP port: 51801
```

> هر دو طرف برای یک تونل باید شماره تونل یکسان داشته باشند.

---

## چند سرور به یک سرور

روی سرور اصلی برای هر سرور مقابل، یک شماره تونل جدا بزنید.

مثال GRE:

```text
Remote 1 => tunnel 1 => gre1 => 10.10.1.x
Remote 2 => tunnel 2 => gre2 => 10.10.2.x
Remote 3 => tunnel 3 => gre3 => 10.10.3.x
```

مثال WireGuard:

```text
Remote 1 => tunnel 1 => wgtun1 => 10.20.1.x => UDP 51801
Remote 2 => tunnel 2 => wgtun2 => 10.20.2.x => UDP 51802
Remote 3 => tunnel 3 => wgtun3 => 10.20.3.x => UDP 51803
```

در WireGuard، پورت هر تونل به‌صورت خودکار از شماره تونل ساخته می‌شود:

```text
51800 + tunnel number
```

یعنی:

```text
Tunnel 1 => UDP 51801
Tunnel 2 => UDP 51802
Tunnel 3 => UDP 51803
```

در این نسخه برای کم شدن سوال‌ها، پورت و AllowedIPs هنگام ساخت پرسیده نمی‌شود. AllowedIPs پیش‌فرض فقط IP داخلی طرف مقابل است؛ مثلاً برای تونل 1 روی ایران، مقدار peer برابر `10.20.1.2/32` می‌شود.

---

## نسخه v6: انتخاب Local IPv4 برای سرورهای چند IP

اگر روی سرور ایران یا خارج چند IP دارید، اسکریپت دیگر فقط به تشخیص خودکار اکتفا نمی‌کند. هنگام ساخت یا آپدیت تونل، لیست IPv4های موجود روی سرور را نشان می‌دهد و از شما Local IPv4 می‌پرسد.

### در GRE

Local IPv4 مستقیماً در دستور GRE استفاده می‌شود:

```bash
ip tunnel add greN mode gre local <LOCAL_IP> remote <REMOTE_IP> key N ttl 255
```

پس اگر سرور چند IP دارد، باید IPی را انتخاب کنید که می‌خواهید GRE از همان IP bind و خارج شود. این مقدار در فایل زیر ذخیره می‌شود:

```text
/etc/gre-tunnels/tunnel-N.conf
```

### در WireGuard

WireGuard معمولاً روی همه IPهای سرور روی پورت UDP همان تونل listen می‌کند، ولی سرور مقابل باید بداند به کدام IP وصل شود. برای همین v6 از شما Local IPv4 را می‌پرسد و همان را در metadata ذخیره و در خروجی نمایش می‌دهد:

```text
Use this IP as the REMOTE server Public IPv4 on the other server
```

یعنی اگر روی سرور ایران Local IPv4 را مثلاً `2.189.x.x` انتخاب کردید، روی سرور خارج همین IP را به‌عنوان Remote Public IPv4 سرور ایران وارد کنید.

### نکته

اگر فقط Enter بزنید، مقدار پیش‌فرض همان IP تشخیص‌داده‌شده توسط route سیستم است. اگر چند IP دارید، بهتر است دستی IP درست را وارد کنید.
---

## حذف تونل

از منوی اصلی:

```text
3) remove tunnel
```

بعد اسکریپت می‌پرسد:

```text
1) Normal GRE tunnel
2) WireGuard tunnel
```

بعد از انتخاب نوع، لیست تونل‌های همان نوع را نشان می‌دهد. مثلاً:

```text
Normal GRE tunnels:
  - tunnel 1 | iface gre1 | active
  - tunnel 2 | iface gre2 | inactive
```

یا:

```text
WireGuard tunnels:
  - tunnel 1 | iface wgtun1 | active
  - tunnel 2 | iface wgtun2 | inactive
```

بعد کافی است شماره تونل را وارد کنید، مثلاً:

```text
1
```

برای WireGuard، حذف شامل این‌هاست:

- پایین آوردن اینترفیس `wgtunN`
- غیرفعال کردن سرویس `wg-quick@wgtunN.service`
- حذف `/etc/wireguard/wgtunN.conf`
- حذف metadata از `/etc/wgtun-tunnels/tunnel-N.conf`
- حذف keyهای همان تونل

برای GRE، حذف شامل این‌هاست:

- پایین آوردن اینترفیس `greN`
- حذف تونل GRE
- غیرفعال کردن سرویس `gre-tunnel@N.service`
- حذف `/etc/gre-tunnels/tunnel-N.conf`

---

## بررسی وضعیت

از منوی اصلی:

```text
2) status
```

بعد نوع تونل را انتخاب کنید:

```text
1) Normal GRE tunnel
2) WireGuard tunnel
```

اسکریپت لیست تونل‌ها را نشان می‌دهد و می‌توانید شماره تونل را برای تست وارد کنید.

---

## پیش‌نیازها

برای GRE:

- Linux
- root access
- `iproute2`
- `iptables`

برای WireGuard:

- `wireguard`
- `wireguard-tools`
- `wg`
- `wg-quick`

اگر WireGuard نصب نباشد، اسکریپت بدون سوال اضافه تلاش می‌کند با `apt-get`، `dnf` یا `yum` نصبش کند.

---

## نکات مهم امنیتی

- GRE خام رمزنگاری ندارد.
- WireGuard رمزنگاری دارد و برای استفاده روی اینترنت گزینه امن‌تری است.
- GRE و WireGuard در این نسخه کنار هم وجود دارند ولی به خاطر جدا بودن رنج IP و نام فایل‌ها و اینترفیس‌ها با هم تداخل ندارند.
- برای هر تونل شماره جدا استفاده کنید.
- برای دو طرف یک تونل، شماره تونل باید یکی باشد.
- اگر چند سرور به یک سرور وصل می‌شوند، روی سرور اصلی برای هر peer شماره جدا تعریف کنید.

---

## ساختار فایل‌ها

```text
/etc/gre-tunnels/tunnel-N.conf              # GRE metadata/config
/etc/wireguard/wgtunN.conf                 # WireGuard wg-quick config
/etc/wgtun-tunnels/tunnel-N.conf           # WireGuard metadata
/etc/wgtun-tunnels/keys/tunnel-N.private   # WireGuard private key
/etc/wgtun-tunnels/keys/tunnel-N.public    # WireGuard public key
/usr/local/bin/gretun-manager.sh           # copy of this script for GRE systemd service
/etc/systemd/system/gre-tunnel@.service    # GRE template service
wg-quick@wgtunN.service                    # WireGuard native service
```

---

## رفع مشکل خطای `wg-quick@wgtunN.service failed`

در نسخه قبلی، اسکریپت اول `wg-quick up wgtunN` را اجرا می‌کرد و بعد `systemctl enable --now wg-quick@wgtunN.service` را می‌زد. این باعث می‌شد systemd دوباره تلاش کند همان اینترفیس را بسازد و سرویس fail شود.

در این نسخه اصلاح شده:

- WireGuard فقط از یک مسیر بالا می‌آید.
- اگر systemd وجود داشته باشد، اسکریپت اول فقط همین اینترفیس را پایین می‌آورد و بعد `wg-quick@wgtunN.service` را restart می‌کند.
- اگر systemd وجود نداشته باشد، از `wg-quick up` مستقیم استفاده می‌شود.
- اگر سرویس fail شود، دیگر پیام موفقیت اشتباه چاپ نمی‌شود و دستورهای debug نشان داده می‌شود.

برای بررسی دستی خطا:

```bash
systemctl status wg-quick@wgtun1.service --no-pager -l
journalctl -xeu wg-quick@wgtun1.service --no-pager
```

---

## سوال‌هایی که هنگام ساخت پرسیده می‌شود

### GRE

- نوع تونل
- نقش سرور: ایران یا خارج
- شماره تونل
- Local IPv4 همین سرور برای bind تونل، با مقدار پیش‌فرض خودکار
- IP پابلیک سرور مقابل

بقیه موارد خودکار است: IP داخلی، اسم اینترفیس، GRE key، ذخیره کانفیگ و فعال‌سازی سرویس بوت.

### WireGuard

- نوع تونل
- نقش سرور: ایران یا خارج
- شماره تونل
- Local IPv4 همین سرور برای اینکه طرف مقابل endpoint درست را بداند
- IP پابلیک سرور مقابل فقط وقتی لازم است که WireGuard مستقیم روی اینترنت عمومی کار کند
- Public key طرف مقابل، اگر آماده باشد

اگر GRE همان شماره از قبل فعال و قابل ping باشد، v6 به‌صورت خودکار WireGuard را روی GRE می‌برد و برای endpoint وایرگارد، IP پابلیک سرور مقابل را نمی‌پرسد.

اگر ابزار WireGuard نصب نباشد، نصب هم خودکار انجام می‌شود. بقیه موارد خودکار است: IP داخلی، اسم اینترفیس، UDP port، AllowedIPs، ذخیره کانفیگ، rule فایروال و start/enable سرویس.

اگر public key طرف مقابل را خالی بگذارید، اسکریپت فقط key همین سرور را می‌سازد و public key را نشان می‌دهد؛ سرویس WireGuard را شروع نمی‌کند تا کانفیگ خراب ساخته نشود. در این حالت ping به `10.20.N.1` یا `10.20.N.2` جواب نمی‌دهد، چون اینترفیس هنوز بالا نیامده است.

برای دیدن public key ذخیره‌شده هر تونل:

```bash
cat /etc/wgtun-tunnels/keys/tunnel-1.public
```

برای debug بعد از اینکه هر دو طرف کامل شدند:

```bash
systemctl status wg-quick@wgtun1.service --no-pager -l
wg show wgtun1
ip -br addr show wgtun1
ping 10.20.1.1   # از سمت خارج
ping 10.20.1.2   # از سمت ایران
```

---

## نسخه v5/v6: WireGuard over GRE برای وقتی UDP/WireGuard روی اینترنت بسته است

اگر GRE معمولی شما وصل است، ولی WireGuard روی IP پابلیک وصل نمی‌شود، احتمال دارد مسیر UDP یا fingerprint وایرگارد روی اینترنت مشکل داشته باشد. در v5 این حالت خودکار اضافه شد و در v6 امکان انتخاب Local IPv4 هم به آن اضافه شده است:

```text
GRE tunnel N:       greN   => 10.10.N.1 <-> 10.10.N.2
WireGuard tunnel N: wgtunN => 10.20.N.1 <-> 10.20.N.2
WireGuard endpoint: به‌جای IP پابلیک، از IP داخلی GRE استفاده می‌کند
```

مثال تونل شماره 1:

```text
روی ایران:
  GRE: 10.10.1.1
  WG : 10.20.1.1
  WireGuard Endpoint: 10.10.1.2:51801

روی خارج:
  GRE: 10.10.1.2
  WG : 10.20.1.2
  WireGuard Endpoint: 10.10.1.1:51801
```

### v5/v6 چطور خودش تصمیم می‌گیرد؟

هنگام ساخت یا آپدیت WireGuard:

1. اسکریپت چک می‌کند آیا `greN` با همان شماره وجود دارد یا نه.
2. بعد IP داخلی GRE طرف مقابل را ping می‌کند.
3. اگر جواب داد، WireGuard را خودکار روی حالت `endpoint mode: gre` می‌گذارد.
4. اگر GRE همان شماره فعال نبود، حالت عادی `endpoint mode: public` استفاده می‌شود.

یعنی اگر اول GRE tunnel 1 را روی دو طرف بسازید و ping `10.10.1.x` جواب بدهد، بعد ساخت WireGuard tunnel 1 به‌صورت خودکار روی GRE سوار می‌شود. در این حالت دیگر برای endpoint وایرگارد، IP پابلیک لازم نیست و اسکریپت سوال اضافه نمی‌پرسد.

### مزیت این حالت

- GRE همان نسخه معمولی قبلی باقی می‌ماند.
- WireGuard رمزنگاری را اضافه می‌کند.
- اگر UDP/WireGuard روی مسیر پابلیک مشکل داشته باشد، WireGuard از مسیر GRE استفاده می‌کند.
- IPها و اسم‌ها همچنان جدا هستند و تداخل ندارند:
  - GRE: `greN` و `10.10.N.x`
  - WireGuard: `wgtunN` و `10.20.N.x`
- MTU در حالت WireGuard over GRE خودکار `1280` تنظیم می‌شود تا مشکل fragmentation کمتر شود.

### روش پیشنهادی برای شرایط فیلترینگ شدید

روی هر دو سرور:

1. اول GRE همان شماره را بسازید.
2. مطمئن شوید ping داخلی GRE جواب می‌دهد:

```bash
ping 10.10.1.2   # از سمت ایران
ping 10.10.1.1   # از سمت خارج
```

3. بعد WireGuard همان شماره را بسازید.
4. در خروجی باید چیزی شبیه این ببینید:

```text
Endpoint mode        : gre
Endpoint IP          : 10.10.1.2
Transport interface  : gre1
MTU                  : 1280
```

5. بعد WireGuard را تست کنید:

```bash
ping 10.20.1.2   # از سمت ایران
ping 10.20.1.1   # از سمت خارج
wg show wgtun1
```

اگر `Latest handshake: never` بود، یعنی هنوز key طرف مقابل، سرویس سمت مقابل، یا UDP روی مسیر GRE مشکل دارد. گزینه repair/restart را از منو اجرا کنید.

---

## License

MIT License

---

## نسخه v4: رفع مشکل WireGuard و ابزار Repair

در v4 چند تغییر برای پایدارتر شدن WireGuard اضافه شده است:

- گزینه جدید منوی اصلی:

```text
5) repair/restart WireGuard tunnel
```

این گزینه برای همان تونل انتخابی کارهای زیر را انجام می‌دهد:

1. ruleهای فایروال مربوط به UDP همان تونل را دوباره اعمال می‌کند.
2. `rp_filter` را برای مسیر تونل خاموش می‌کند تا برگشت پکت‌ها روی بعضی دیتاسنترها مشکل نخورد.
3. فقط همان سرویس WireGuard را restart می‌کند، مثل `wg-quick@wgtun1.service`.
4. بعد از restart، وضعیت `wg show`، endpoint، transfer، آخرین handshake و ping داخلی را نشان می‌دهد.

### چرا ممکن است GRE وصل شود ولی WireGuard نه؟

اگر GRE با `10.10.N.x` وصل است ولی WireGuard با `10.20.N.x` وصل نیست، مسیر کلی بین سرورها باز است؛ اما WireGuard هنوز ممکن است به یکی از این دلایل کار نکند:

- public key طرف مقابل اشتباه وارد شده باشد.
- یکی از دو طرف سرویس `wg-quick@wgtunN.service` را خاموش کرده باشد.
- UDP port مربوط به تونل، مثلاً `51801` برای تونل 1، توسط فایروال یا دیتاسنتر بسته باشد.
- endpoint IP اشتباه باشد.
- فایل کانفیگ با اجرای نسخه قدیمی‌تر اسکریپت بازنویسی شده باشد.
- `rp_filter` یا firewall داخلی سرور ICMP روی اینترفیس WireGuard را drop کند.

### تست درست WireGuard

روی هر دو سرور این‌ها را بزنید:

```bash
systemctl status wg-quick@wgtun1.service --no-pager -l
wg show wgtun1
ip -br addr show wgtun1
```

بعد از منوی اسکریپت:

```text
2) status
2) WireGuard tunnel
```

یا برای repair:

```text
5) repair/restart WireGuard tunnel
```

اگر status بگوید:

```text
Latest handshake: never
```

یعنی WireGuard اصلاً handshake نکرده و باید key، endpoint، UDP port و firewall دو طرف چک شود.

اگر handshake وجود دارد ولی ping نمی‌دهد، معمولاً مشکل از AllowedIPs، firewall روی اینترفیس WireGuard یا rp_filter است؛ گزینه repair این موارد را تا حد امکان خودکار اصلاح می‌کند.

### نکته مهم درباره اجرای curl از GitHub

اگر این نسخه را از فایل ZIP گرفته‌اید ولی بعداً این دستور را بزنید:

```bash
bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh)
```

در واقع نسخه‌ای را اجرا می‌کنید که روی GitHub branch `main` است، نه الزاماً همین نسخه ZIP. اگر GitHub هنوز آپدیت نشده باشد، ممکن است نسخه قدیمی‌تر اجرا شود و کانفیگ یا سرویس را تغییر دهد. تا وقتی فایل جدید را روی GitHub جایگزین نکرده‌اید، بهتر است همین فایل `GRETUN.sh` داخل ZIP را اجرا کنید.
