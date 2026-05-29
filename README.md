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
- جدا بودن کامل GRE و WireGuard از نظر نام و IP و فایل
- پشتیبانی از سناریوی چند سرور به یک سرور یا برعکس
- ساخت سرویس systemd جدا برای هر GRE tunnel
- استفاده از سرویس استاندارد `wg-quick@...` برای هر WireGuard tunnel
- حذف مرحله‌ای: اول انتخاب نوع تونل، بعد نمایش لیست، بعد زدن شماره تونل برای حذف
- عدم تغییر default route
- عدم دستکاری SSH
- فعال‌سازی IP forwarding
- باز کردن rule فایروال برای همان تونل

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
- IP پابلیک سرور مقابل را وارد کنید.

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

WireGuard برای راه‌اندازی کامل، public key هر دو طرف را لازم دارد. اسکریپت این روند را ساده کرده است:

1. روی سرور اول WireGuard tunnel را بسازید.
2. اگر public key طرف مقابل را ندارید، فیلد `REMOTE WireGuard public key` را خالی بگذارید.
3. اسکریپت public key همین سرور را نشان می‌دهد و ذخیره می‌کند.
4. همین کار را روی سرور دوم انجام دهید.
5. حالا public key سرور دوم را بردارید و روی سرور اول دوباره کانفیگ همان شماره تونل را اجرا کنید و public key طرف مقابل را وارد کنید.
6. public key سرور اول را هم روی سرور دوم وارد کنید.

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

در WireGuard، پورت پیش‌فرض هر تونل این‌طور ساخته می‌شود:

```text
51800 + tunnel number
```

یعنی:

```text
Tunnel 1 => UDP 51801
Tunnel 2 => UDP 51802
Tunnel 3 => UDP 51803
```

می‌توانید هنگام ساخت WireGuard پورت را عوض کنید.

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

اگر WireGuard نصب نباشد، اسکریپت تلاش می‌کند با `apt-get`، `dnf` یا `yum` نصبش کند.

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

## License

MIT License
