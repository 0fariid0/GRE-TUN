
## 🚀 دستورات نصب آسان (Quick Install)


```bash
bash <(curl -Ls --ipv4 https://raw.githubusercontent.com/Arash-Ariaye/GRE-TUN/refs/heads/main/GRETUN.sh)
```

📌 ترتیب اجرا:

1. اول روی **سرور ایران**
2. بعد روی **سرور خارج**

---



---

## Multi-tunnel update

This version supports multiple GRE tunnels on the same server.

### Tunnel numbering

The script now asks for the tunnel number before it asks for the remote public IP.

Examples:

| Tunnel number | Interface | Iran role IP | Kharej role IP | Config file | Service |
|---|---|---|---|---|---|
| 1 | `gre1` | `10.10.1.1/30` | `10.10.1.2/30` | `/etc/gre-tunnels/tunnel-1.conf` | `gre-tunnel@1.service` |
| 2 | `gre2` | `10.10.2.1/30` | `10.10.2.2/30` | `/etc/gre-tunnels/tunnel-2.conf` | `gre-tunnel@2.service` |
| N | `greN` | `10.10.N.1/30` | `10.10.N.2/30` | `/etc/gre-tunnels/tunnel-N.conf` | `gre-tunnel@N.service` |

The GRE key is also set to the same tunnel number. Both sides of the same tunnel must use the same tunnel number.

### Many servers to one server

On the main server, create a separate tunnel for each remote server:

- Remote server 1: tunnel `1`, interface `gre1`, inner IP `10.10.1.x`
- Remote server 2: tunnel `2`, interface `gre2`, inner IP `10.10.2.x`
- Remote server 3: tunnel `3`, interface `gre3`, inner IP `10.10.3.x`

Use the same tunnel number on the matching remote server.

### Important notes

- Do not reuse the same tunnel number for different peers on the same server.
- Existing tunnels are not removed when a new tunnel is created; only the selected `greN` interface is recreated.
- The old single-tunnel config `/etc/gre-tunnel.conf` is still supported as a legacy fallback for tunnel `1`.

---

# GRE-TUN

اسکریپت Bash ساده، امن و حرفه‌ای برای راه‌اندازی تانل GRE بین دو سرور لینوکس (مثلاً ایران و خارج) بدون ایجاد اختلال در اینترفیس اصلی شبکه و بدون دست‌کاری SSH.

این اسکریپت به‌صورت مرحله‌ای اجرا می‌شود:
- یک بار روی سرور ایران
- یک بار روی سرور خارج

و در انتها، وضعیت موفق یا ناموفق بودن تانل را بررسی می‌کند.



## ✨ امکانات

- منوی انتخاب نقش سرور (ایران / خارج)
- تشخیص خودکار IP پابلیک واقعی سرور (بدون سایت خارجی)
- ساخت تانل GRE به‌عنوان **اینترفیس ثانویه**
- عدم تغییر Default Route
- عدم اختلال در SSH (پورت 22)
- تنظیم خودکار MTU مناسب GRE
- باز کردن خودکار پروتکل GRE در فایروال
- قابلیت اجرای مجدد بدون خطا
- تست نهایی اتصال تانل

---

## 🧱 ساختار شبکه تانل

- نام اینترفیس: `greN` برای شماره تونل N، مثل `gre1` و `gre2`
- رنج IP تانل: `10.10.N.0/30` برای شماره تونل N

| سرور | IP تانل |
|-----|---------|
| ایران | 10.10.N.1 |
| خارج | 10.10.N.2 |

> اینترفیس اصلی شبکه (مثل `eth0` یا `ens3`) بدون هیچ تغییری باقی می‌ماند.

---

## 📋 پیش‌نیازها

- سیستم‌عامل لینوکس (Ubuntu / Debian پیشنهاد می‌شود)
- دسترسی root
- نصب بودن:
  - iproute2
  - iptables

---

## 🚀 نصب و اجرا (سریع)

```bash
git clone https://github.com/Arash-Ariaye/GRE-TUN.git
cd GRE-TUN
chmod +x GRETUN.sh
sudo ./GRETUN.sh
````

---

## 🧭 نحوه استفاده

### 1️⃣ اجرا روی سرور ایران

* گزینه `1) Iran Server` را انتخاب کنید
* IP پابلیک سرور خارج را وارد کنید

---

### 2️⃣ اجرا روی سرور خارج

* گزینه `2) Foreign Server` را انتخاب کنید
* IP پابلیک سرور ایران را وارد کنید

---

### 3️⃣ تست نهایی

در انتهای اجرای اسکریپت روی سرور خارج، تست زیر انجام می‌شود:

```text
Tunnel is OK ✅
```

یا در صورت مشکل:

```text
Tunnel is NOT OK ❌
```

---

## 🔐 نکات امنیتی مهم

* تانل GRE به‌صورت پیش‌فرض **رمزنگاری ندارد**
* این اسکریپت:

  * مسیر پیش‌فرض اینترنت را تغییر نمی‌دهد
  * ترافیک SSH را وارد تانل نمی‌کند
* برای امنیت بیشتر می‌توانید از:

  * GRE over IPsec
  * WireGuard
    استفاده کنید

---

## 🧠 کاربردها

* اتصال امن ایران و خارج
* عبور ترافیک سرویس‌های خاص از تانل
* DNS تحریم‌شکن
* استفاده در کنار WireGuard
* سناریوهای Anti-DDoS
* Routing سفارشی

---

## 🧹 حذف تانل

```bash
ip link set greN down
ip tunnel del greN
```

---

## 📜 لایسنس

MIT License
استفاده، تغییر و انتشار آزاد است.

---

## 🤝 مشارکت

 برای پیشنهادات بهبود Pull Request.

هدف پروژه: **سادگی، امنیت و عدم ریسک برای سرور**.

---

## ⭐ حمایت

اگر این اسکریپت به کارت آمد، با ⭐ دادن به ریپو حمایت کن 🙏

