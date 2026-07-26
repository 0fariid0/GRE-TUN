# Tunnel Manager v9.0.0

این نسخه بر پایه فایل `GRETUN-fixed.sh` ساخته شده و بخش **Normal GRE** در آن بدون تغییر نگه داشته شده است.

## انواع تونل

1. Normal GRE
2. Improved Vira7
3. WireGuard over GRE
4. WireGuard over Vira7
5. Hybrid GRE + Vira Failover
6. WSS/TCP Emergency Tunnel

## رنج‌های IP

| نوع | رنج |
|---|---|
| Normal GRE قدیمی | `10.10.N.1/30` و `10.10.N.2/30` |
| WireGuard قدیمی | `10.20.N.1/30` و `10.20.N.2/30` |
| Vira7 | `10.71.N.1` و `10.71.N.2` |
| WireGuard over GRE | `10.81.N.1/30` و `10.81.N.2/30` |
| WireGuard over Vira7 | `10.82.N.1/30` و `10.82.N.2/30` |
| Hybrid stable IP | `10.83.N.1` و `10.83.N.2` |
| WSS/TCP WireGuard | `10.84.N.1/30` و `10.84.N.2/30` |

## بازه پورت‌های رزروشده

- WireGuard over GRE: `54001-54254/UDP`
- WireGuard over Vira7: `54401-54654/UDP`
- WSS remote WireGuard: `54801-55054/UDP`
- WSS client WireGuard: `55201-55454/UDP`
- WSS public transport: `24001-24254/TCP`

پورت‌های نسخه ۹ ثابت و وابسته به شماره تونل هستند و به‌صورت خودکار به پورت دیگری تغییر نمی‌کنند. اگر پورت اشغال باشد، نصب متوقف می‌شود تا دو سرور روی پورت متفاوت قرار نگیرند.

## نصب و اجرا

```bash
chmod +x Tunnel-Manager-v9.sh
sudo ./Tunnel-Manager-v9.sh
```

قبل از اجرای نسخه جدید، تهیه بکاپ توصیه می‌شود:

```bash
BACKUP="/root/tunnel-manager-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a /etc/gre-tunnels "$BACKUP/" 2>/dev/null || true
cp -a /etc/vira7-tunnels "$BACKUP/" 2>/dev/null || true
cp -a /etc/wireguard "$BACKUP/" 2>/dev/null || true
cp -a /etc/tunnel-manager-v9 "$BACKUP/" 2>/dev/null || true
cp -a /usr/local/bin/gretun-manager.sh "$BACKUP/" 2>/dev/null || true
```

## ترتیب پیشنهادی ساخت Hybrid

در هر دو سرور از یک شماره یکسان استفاده کنید؛ مثلاً شماره 3.

1. ابتدا `Normal GRE 3` را در هر دو سمت بسازید.
2. سپس `Improved Vira7 3` را در هر دو سمت با یک پورت یکسان بسازید.
3. گزینه `WireGuard over GRE 3` را در هر دو سمت اجرا و Public Keyها را مبادله کنید.
4. گزینه `WireGuard over Vira7 3` را در هر دو سمت اجرا و Public Keyها را مبادله کنید.
5. در پایان `Hybrid GRE + Vira Failover 3` را روی هر دو سرور بسازید.
6. در HAProxy یا سرویس مقصد، از IP ثابت Hybrid سمت مقابل یعنی `10.83.3.2` یا `10.83.3.1` استفاده کنید.

## Health Manager

Health Manager به‌صورت پیش‌فرض خاموش است و از منوی اصلی قابل روشن یا خاموش‌کردن است.

- فاصله پیش‌فرض: 30 ثانیه
- هر بار فقط یک Ping برای هر تونل فعال
- اقدام پس از 3 شکست متوالی
- فاصله جلوگیری از Restart پشت سرهم: 120 ثانیه
- سرویس با `Nice=10` و I/O idle اجرا می‌شود

Improved Vira7 یک Dead-path recovery داخلی و سبک هم دارد که مستقل از Health Manager است و هنگام تنظیم Vira قابل خاموش‌کردن است.

## سازگاری تونل‌های قبلی

- فایل‌های Normal GRE قبلی حذف یا تبدیل نمی‌شوند.
- WireGuard قدیمی با نام `wgtunN` و رنج `10.20.N.x` نگه داشته می‌شود.
- Vira7 قدیمی تا زمانی که همان شماره را از منوی Improved Vira7 به‌روزرسانی نکنید، تغییر نمی‌کند.
- هنگام Update، فایل قبلی قبل از توقف سرویس بکاپ موقت می‌شود و در صورت شکست تنظیم جدید، بازیابی می‌شود.
- حذف Overlayهای نسخه ۹، GRE یا Vira زیر آن را حذف نمی‌کند.
- حذف GRE/Vira در صورت وجود Overlay وابسته مسدود می‌شود.

## Improved Vira7

فرمت بسته قبلی حفظ شده تا سازگاری از بین نرود، ولی امکانات زیر اضافه شده‌اند:

- قفل‌کردن Peer به IP عمومی تعریف‌شده
- تشخیص مسیر مرده با زمان آخرین بسته دریافتی
- Restart خودکار سمت Client پس از Timeout
- پاک‌کردن Peer مرده سمت Server و پذیرش دوباره همان Peer مجاز
- شمارنده سبک TX/RX/Drop و زمان آخرین دریافت
- توقف Update در صورت اشغال بودن پورت
- MTU پیش‌فرض جدید `1320` برای کاهش Fragmentation

## WSS/TCP Emergency Tunnel

در این حالت ترافیک WireGuard داخل WebSocket TLS روی TCP عبور می‌کند. سمت ایران Client و سمت خارج Server است. فایل اجرایی wstunnel هنگام اولین استفاده از GitHub دریافت می‌شود. این مسیر برای شرایط اضطراری است و معمولاً از GRE یا Vira کندتر خواهد بود.

## بررسی محلی نسخه تحویلی

- Bash syntax: موفق
- کامپایل موتور Vira با `-Wall -Wextra -Werror`: موفق
- تولید کانفیگ WireGuard over GRE/Vira/WSS: موفق
- تست رنج IP و پورت: بدون هم‌پوشانی
- تست آرگومان‌های Client و Server مربوط به WSS: موفق
- مقایسه بخش Normal GRE با نسخه قبلی: یکسان

تست اتصال واقعی WSS و Hybrid نیازمند اجرای هم‌زمان روی دو سرور واقعی است.
