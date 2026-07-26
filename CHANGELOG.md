# Changelog

## v10.0.0 — Vira Hybrid Rewrite

- موتور Vira از ابتدا بازنویسی شد.
- پروتکل فریم جدید با Version، Tunnel ID، Cookie، Session Nonce، Sequence و CRC32 اضافه شد.
- حالت Auto Hybrid اضافه شد: UDP در اولویت و TCP به‌عنوان fallback خودکار.
- Client دیگر پورت مقصد را روی مبدأ bind نمی‌کند و از پورت موقت سیستم استفاده می‌کند.
- مسیر UDP یک‌طرفه شناسایی می‌شود و TCP می‌تواند نشست UDP نیمه‌کاره را جایگزین کند.
- UDP و TCP روی یک شماره پورت در سمت Server پشتیبانی می‌شوند.
- حالت‌های Auto، UDP only و TCP only اضافه شدند.
- timeout، reconnect و heartbeat بازنویسی شدند.
- TCP keepalive و TCP_NODELAY اضافه شدند.
- فریم‌بندی مطمئن برای عبور Packet روی TCP اضافه شد.
- آمار active transport، fallback، handshake، reconnect، packet و byte اضافه شد.
- تست داخلی CRC، UDP handshake، TCP framing و UDP-to-TCP takeover اضافه شد.
- باینری جدید فقط بعد از موفقیت self-test نصب می‌شود.
- اعتبارسنجی کانفیگ قبل از restart سرویس اضافه شد.
- قوانین فایروال TCP و UDP در ابتدای chain اضافه می‌شوند.
- Client و Server در بررسی اشغال بودن پورت به‌درستی از هم جدا شدند.
- منوی CPU قدیمی به منوی تغییر Transport Profile تبدیل شد.
- Diagnostics برای UDP/TCP و active transport بازنویسی شد.
- کانفیگ‌ها به Version 3 مهاجرت کردند.
- README کامل بازنویسی شد.
