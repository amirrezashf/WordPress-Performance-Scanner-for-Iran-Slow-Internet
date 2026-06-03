# WordPress-Performance-Scanner-for-Iran-Slow-Internet
Unfortunately, A plugin for Iranian's wordpress websites!

فایروال درخواست‌های خارجی وردپرس

🚀 افزونه‌ای برای شناسایی، مانیتورینگ و مسدودسازی درخواست‌های خارجی کند یا مشکل‌ساز در وردپرس که می‌توانند باعث کندی پیشخوان یا افزایش زمان بارگذاری شوند.

✨ امکانات

* ✅ مسدودسازی دامنه‌ها
* ✅ مسدودسازی آی‌پی‌ها
* ✅ پشتیبانی از الگوها (*.example.com)
* ✅ ثبت لاگ درخواست‌های مسدودشده
* ✅ ثبت درخواست‌های کند
* ✅ تشخیص منبع درخواست (افزونه، قالب یا هسته وردپرس)
* ✅ نمایش آمار و نمودارهای مدیریتی
* ✅ هشدار دامنه‌های پرخطر
* ✅ غیرفعال‌سازی موقت قوانین
* ✅ پاکسازی خودکار لاگ‌ها پس از ۹۰ روز
* ✅ دسترسی فقط برای مدیر کل سایت

🎯 کاربرد

برخی افزونه‌ها و قالب‌ها به سرویس‌های خارجی متصل می‌شوند که ممکن است:

* فیلتر یا تحریم شده باشند
* پاسخ‌دهی کندی داشته باشند
* باعث کند شدن پیشخوان وردپرس شوند

این افزونه به شما کمک می‌کند این درخواست‌ها را شناسایی و در صورت نیاز مسدود کنید.

📌 نمونه قوانین

دامنه:

example.com

زیر دامنه:

*.example.com

آی‌پی:

34.120.12.1

مسیر خاص:

api.example.com/license

📊 بخش‌های افزونه

داشبورد

نمایش خلاصه آمار، دامنه‌های پرخطر، درخواست‌های کند و درخواست‌های مسدودشده.

قوانین مسدودسازی

افزودن، حذف، فعال یا غیرفعال کردن قوانین.

فعالیت دامنه‌های مسدودشده

نمایش لاگ کامل درخواست‌هایی که توسط افزونه مسدود شده‌اند.

درخواست‌های کند

نمایش دامنه‌ها و آی‌پی‌هایی که هنوز مسدود نشده‌اند اما باعث کندی سایت شده‌اند.

⚠️ دامنه‌های پرخطر

افزونه دامنه‌هایی را که در ۲۴ ساعت اخیر تعداد زیادی درخواست کند داشته‌اند یا میانگین زمان پاسخ‌دهی بالایی دارند شناسایی و نمایش می‌دهد.

🧹 پاکسازی خودکار لاگ‌ها

لاگ‌های قدیمی‌تر از ۹۰ روز به‌صورت خودکار حذف می‌شوند تا حجم دیتابیس افزایش پیدا نکند.

🔐 دسترسی

این افزونه فقط برای نقش کاربری Administrator قابل مشاهده و استفاده است.

⸻

WordPress External Request Firewall

🚀 A lightweight plugin to monitor, log, and block slow or problematic external HTTP requests that may affect WordPress admin performance.

✨ Features

* ✅ Block domains
* ✅ Block IP addresses
* ✅ Wildcard support (*.example.com)
* ✅ Log blocked requests
* ✅ Log slow requests
* ✅ Detect request source (plugin, theme, or WordPress core)
* ✅ Statistics and charts
* ✅ Dangerous domain alerts
* ✅ Temporarily disable rules
* ✅ Automatic log cleanup after 90 days
* ✅ Administrator-only access

🎯 Use Case

Many WordPress plugins and themes send requests to external services that may be:

* Slow
* Blocked by network restrictions
* Unreachable
* Causing delays in the WordPress dashboard

This plugin helps identify and block those requests.

📌 Rule Examples

Domain:

example.com

Wildcard:

*.example.com

IP Address:

34.120.12.1

Specific Path:

api.example.com/license

📊 Sections

Dashboard

Overview of blocked requests, slow requests, dangerous domains, and statistics.

Blocking Rules

Create, edit, enable, disable, or remove rules.

Blocked Activity

View requests that were actually blocked.

Slow Requests

Review slow external requests that are not yet blocked.

⚠️ Dangerous Domains

The plugin automatically identifies domains with excessive slow requests or high response times within the last 24 hours.

🧹 Automatic Cleanup

Logs older than 90 days are automatically removed to keep the database clean and optimized.

🔐 Access Control

Only users with the Administrator role can access and manage the plugin.
