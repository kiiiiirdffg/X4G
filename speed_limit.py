# speed_limit.py
# محدودیت سرعت (Bandwidth Throttling) به‌ازای هر کانفیگ
# پیاده‌سازی با الگوی Token Bucket
#
# این ماژول توسط relay_vless.py و xhttp_siz10.py استفاده می‌شود.
# برای جلوگیری از Circular Import، LINKS از main.py فقط هنگام
# اجرای throttle() دریافت می‌شود، نه هنگام import شدن این ماژول.

import asyncio
import time


# هر UUID یک Bucket جدا دارد.
# Bucket با نرخ صفر (بدون محدودیت) اصلاً ساخته نمی‌شود.
_buckets: dict = {}

MIN_RATE = 1024          # حداقل نرخ: 1 KB/s
MIN_BURST = 16 * 1024    # حداقل ظرفیت burst: 16 KB


class _Bucket:
    __slots__ = ("rate", "capacity", "tokens", "last")

    def __init__(self, rate_bytes_per_sec: float):
        self.rate = max(rate_bytes_per_sec, MIN_RATE)

        # ظرفیت burst معادل حداقل ۱ ثانیه از نرخ مجاز
        # و حداقل ۱۶ کیلوبایت
        self.capacity = max(self.rate, MIN_BURST)

        self.tokens = self.capacity
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last

        if elapsed > 0:
            self.last = now
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )

    async def consume(self, n: int):
        """
        تا زمانی که n بایت توکن آماده شود صبر می‌کند.
        از asyncio.sleep استفاده می‌شود تا Event Loop مسدود نشود.
        """

        while True:
            self._refill()

            if self.tokens >= n:
                self.tokens -= n
                return

            deficit = n - self.tokens
            wait = deficit / self.rate

            # sleep کوتاه نگه داشته می‌شود تا اگر نرخ کانفیگ
            # تغییر کرد، تغییرات سریع‌تر اعمال شوند.
            await asyncio.sleep(
                min(max(wait, 0.004), 0.5)
            )


def _get_bucket(uuid: str, rate: int) -> _Bucket:
    """
    Bucket مربوط به UUID را برمی‌گرداند.
    اگر وجود نداشته باشد یا نرخ آن تغییر کرده باشد،
    Bucket جدید ساخته می‌شود.
    """

    normalized_rate = max(rate, MIN_RATE)

    bucket = _buckets.get(uuid)

    if bucket is None or bucket.rate != normalized_rate:
        bucket = _Bucket(rate)
        _buckets[uuid] = bucket

    return bucket


async def throttle(uuid: str, nbytes: int):
    """
    اعمال محدودیت سرعت برای یک کانفیگ.

    اگر speed_limit_bytes <= 0 باشد، هیچ محدودیتی اعمال نمی‌شود.

    نکته:
    LINKS عمداً در ابتدای فایل import نشده است.
    این کار برای جلوگیری از Circular Import بین:
        main.py
        relay_vless.py
        speed_limit.py
    انجام شده است.
    """

    if nbytes <= 0:
        return

    # Lazy import:
    # main.py باید قبل از اجرای واقعی throttle() کاملاً initialize
    # شده باشد، بنابراین این import دیگر باعث Circular Import
    # در زمان load شدن ماژول نمی‌شود.
    from main import LINKS

    link = LINKS.get(uuid)

    rate = int(
        (link or {}).get("speed_limit_bytes", 0) or 0
    )

    # بدون محدودیت
    if rate <= 0:
        return

    bucket = _get_bucket(uuid, rate)

    await bucket.consume(nbytes)


def reset_bucket(uuid: str):
    """
    Bucket مربوط به یک UUID را حذف می‌کند.

    در صورت تغییر محدودیت سرعت یا حذف کانفیگ،
    Bucket قبلی پاک می‌شود تا در فراخوانی بعدی
    Bucket با نرخ جدید ساخته شود.
    """

    _buckets.pop(uuid, None)
