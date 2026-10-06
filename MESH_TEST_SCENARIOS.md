# 🧪 Mesh Connectivity Test Scenarios — 3 iPhones

> **LEGACY / OFF-MAIN — not the serverless RVN1 acceptance test.**
> This is a Persian-language manual radio script for the **legacy iOS `MeshEnvelope` app** (3 iPhones,
> serverless flag **OFF**). The iOS tree (`ios-native`) is **not in this repository**, so nothing here can
> be run or verified from this checkout. In particular, scenario 3 ("Internet-First → Mesh Fallback":
> a blue "Server" badge and a `MessageRouter` presence check against the server) describes the legacy
> server-first routing; it is **not** part of the serverless RVN1 contract, which has no server in the
> message path and no silent fallback (README "FastAPI: NEVER in the path"). Do not use it as the
> project's mesh acceptance criteria. For the RVN1 hardware runbook see
> [`docs/PHYSICAL_BLE_THREE_DEVICE.md`](docs/PHYSICAL_BLE_THREE_DEVICE.md); for the wire contract see
> [`protocol/SPEC.md`](protocol/SPEC.md) and
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](protocol/SECURITY_ERRATA_RVN1_2026-08-13.md).
>
> **قدیمی / خارج از این مخزن:** این سند فقط برای اپ قدیمی iOS با `MeshEnvelope` (فلگ serverless خاموش) است؛
> سناریوی ۳ (نشان «Server» و بررسی حضور از سرور) بخشی از قرارداد serverless نیست.

## تنظیم اولیه

| Device | نام | یوزر |
|--------|-----|------|
| 📱 iPhone A | "Alice" | حساب ۱ |
| 📱 iPhone B | "Bob" | حساب ۲ |
| 📱 iPhone C | "Charlie" | حساب ۳ |

**پیش‌نیازها:**
- هر ۳ تا Bluetooth روشن
- هر ۳ تا RAVEN رو باز دارن
- Alice و Bob با هم Chat Room دارن
- Alice و Charlie با هم Chat Room دارن
- Bob و Charlie با هم Chat Room دارن

---

## 🟢 سناریو ۱: Direct Mesh (ساده‌ترین)

**هدف:** پیام بین ۲ گوشی بدون اینترنت از طریق BLE

**مراحل:**
1. **iPhone A** → Airplane Mode روشن کن ✈️
2. **iPhone B** → Airplane Mode روشن کن ✈️
3. **هر دو** → Bluetooth رو دستی روشن کن (از Control Center)
4. **iPhone A و B** رو کنار هم بذار (فاصله < 5 متر)
5. ۱۰ ثانیه صبر کن تا peer discovery انجام بشه
6. **iPhone A** → به Bob پیام بده: "سلام از mesh! ⏰ [ساعت فعلی]"

**✅ نتیجه مورد انتظار:**
- [ ] پیام در iPhone B ظاهر بشه
- [ ] Badge بنفش 🟣 "Mesh" نشون بده
- [ ] Delivery ACK برگرده به iPhone A (دو تیک)
- [ ] زمان ارسال < 30 ثانیه

**🔍 چی چک کن:**
- Xcode Console → `[BLE]` لاگ‌ها رو ببین
- `connectedPeers` باید ≥ 1 باشه

---

## 🔵 سناریو ۲: Multi-Hop Relay (پیام از طریق بریج)

**هدف:** پیام از A به C از طریق B (relay)

**مراحل:**
1. هر ۳ تا Airplane Mode ✈️ + Bluetooth روشن
2. **iPhone A** رو یک سمت اتاق بذار
3. **iPhone C** رو سمت دیگه اتاق بذار (دور از A, فاصله > 15 متر)
4. **iPhone B** رو **وسط** بذار (که هم A و هم C رو ببینه)
5. ۱۵ ثانیه صبر کن
6. **iPhone A** → به Charlie پیام بده: "relay test at [ساعت]"

**✅ نتیجه مورد انتظار:**
- [ ] پیام در iPhone C ظاهر بشه
- [ ] `hopCount` باید ≥ 1 باشه (یعنی relay شده)
- [ ] Badge "Bridge Mesh" یا "Multi-Hop" نشون بده
- [ ] iPhone B خودش پیام رو نمی‌بینه (چون مال اون نیست)

**⚠️ نکته:** اگه فاصله واقعی خیلی کم باشه ممکنه direct بره. بهترین کار:
- A رو تو یه اتاق بذار
- C رو تو اتاق دیگه
- B رو تو راهرو وسط بذار

---

## 🟡 سناریو ۳: Internet-First → Mesh Fallback

**هدف:** تست routing هوشمند — اول سرور، بعد mesh

**مراحل:**
1. **همه** اینترنت دارن (Airplane Mode خاموش)
2. **iPhone A** → به Bob پیام بده: "online test 1"
3. ✅ باید سریع و با badge آبی 🔵 "Server" برسه
4. حالا **iPhone B** → Airplane Mode ✈️ کن + Bluetooth روشن
5. ۵ ثانیه صبر کن
6. **iPhone A** → به Bob پیام بده: "offline test 2"

**✅ نتیجه مورد انتظار:**
- [ ] پیام اول "online test 1" → badge آبی (Server) ✅
- [ ] پیام دوم "offline test 2" → badge بنفش (Mesh) ✅
- [ ] MessageRouter اول سرور تست کرده، فهمیده Bob آفلاینه → mesh fallback

**🔍 لاگ مورد انتظار:**
```
[Router] Checking presence for Bob...
[Router] Recipient offline → mesh fallback
[BLE] Enqueued for broadcast
```

---

## 🔴 سناریو ۴: Mesh ACK + Delivery Receipt

**هدف:** تست اینکه ACK از mesh برمی‌گرده

**مراحل:**
1. هر ۲ تا Airplane Mode ✈️ + Bluetooth روشن
2. **iPhone A** → به Bob پیام بده
3. **لحظه‌ای که ارسال کردی، وضعیت پیام رو ببین:**

**✅ تغییرات وضعیت مورد انتظار:**
- [ ] ابتدا: ⏳ pending/sending
- [ ] بعد چند ثانیه: ✓ forwarding (mesh relay)
- [ ] وقتی رسید: ✓✓ delivered (دو تیک)
- [ ] وقتی Bob باز کرد: 👁 read (تیک آبی)

**🔍 تست خاص Read Receipt:**
1. iPhone B → پیام رو **نخون** (اپ رو ببند)
2. بعد ۱۰ ثانیه اپ رو باز کن و چت Alice رو باز کن
3. iPhone A باید Read Receipt بگیره

---

## 🟠 سناریو ۵: Deduplication (جلوگیری از پیام تکراری)

**هدف:** مطمئن شو پیام duplicate نمیشه

**مراحل:**
1. هر ۳ تا Airplane Mode ✈️ + Bluetooth روشن
2. ۳ تا رو نزدیک هم بذار (هر ۳ تا همدیگه رو ببینن)
3. **iPhone A** → به Bob پیام بده: "dedup test"

**✅ نتیجه مورد انتظار:**
- [ ] Bob فقط **یک بار** پیام رو می‌بینه (نه ۲ بار)
- [ ] Charlie پیام رو relay می‌کنه ولی خودش نمی‌بینه
- [ ] اگه Bob از هر ۲ مسیر (مستقیم + relay) دریافت کنه، فقط اولی نشون داده بشه

**🔍 لاگ مورد انتظار:**
```
[Dedup] Message ABC already seen → dropping duplicate
```

---

## 🟣 سناریو ۶: Store-and-Forward (DTN واقعی)

**هدف:** پیام رو ذخیره کن و بعداً deliver کن

**مراحل:**
1. **iPhone A** و **iPhone B** → Airplane Mode ✈️ + Bluetooth روشن
2. **iPhone C** → خاموش یا اپ رو ببند
3. **iPhone A** → به Charlie پیام بده: "DTN store test"
4. پیام نباید فوری برسه (C آفلاینه)
5. صبر کن ۱ دقیقه
6. **iPhone C** رو روشن کن، اپ رو باز کن، Bluetooth رو روشن کن
7. C رو نزدیک B ببر

**✅ نتیجه مورد انتظار:**
- [ ] پیام بعد از روشن شدن C ظاهر بشه
- [ ] `hopCount ≥ 1` باشه
- [ ] زمان اصلی ارسال (timestamp) درست باشه

---

## 🔶 سناریو ۷: Mesh Post Broadcast

**هدف:** تست ارسال Post از طریق mesh

**مراحل:**
1. هر ۳ تا Airplane Mode ✈️ + Bluetooth روشن
2. **iPhone A** → یه Post جدید بساز (فقط text، بدون عکس)
3. scope رو بذار "Local" یا "Public"

**✅ نتیجه مورد انتظار:**
- [ ] Post در Nearby Feed هر ۲ گوشی دیگه ظاهر بشه
- [ ] Source "Nearby" نشون بده
- [ ] Post فقط text باشه (media از mesh رد نمیشه)

---

## 📋 جدول خلاصه

| # | سناریو | A اینترنت | B اینترنت | C اینترنت | چی تست میشه |
|---|--------|-----------|-----------|-----------|-------------|
| 1 | Direct Mesh | ❌ | ❌ | - | BLE پایه |
| 2 | Multi-Hop | ❌ | ❌ | ❌ | Relay/Bridge |
| 3 | Fallback | ✅ | ❌ | - | Smart Routing |
| 4 | ACK | ❌ | ❌ | - | Delivery Receipt |
| 5 | Dedup | ❌ | ❌ | ❌ | Deduplication |
| 6 | Store-Forward | ❌ | ❌ | ❌→✅ | DTN |
| 7 | Post Broadcast | ❌ | ❌ | ❌ | MeshPost |

---

## 🐛 اگه کار نکرد

**BLE Connect نمیشه:**
- Bluetooth خاموش/روشن کن
- اپ رو Force Quit و دوباره باز کن
- Settings → Bluetooth → "Forget" دیوایس‌های قدیمی

**پیام نمیرسه:**
- Xcode Console چک کن: `[BLE]` و `[Router]`
- مطمئن شو `connectedPeers > 0`
- فاصله رو کم کن (BLE range ≈ 10-30 متر)

**Duplicate پیام:**
- Dedup cache پر شده؟ لاگ `[Dedup]` چک کن
- اپ رو restart کن

**ACK نمیاد:**
- لاگ `[ACK]` چک کن
- مطمئن شو هر ۲ طرف اپ foreground هست
