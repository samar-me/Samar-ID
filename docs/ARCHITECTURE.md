# SAMAR OS — MEGA-ECOSYSTEM MANIFEST & ARCHITECTURE

> **Falsafa:**  
> "Katta korporatsiyalarning kuzatuvi va keraksiz reklamalaridan xoli, erkin, mustaqil va xavfsiz shaxsiy raqamli ekotizim."

---

## 1. Asosiy Tamoyillar (Core Principles)

1. **Reklamasizlik va Maxfiylik (No Ads & Zero Tracking):**
   - Tizim ichida hech qanday uchinchi tomon trekerlari va reklama tarmoqlari bo'lmaydi.
   - Foydalanuvchi ma'lumotlari uning shaxsiy mulki hisoblanadi.

2. **Har bir inson uchun to'liq erkinlik (Equal Power to Every User):**
   - Samar ID olgan har bir foydalanuvchi (muallif, do'st, dasturchi yoki hamkasb) tizimning barcha imkoniyatlaridan to'laqonli foydalana oladi (shaxsiy messenjer, bulut, xotira, bilimlar bazasi).

3. **Ishonchli va Toza Auditoriya (Community of Trust):**
   - Dunyodagi barcha odamlarni majburlab jalb qilish maqsadi yo'q.
   - Tizim haqiqiy qulaylik, erkinlik va xavfsizlikni qadrlaydigan, bir-biriga ishonadigan insonlar va dasturchilar uchun mo'ljallangan.

4. **Saralangan Axborot (Samar News):**
   - Tashqi dunyodan shovqin-suronsiz, shov-shuvli clickbaitlardan xoli, eng muhim texnologik va global yangiliklar filtrlangan holda yetkaziladi.

---

## 2. Ekotizimning Bosqichma-bosqich Yo'l Xaritasi

### 1-Bosqich: Poydevor va O'zak (1-2 Yil)
- **Samar ID:** Yagona xavfsiz kirish va profil boshqaruvi tizimi (SSO). Rasmiy format: `nom@samar.os`.
- **Samar AI Agent:** Tizim bilan integratsiyalashgan shaxsiy intellektual yordamchi.
- **Samar Cloud & Moments:** Xavfsiz shaxsiy fayl va foto arxivlari.
- **Samar Drop:** Qurilmalararo tezkor va shifrlangan fayl almashish.
- **Samar Browser & App Store:** Xavfsiz brauzer va ekotizim ilovalar markazi.

### 2-Bosqich: Muloqot va Unumdorlik (3-Yil)
- **Samar Chat:** Shaxsiy, shifrlangan messenjer (P2P / shaxsiy server aloqasi).
- **Samar News:** Shovqinsiz, toza yangiliklar oqimi.
- **Samar Docs & Notes:** Notion va Office muqobili bo'lgan bilimlar bazasi.
- **Samar Launcher:** Samar OS ishchi muhiti va interfeysi.
- **Samar Calendar & Pay:** Taqvim va ichki hisob-kitoblar tizimi.

### 3 & 4-Bosqichlar: To'liq Ekotizim va Kelajak (4-7+ Yil)
- Mail, Meet, Maps, SDK, Spatial/VR, Mesh (Offline aloqa) va boshqa ilg'or modullar.

---

## 3. Qurilmalar Bo'yicha Tizim Arxitekturasi (Device Architecture)

### A. Samar OS Mobile (Smartfonlar uchun)
- **Yadro (Base):** AOSP (Android Open Source Project) — toza, ochiq kodli, mustaqil poydevor.
- **Brending & Boot:** "Powered by Samar OS" shaxsiy yuklanish animatsiyasi va ovozi.
- **Samar System UI:** Sozlamalar (Settings), Holat paneli (Status Bar), Bildirishnomalar markazi (Notification Center) va Qulflangan ekran (Lockscreen) — barchasi noldan Samar OS dizayn tili asosida.
- **Moslik (Compatibility):** Davlat (Soliq, MyGov) va bank ilovalari (Click, Payme) bilan tabiiy va to'laqonli moslik.
- **Tizim O'zagi:** Google xizmatlari o'rniga — **Samar ID**, **Samar Cloud**, **Samar AI**.

### B. Samar OS Desktop (Kompyuter va Noutbuklar uchun)
- **Yadro (Base):** Mustaqil Linux Distro (Debian / Arch poydevori).
- **Desktop Shell:** Samar Shell — qulay, minimalist, zamonaviy ishchi stoli va oynalar tizimi.
- **Ekotizim Integratsiyasi:** Mobil Samar OS bilan uzluksiz sinxronizatsiya (Samar Drop, Clipboard, Bildirishnomalar).

---

## 4. Texnik Stek (Core Tech Stack)

- **Miya va Yurak (Core Backend & AI):** Python (FastAPI, AI agentlari, xavfsizlik, ma'lumotlar bazasi).
- **Mobil Tizim (Mobile UI & AOSP):** Kotlin / Java (AOSP Framework & SystemUI modifikatsiyalari).
- **Desktop Interfeys (UI / Shell):** TypeScript / Web / Rust / Wayland.
- **Ma'lumotlar Bazasi:** PostgreSQL + SQLite (lokal shifrlangan saqlash uchun).

