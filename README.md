# Kavach — secure messenger (relay + E2EE web client)

**WebSocket** se messaging aur **WebRTC** se voice/video calls. Saara encryption phone/laptop ke browser mein hota hai. Server (tumhara NUC) sirf ek "andha dakiya" hai: encrypted lifafe aage pahunchata hai, padh kuch nahi sakta.

## Kya-kya secure hai

| Cheez | Kaise |
|---|---|
| Pehchaan | Koi account, user ID, username ya phone number nahi hai. Har contact ke liye fresh P-256 keys aur ek alag random mailbox banta hai. |
| Jodna | **One-time QR/link**. Har QR naya aur unique hota hai, ek hi baar use hota hai, har 30s mein rotate hota hai (ya 10 min mein khatam). Purana QR server se delete ho jaata hai. |
| Bichauliya (MITM) se bachav | Dono screens par 6 emoji aur 10 digit ka safety code aata hai. Match hone par hi Accept karo. |
| Messages | AES-256-GCM. **Har message ki alag key** (hash-chain ratchet), isliye forward secrecy milti hai. |
| Key refresh | Har 40 messages par naya ECDH re-key hota hai, jisse chori hui key ki recovery ho jaati hai. "Refresh keys" button bhi hai. |
| Length chhupana | Har message fixed size buckets (256 B / 1 KB / 4 KB / …) mein pad hota hai. |
| Replay / tamper | Header AAD se bandha hai. Purana ya badla hua message chupchaap reject ho jaata hai. |
| Calls | WebRTC DTLS-SRTP. Offer, answer aur ICE candidates **E2EE channel ke andar** jaate hain, toh server ko SDP ya IP nahi dikhte. TURN relay laga ho toh IP chhupane ka option bhi hai. |
| Server | Memory-only, disk par kuch nahi, koi logs nahi. Message delivery ke turant baad delete hota hai. Rate-limit lagi hai. Strict CSP aur security headers hain. Mailbox ID = SHA-256(secret), isliye sirf owner padh sakta hai. |
| Device | Saara data ek random key se encrypt hota hai. Wo key tumhare **PIN** aur ek **Recovery Key** (24 characters, sirf ek baar dikhti hai) se lock hoti hai. PBKDF2 310k rounds + AES-GCM. **Change PIN** ke liye purana PIN chahiye. **PIN bhool gaye** toh recovery key se naya PIN set karo, chats safe rehti hain. Settings se nayi recovery key bana sakte ho, purani bekaar ho jaati hai. 10 galat koshish par erase (Settings mein off kar sakte ho). Background mein screen chhup jaati hai, auto-lock bhi hai. |
| Extra | Disappearing messages, delete for everyone, read receipts aur typing indicator off kar sakte ho, clipboard 60s mein auto-clear, panic wipe. |


## Naye features (batch 1)
| Feature | Kaise kaam karta hai |
|---|---|
| 🔢 Secret code se jodna | Dono log same 3 shabd type karte hain (jaise `kari-mope-sutu`). Na QR, na link, na ID. Code ko PBKDF2 300k rounds se mazboot kiya jaata hai, ye 10 min tak aur sirf ek baar chalta hai. Uske baad emoji check hota hai. |
| ↩️ Reply / 🔥 React | Message par long-press ya right-click karo. Double-tap karne par ❤️ lagta hai. Ye bhi encrypted jaata hai. |
| 🖼 Photo / 📎 File | 8 MB tak, 24 KB ke tukdon mein, har tukda ratchet se encrypt. Photo dobara banayi jaati hai, isliye **EXIF/GPS hat jaata hai**. Phone mein IndexedDB ke andar vault key se encrypted rehti hai. |
| 🎤 Voice note | Opus codec, 5 min tak. Baaki sab file jaisa hi. |
| 🎭 Duress PIN | Doosra PIN daalo toh ek khaali Kavach khulta hai jo bilkul normal dikhta hai. Chaho toh asli chats bhi chupchaap mit jaati hain. Data mein dekh kar pata nahi chalta ki duress PIN set hai ya nahi. |
| 🧮 Calculator disguise | Lock screen ek chalta hua calculator ban jaata hai. PIN type karke `=` dabao toh app khulta hai. `=` ko 1.5 sec dabaye rakho toh normal lock screen aata hai. |
| ⚠️ Screenshot alert | Desktop par PrintScreen dabane par screen chhup jaati hai aur doosre ko alert jaata hai. Mobile browser mein ye detect nahi ho sakta, uske liye native app chahiye. |
| 🎨 32 themes + 18 accent colors | Settings → Look |
| 💞 Random Connect (18+) | Ladka sirf ladki se aur ladki sirf ladke se milta hai (gender user khud batata hai). Har stranger ke liye nayi keys aur naya mailbox banta hai, koi naam ya ID share nahi hota. Chat, photo, voice aur call shuru se khule hain. ⏭ **Next** dabane par poori chat, media aur keys mit jaati hain. 🚩 **Report** karne par 1 ghante mein 3 alag logon ke report aaye toh us network ko 1 ghante ke liye block kar diya jaata hai (IP sirf salted hash ke roop mein memory mein rehta hai). Strangers ki photo blur karne ka option bhi hai. |
| 🔒 Protected chat | Chat menu (⋮) mein ek switch hai, jo dono taraf ek saath on hota hai. Isme save, share, copy aur download band ho jaate hain. Photo blur rehti hai aur sirf **dabaye rakhne par** dikhti hai. Video aur voice download nahi ho sakte. Koi bhi ise on/off kare, doosre ko pata chalta hai. |
| 👁 View once | Composer mein 👁 dabao, phir photo, video ya voice bhejo. Receiver use sirf ek baar dekh sakta hai: photo 10 sec ke liye, video/voice khatam hone tak. App background mein jaate hi band ho jaata hai. Uske baad file **dono phones se mit jaati hai**, sender ke paas bhi copy nahi rehti. Sender ko "opened ✓" dikhta hai. |
| 🔑 Private server mode | `kavach.env` mein `ACCESS_KEY=...` set karo. Ab sirf wahi devices connect ho payenge jinhone Settings → Security → Private server mein wahi key daali hai. Baaki sabko server mana kar deta hai. |
| 😀 Saare emoji | Unicode ke saare **1,898 emoji** hain (Emoji 15.1 tak, jo har naye phone par dikhte hain). Search, 9 categories, recent, aur **skin tone** bhi (👍🏾, 🧑🏾‍💻). Reaction mein bhi koi bhi emoji laga sakte ho (➕). |
| 🧩 Stickers | Har format chalta hai: **WebP** (static aur animated, WhatsApp wala format), **PNG/APNG**, **GIF**, **WebM video stickers** aur **.tgs animated stickers** (Telegram ka Lottie format). Apne packs bana sakte ho, files import kar sakte ho, kisi bhi emoji ko bada sticker bana sakte ho, aur mile hue sticker ko "⭐ Saved" mein rakh sakte ho. Sab phone mein encrypted rehta hai. |
| 📤 Doosri apps par share | Message ya media par long-press karke **Share to other apps** chuno. Phone ka share menu khulta hai (WhatsApp, Instagram, Facebook, Snapchat, Telegram…). Text ke liye WhatsApp, Telegram, X aur Email ke seedhe buttons bhi hain. Share se pehle warning aati hai ki bahar jaane ke baad encryption nahi rahega. |

## Jaldi test (ek hi laptop par)

```bash
npm install
npm run dev            # http://localhost:8080
```

Do alag browser profiles kholo (jaise Chrome aur Chrome Incognito). Ek mein **Invite** dabao, doosre mein **Join** karke link paste karo, emoji match karo aur Accept karo.

## NUC par asli setup (LAN / offline Wi-Fi par bhi chalega)

1. **TLS certificate** (zaroori hai, kyunki browser camera/mic aur crypto sirf HTTPS par deta hai):
   ```bash
   sudo apt install mkcert libnss3-tools && mkcert -install
   sudo mkdir -p /etc/kavach && cd /etc/kavach
   sudo mkcert -cert-file cert.pem -key-file key.pem 192.168.1.50 nuc.local localhost
   ```
   Phones par `mkcert -CAROOT` wala `rootCA.pem` install karna hoga, tabhi warning nahi aayegi.

2. **Relay ko service ki tarah chalao:**
   ```bash
   sudo useradd -r -s /usr/sbin/nologin kavach
   sudo mkdir -p /opt/kavach && sudo cp -r server.js package.json public node_modules /opt/kavach/
   sudo cp deploy/kavach.env /etc/kavach/ && sudo nano /etc/kavach/kavach.env   # IP + secret badlo
   sudo chown -R root:kavach /etc/kavach && sudo chmod 640 /etc/kavach/*
   sudo cp deploy/kavach.service /etc/systemd/system/ && sudo systemctl enable --now kavach
   ```
   Secret banane ke liye: `openssl rand -hex 32`

3. **coturn (calls ke liye TURN/STUN):**
   ```bash
   sudo apt install coturn
   sudo cp deploy/turnserver.conf /etc/turnserver.conf   # wahi secret daalo
   sudo systemctl enable --now coturn
   ```

4. **Firewall:** `8443/tcp`, `3478/tcp+udp`, `5349/tcp` aur `49152-65535/udp` kholo.

5. Phone ke browser mein `https://192.168.1.50:8443` kholo, phir "Add to Home screen" kar lo.

### Offline mode (bina internet ke)
Router, hotspot ya NUC ka Wi-Fi on karo, internet ki zarurat nahi. Sab devices usi Wi-Fi par honge toh chat aur calls dono LAN par chalenge. LAN-only setup mein `turnserver.conf` ki private-IP wali `denied-peer-ip` lines comment kar dena.

## Imaandari se limits
- **WhatsApp/Telegram ke sticker packs** unke artists ki copyrighted artwork hain, isliye app ke saath nahi diye gaye. Jo stickers tumhare paas files ke roop mein hain (.webp, .tgs, .webm, .gif), unhe import kar sakte ho. Emoji ka design phone ke font ka hota hai, isliye Android, iPhone aur Windows par thoda alag dikhta hai.
- **Random Connect:** Gender aur 18+ user khud batata hai, inhe verify karne ka koi tarika nahi hai. Server hi match karwata hai, isliye stranger chats mein theory mein wo beech mein aa sakta hai (MITM). Agar kisi stranger par bharosa karna hai, toh "Save as contact" karke safety code milao.
- Ye ek mazboot prototype hai, **audit nahi hua**. Production ke liye ratchet ko **libsignal** (Double Ratchet + PQXDH) se badalna aur kisi security expert se review karwana sahi rahega.
- Server tumhara IP aur kaun-kaun se mailbox ek hi connection par hain, ye dekh sakta hai. Asli anonymity ke liye Tor/onion service ya alag connections chahiye.
- Agar phone khud hack hai, toh koi bhi app nahi bacha sakta.
- Browser version mein screenshots poori tarah block nahi ho sakte. Native app (Android `FLAG_SECURE`) mein ho sakte hain.
