# Kavach — har device ke liye app (Ubuntu PC se)

| Device | File | Kahan banegi |
|---|---|---|
| Android phone/tab | `Kavach-test.apk` | Tumhara Ubuntu PC |
| Ubuntu/Linux | `.AppImage` / `.deb` | Tumhara Ubuntu PC |
| Windows | `Kavach-Setup-1.0.0.exe` | GitHub (free cloud Windows) |
| MacBook | `.dmg` | GitHub (free cloud Mac) |
| iPhone/iPad | `Kavach-unsigned.ipa` | GitHub (free cloud Mac) |

Mac aur iPhone ki files sirf Mac par ban sakti hain (Apple ka rule). Windows ki file bhi Windows par sabse
bharose se banti hai. Isliye ye teeno GitHub ki free cloud machines par bante hain. Tumhe sirf ek button dabana hai.

---

## 0. Ek baar ka setup (Ubuntu)
```bash
sudo apt update
sudo apt install -y git curl unzip openjdk-17-jdk
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```
Android SDK: `android-app/BUILD-APK.md` ka step 2.

Project kholo:
```bash
unzip kavach-secure.zip -d ~/
code ~/kavach-secure          # VS Code mein Ctrl + ` se terminal
```

## 1. Android APK (Ubuntu par)
```bash
cd ~/kavach-secure/android-app
./build-apk.sh https://192.168.1.50:8443        # apne NUC ka IP
```
Result: `~/kavach-secure/Kavach-test.apk`

## 2. Ubuntu desktop app (Ubuntu par)
```bash
cd ~/kavach-secure/desktop-app
npm install
npm start                    # bina build kiye seedha chala ke dekho
npm run build:linux          # installer banao
sudo apt install ./dist/kavach-desktop_1.0.0_amd64.deb
```
Ya bina install: `chmod +x dist/Kavach-1.0.0.AppImage && ./dist/Kavach-1.0.0.AppImage`
Pehli baar app server ka address poochegi; baad mein menu **Kavach → Change server** se badlo.

## 3. Windows, MacBook, iPhone (GitHub se)
Ek baar:
1. https://github.com par free account banao → **New repository** → naam `kavach` → **Private** → Create.
2. Ubuntu terminal:
```bash
cd ~/kavach-secure
git remote add origin https://github.com/<tumhara-username>/kavach.git
git branch -M main
git push -u origin main
```
(password ki jagah GitHub **Personal access token** lagega: GitHub → Settings → Developer settings → Tokens.)
3. GitHub par repo → **Settings → Secrets and variables → Actions → Variables → New variable**:
   naam `KAVACH_URL`, value `https://192.168.1.50:8443`

Har baar build ke liye:
4. Repo → **Actions** → **Build Kavach apps** → **Run workflow**.
5. ~15 minute baad wahi page par neeche **Artifacts** mein files download karo:
   `Kavach-desktop-windows-latest` (.exe), `Kavach-desktop-macos-latest` (.dmg),
   `Kavach-desktop-ubuntu-latest`, `Kavach-android` (.apk), `Kavach-ios-unsigned` (.ipa).

Private repo par GitHub har mahine free minutes deta hai (Mac machine minutes zyada kha'ti hai) — testing ke liye kaafi hai.

## 4. Install karte waqt
- **Windows:** `.exe` chalao. "Windows protected your PC" aaye to **More info → Run anyway** (app signed nahi hai).
- **MacBook:** `.dmg` kholo, Kavach ko Applications mein daalo. Pehli baar **right-click → Open → Open**
  (unsigned app). Agar "damaged" bole: `xattr -cr /Applications/Kavach.app`
- **iPhone:** unsigned `.ipa` seedha install nahi hoti. Windows ya Mac par **Sideloadly** se, free Apple ID ke saath
  install karo. Free Apple ID par app 7 din chalti hai, phir Sideloadly se dobara. Bina is jhanjhat ke:
  Safari → server address → Share → **Add to Home Screen**.
- **Har device par** mkcert ka `rootCA.pem` trust hona chahiye:
  - Ubuntu: `sudo cp rootCA.pem /usr/local/share/ca-certificates/kavach.crt && sudo update-ca-certificates`
    aur Chrome/desktop app ke liye `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n kavach -i rootCA.pem` (`sudo apt install libnss3-tools`)
  - Windows: `rootCA.pem` ko `rootCA.crt` naam do → double-click → Install Certificate → Local Machine → "Trusted Root Certification Authorities"
  - Mac: double-click → Keychain "System" → certificate kholo → Trust → **Always Trust**
  - iPhone: file bhejo → Settings → Profile Downloaded → Install → phir Settings → General → About → Certificate Trust Settings → ON
  - Android: Settings → Security → Install a certificate → CA certificate

## Desktop app mein extra
- Windows aur Mac par Kavach ki window screenshot/screen-recording mein **kaali** dikhti hai.
- Linux par ye block possible nahi hai (Linux mein aisa koi system feature nahi).
