# Kavach test APK — Ubuntu par bina Android Studio ke

Ye APK ek Android app hai jo khulte hi tumhare Kavach server (NUC) ko full screen mein kholta hai.
App ka code server se hi aata hai, isliye server par jo update karoge wo app mein apne aap aa jayega.

## 1. Ek baar ka setup: Node.js aur Java 17
```bash
sudo apt update
sudo apt install -y openjdk-17-jdk unzip curl
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
java -version     # 17 dikhna chahiye
node -v           # v20 dikhna chahiye
```
Agar `java -version` 17 nahi dikhata: `sudo update-alternatives --config java` chala ke 17 chuno.

## 2. Ek baar ka setup: Android SDK (sirf command-line tools)
```bash
mkdir -p ~/Android/Sdk/cmdline-tools && cd ~/Android/Sdk/cmdline-tools
curl -LO https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q commandlinetools-linux-*_latest.zip && mv cmdline-tools latest && rm commandlinetools-linux-*_latest.zip

echo 'export ANDROID_HOME=$HOME/Android/Sdk' >> ~/.bashrc
echo 'export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools' >> ~/.bashrc
source ~/.bashrc

yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```
Agar link kaam na kare to https://developer.android.com/studio par "Command line tools only" → Linux wala zip lo.

## 3. VS Code mein project kholo
```bash
unzip kavach-secure.zip -d ~/
code ~/kavach-secure
```
VS Code mein terminal kholo: **Ctrl + `** (ya menu Terminal → New Terminal). Terminal `kavach-secure` folder mein khulega.

## 4. APK banao (har baar yahi ek command)
```bash
cd android-app
./build-apk.sh https://192.168.1.50:8443
```
`192.168.1.50` ki jagah apne NUC ka IP likho. Pehli baar 5–10 minute lagenge, kyunki Gradle download hota hai.
Last mein likha aayega: `DONE -> .../kavach-secure/Kavach-test.apk`

## 5. Phone par install
1. Phone mein mkcert ka `rootCA.pem` pehle se install hona chahiye: Settings → Security → Encryption & credentials → Install a certificate → **CA certificate**.
2. `Kavach-test.apk` phone par bhejo (USB, Telegram, Drive, kuch bhi) aur kholo. "Install unknown apps" ki permission maange to de do.
3. Ya USB debugging on karke: `adb install -r ../Kavach-test.apk`
4. Pehli call par camera aur mic ki permission Allow karo.

## Dikkat aaye to
| Problem | Kya karo |
|---|---|
| `Android SDK not found` | Step 2 dobara karo, phir `source ~/.bashrc` |
| `Unsupported class file major version` | Java 17 nahi chal raha → `sudo update-alternatives --config java` |
| App khulti hai par safed/khaali screen | Phone aur NUC ek hi Wi-Fi par hain? Phone ke Chrome mein wahi address khulta hai? |
| Certificate error | rootCA phone mein **CA certificate** ke roop mein install karo (VPN/app user cert nahi) |
| Server ka IP badla | Naye IP ke saath `./build-apk.sh` dobara chalao aur APK dobara install karo |
