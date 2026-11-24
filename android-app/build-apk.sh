#!/usr/bin/env bash
# Builds a test APK of Kavach that opens your Kavach server.
# Usage:  ./build-apk.sh https://192.168.1.50:8443
set -e
URL="$1"
if [ -z "$URL" ]; then
  echo "Usage: ./build-apk.sh https://<NUC-IP>:8443"; exit 1
fi
case "$URL" in https://*) ;; *) echo "Address must start with https://"; exit 1;; esac

cd "$(dirname "$0")"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
[ -d "$ANDROID_HOME/platforms" ] || { echo "Android SDK not found in $ANDROID_HOME (see BUILD-APK.md step 2)"; exit 1; }
command -v java >/dev/null || { echo "Java not found (see BUILD-APK.md step 1)"; exit 1; }

echo "==> Installing Capacitor (first time only)"
[ -d node_modules ] || npm install --no-audit --no-fund

echo "==> Writing capacitor.config.json for $URL"
cat > capacitor.config.json <<EOF
{
  "appId": "com.araham.kavach",
  "appName": "Kavach",
  "webDir": "www",
  "server": { "url": "$URL", "cleartext": false },
  "android": { "backgroundColor": "#070027" }
}
EOF

if [ ! -d android ]; then
  echo "==> Creating Android project"
  npx cap add android
fi

echo "==> App icon"
npx capacitor-assets generate --android --iconBackgroundColor '#070027' --splashBackgroundColor '#070027' \
  || echo "   (icon step failed, APK will use the default icon)"

echo "==> Syncing"
npx cap sync android

MF=android/app/src/main/AndroidManifest.xml
echo "==> Camera, mic and certificate permissions"
for P in CAMERA RECORD_AUDIO MODIFY_AUDIO_SETTINGS; do
  grep -q "android.permission.$P" "$MF" || \
    sed -i "s#<application#<uses-permission android:name=\"android.permission.$P\" />\n    <application#" "$MF"
done
grep -q networkSecurityConfig "$MF" || \
  sed -i 's#<application#<application android:networkSecurityConfig="@xml/network_security_config"#' "$MF"
mkdir -p android/app/src/main/res/xml
cat > android/app/src/main/res/xml/network_security_config.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- Trust the mkcert root CA you installed on the phone (user certificates). -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
EOF

echo "==> Building APK (first build downloads Gradle, takes a few minutes)"
( cd android && chmod +x gradlew && ./gradlew assembleDebug )

cp android/app/build/outputs/apk/debug/app-debug.apk ../Kavach-test.apk
echo ""
echo "DONE  ->  $(cd .. && pwd)/Kavach-test.apk"
