# Browser tests (Playwright + Chrome)

```bash
pip install playwright pillow && python3 tests/make_assets.py
ALLOW_INSECURE=1 PORT=8099 HOST=127.0.0.1 node server.js &       # test_priv.py needs ACCESS_KEY=my-secret-key-123
for t in e2e b1 rand pin sh prot emo emo2; do python3 tests/test_$t.py; done
```
Each test drives 2–3 real browser sessions against the relay: pairing, messaging, re-keying, calls,
files, duress PIN, calculator, Random Connect, PIN recovery, share-out, protected chat, view-once,
emoji/stickers, private server mode. Every test also checks that no plaintext ever reaches the relay.
Edit the Chrome path (`/usr/bin/google-chrome`) in the scripts if yours differs.
