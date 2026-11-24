from playwright.sync_api import sync_playwright
def log(*a): print(*a, flush=True)
with sync_playwright() as p:
    dev=dict(p.devices["Pixel 7"]); dev["device_scale_factor"]=2
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome")
    pg=b.new_context(**dev).new_page(); pg.on("pageerror",lambda e:log("ERR",e)); pg.on("console",lambda m: log("console",m.text) if m.type=="error" else None)
    fonts=[]; pg.on("response", lambda r: fonts.append((r.url.split('/')[-1], r.status)) if r.url.endswith('.woff2') else None)
    pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(500)
    pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#recOk"); pg.click("#recOk")
    log("default picker count:", pg.evaluate("(async()=>{const d=await (await fetch('vendor/emoji.json')).json();return [d.flatMap(g=>g[1]).length, d.flatMap(g=>g[1]).filter(e=>e[3]<=15.1).length]})()"))
    log("fonts downloaded before toggle:", len(fonts))
    pg.click("#setBtn"); pg.wait_for_selector("#evSel"); pg.select_option("#evSel","99"); pg.click("[data-k='notoEmoji']"); pg.wait_for_timeout(300)
    log("html class notoemoji:", pg.evaluate("document.documentElement.classList.contains('notoemoji')"))
    pg.click("#mClose")
    # open a chat-less picker via settings? use emojiGrid through test: open message composer requires chat; render picker into modal
    pg.evaluate("""(async()=>{ document.getElementById('mTitle'); })()""")
    pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(400); pg.fill("#pin","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#app:not(.hidden)")
    log("settings persisted:", pg.evaluate("[window.__kv.ST.set.emojiVer, window.__kv.ST.set.notoEmoji]"))
    pg.evaluate("document.fonts.load('40px KavachEmoji','🫩')"); pg.wait_for_timeout(1500)
    log("KavachEmoji font loaded:", pg.evaluate("document.fonts.check('40px KavachEmoji','🫩')"), " woff2 fetched:", fonts[:3])
    b.close()
