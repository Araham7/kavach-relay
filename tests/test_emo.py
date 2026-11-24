from playwright.sync_api import sync_playwright
def log(*a): print(*a, flush=True)
frames=[]
with sync_playwright() as p:
    dev=dict(p.devices["Pixel 7"]); dev["device_scale_factor"]=2
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome")
    def mk(n):
        pg=b.new_context(**dev).new_page(); pg.on("pageerror",lambda e:log(n,"ERR",e)); pg.on("console",lambda m: log(n,"console",m.text) if m.type=="error" else None)
        pg.on("websocket",lambda ws: ws.on("framesent",lambda f: frames.append(str(f))))
        pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(500)
        pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on",state="attached"); return pg
    A=mk("A"); B=mk("B")
    A.click("#invBtn"); A.wait_for_selector("#qrBox svg"); link=A.evaluate("window.__kv.inviteLink(window.__kv.invCur)")
    B.click("#joinBtn"); B.fill("#joinIn",link); B.click("#joinGo"); A.wait_for_selector("#reqYes"); A.click("#reqYes"); B.wait_for_selector("#chat:not(.hidden)",timeout=10000)
    log("emoji count:", A.evaluate("window.__kv.emojiCount()"))
    A.click("#emoBtn"); A.wait_for_selector(".egrid button"); A.screenshot(path="/tmp/e_picker.png")
    A.fill(".esearch","fire"); A.wait_for_timeout(200); log("search 'fire' results:", A.eval_on_selector_all(".egrid button","b=>b.slice(0,6).map(x=>x.textContent)"))
    A.click(".egrid button >> nth=0")
    A.fill(".esearch","thumbs up"); A.click("[data-tone='4']"); A.wait_for_timeout(200); toned=A.inner_text(".egrid button >> nth=0"); log("toned thumbs:", toned); A.click(".egrid button >> nth=0")
    A.fill(".esearch","flag india"); A.wait_for_timeout(200); A.click(".egrid button >> nth=0")
    A.fill(".esearch","technologist"); A.wait_for_timeout(200); log("toned ZWJ:", A.inner_text(".egrid button >> nth=0")); A.click(".egrid button >> nth=0")
    log("input now:", A.input_value("#input")); A.click("#send")
    B.wait_for_selector("#msgs .m.in .tx"); log("B got:", B.inner_text("#msgs .m.in .tx"))
    # stickers: emoji sticker
    A.click("[data-ptab='stk']"); A.click("[data-pack='emoji']"); A.wait_for_selector("#sGrid .egrid button"); A.fill("#sGrid .esearch","cat with tears"); A.wait_for_timeout(200); A.click("#sGrid .egrid button >> nth=0")
    B.wait_for_selector("#msgs .m.in.stkm img.stk",timeout=15000); log("B got emoji sticker")
    # new pack + import
    A.click("[data-act='newpack']"); A.fill("#pkName","Hum dono 💕"); A.click("#pkOk"); A.wait_for_selector("[data-act='import']")
    A.set_input_files("#stkIn",["/tmp/stk/heart.gif","/tmp/stk/anim.webp","/tmp/stk/static.jpg","/tmp/stk/clip.webm","/tmp/stk/bounce.tgs"]); A.wait_for_timeout(2500)
    log("pack items:", A.evaluate("window.__kv.ST.stk.packs.find(p=>p.name.startsWith('Hum')).items.map(i=>i.mime)"))
    A.screenshot(path="/tmp/e_pack.png")
    for i in range(5):
        A.click(f"#sGrid .sitem[data-i='{i}']"); A.wait_for_timeout(600)
    B.wait_for_selector("#msgs .stk.lottie svg",timeout=20000); B.wait_for_selector("#msgs video.stk",timeout=20000)
    log("B stickers: imgs", B.eval_on_selector_all("#msgs img.stk","x=>x.length"), " video", B.eval_on_selector_all("#msgs video.stk","x=>x.length"), " lottie-svg", B.eval_on_selector_all("#msgs .lottie svg","x=>x.length"))
    B.wait_for_timeout(800); B.screenshot(path="/tmp/e_chat.png")
    # any-emoji reaction + save received sticker
    B.click("#msgs .m.in .tx", button="right"); B.click("#maMore"); B.wait_for_selector("#maPick .egrid button"); B.fill("#maPick .esearch","melting"); B.wait_for_timeout(200); B.click("#maPick .egrid button >> nth=0")
    A.wait_for_selector("#msgs .rc:has-text('🫠')",timeout=8000); log("any-emoji reaction ok (🫠)")
    B.click("#msgs .m.in.stkm >> nth=-1", button="right"); B.click("#maStk"); B.wait_for_timeout(600); log("saved received sticker:", B.evaluate("window.__kv.ST.stk.packs[0].items.length"))
    log("recent stickers on A:", A.evaluate("window.__kv.ST.stk.recent.length"))
    log("leaks:", len([f for f in frames if 'technologist' in f or '🔥' in f]))
    b.close()
