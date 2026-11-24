from playwright.sync_api import sync_playwright
def log(*a): print(*a, flush=True)
frames=[]
with sync_playwright() as p:
    dev=dict(p.devices["Pixel 7"]); dev["device_scale_factor"]=2
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--use-fake-device-for-media-stream","--use-fake-ui-for-media-stream"])
    def mk(n):
        pg=b.new_context(**dev,bypass_csp=True,permissions=["microphone","camera"]).new_page(); pg.on("pageerror",lambda e:log(n,"ERR",e))
        pg.on("websocket",lambda ws: ws.on("framesent",lambda f: frames.append(str(f))))
        pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(500)
        pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on",state="attached"); return pg
    A=mk("A"); B=mk("B")
    A.click("#invBtn"); A.wait_for_selector("#qrBox svg"); link=A.evaluate("window.__kv.inviteLink(window.__kv.invCur)")
    B.click("#joinBtn"); B.fill("#joinIn",link); B.click("#joinGo"); A.wait_for_selector("#reqYes"); A.fill("#reqName","GF"); A.click("#reqYes"); B.wait_for_selector("#chat:not(.hidden)",timeout=10000)
    # ---- protected chat ----
    A.click("#cMenu"); A.click("#protSw"); A.click("#mClose")
    B.wait_for_selector("#msgs .sys:has-text('turned on Protected')",timeout=8000); log("B notified:", B.inner_text("#msgs .sys >> nth=-1")[:60])
    log("B subtitle:", B.inner_text("#cSub"), "| A subtitle:", A.inner_text("#cSub"))
    A.fill("#input","secret baat 🤫"); A.click("#send"); B.wait_for_selector("#msgs .m.in:has-text('secret baat')")
    A.set_input_files("#fileIn","/tmp/photo.jpg"); B.wait_for_selector("#msgs .holdview img.blurred",timeout=20000); log("B photo is blurred hold-view")
    box=B.query_selector("#msgs .holdview").bounding_box()
    B.mouse.move(box["x"]+50,box["y"]+50); B.mouse.down(); B.wait_for_timeout(300)
    log("while holding -> revealed:", B.evaluate("document.querySelector('#msgs .holdview').classList.contains('reveal')")); B.screenshot(path="/tmp/p_hold.png")
    B.mouse.up(); B.wait_for_timeout(200); log("after release -> revealed:", B.evaluate("document.querySelector('#msgs .holdview').classList.contains('reveal')"))
    B.click("#msgs .m.in:has-text('secret baat')", button="right")
    log("protected msg actions -> copy:", B.is_visible("#maCopy"), " share:", B.is_visible("#maShare"), " note:", B.is_visible("text=copy, save and share are disabled"))
    B.screenshot(path="/tmp/p_actions.png"); B.click("#mClose")
    A.set_input_files("#fileIn","/tmp/doc.pdf"); B.wait_for_selector("#msgs .fdl:has-text('saving disabled')",timeout=20000); log("B pdf: no download link:", B.query_selector("#msgs a.fdl") is None)
    # ---- view once ----
    A.click("#voBtn"); log("A vo toggled:", A.evaluate("document.getElementById('voBtn').classList.contains('on')"))
    A.set_input_files("#fileIn","/tmp/photo.jpg")
    B.wait_for_selector("#msgs [data-vo]",timeout=20000); A.wait_for_selector("#msgs .vochip:has-text('sent')",timeout=20000); log("A sees: 'view-once sent', voBtn reset:", not A.evaluate("document.getElementById('voBtn').classList.contains('on')"))
    B.click("#msgs [data-vo]"); B.wait_for_selector("#vo:not(.hidden) img"); B.wait_for_timeout(1200); log("B viewer:", B.inner_text("#voInfo")); B.screenshot(path="/tmp/p_vo.png")
    B.click("#voX"); B.wait_for_selector("#msgs .vochip:has-text('opened')"); A.wait_for_selector("#msgs .vochip:has-text('opened ✓')",timeout=8000); log("both sides show opened")
    log("B can re-open?", B.query_selector("#msgs [data-vo]") is not None)
    # view-once voice note
    A.click("#voBtn"); A.click("#micBtn"); A.wait_for_timeout(1500); A.click("#recSend")
    B.wait_for_selector("#msgs [data-vo]:has-text('voice')",timeout=20000); log("view-once voice arrived")
    B.click("#msgs [data-vo]"); B.wait_for_selector("#vo:not(.hidden) audio"); B.wait_for_timeout(3500)
    log("voice auto-closed after playing:", B.evaluate("document.getElementById('vo').classList.contains('hidden')"))
    # turn protected off from B side
    B.click("#cMenu"); B.click("#protSw"); B.click("#mClose"); A.wait_for_selector("#msgs .sys:has-text('turned off Protected')",timeout=8000); log("A notified of off")
    log("leaks:", len([f for f in frames if 'secret baat' in f]))
    b.close()
