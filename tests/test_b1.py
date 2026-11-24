import time
from playwright.sync_api import sync_playwright
URL="http://localhost:8099/?test=1"
frames=[]
def log(*a): print(*a, flush=True)
with sync_playwright() as p:
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--use-fake-device-for-media-stream","--use-fake-ui-for-media-stream"])
    def mk(name, pin="123456"):
        ctx=b.new_context(viewport={"width":1200,"height":800}, permissions=["camera","microphone","clipboard-read","clipboard-write"], bypass_csp=True)
        pg=ctx.new_page()
        pg.on("pageerror",lambda e:log(name,"PAGEERROR",e))
        pg.on("websocket",lambda ws: ws.on("framesent",lambda f: frames.append(f if isinstance(f,str) else str(f))))
        pg.goto(URL); pg.wait_for_timeout(600)
        pg.fill("#pin",pin); pg.fill("#pin2",pin); pg.click("#pinBtn")
        pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on", state="attached")
        return ctx,pg
    ca,A=mk("A"); cb,B=mk("B")
    # ---- room code pairing ----
    A.click("#roomBtn"); A.click("#rmNew")
    A.wait_for_selector("#rmState .reccode", timeout=15000); code=A.inner_text("#rmState .reccode"); log("room code:",code)
    B.click("#roomBtn"); B.fill("#rmIn", code.upper().replace('-',' ')); B.click("#rmGo")
    A.wait_for_selector("text=New contact request", timeout=20000); B.wait_for_selector("text=Waiting for approval", timeout=20000)
    log("room SAS match:", A.inner_text("#mBody .sas")==B.inner_text("#mBody .sas"))
    A.click("#reqYes"); A.wait_for_selector("#chat:not(.hidden)"); B.wait_for_selector("#chat:not(.hidden)", timeout=10000)
    # wrong code attempt from C
    cc,C=mk("C"); C.click("#roomBtn"); C.fill("#rmIn", code); C.click("#rmGo"); C.wait_for_timeout(3000); log("reuse room code:", C.inner_text("#rmState"))
    # ---- reply + react ----
    A.fill("#input","pehla message"); A.press("#input","Enter")
    B.wait_for_selector("#msgs .m.in:has-text('pehla message')")
    B.click("#msgs .m.in:has-text('pehla message')", button="right"); B.click("#maReply")
    B.fill("#input","ye reply hai"); B.press("#input","Enter")
    A.wait_for_selector("#msgs .m.in .quote:has-text('pehla message')", timeout=8000); log("reply quote shown on A")
    A.click("#msgs .m.in:has-text('ye reply hai')", button="right"); A.click("[data-qr='🔥']")
    B.wait_for_selector("#msgs .m.out .rc:has-text('🔥')", timeout=8000); log("reaction arrived on B")
    # ---- photo with EXIF ----
    A.set_input_files("#fileIn","/tmp/photo.jpg")
    B.wait_for_selector("#msgs img.fimg", timeout=20000); log("photo received & rendered")
    got=B.evaluate("""async()=>{const im=document.querySelector('#msgs img.fimg');const r=await fetch(im.src);const t=new Uint8Array(await r.arrayBuffer());const s=new TextDecoder('latin1').decode(t);return [t.length, s.includes('GPSDATA-SECRET'), s.includes('Exif')]}""")
    log("received photo bytes/has GPS/has EXIF:", got)
    # ---- file ----
    A.set_input_files("#fileIn","/tmp/doc.pdf")
    B.wait_for_selector("#msgs a.fdl:has-text('doc.pdf')", timeout=20000); log("pdf received")
    sz=B.evaluate("""async()=>{const a=[...document.querySelectorAll('#msgs a.fdl')].pop();const r=await fetch(a.href);return (await r.arrayBuffer()).byteLength}"""); log("pdf size ok:", sz==90015)
    # ---- voice note ----
    A.click("#micBtn"); A.wait_for_timeout(2200); A.click("#recSend")
    B.wait_for_selector("#msgs .voice audio", timeout=20000); log("voice note received")
    leaks=[f for f in frames if "pehla message" in f or "GPSDATA" in f or "doc.pdf" in f or "%PDF" in f]
    log("plaintext/file-name leaks in frames:", len(leaks))
    B.screenshot(path="/tmp/b1_chat.png")
    # ---- screenshot alert ----
    A.keyboard.press("PrintScreen"); B.wait_for_selector("#msgs .sys:has-text('screenshot')", timeout=8000); log("screenshot alert ok")
    # ---- duress PIN with wipe ----
    A.click("#setBtn"); A.click("[data-tab='security']"); A.click("#setDur")
    A.fill("#d1","999999"); A.fill("#d2","999999"); A.click("#dW"); A.click("#dOk"); A.wait_for_timeout(2500); log("duress toast:", A.inner_text("#toast"))
    A.click("#mClose") if A.is_visible("#mClose") else None
    A.click("#lockBtn"); A.wait_for_selector("#lock:not(.hidden)")
    A.fill("#pin","999999"); A.click("#pinBtn"); A.wait_for_selector("#app:not(.hidden)", timeout=15000)
    log("duress unlock -> slot:", A.evaluate("window.__kv.slot"), " contacts:", A.evaluate("Object.keys(window.__kv.ST.contacts).length"))
    A.click("#lockBtn"); A.fill("#pin","123456"); A.click("#pinBtn"); A.wait_for_timeout(2500); log("real PIN after duress-wipe:", A.inner_text("#lockHint"))
    # ---- disguise on B ----
    B.click("#setBtn"); B.click("[data-tab='security']"); B.click("[data-k='disguise']"); B.click("#mClose"); B.click("#lockBtn")
    B.wait_for_selector("#calc:not(.hidden)"); log("title:", B.title())
    for k in ["7","*","6","="]: B.click(f"#calcKeys [data-k='{k}']")
    log("calc 7*6 =", B.inner_text("#calcDisp"))
    B.click("#calcKeys [data-k='C']")
    for k in "123456": B.click(f"#calcKeys [data-k='{k}']")
    B.click("#calcKeys [data-k='=']"); B.wait_for_selector("#app:not(.hidden)", timeout=15000); log("calculator PIN unlock OK, contacts:", B.evaluate("Object.keys(window.__kv.ST.contacts).length"))
    B.click("#setBtn"); B.screenshot(path="/tmp/b1_set.png")
    B.click("#mClose"); B.click("#lockBtn"); B.wait_for_selector("#calc:not(.hidden)"); B.screenshot(path="/tmp/b1_calc.png")
    b.close()
log("DONE")
