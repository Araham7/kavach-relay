import re, sys, time
from playwright.sync_api import sync_playwright
URL="http://localhost:8099/?test=1"
frames=[]
def log(*a): print(*a, flush=True)
with sync_playwright() as p:
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--use-fake-device-for-media-stream","--use-fake-ui-for-media-stream"])
    def mk(name):
        ctx=b.new_context(viewport={"width":1200,"height":800}, permissions=["camera","microphone","clipboard-read","clipboard-write"], bypass_csp=True)
        pg=ctx.new_page()
        pg.on("pageerror",lambda e:log(name,"PAGEERROR",e))
        pg.on("console",lambda m: log(name,"console",m.text) if m.type in("error",) else None)
        pg.on("websocket",lambda ws: ws.on("framesent",lambda f: frames.append(f if isinstance(f,str) else str(f))) )
        pg.goto(URL); pg.wait_for_timeout(600)
        pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn")
        pg.wait_for_timeout(2500); print(name, repr(pg.get_attribute("#app","class")), pg.inner_text("#lockHint")); pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on", state="attached")
        return ctx,pg
    ca,A=mk("A"); cb,B=mk("B")
    A.click("#invBtn"); A.wait_for_selector("#qrBox svg")
    link=A.evaluate("window.__kv.inviteLink(window.__kv.invCur)")
    log("invite link:", link[:60]+"...", "len", len(link))
    B.click("#joinBtn"); B.fill("#joinIn", link); B.click("#joinGo")
    B.wait_for_selector("text=Waiting for approval")
    sasB=B.inner_text("#mBody .sas")
    A.wait_for_selector("text=New contact request")
    sasA=A.inner_text("#mBody .sas")
    log("SAS A:",sasA," SAS B:",sasB, "MATCH" if sasA==sasB else "MISMATCH")
    assert sasA==sasB
    A.fill("#reqName","Bob"); A.click("#reqYes")
    A.wait_for_selector("#chat:not(.hidden)"); B.wait_for_selector("#chat:not(.hidden)", timeout=10000)
    secret="supersecret-namaste-12345"
    A.fill("#input",secret); A.press("#input","Enter")
    B.wait_for_selector(f"#msgs .m.in:has-text('{secret}')", timeout=8000)
    log("B got message from A")
    B.fill("#input","reply from B ✅"); B.press("#input","Enter")
    A.wait_for_selector("#msgs .m.in:has-text('reply from B')", timeout=8000)
    A.wait_for_selector("#msgs .m.out .rd", timeout=8000); log("read receipt ok")
    leak=[f for f in frames if secret in f or "reply from B" in f]
    log("frames sent:",len(frames)," plaintext leaks:",len(leak))
    assert not leak
    # reuse invite link from a third party
    cc,C=mk("C")
    C.click("#joinBtn"); C.fill("#joinIn",link); C.click("#joinGo"); time.sleep(1.5)
    log("reuse attempt toast:", C.inner_text("#toast"))
    # rekey via 45 messages
    for i in range(45):
        A.fill("#input",f"msg {i}"); A.press("#input","Enter")
    B.wait_for_selector("#msgs .m.in:has-text('msg 44')", timeout=20000)
    time.sleep(1)
    ep=A.evaluate("Object.values(window.__kv.ST.contacts)[0].ep"); epB=B.evaluate("Object.values(window.__kv.ST.contacts)[0].ep")
    log("epochs after 45 msgs A/B:",ep,epB)
    B.fill("#input","after rekey from B"); B.press("#input","Enter")
    A.wait_for_selector("#msgs .m.in:has-text('after rekey from B')", timeout=8000); log("post-rekey messaging ok")
    # disappearing
    A.select_option("#tmr","30"); time.sleep(0.5)
    log("B timer:", B.evaluate("Object.values(window.__kv.ST.contacts)[0].timer"))
    # call
    A.click("#vCall"); B.wait_for_selector("#ringBtns:not(.hidden)", timeout=8000); log("B ringing")
    B.click("#accV")
    A.wait_for_function("document.getElementById('callState').textContent.includes('encrypted')", timeout=20000)
    B.wait_for_function("document.getElementById('callState').textContent.includes('encrypted')", timeout=20000)
    time.sleep(2)
    log("call state A:",A.inner_text("#callState")," B:",B.inner_text("#callState"))
    vw=B.evaluate("document.getElementById('remoteV').videoWidth"); log("B sees remote video width:",vw)
    sdpleak=[f for f in frames if "a=fingerprint" in f or "candidate:" in f]
    log("SDP/ICE plaintext leaks:",len(sdpleak))
    A.screenshot(path="/tmp/callA.png")
    A.click("#hang"); B.wait_for_selector("#call.hidden", state="attached", timeout=8000); log("call ended both sides")
    # lock/unlock
    A.click("#lockBtn"); A.wait_for_selector("#lock:not(.hidden)")
    A.fill("#pin","000000"); A.click("#pinBtn"); time.sleep(0.8); log("wrong pin hint:",A.inner_text("#lockHint"))
    A.fill("#pin","123456"); A.click("#pinBtn"); A.wait_for_selector("#app:not(.hidden)")
    log("contacts after unlock:",A.evaluate("Object.keys(window.__kv.ST.contacts).length"))
    vault=A.evaluate("localStorage.getItem('kavach_vault_v1')")
    log("vault contains plaintext?", secret in vault or "Bob" in vault)
    B.screenshot(path="/tmp/chatB.png")
    b.close()
log("ALL DONE")
