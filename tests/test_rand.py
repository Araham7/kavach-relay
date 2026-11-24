from playwright.sync_api import sync_playwright
def log(*a): print(*a, flush=True)
frames=[]
with sync_playwright() as p:
    dev=dict(p.devices["Pixel 7"]); dev["device_scale_factor"]=2
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome")
    def mk(n):
        pg=b.new_context(**dev,bypass_csp=True).new_page(); pg.on("pageerror",lambda e:log(n,"ERR",e))
        pg.on("websocket",lambda ws: ws.on("framesent",lambda f: frames.append(str(f))))
        pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(500)
        pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on",state="attached"); return pg
    def enter(pg, g, shot=None):
        pg.click("#randBtn"); pg.wait_for_selector("#rgGo")
        pg.click(f"[data-g='{g}']"); pg.click("#rgGo"); pg.wait_for_timeout(300); log("without 18+ tick:", pg.inner_text("#toast"))
        if shot: pg.screenshot(path=shot)
        pg.check("#adult18"); pg.click("#rgGo")
    A=mk("A-boy"); C=mk("C-boy"); B=mk("B-girl")
    enter(A,"m","/tmp/r_gate.png"); A.wait_for_selector(".spin"); A.screenshot(path="/tmp/r_search.png")
    enter(C,"m"); C.wait_for_timeout(1500)
    log("boy-boy matched?", A.evaluate("Object.keys(window.__kv.ST.contacts).length"), C.evaluate("Object.keys(window.__kv.ST.contacts).length"))
    enter(B,"f"); B.wait_for_selector("#chat:not(.hidden)", timeout=10000)
    a_n=A.evaluate("Object.keys(window.__kv.ST.contacts).length"); c_n=C.evaluate("Object.keys(window.__kv.ST.contacts).length")
    boy = A if a_n==1 else C; other = C if boy is A else A
    log("girl matched with:", "A" if boy is A else "C", " other boy still searching:", other.is_visible(".spin"))
    boy.wait_for_selector("#chat:not(.hidden)")
    boy.fill("#input","Hi! Kaise ho? 🙂"); boy.click("#send")
    B.wait_for_selector("#msgs .m.in:has-text('Kaise ho')", timeout=8000); log("girl got message")
    B.fill("#input","Main theek, aap batao 😊"); B.click("#send"); boy.wait_for_selector("#msgs .m.in:has-text('theek')", timeout=8000)
    B.set_input_files("#fileIn","/tmp/photo.jpg"); boy.wait_for_selector("#msgs img.fimg", timeout=20000); log("photo across strangers ok")
    boy.screenshot(path="/tmp/r_chat.png")
    log("plaintext leak:", len([f for f in frames if 'Kaise ho' in f or 'theek' in f]))
    # Next from girl -> matches other boy
    B.click("#rNext"); boy.wait_for_selector("#msgs .sys:has-text('left')", timeout=8000); log("boy sees: stranger left")
    B.wait_for_selector("#chat:not(.hidden)", timeout=10000); other.wait_for_selector("#chat:not(.hidden)", timeout=10000); log("girl re-matched with other boy after Next")
    log("girl contacts after next (old chat erased):", B.evaluate("Object.keys(window.__kv.ST.contacts).length"))
    other.click("#rRep"); other.screenshot(path="/tmp/r_report.png"); other.click("#rpGo"); other.wait_for_timeout(800); log("report toast:", other.inner_text("#toast"))
    B.wait_for_selector("#msgs .sys:has-text('left')", timeout=8000); log("girl sees reporter left")
    b.close()
