from playwright.sync_api import sync_playwright
def log(*a): print(*a, flush=True)
with sync_playwright() as p:
    b=p.chromium.launch(executable_path="/usr/bin/google-chrome")
    def mk(n):
        pg=b.new_context(viewport={"width":390,"height":844},bypass_csp=True,permissions=["clipboard-read","clipboard-write"]).new_page()
        pg.on("pageerror",lambda e:log(n,"ERR",e)); pg.goto("http://localhost:8099/?test=1"); pg.wait_for_timeout(500)
        pg.fill("#pin","123456"); pg.fill("#pin2","123456"); pg.click("#pinBtn"); pg.wait_for_selector("#recOk"); pg.click("#recOk"); pg.wait_for_selector("#net.on",state="attached"); return pg
    A=mk("A"); B=mk("B")
    A.click("#invBtn"); A.wait_for_selector("#qrBox svg"); link=A.evaluate("window.__kv.inviteLink(window.__kv.invCur)")
    B.click("#joinBtn"); B.fill("#joinIn",link); B.click("#joinGo"); A.wait_for_selector("#reqYes"); A.click("#reqYes"); B.wait_for_selector("#chat:not(.hidden)",timeout=10000)
    A.fill("#input","Kal ka plan pakka 🎉"); A.click("#send"); A.set_input_files("#fileIn","/tmp/photo.jpg")
    B.wait_for_selector("#msgs img.fimg",timeout=20000)
    B.click("#msgs .m.in:has-text('Kal ka plan')", button="right"); B.click("#maShare"); B.wait_for_selector("#shNative")
    log("text share links:", B.eval_on_selector_all(".apps a", "els=>els.map(e=>e.textContent.trim()+' -> '+e.href.slice(0,60))"))
    B.click("#mClose")
    B.click("#msgs img.fimg", button="right"); B.click("#maShare"); B.wait_for_selector("#shNative")
    log("photo share: preview?", B.is_visible(".shareprev"), " save link:", B.get_attribute("#shDl","href")[:30], B.get_attribute("#shDl","download"))
    B.click("#shNative"); B.wait_for_timeout(500); log("native share result toast:", B.inner_text("#toast"))
    B.screenshot(path="/tmp/share.png")
    b.close()
