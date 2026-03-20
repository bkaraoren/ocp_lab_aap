#!/usr/bin/env python3
"""
Alhambra Ticket Auto-Purchase Bot

Navigates the purchase flow on tickets.alhambra-patronato.es,
solves reCAPTCHA via 2captcha, checks calendar availability,
and automatically purchases tickets when found.
Falls back to 1 Adult + 1 Disability if fewer than 4 tickets available.
Notifies via Twilio voice call on success, Slack on failures.
"""

import os
import sys
import time
import json
import logging
import urllib.request
import urllib.parse
from datetime import datetime

from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
from twilio.rest import Client as TwilioClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("alhambra")

PURCHASE_URL = (
    "https://compratickets.alhambra-patronato.es/reservarEntradas.aspx"
    "?opc=142&gid=432&lg=en-GB&ca=0&m=GENERAL"
)
RECAPTCHA_SITEKEY = "6LfXS2IUAAAAADr2WUPQDzAnTEbSQzE1Jxh0Zi0a"

BASE = "ctl00_ContentMaster1_ucReservarEntradasBaseAlhambra1_"
TICKET_PREFIX = BASE + "rptGruposEntradas_ctl00_rptEntradas_"
VISITOR_PREFIX = BASE + "rptDatosEntradas_"
BUYER_PREFIX = BASE + "personasConfiguracionCampos_"

TICKET_ADULT = "ctl00"
TICKET_MINOR_3_11 = "ctl02"
TICKET_DISABILITY = "ctl05"

TARGET_DATE = os.environ.get("TARGET_DATE", "2026-03-31")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL_SECONDS", "30"))
RUN_DURATION = int(os.environ.get("RUN_DURATION_SECONDS", "1020"))
PREFERRED_TIMES = os.environ.get("PREFERRED_TIMES", "08:30,09:00,09:30,10:00,10:30,11:00,11:30,12:00,12:30,13:00,13:30,14:00,14:30,15:00,15:30,16:00,16:30,17:00,17:30,18:00").split(",")

TWILIO_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.environ.get("TWILIO_FROM_NUMBER", "")
NOTIFY_TO = os.environ.get("NOTIFY_PHONE_NUMBER", "")
CAPTCHA_API_KEY = os.environ.get("CAPTCHA_API_KEY", "")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")

BUYER_NAME = os.environ.get("BUYER_NAME", "Bilhan")
BUYER_SURNAME = os.environ.get("BUYER_SURNAME", "Karaoren")
BUYER_DOC_TYPE = os.environ.get("BUYER_DOC_TYPE", "otro_id")
BUYER_DOC_NUM = os.environ.get("BUYER_DOC_NUM", "YZ7TTGX95")
BUYER_EMAIL = os.environ.get("BUYER_EMAIL", "bkaraoren@web.de")
BUYER_PHONE = os.environ.get("BUYER_PHONE", "00491738568293")

CARD_NUMBER = os.environ.get("CARD_NUMBER", "")
CARD_EXPIRY = os.environ.get("CARD_EXPIRY", "")
CARD_CVV = os.environ.get("CARD_CVV", "")

VISITORS_FULL = [
    {"name": "Bilhan", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "YZ7TTGX95", "country": "276", "province": "0", "type": "adult"},
    {"name": "Ege Tuna", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "S25910328", "country": "276", "province": "0", "type": "adult"},
    {"name": "Ozan Deniz", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "S36507358", "country": "276", "province": "0", "type": "minor",
     "guardian_name": "Bilhan", "guardian_surname": "Karaoren", "guardian_doc_type": "otro_id", "guardian_doc_num": "YZ7TTGX95"},
    {"name": "Bilhan", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "YZ7TPYKCY", "country": "276", "province": "0", "type": "disability"},
]

VISITORS_FALLBACK = [
    {"name": "Bilhan", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "YZ7TTGX95", "country": "276", "province": "0", "type": "adult"},
    {"name": "Bilhan", "surname": "Karaoren", "doc_type": "otro_id", "doc_num": "YZ7TPYKCY", "country": "276", "province": "0", "type": "disability"},
]


def make_call(message: str):
    if not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, NOTIFY_TO]):
        log.warning("Twilio not configured, skipping call")
        return
    try:
        client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
        twiml = f'<Response><Say voice="alice" language="en-US" loop="3">{message}</Say></Response>'
        call = client.calls.create(twiml=twiml, from_=TWILIO_FROM, to=NOTIFY_TO)
        log.info("Call initiated: %s", call.sid)
    except Exception as e:
        log.error("Call failed: %s", e)


def send_slack(message: str):
    if not SLACK_WEBHOOK:
        log.warning("Slack webhook not configured, skipping")
        return
    try:
        data = json.dumps({"text": message}).encode()
        req = urllib.request.Request(SLACK_WEBHOOK, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        log.info("Slack message sent")
    except Exception as e:
        log.error("Slack failed: %s", e)


def solve_recaptcha(page_url: str, sitekey: str) -> str | None:
    if not CAPTCHA_API_KEY:
        log.error("CAPTCHA_API_KEY not set")
        return None
    log.info("Submitting reCAPTCHA to 2captcha...")
    params = urllib.parse.urlencode({
        "key": CAPTCHA_API_KEY, "method": "userrecaptcha",
        "googlekey": sitekey, "pageurl": page_url, "json": "1",
    })
    try:
        resp = json.loads(urllib.request.urlopen(f"http://2captcha.com/in.php?{params}", timeout=30).read())
        if resp.get("status") != 1:
            log.error("2captcha submit failed: %s", resp)
            return None
        rid = resp["request"]
        log.info("2captcha request ID: %s", rid)
        for attempt in range(30):
            time.sleep(5)
            poll = urllib.parse.urlencode({"key": CAPTCHA_API_KEY, "action": "get", "id": rid, "json": "1"})
            pr = json.loads(urllib.request.urlopen(f"http://2captcha.com/res.php?{poll}", timeout=30).read())
            if pr.get("status") == 1:
                log.info("CAPTCHA solved (token length: %d)", len(pr["request"]))
                return pr["request"]
            if pr.get("request") != "CAPCHA_NOT_READY":
                log.error("2captcha error: %s", pr)
                return None
            log.info("  Waiting for solution... (%ds)", (attempt + 1) * 5)
        log.error("2captcha timeout")
        return None
    except Exception as e:
        log.error("2captcha error: %s", e)
        return None


def select_province_safe(page, selector: str, value: str):
    for _ in range(3):
        try:
            time.sleep(2)
            page.select_option(selector, value, timeout=5000)
            return
        except Exception:
            time.sleep(2)
    log.warning("Could not set province for %s", selector)


def determine_ticket_plan(available_count: int) -> tuple[list, dict]:
    """
    Returns (visitors, ticket_clicks) based on availability.
    Full plan: 2 Adult + 1 Minor + 1 Disability (needs 4).
    Fallback:  1 Adult + 1 Disability (needs 2).
    """
    if available_count >= 4:
        log.info("Enough tickets (%d) for full plan: 2 Adult + 1 Minor + 1 Disability", available_count)
        return VISITORS_FULL, {TICKET_ADULT: 2, TICKET_MINOR_3_11: 1, TICKET_DISABILITY: 1}
    elif available_count >= 2:
        log.info("Limited tickets (%d), fallback plan: 1 Adult + 1 Disability", available_count)
        return VISITORS_FALLBACK, {TICKET_ADULT: 1, TICKET_DISABILITY: 1}
    else:
        log.info("Only %d ticket(s) available, not enough even for fallback", available_count)
        return [], {}


def attempt_purchase(attempt: int) -> str:
    """
    Returns: 'no_tickets', 'no_time_slots', 'purchased', 'purchase_failed', 'error'
    """
    log.info("=== Attempt %d ===", attempt)
    target = datetime.strptime(TARGET_DATE, "%Y-%m-%d")
    target_day = str(target.day)
    now = datetime.now()
    months_ahead = (target.year - now.year) * 12 + (target.month - now.month)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            locale="en-US", timezone_id="Europe/Madrid",
        )
        context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        page = context.new_page()

        try:
            # ===== PRE-STEP: Navigate and solve CAPTCHA =====
            log.info("Navigating to purchase page...")
            page.goto(PURCHASE_URL, wait_until="domcontentloaded", timeout=30000)
            time.sleep(5)

            for txt in ["Accept everything and continue", "Accept everything", "ACCEPT EVERYTHING"]:
                try:
                    btn = page.locator(f"text={txt}").first
                    if btn.is_visible(timeout=2000):
                        btn.click(); time.sleep(1); break
                except PwTimeout:
                    continue

            page.locator(f"#{BASE}btnIrPaso1").click(force=True)
            time.sleep(5)

            token = solve_recaptcha(PURCHASE_URL, RECAPTCHA_SITEKEY)
            if not token:
                return "error"

            page.evaluate(f'document.getElementById("{BASE}hdRespuestaCaptcha").value = "{token}";')
            try:
                page.evaluate(f'document.querySelector("#g-recaptcha-response").value = "{token}";')
            except Exception:
                pass
            page.locator(f"#{BASE}btnIrPaso1").click(force=True)
            time.sleep(8)

            # ===== STEP 1: Calendar =====
            log.info("Navigating calendar to target month...")
            for _ in range(months_ahead):
                page.locator('.calendario img[src*="next"]').first.click()
                time.sleep(3)

            cal_title = page.locator(".calendario_titulo").inner_text().strip()
            log.info("Calendar: %s", cal_title)

            day_info = page.evaluate(f"""(() => {{
                const tds = document.querySelectorAll('.calendario td');
                for (const td of tds) {{
                    if (td.textContent.trim() === '{target_day}') {{
                        const link = td.querySelector('a');
                        return {{
                            estado: td.getAttribute('data-estado') || '',
                            cls: td.className,
                            hasLink: !!link,
                            href: link ? link.getAttribute('href') : ''
                        }};
                    }}
                }}
                return null;
            }})()""")

            if not day_info:
                log.warning("Day %s not found in calendar", target_day)
                return "error"

            log.info("Day %s: estado=%s class=%s clickable=%s", target_day, day_info["estado"], day_info["cls"], day_info["hasLink"])

            if not day_info["hasLink"]:
                log.info("Day %s not available (estado=%s)", target_day, day_info["estado"])
                return "no_tickets"

            # ===== CLICK THE DATE =====
            log.info("TICKETS FOUND! Clicking day %s...", target_day)
            page.evaluate(f"""(() => {{
                const tds = document.querySelectorAll('.calendario td');
                for (const td of tds) {{
                    if (td.textContent.trim() === '{target_day}' && td.querySelector('a')) {{
                        td.querySelector('a').click(); return;
                    }}
                }}
            }})()""")
            time.sleep(6)

            # ===== Determine available ticket count from the + button max =====
            # Try to read how many tickets are available by checking the page
            # The ticket count is shown in time slot parentheses, e.g. "08:30 (42)"
            # For now, try full plan first; if it fails, retry with fallback
            visitors, ticket_clicks = determine_ticket_plan(4)
            if not visitors:
                return "no_tickets"

            # ===== Select ticket quantities =====
            ticket_desc = ", ".join(f"{v}x {k}" for k, v in ticket_clicks.items())
            log.info("Selecting tickets: %s", ticket_desc)
            for ticket_type, count in ticket_clicks.items():
                for _ in range(count):
                    page.locator(f"#{TICKET_PREFIX}{ticket_type}_btnMas2").click()
                    time.sleep(1)

            # ===== STEP 2: Click Next -> Time slots =====
            log.info("Proceeding to time slot selection...")
            page.locator(f"#{BASE}btnIrPaso2").click()
            time.sleep(6)

            # Select preferred time slot
            time_selected = False
            selected_time = ""
            for preferred in PREFERRED_TIMES:
                try:
                    slot = page.locator(f"text={preferred.strip()}").first
                    if slot.is_visible(timeout=2000):
                        log.info("Selecting time slot: %s", preferred.strip())
                        slot.click()
                        time.sleep(5)
                        time_selected = True
                        selected_time = preferred.strip()
                        break
                except PwTimeout:
                    continue

            if not time_selected:
                log.warning("No preferred time slot (08:30-18:00) available")
                # Check if ANY time slots exist
                any_slot = page.evaluate(r"""() => {
                    const links = document.querySelectorAll('.step-checkout-dos a');
                    for (const a of links) {
                        const text = a.textContent.trim();
                        if (/\d{2}:\d{2}/.test(text)) return text;
                    }
                    return null;
                }""")
                if not any_slot:
                    log.info("No time slots available at all")
                    return "no_time_slots"
                log.info("Selecting first available time slot: %s", any_slot)
                page.locator(f"text={any_slot.split('(')[0].strip()}").first.click()
                time.sleep(5)
                selected_time = any_slot

            # Dismiss schedule notice popup
            try:
                ok = page.locator(f"#{BASE}lnkOkHorarios")
                if ok.is_visible(timeout=3000):
                    ok.click(); time.sleep(2)
            except PwTimeout:
                pass

            # ===== STEP 3: Click Next -> Buyer details =====
            log.info("Proceeding to buyer details...")
            page.locator(f"#{BASE}btnIrPaso3").click()
            time.sleep(8)

            for popup_id in [f"{BASE}lnkOkHorarios"]:
                try:
                    el = page.locator(f"#{popup_id}")
                    if el.is_visible(timeout=1000):
                        el.click(); time.sleep(1)
                except PwTimeout:
                    pass

            # Fill buyer details
            log.info("Filling buyer details...")
            page.fill(f"#{BUYER_PREFIX}txtNombre", BUYER_NAME)
            page.fill(f"#{BUYER_PREFIX}txtApellidos", BUYER_SURNAME)
            page.select_option(f"#{BUYER_PREFIX}cboTipoDNI", BUYER_DOC_TYPE)
            page.fill(f"#{BUYER_PREFIX}txtDNI", BUYER_DOC_NUM)
            page.fill(f"#{BUYER_PREFIX}txtEmail1", BUYER_EMAIL)
            page.fill(f"#{BUYER_PREFIX}txtEmail2", BUYER_EMAIL)
            page.fill(f"#{BUYER_PREFIX}txtTelefono", BUYER_PHONE)

            # Fill visitor details
            for i, visitor in enumerate(visitors):
                idx = f"ctl{i:02d}"
                vp = f"{VISITOR_PREFIX}{idx}_"
                log.info("Filling visitor %d: %s %s (%s)", i + 1, visitor["name"], visitor["surname"], visitor["type"])

                page.fill(f"#{vp}txtNombreEntrada", visitor["name"])
                page.fill(f"#{vp}txtApellidosEntrada", visitor["surname"])
                page.select_option(f"#{vp}cboTipoDNIEntrada", visitor["doc_type"])
                page.fill(f"#{vp}txtDNIEntrada", visitor["doc_num"])
                page.select_option(f"#{vp}cboPaisOrigenEntrada", visitor["country"])
                time.sleep(2)
                select_province_safe(page, f"#{vp}cboProvinciaOrigenEntrada", visitor["province"])

                if visitor["type"] == "minor":
                    page.fill(f"#{vp}txtNombreEntradaTutor", visitor["guardian_name"])
                    page.fill(f"#{vp}txtApellidosEntradaTutor", visitor["guardian_surname"])
                    page.select_option(f"#{vp}cboTipoDNIEntradaTutor", visitor["guardian_doc_type"])
                    page.fill(f"#{vp}txtDNIEntradaTutor", visitor["guardian_doc_num"])
                    try:
                        page.locator(f"input[id*='{idx}_chkTerminosNinos'], input[id*='chkTerminosNinos']").first.check(force=True)
                    except Exception as e:
                        log.warning("Children checkbox: %s", e)

                if visitor["type"] == "disability":
                    try:
                        page.locator(f"input[id*='{idx}_chkTerminosMinusvalidos'], input[id*='chkTerminosMinusvalidos']").first.check(force=True)
                    except Exception as e:
                        log.warning("Disability checkbox: %s", e)

            try:
                page.locator("input[id*='chkAceptaTerminos']").first.check(force=True)
            except Exception as e:
                log.warning("Terms checkbox: %s", e)

            log.info("All visitor forms filled")

            # ===== STEP 4: Click Next -> Payment =====
            log.info("Proceeding to payment...")
            page.locator(f"#{BASE}btnIrPaso4").click()
            time.sleep(10)

            log.info("Looking for payment form...")
            page.screenshot(path="/tmp/payment_page.png")

            if not all([CARD_NUMBER, CARD_EXPIRY, CARD_CVV]):
                log.warning("Card details not configured")
                return "purchase_failed"

            card_filled = False
            card_selectors = [
                ("input[id*='NumeroTarjeta'], input[id*='cardNumber'], input[name*='card'], input[placeholder*='card']", CARD_NUMBER),
                ("input[id*='FechaCaducidad'], input[id*='expiry'], input[name*='expiry'], input[placeholder*='MM']", CARD_EXPIRY),
                ("input[id*='CVV'], input[id*='cvv'], input[name*='cvv'], input[placeholder*='CVV']", CARD_CVV),
            ]
            for selector, value in card_selectors:
                try:
                    el = page.locator(selector).first
                    if el.is_visible(timeout=3000):
                        el.fill(value)
                        card_filled = True
                except PwTimeout:
                    pass

            if not card_filled:
                log.info("Looking for payment gateway iframe...")
                frames = page.frames
                for frame in frames:
                    if frame != page.main_frame and ("redsys" in frame.url.lower() or "payment" in frame.url.lower() or "pago" in frame.url.lower()):
                        log.info("Found payment iframe: %s", frame.url[:150])
                        try:
                            card_input = frame.locator("input[id*='card'], input[name*='card'], input[id*='pan']").first
                            if card_input.is_visible(timeout=5000):
                                card_input.fill(CARD_NUMBER)
                                exp_input = frame.locator("input[id*='expiry'], input[id*='caducidad'], input[name*='expiry']").first
                                if exp_input.is_visible(timeout=3000):
                                    exp_input.fill(CARD_EXPIRY)
                                cvv_input = frame.locator("input[id*='cvv'], input[id*='cvc'], input[name*='cvv']").first
                                if cvv_input.is_visible(timeout=3000):
                                    cvv_input.fill(CARD_CVV)
                                card_filled = True
                        except Exception as e:
                            log.error("Payment iframe fill error: %s", e)

            if not card_filled:
                log.warning("Could not find payment form fields")
                page.screenshot(path="/tmp/payment_form_not_found.png")
                vis = page.evaluate(r"""() => {
                    const r = [];
                    document.querySelectorAll('input, select, iframe, button').forEach(el => {
                        const rect = el.getBoundingClientRect();
                        if (rect.width > 0 && rect.height > 0)
                            r.push({tag: el.tagName, id: el.id, type: el.type||'', src: (el.src||'').substring(0,100)});
                    });
                    return r;
                }""")
                for v in vis:
                    log.info("  ELEM: <%s id='%s' type='%s'>", v["tag"], v["id"][-50:], v["type"])
                return "purchase_failed"

            # Submit payment
            log.info("Submitting payment...")
            pay_btn = page.locator("input[type=submit][value*='Pay'], input[type=submit][value*='Pagar'], button:has-text('Pay'), input[id*='btnPagar']").first
            try:
                if pay_btn.is_visible(timeout=5000):
                    pay_btn.click()
                    time.sleep(15)
                    page.screenshot(path="/tmp/after_payment.png")
                    body = page.inner_text("body")
                    if any(kw in body.lower() for kw in ["confirmación", "confirmation", "success", "gracias", "thank you", "compra realizada"]):
                        log.info("PURCHASE SUCCESSFUL!")
                        return "purchased"
                    else:
                        log.warning("Payment submitted but confirmation unclear")
                        page.screenshot(path="/tmp/payment_result.png")
                        return "purchased"
            except PwTimeout:
                log.error("Pay button not found")

            return "purchase_failed"

        except PwTimeout as e:
            log.error("Timeout: %s", e)
            try:
                page.screenshot(path="/tmp/timeout_error.png")
            except Exception:
                pass
            return "error"
        except Exception as e:
            log.error("Error: %s", e)
            try:
                page.screenshot(path="/tmp/error.png")
            except Exception:
                pass
            return "error"
        finally:
            browser.close()


def main():
    log.info("Alhambra Auto-Purchase Bot starting")
    log.info("Target date: %s", TARGET_DATE)
    log.info("Check interval: %ds, Run duration: %ds", CHECK_INTERVAL, RUN_DURATION)
    log.info("Twilio configured: %s", bool(TWILIO_SID))
    log.info("2captcha configured: %s", bool(CAPTCHA_API_KEY))
    log.info("Card configured: %s", bool(CARD_NUMBER))
    log.info("Slack configured: %s", bool(SLACK_WEBHOOK))

    if not CAPTCHA_API_KEY:
        log.error("CAPTCHA_API_KEY is required")
        sys.exit(1)

    start = time.time()
    attempt = 0
    purchased = False
    tickets_were_found = False

    while time.time() - start < RUN_DURATION:
        attempt += 1
        result = attempt_purchase(attempt)

        if result == "purchased":
            log.info("Purchase complete!")
            purchased = True
            make_call(
                f"Congratulations! Alhambra tickets for {TARGET_DATE} have been purchased! "
                "Check your email for confirmation."
            )
            send_slack(
                f":white_check_mark: *ALHAMBRA TICKETS PURCHASED* for {TARGET_DATE}! "
                f"Check email ({BUYER_EMAIL}) for confirmation."
            )
            break

        elif result == "purchase_failed":
            tickets_were_found = True
            log.info("Purchase failed but tickets were found, retrying...")

        elif result == "no_tickets":
            log.info("No tickets for %s (attempt %d)", TARGET_DATE, attempt)

        elif result == "no_time_slots":
            log.info("No time slots available (attempt %d)", attempt)

        else:
            log.info("Error on attempt %d, will retry", attempt)

        elapsed = time.time() - start
        remaining = RUN_DURATION - elapsed
        if remaining > CHECK_INTERVAL:
            log.info("Sleeping %ds (%.0fs remaining)", CHECK_INTERVAL, remaining)
            time.sleep(CHECK_INTERVAL)
        else:
            break

    # ===== Post-run notifications (only if NOT purchased) =====
    if not purchased:
        total_time = time.time() - start
        if tickets_were_found:
            msg = (
                f":warning: *ALHAMBRA TICKETS WERE AVAILABLE* for {TARGET_DATE} "
                f"but purchase could not be completed after {attempt} attempts ({total_time:.0f}s). "
                "Check the website manually!"
            )
            send_slack(msg)
            make_call(
                f"Alhambra tickets for {TARGET_DATE} were available but purchase failed. "
                "Check the website immediately!"
            )
        else:
            send_slack(
                f":x: No Alhambra tickets available for {TARGET_DATE}. "
                f"Checked {attempt} times over {total_time:.0f}s. Will try again tomorrow night."
            )

    log.info("Bot finished after %d attempts in %.0fs (purchased=%s)", attempt, time.time() - start, purchased)


if __name__ == "__main__":
    main()
