"""Free Money — slim deployable Flask app.

Self-contained — no Marvis dependencies. Reads config from environment variables.
Designed for Railway / Render / Fly.io / any container host.

Required env vars (set in Railway dashboard):
  STRIPE_SECRET_KEY        - sk_live_... or rk_live_... (restricted key recommended)
  STRIPE_PUBLISHABLE_KEY   - pk_live_...
  STRIPE_PRICE_ID          - price_... (monthly $4.99)
  STRIPE_ANNUAL_PRICE_ID   - price_... (annual $54)
  STRIPE_WEBHOOK_SECRET    - whsec_... (from Stripe webhook endpoint settings)
  FREEMONEY_BASE_URL       - https://myfreemoney.app (no trailing slash)
  DB_PATH                  - /data/settlements.db (mount a Railway Volume at /data)

Optional:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM   - for restore-code emails
  ADMIN_EMAIL              - where security@ contact goes (default: info@myfreemoney.app)
  FREEMONEY_ENV            - "prod" forces Secure cookies even on HTTP (behind a TLS proxy)
"""
import os, re, sys, json, time, uuid, threading, sqlite3, smtplib, hmac as _hmac
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, make_response, redirect

# ── App + config ────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "settlements.db"))
BASE_URL = os.environ.get("FREEMONEY_BASE_URL", "https://myfreemoney.app").rstrip("/")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "info@myfreemoney.app")
IS_PROD = os.environ.get("FREEMONEY_ENV", "prod").lower() == "prod"

# Make sure data directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def cfg():
    return {
        "stripe_secret_key": os.environ.get("STRIPE_SECRET_KEY", ""),
        "stripe_publishable_key": os.environ.get("STRIPE_PUBLISHABLE_KEY", ""),
        "stripe_price_id": os.environ.get("STRIPE_PRICE_ID", ""),
        "stripe_annual_price_id": os.environ.get("STRIPE_ANNUAL_PRICE_ID", ""),
        "stripe_webhook_secret": os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
        "freemoney_base_url": BASE_URL,
    }

def log(msg):
    print(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)

# ── DB bootstrap ────────────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_tables():
    if not os.path.exists(DB_PATH):
        log(f"WARN: DB not present at {DB_PATH} — empty DB will be created. Run scanner to seed.")
    conn = db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS settlements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            company TEXT,
            payout TEXT,
            payout_low REAL,
            payout_high REAL,
            deadline TEXT,
            claim_url TEXT,
            description TEXT,
            status TEXT DEFAULT 'active',
            claimed INTEGER DEFAULT 0,
            no_proof_flag INTEGER DEFAULT 0,
            proof_needed TEXT,
            category TEXT DEFAULT 'settlement',
            state TEXT,
            eligibility TEXT,
            source TEXT,
            found_date TEXT,
            confidence_score TEXT,
            groq_analysis TEXT,
            ease_score INTEGER
        );
        CREATE TABLE IF NOT EXISTS pro_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            stripe_customer_id TEXT,
            push_subscription TEXT,
            email_alerts INTEGER DEFAULT 1,
            phone TEXT,
            created_at TEXT,
            active INTEGER DEFAULT 1
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pro_users_email ON pro_users(email);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pro_users_customer ON pro_users(stripe_customer_id);
        CREATE TABLE IF NOT EXISTS pro_sessions (
            session_token TEXT UNIQUE NOT NULL,
            stripe_customer_id TEXT,
            email TEXT,
            created_at TEXT,
            expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS restore_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            code TEXT,
            created_at TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS consumed_checkout_sessions (
            session_id TEXT PRIMARY KEY,
            used_at TEXT
        );
    """)
    conn.commit()
    conn.close()

try:
    init_tables()
except Exception as e:
    log(f"WARN: init_tables failed: {e}")

# ── Security / rate-limit helpers ───────────────────────────────────────────────
_rate = {}  # "ip:endpoint" -> [timestamps]

def rate_check(endpoint, maxn, window=60):
    ip = (request.headers.get("CF-Connecting-IP")
          or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or request.remote_addr or "unknown")
    k = f"{ip}:{endpoint}"
    now = time.time()
    ts = [t for t in _rate.get(k, []) if now - t < window]
    if len(ts) >= maxn:
        _rate[k] = ts
        return False
    ts.append(now)
    _rate[k] = ts
    return True

def _rate_cleanup():
    while True:
        time.sleep(600)
        now = time.time()
        stale = [k for k, v in _rate.items() if all(now - t > 120 for t in v)]
        for k in stale:
            _rate.pop(k, None)
threading.Thread(target=_rate_cleanup, daemon=True).start()

MAX_BODY = 64 * 1024
def check_body_size(maxb=MAX_BODY):
    cl = request.content_length
    if cl is not None and cl > maxb:
        return False, (sec_headers(jsonify({"error": "Request body too large"})), 413)
    return True, None

def require_xhr():
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return sec_headers(jsonify({"error": "Invalid request"})), 400
    return None

def sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Permissions-Policy"] = ("camera=(), microphone=(), payment=(self \"https://checkout.stripe.com\"), "
                                          "usb=(), geolocation=(), interest-cohort=()")
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp

def no_cache(resp):
    sec_headers(resp)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp

def csp_headers(resp):
    sec_headers(resp)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://js.stripe.com 'unsafe-inline' https://static.cloudflareinsights.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "connect-src 'self' https://api.stripe.com https://checkout.stripe.com; "
        "frame-src https://js.stripe.com https://checkout.stripe.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self' https://checkout.stripe.com; "
        "frame-ancestors 'none'"
    )
    return resp

def validate_str(val, name, max_len=2000):
    if val is None: return "", None
    if not isinstance(val, str): return None, f"{name} must be a string"
    if len(val) > max_len: return None, f"{name} exceeds maximum length of {max_len}"
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", val)
    return cleaned, None

def validate_email(val):
    if not val or not isinstance(val, str): return None, "Invalid email"
    val = val.strip()[:254]
    if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", val):
        return None, "Invalid email format"
    return val, None

def redact_email(e):
    if not e or "@" not in e: return "***"
    u, d = e.split("@", 1)
    return (u[0] + "***" if u else "***") + "@" + (d[0] + "***" if d else "***")

def ct_equal(a, b):
    try: return _hmac.compare_digest(str(a or ""), str(b or ""))
    except Exception: return False

# ── Pro session / user helpers ─────────────────────────────────────────────────
def upsert_pro_user(email, stripe_customer_id, phone=None):
    conn = db()
    try:
        conn.execute("""INSERT INTO pro_users (email, stripe_customer_id, phone, created_at, active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(stripe_customer_id) DO UPDATE SET
                active = 1,
                email = excluded.email,
                phone = COALESCE(excluded.phone, phone)""",
            (email, stripe_customer_id, phone, datetime.now().isoformat()))
    except Exception:
        cur = conn.execute(
            "UPDATE pro_users SET active = 1, email = ?, phone = COALESCE(?, phone) WHERE stripe_customer_id = ?",
            (email, phone, stripe_customer_id))
        if cur.rowcount == 0:
            conn.execute("INSERT OR IGNORE INTO pro_users (email, stripe_customer_id, phone, created_at, active) "
                         "VALUES (?, ?, ?, ?, 1)",
                         (email, stripe_customer_id, phone, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def create_pro_session(stripe_customer_id, email):
    token = str(uuid.uuid4())
    conn = db()
    conn.execute("INSERT INTO pro_sessions (session_token, stripe_customer_id, email, created_at, expires_at) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (token, stripe_customer_id or "", email or "",
                  datetime.now().isoformat(),
                  (datetime.now() + timedelta(days=30)).isoformat()))
    conn.commit()
    conn.close()
    return token

def verify_pro_session(token):
    if not token or not isinstance(token, str) or len(token) > 100: return False, ""
    try:
        conn = db()
        row = conn.execute(
            "SELECT email, expires_at, stripe_customer_id FROM pro_sessions WHERE session_token = ?",
            (token,)).fetchone()
        conn.close()
        if not row: return False, ""
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.now():
            return False, ""
        # Check user still active
        if row["stripe_customer_id"]:
            conn2 = db()
            u = conn2.execute("SELECT active FROM pro_users WHERE stripe_customer_id = ?",
                              (row["stripe_customer_id"],)).fetchone()
            conn2.close()
            if u and u["active"] == 0: return False, ""
        return True, row["email"] or ""
    except Exception:
        return False, ""

# ── Email sending (SMTP via Google Workspace) ──────────────────────────────────
def send_email(to_addr, subject, body):
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    passwd = os.environ.get("SMTP_PASS", "")
    from_addr = os.environ.get("SMTP_FROM", user or ADMIN_EMAIL)
    if not user or not passwd:
        log(f"SMTP not configured — would have emailed {redact_email(to_addr)}: {subject}")
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            s.login(user, passwd)
            s.sendmail(from_addr, [to_addr], msg.as_string())
        log(f"Sent email to {redact_email(to_addr)}: {subject}")
        return True
    except Exception as e:
        log(f"Email send failed for {redact_email(to_addr)}: {e}")
        return False

# ── Routes: pages ──────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return redirect("/freemoney")

@app.route("/freemoney")
def freemoney_page():
    resp = make_response(render_template("freemoney.html"))
    resp = csp_headers(resp)
    if request.args.get("pro") == "success":
        resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.route("/privacy-policy.html")
@app.route("/privacy-policy")
def privacy_page():
    return sec_headers(make_response(render_template("privacy-policy.html")))

@app.route("/terms-of-service.html")
@app.route("/terms-of-service")
@app.route("/terms")
def terms_page():
    return sec_headers(make_response(render_template("terms-of-service.html")))

@app.route("/robots.txt")
def robots_txt():
    body = "User-agent: *\nDisallow: /api/\nAllow: /freemoney\nAllow: /privacy-policy\nAllow: /terms\n"
    r = make_response(body, 200)
    r.headers["Content-Type"] = "text/plain; charset=utf-8"
    return sec_headers(r)

@app.route("/.well-known/security.txt")
@app.route("/security.txt")
def security_txt():
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = (f"Contact: mailto:{ADMIN_EMAIL}\nExpires: {expires}\nPreferred-Languages: en\n"
            f"Canonical: {BASE_URL}/.well-known/security.txt\nPolicy: {BASE_URL}/privacy-policy\n")
    r = make_response(body, 200)
    r.headers["Content-Type"] = "text/plain; charset=utf-8"
    return sec_headers(r)

@app.route("/sw-freemoney.js")
def sw_freemoney():
    # Minimal service worker — no caching, just registration for future push support.
    body = """// Free Money service worker (minimal)
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', function(e) {
    if (!e.data) return;
    try {
        var d = e.data.json();
        e.waitUntil(self.registration.showNotification(d.title || 'Free Money', {
            body: d.body || '', icon: '/static/icon-192.png', badge: '/static/badge.png',
            data: { url: d.url || '/freemoney' }
        }));
    } catch (err) {}
});
self.addEventListener('notificationclick', function(e) {
    e.notification.close();
    var url = (e.notification.data && e.notification.data.url) || '/freemoney';
    e.waitUntil(clients.openWindow(url));
});
"""
    r = make_response(body, 200)
    r.headers["Content-Type"] = "application/javascript; charset=utf-8"
    r.headers["Cache-Control"] = "public, max-age=3600"
    return sec_headers(r)

# ── Routes: settlements data API ───────────────────────────────────────────────
@app.route("/api/settlements")
def settlements_api():
    if not rate_check("settlements_api", 30):
        return jsonify({"settlements": [], "error": "rate limited"}), 429
    try:
        conn = db()
        query = "SELECT * FROM settlements WHERE status = 'active'"
        params = []
        cat = request.args.get("category")
        if cat:
            query += " AND category = ?"
            params.append(cat)
        if request.args.get("no_proof") == "1":
            query += " AND no_proof_flag = 1"
        st = request.args.get("state")
        if st:
            query += " AND (UPPER(TRIM(state)) = ? OR TRIM(state) = '' OR state IS NULL OR UPPER(TRIM(state)) = 'NATIONAL')"
            params.append(st.upper().strip())
        query += " ORDER BY deadline ASC"
        rows = conn.execute(query, params).fetchall()
        cat_counts = {}
        for r in conn.execute("SELECT COALESCE(category, 'settlement') as cat, COUNT(*) as c "
                              "FROM settlements WHERE status = 'active' GROUP BY cat").fetchall():
            cat_counts[r["cat"]] = r["c"]
        conn.close()
        public = {"id","name","company","payout","payout_low","payout_high","deadline","claim_url",
                  "description","status","claimed","no_proof_flag","category","eligibility","state",
                  "proof_needed","found_date"}
        out = [{k: v for k, v in dict(r).items() if k in public} for r in rows]
        resp = jsonify({"settlements": out, "categories": cat_counts})
        resp.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=120"
        return resp
    except Exception as e:
        log(f"/api/settlements error: {e}")
        return jsonify({"settlements": []})

# ── Routes: Stripe Checkout ────────────────────────────────────────────────────
@app.route("/api/freemoney/checkout", methods=["POST"])
def fm_checkout():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    if not rate_check("checkout", 5):
        return sec_headers(jsonify({"error": "Too many requests. Try again in a minute."})), 429
    import stripe
    c = cfg()
    stripe.api_key = c["stripe_secret_key"]
    if not stripe.api_key:
        return sec_headers(jsonify({"error": "Stripe not configured"})), 500
    body = request.get_json(silent=True) or {}
    plan = (body.get("plan") or "monthly").lower()
    if plan == "annual":
        price_id = c["stripe_annual_price_id"] or c["stripe_price_id"]
        if not c["stripe_annual_price_id"]:
            plan = "monthly"
    else:
        price_id = c["stripe_price_id"]
    if not price_id:
        return sec_headers(jsonify({"error": "Pricing not configured"})), 500
    try:
        sess = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            subscription_data={"trial_period_days": 7},
            success_url=BASE_URL + "/freemoney?pro=success&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=BASE_URL + "/freemoney?pro=cancelled",
            allow_promotion_codes=True,
            consent_collection={"terms_of_service": "required"},
            custom_text={
                "terms_of_service_acceptance": {
                    "message": (f"I agree to the Free Money [Terms of Service]({BASE_URL}/terms) and "
                                f"[Privacy Policy]({BASE_URL}/privacy-policy), including the 7-day free trial "
                                f"then auto-renewing $4.99/month or $54/year subscription.")
                }
            },
            metadata={"plan": plan},
        )
        return sec_headers(jsonify({"url": sess.url, "session_id": sess.id, "plan": plan}))
    except Exception as e:
        log(f"checkout error: {e}")
        return sec_headers(jsonify({"error": "Checkout unavailable. Try again."})), 500

@app.route("/api/freemoney/verify", methods=["POST"])
def fm_verify():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    if not rate_check("verify", 5):
        return no_cache(jsonify({"pro": False, "error": "Too many requests."})), 429
    import stripe
    stripe.api_key = cfg()["stripe_secret_key"]
    data = request.get_json(silent=True) or {}
    sid, e = validate_str(data.get("session_id"), "session_id", max_len=200)
    if e or not sid:
        return no_cache(jsonify({"pro": False, "error": e or "No session ID"}))
    if not re.match(r"^cs_(test|live)_[A-Za-z0-9_]{10,}$", sid):
        return no_cache(jsonify({"pro": False, "error": "Invalid checkout session"})), 400
    try:
        sess = stripe.checkout.Session.retrieve(sid)
        if sess.payment_status in ("paid", "no_payment_required"):
            customer_id = sess.customer or ""
            email = phone = ""
            if sess.customer_details:
                email = sess.customer_details.email or ""
                phone = sess.customer_details.phone or ""
            if email or phone:
                upsert_pro_user(email, customer_id, phone=phone or None)
            conn = db()
            cur = conn.execute(
                "INSERT OR IGNORE INTO consumed_checkout_sessions (session_id, used_at) VALUES (?, ?)",
                (sid, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            if cur.rowcount == 0:
                return no_cache(jsonify({"pro": False, "error": "Checkout session already used"})), 400
            token = create_pro_session(customer_id, email)
            resp = jsonify({"pro": True, "customer": customer_id, "email": email})
            resp.set_cookie("fm_pro_token", token, httponly=True, samesite="Strict",
                            max_age=30*24*3600, path="/",
                            secure=(IS_PROD or request.is_secure))
            return no_cache(resp)
        return no_cache(jsonify({"pro": False}))
    except Exception as e:
        log(f"verify error: {e}")
        return no_cache(jsonify({"pro": False, "error": "Verification failed"}))

@app.route("/api/freemoney/pro-status")
def fm_pro_status():
    token = request.cookies.get("fm_pro_token", "")
    is_pro, email = verify_pro_session(token)
    return no_cache(jsonify({"pro": is_pro, "email": email}))

@app.route("/api/freemoney/report", methods=["POST"])
def fm_report():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    if not rate_check("report", 10, window=300):
        return sec_headers(jsonify({"error": "Too many reports. Try again later."})), 429
    data = request.get_json(silent=True) or {}
    try: sid = int(data.get("settlement_id") or 0)
    except Exception: sid = 0
    if sid <= 0:
        return sec_headers(jsonify({"error": "Invalid claim id"})), 400
    valid = {"proof_required","wrong_amount","wrong_deadline","expired","broken_link",
             "class_id_required","not_eligible","duplicate","other"}
    reason = (data.get("reason") or "").strip().lower()
    if reason not in valid:
        return sec_headers(jsonify({"error": "Invalid reason"})), 400
    details, derr = validate_str(data.get("details", ""), "details", max_len=500)
    if derr:
        return sec_headers(jsonify({"error": derr})), 400
    reporter_email = ""
    token = request.cookies.get("fm_pro_token", "")
    is_pro, eml = verify_pro_session(token)
    if is_pro: reporter_email = eml or ""
    ip = (request.headers.get("CF-Connecting-IP")
          or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or request.remote_addr or "unknown")
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS claim_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        settlement_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        details TEXT, reporter_email TEXT, reporter_ip TEXT,
        created_at TEXT, reviewed INTEGER DEFAULT 0
    )""")
    try: conn.execute("ALTER TABLE settlements ADD COLUMN reports_count INTEGER DEFAULT 0")
    except Exception: pass
    row = conn.execute("SELECT id, COALESCE(reports_count, 0) FROM settlements WHERE id = ?", (sid,)).fetchone()
    if not row:
        conn.close()
        return sec_headers(jsonify({"error": "Claim not found"})), 404
    conn.execute("""INSERT INTO claim_reports
        (settlement_id, reason, details, reporter_email, reporter_ip, created_at, reviewed)
        VALUES (?, ?, ?, ?, ?, ?, 0)""",
        (sid, reason, details, reporter_email, ip, datetime.now().isoformat()))
    new_count = (row[1] or 0) + 1
    conn.execute("UPDATE settlements SET reports_count = ? WHERE id = ?", (new_count, sid))
    if new_count >= 3:
        conn.execute("UPDATE settlements SET no_proof_flag = 0 WHERE id = ? AND no_proof_flag = 1", (sid,))
        log(f"AUTO-DEFLAGGED claim {sid} after {new_count} reports")
    conn.commit()
    conn.close()
    log(f"report claim={sid} reason={reason} count={new_count} "
        f"reporter={redact_email(reporter_email) if reporter_email else ip}")
    return sec_headers(jsonify({"ok": True, "count": new_count}))

@app.route("/api/freemoney/portal", methods=["POST"])
def fm_portal():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    token = request.cookies.get("fm_pro_token", "")
    is_pro, _ = verify_pro_session(token)
    if not is_pro:
        return sec_headers(jsonify({"error": "Not a Pro subscriber"})), 403
    try:
        import stripe
        stripe.api_key = cfg()["stripe_secret_key"]
        conn = db()
        row = conn.execute("SELECT stripe_customer_id FROM pro_sessions WHERE session_token = ?",
                           (token,)).fetchone()
        conn.close()
        if not row or not row["stripe_customer_id"]:
            return sec_headers(jsonify({"error": "Subscription not found"})), 404
        portal = stripe.billing_portal.Session.create(
            customer=row["stripe_customer_id"],
            return_url=BASE_URL + "/freemoney",
        )
        return no_cache(jsonify({"url": portal.url}))
    except Exception as e:
        log(f"portal error: {e}")
        return sec_headers(jsonify({"error": "Could not open billing portal."})), 500

# ── Routes: Stripe webhook ─────────────────────────────────────────────────────
@app.route("/api/freemoney/webhook", methods=["POST"])
@app.route("/api/stripe/webhook", methods=["POST"])
def stripe_webhook():
    ok, err = check_body_size(maxb=128*1024)
    if not ok: return err
    import stripe
    c = cfg()
    stripe.api_key = c["stripe_secret_key"]
    secret = c["stripe_webhook_secret"]
    payload = request.get_data(as_text=False)
    sig = request.headers.get("Stripe-Signature", "")
    if not secret or secret.startswith("whsec_PLACEHOLDER"):
        log("webhook secret not configured — rejecting")
        return "Webhook secret not configured", 400
    try:
        event = stripe.Webhook.construct_event(payload, sig, secret)
    except stripe.error.SignatureVerificationError:
        log("Webhook signature verification FAILED")
        return "Signature verification failed", 400
    except Exception as e:
        log(f"webhook invalid payload: {e}")
        return "Invalid payload", 400
    if event.type == "checkout.session.completed":
        s = event.data.object
        email = (s.get("customer_details") or {}).get("email", "")
        customer_id = s.get("customer", "")
        log(f"New Pro subscriber: {redact_email(email) if email else 'unknown'}")
        if email:
            try: upsert_pro_user(email, customer_id)
            except Exception as e: log(f"upsert failed: {e}")
    elif event.type in ("customer.subscription.deleted", "invoice.payment_failed", "customer.subscription.paused"):
        cid = event.data.object.get("customer", "")
        if cid:
            try:
                conn = db()
                conn.execute("UPDATE pro_users SET active = 0 WHERE stripe_customer_id = ?", (cid,))
                conn.execute("DELETE FROM pro_sessions WHERE stripe_customer_id = ?", (cid,))
                conn.commit()
                conn.close()
                log(f"Subscription inactive: {cid}")
            except Exception: pass
    elif event.type in ("customer.subscription.updated", "customer.subscription.resumed"):
        sub = event.data.object
        cid = sub.get("customer", "")
        status = sub.get("status", "")
        active = 1 if event.type == "customer.subscription.resumed" or status in ("active", "trialing") else 0
        if cid:
            try:
                conn = db()
                conn.execute("UPDATE pro_users SET active = ? WHERE stripe_customer_id = ?", (active, cid))
                if not active:
                    conn.execute("DELETE FROM pro_sessions WHERE stripe_customer_id = ?", (cid,))
                conn.commit()
                conn.close()
            except Exception: pass
    return "OK", 200

# ── Routes: magic-link restore (email-based) ───────────────────────────────────
@app.route("/api/freemoney/restore", methods=["POST"])
def fm_restore():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    if not rate_check("restore", 5):
        return sec_headers(jsonify({"error": "Too many requests. Try again in a minute."})), 429
    data = request.get_json(silent=True) or {}
    email, e = validate_email(data.get("email", ""))
    if e:
        # generic response — don't leak whether email exists
        return sec_headers(jsonify({"ok": True}))
    # per-email cooldown 5 minutes
    conn = db()
    last = conn.execute(
        "SELECT created_at FROM restore_codes WHERE email = ? ORDER BY id DESC LIMIT 1",
        (email,)).fetchone()
    if last:
        try:
            if (datetime.now() - datetime.fromisoformat(last["created_at"])).total_seconds() < 300:
                conn.close()
                return sec_headers(jsonify({"ok": True}))  # silent rate
        except Exception: pass
    # only send if user exists
    row = conn.execute("SELECT email FROM pro_users WHERE email = ? AND active = 1", (email,)).fetchone()
    if not row:
        conn.close()
        return sec_headers(jsonify({"ok": True}))  # generic
    import secrets as _sec
    code = f"{_sec.randbelow(900000) + 100000:06d}"
    conn.execute(
        "INSERT INTO restore_codes (email, code, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
        (email, code, datetime.now().isoformat(),
         (datetime.now() + timedelta(minutes=15)).isoformat()))
    conn.commit()
    conn.close()
    send_email(email, "Your Free Money restore code",
               f"Your Free Money restore code:\n\n{code}\n\nExpires in 15 minutes. "
               f"If you didn't request this, ignore this email.")
    return sec_headers(jsonify({"ok": True}))

@app.route("/api/freemoney/restore/confirm", methods=["POST"])
def fm_restore_confirm():
    ok, err = check_body_size()
    if not ok: return err
    x = require_xhr()
    if x: return x
    if not rate_check("restore_confirm", 10):
        return sec_headers(jsonify({"error": "Too many requests."})), 429
    data = request.get_json(silent=True) or {}
    email, e = validate_email(data.get("email", ""))
    code = (data.get("code") or "").strip()
    if e or not code or not re.match(r"^\d{6}$", code):
        return sec_headers(jsonify({"ok": False, "error": "Invalid code or email"})), 400
    conn = db()
    row = conn.execute(
        "SELECT id, expires_at FROM restore_codes WHERE email = ? AND code = ? AND used = 0 "
        "ORDER BY id DESC LIMIT 1", (email, code)).fetchone()
    if not row:
        conn.close()
        return sec_headers(jsonify({"ok": False, "error": "Invalid code"})), 400
    try:
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            conn.close()
            return sec_headers(jsonify({"ok": False, "error": "Code expired"})), 400
    except Exception: pass
    conn.execute("UPDATE restore_codes SET used = 1 WHERE id = ?", (row["id"],))
    user = conn.execute("SELECT stripe_customer_id FROM pro_users WHERE email = ? AND active = 1",
                        (email,)).fetchone()
    conn.commit()
    conn.close()
    if not user:
        return sec_headers(jsonify({"ok": False, "error": "No active subscription"})), 404
    token = create_pro_session(user["stripe_customer_id"], email)
    resp = jsonify({"ok": True, "pro": True, "email": email})
    resp.set_cookie("fm_pro_token", token, httponly=True, samesite="Strict",
                    max_age=30*24*3600, path="/", secure=(IS_PROD or request.is_secure))
    return no_cache(resp)

# ── Health + root ──────────────────────────────────────────────────────────────
@app.route("/healthz")
def healthz():
    try:
        conn = db()
        n = conn.execute("SELECT COUNT(*) FROM settlements WHERE status='active'").fetchone()[0]
        conn.close()
        return jsonify({"ok": True, "active_settlements": n}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── Hard-block any non-Free-Money path (defense in depth) ─────────────────────
# This is a slim app — nothing else should be served. Any unknown URL returns 404.

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    log(f"Free Money starting on port {port}, DB={DB_PATH}, base={BASE_URL}, prod={IS_PROD}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
