import html
import re
import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard – Phishing Awareness Checker",
    page_icon="🛡️",
    layout="centered",
)

# ── Detection rules ───────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires?\b",
    r"\bdeadline\b", r"\blast chance\b", r"\bfinal notice\b",
    r"\bwithin 24 hours?\b", r"\bwithin 48 hours?\b", r"\btoday only\b",
    r"\baction required\b", r"\byour account (will be|has been) (suspended|closed|blocked)\b",
    r"\bverify (now|immediately|your account)\b",
]

SUSPICIOUS_LINK_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # raw IP URLs
    r"https?://[^\s]*\.ru[/\s]",                         # .ru TLD
    r"https?://[^\s]*\.tk[/\s]",                         # .tk TLD (common in phishing)
    r"https?://[^\s]*\.xyz[/\s]",                        # .xyz TLD
    r"bit\.ly|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly",    # URL shorteners
    r"https?://[^\s]*(paypa1|amaz0n|g00gle|micros0ft|app1e|faceb00k)[^\s]*",  # typosquatting
    r"https?://[^\s]*(login|signin|verify|secure|update|account)[^\s]*\.(xyz|tk|ml|ga|cf)",
    r"http://",                                          # plain HTTP (non-HTTPS)
]

OTP_PASSWORD_PATTERNS = [
    r"\b(enter|provide|confirm|share|send|submit)\b.{0,30}\b(otp|one.?time password|pin)\b",
    r"\b(otp|one.?time (password|code)|pin)\b.{0,30}\b(enter|provide|confirm|share|send)\b",
    r"\bdo not share your (otp|password|pin|code)\b",  # reverse warning (often phishing)
    r"\byour (verification|security) code\b",
    r"\benter your password\b",
    r"\bupdate your (password|credentials|login)\b",
    r"\breset your password\b",
    r"\bconfirm your (password|pin|credentials)\b",
]

FINANCIAL_PATTERNS = [
    r"\b(bank account|account number|routing number|sort code)\b",
    r"\b(credit card|debit card|card number|cvv|cvc|expiry date)\b",
    r"\b(wire transfer|bank transfer|money transfer|send money)\b",
    r"\b(gift card|itunes card|google play card|amazon card)\b",
    r"\byou (have won|are a winner|won a prize|are selected)\b",
    r"\b(claim your|collect your) (prize|reward|winnings|cash)\b",
    r"\bunclaimed (funds|money|inheritance|lottery)\b",
    r"\bpay .{0,20}(fee|charge|tax|fine|penalty)\b",
    r"\brefund .{0,20}(account|bank|card)\b",
]

PHISHING_KEYWORDS = [
    r"\bphishing\b",                    # meta (user might paste a warning)
    r"\bmalware\b", r"\bvirus\b",
    r"\bsuspicious (activity|login|access)\b",
    r"\bunauthorized (access|login|activity)\b",
    r"\byour (account|profile) (has been|is|was) (compromised|hacked|breached)\b",
    r"\bclick (here|the link|below) to (verify|confirm|update|secure)\b",
    r"\bopen the attachment\b", r"\bdownload the (file|attachment)\b",
    r"\bwe noticed .{0,30}(unusual|suspicious)\b",
    r"\bkindly (update|verify|confirm|click)\b",
    r"\bdear (customer|user|member|valued)\b",
    r"\bcongratulations[,!]?\s+(you|your)\b",
    r"\b(nigerian?|prince|royalt(y|ies)).{0,40}(million|transfer|funds)\b",
]

SCAM_PATTERNS = [
    # Prize / reward / winner / lottery claims
    r"\b(you have won|you('ve| have) been selected|you are (a )?winner)\b",
    r"\b(prize|reward|lottery|raffle|jackpot|lucky (winner|draw))\b",
    r"\b(congratulations[,!]?.{0,20}(won|winner|selected|chosen|prize|reward))\b",
    r"\bclaim (your|the) (prize|reward|cash|money|winnings|gift)\b",
    r"\bwinner (announcement|notification|alert)\b",
    r"\byou (have been|are) (selected|chosen) (as|to)\b",

    # Money / cash offers
    r"\b(free money|earn (easy )?money|make money (fast|online|now|from home))\b",
    r"\b(guaranteed (income|earnings|returns?|profit)|no (risk|investment) (required|needed))\b",
    r"\b(million (dollars?|pounds?|euros?)|thousand (dollars?|pounds?|euros?)) (transfer|offer|grant|gift)\b",
    r"\bsend (you|us) (a )?cheque\b",
    r"\bcash (prize|reward|offer|back guarantee)\b",

    # Promotional / too-good-to-be-true offers
    r"\b(exclusive (offer|deal|discount)|limited (time )?offer|special (promotion|offer|deal))\b",
    r"\b(100% free|absolutely free|no (cost|charge|strings attached))\b",
    r"\b(double your (money|investment)|get (rich|wealthy) (quick|fast|now))\b",
    r"\b(this is not a scam|not a (joke|trick|spam))\b",      # self-denial — common in scams
    r"\bwork from home.{0,20}(earn|make|income|salary)\b",

    # Suspicious call requests
    r"\b(call (us|me|now|back|this number|immediately)|phone (us|me|now|back))\b",
    r"\bcontact (us|me) (at|on).{0,20}(\+?\d[\d\s\-().]{6,})",  # call + phone number
    r"\b(whatsapp|telegram|signal).{0,20}(us|me|number|contact)\b",
    r"\btext (us|me|back|now).{0,20}(\+?\d[\d\s\-().]{5,})",    # text + number
]

# ── Scoring weights ────────────────────────────────────────────────────────────
# Each category contributes a maximum number of points toward the 100-point score.
# "scam" max is 30 so that even a single hit (60 % × 30 = 18) is meaningful,
# but the floor rules in analyse() are what guarantee MEDIUM / HIGH ratings.
CATEGORY_MAX = {
    "urgency":     20,
    "links":       25,
    "otp":         25,
    "financial":   20,
    "keywords":    10,
    "scam":        30,
}

CATEGORY_LABELS = {
    "urgency":   "⚡ Urgency / Pressure tactics",
    "links":     "🔗 Suspicious links",
    "otp":       "🔑 OTP / Password / Credential requests",
    "financial": "💳 Financial information requests",
    "keywords":  "🚩 Phishing keywords",
    "scam":      "🎰 Scam / Prize / Call-back fraud",
}


def scan_patterns(text: str, patterns: list[str]) -> list[str]:
    """Return a deduplicated list of matched snippets (≤ 80 chars each).

    Collects all match spans across every pattern first, then merges
    overlapping spans so that a single piece of text (e.g. one URL)
    that is caught by multiple patterns only produces one snippet.
    """
    lower = text.lower()

    # 1. Collect all (start, end) spans from every pattern
    raw_spans: list[tuple[int, int]] = []
    for pat in patterns:
        for m in re.finditer(pat, lower):
            raw_spans.append((m.start(), m.end()))

    if not raw_spans:
        return []

    # 2. Sort and merge overlapping/adjacent spans
    raw_spans.sort()
    merged: list[tuple[int, int]] = [raw_spans[0]]
    for start, end in raw_spans[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:          # overlapping or adjacent
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    # 3. Build one snippet per merged span
    hits: list[str] = []
    for start, end in merged:
        snippet = text[max(0, start - 10): end + 10].strip()
        if snippet not in hits:
            hits.append(snippet)
    return hits


def analyse(text: str) -> dict:
    """Run all checks and return a structured result dict."""
    results = {
        "urgency":   scan_patterns(text, URGENCY_PATTERNS),
        "links":     scan_patterns(text, SUSPICIOUS_LINK_PATTERNS),
        "otp":       scan_patterns(text, OTP_PASSWORD_PATTERNS),
        "financial": scan_patterns(text, FINANCIAL_PATTERNS),
        "keywords":  scan_patterns(text, PHISHING_KEYWORDS),
        "scam":      scan_patterns(text, SCAM_PATTERNS),
    }

    # Score: for each category, add proportional points capped at the category max
    score = 0
    for cat, max_pts in CATEGORY_MAX.items():
        hits = len(results[cat])
        # 1 hit = 60 % of max, 2 hits = 80 %, 3+ hits = 100 %
        if hits == 1:
            score += int(max_pts * 0.60)
        elif hits == 2:
            score += int(max_pts * 0.80)
        elif hits >= 3:
            score += max_pts

    score = min(score, 100)

    # ── Floor rules for scam indicators ──────────────────────────────────────
    # Any scam signal alone → never LOW; lift to at least MEDIUM (score 30).
    # Scam combined with any of urgency / links / OTP / financial → at least HIGH (score 60).
    if results["scam"]:
        score = max(score, 30)
        combined_with_scam = (
            results["urgency"]
            or results["links"]
            or results["otp"]
            or results["financial"]
        )
        if combined_with_scam:
            score = max(score, 60)

    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"results": results, "score": score, "risk": risk}


def risk_color(risk: str) -> str:
    return {"LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#ef4444"}[risk]


def recommendations(risk: str, results: dict) -> list[str]:
    tips = []
    if results["links"]:
        tips.append("Do **not** click any links in this message. Hover to preview URLs before clicking.")
        tips.append("If you must visit a site, type the official address directly into your browser.")
    if results["otp"]:
        tips.append("**Never share OTPs, passwords, or PINs** — legitimate services will never ask for them via email or chat.")
    if results["financial"]:
        tips.append("Ignore any requests for bank details, card numbers, or gift cards — these are classic fraud tactics.")
    if results["urgency"]:
        tips.append("Urgency is a manipulation tactic. Pause, breathe, and verify through official channels before acting.")
    if results["keywords"]:
        tips.append("Look up the sender's official contact information independently and call them to verify.")
    if results["scam"]:
        tips.append("Prizes, lotteries, and unexpected cash offers are almost always scams — do not call back, reply, or click anything.")
        tips.append("**Never call an unknown number** provided in an unsolicited message. Look up the organisation's official number independently.")
    if risk == "HIGH":
        tips.append("Report this message to your IT/security team or forward it to your email provider's phishing report address.")
        tips.append("If you already clicked a link or provided information, change your passwords immediately and notify your bank if needed.")
    if not tips:
        tips.append("This message appears safe, but always stay cautious — when in doubt, verify with the sender through a known channel.")
    return tips


# ── UI ─────────────────────────────────────────────────────────────────────────

st.markdown(
    """
    <h1 style='text-align:center;font-size:1.6rem;margin-bottom:.15rem;'>🛡️ PhishGuard</h1>
    <p style='text-align:center;color:#57606a;font-size:.85rem;margin-top:0;'>
        Phishing Awareness Checker &nbsp;·&nbsp; Paste any suspicious email or message below
    </p>
    <hr style='margin:.5rem 0 .75rem;'>
    """,
    unsafe_allow_html=True,
)

with st.expander("ℹ️  What does PhishGuard check?"):
    st.markdown(
        """
        PhishGuard scans your message for five categories of phishing signals:

        | Category | What it detects |
        |---|---|
        | ⚡ **Urgency** | Pressure words like "act now", "expires", "final notice" |
        | 🔗 **Suspicious links** | Raw IP URLs, URL shorteners, typosquatted domains, plain HTTP |
        | 🔑 **OTP / Credentials** | Requests to share passwords, PINs, or one-time codes |
        | 💳 **Financial requests** | Bank details, card numbers, wire transfers, gift cards |
        | 🚩 **Phishing keywords** | Classic scam phrases, spoofed brands, unusual activity notices |

        Results are for **awareness only** — always use your own judgement and consult your IT team for official guidance.
        """
    )

SAMPLE_EMAIL = (
    "Dear Customer,\n\n"
    "We have noticed suspicious activity on your account. "
    "Your account will be suspended within 24 hours unless you verify immediately.\n\n"
    "Click here to verify: http://paypa1-secure.tk/verify\n\n"
    "Enter your OTP and password to confirm your identity.\n\n"
    "Regards,\nSupport Team"
)

# Initialise session state keys on first load
if "pg_text" not in st.session_state:
    st.session_state["pg_text"] = ""
if "pg_result" not in st.session_state:
    st.session_state["pg_result"] = None

# ── Input row ─────────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown(
        "<p style='margin-bottom:.25rem;font-size:.9rem;font-weight:600;'>"
        "Paste your email or message:</p>",
        unsafe_allow_html=True,
    )
with col2:
    if st.button("Load sample ↓", use_container_width=True):
        st.session_state["pg_text"] = SAMPLE_EMAIL
        st.session_state["pg_result"] = None   # clear any previous result

user_input = st.text_area(
    label="Message input",
    label_visibility="collapsed",
    placeholder="Paste the email or message text here…",
    height=160,
    value=st.session_state["pg_text"],
)

# Keep pg_text in sync with whatever the user typed
st.session_state["pg_text"] = user_input

# ── Analyse button ─────────────────────────────────────────────────────────────
if st.button("🔍  Analyse Message", type="primary", use_container_width=True):
    text = user_input.strip()
    if not text:
        st.warning("Please paste a message before analysing.")
        st.session_state["pg_result"] = None
    else:
        st.session_state["pg_result"] = analyse(text)

# ── Results ────────────────────────────────────────────────────────────────────
if st.session_state["pg_result"] is not None:
    result = st.session_state["pg_result"]
    score = result["score"]
    risk  = result["risk"]
    cats  = result["results"]
    color = risk_color(risk)

    st.markdown(
        "<hr style='margin:.5rem 0 .75rem;'>",
        unsafe_allow_html=True,
    )

    # ── Risk badge + score ────────────────────────────────────────────────
    badge_col, score_col = st.columns(2)
    with badge_col:
        st.markdown(
            f"""
            <div style='background:{color};border-radius:10px;padding:.7rem;text-align:center;'>
                <div style='font-size:1.5rem;font-weight:700;color:#fff;line-height:1.2;'>{risk} RISK</div>
                <div style='color:#fff;opacity:.85;font-size:.8rem;'>Phishing likelihood</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with score_col:
        st.markdown(
            f"""
            <div style='background:#f7f8fa;border:1px solid #e5e7eb;border-radius:10px;
                        padding:.7rem;text-align:center;'>
                <div style='font-size:1.5rem;font-weight:700;color:{color};line-height:1.2;'>{score}<span style='font-size:.9rem;color:#57606a;'>/100</span></div>
                <div style='color:#57606a;font-size:.8rem;'>Phishing Score</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Progress bar ──────────────────────────────────────────────────────
    st.progress(score / 100)

    # ── Warning signs ─────────────────────────────────────────────────────
    st.markdown(
        "<p style='font-size:.95rem;font-weight:600;margin:.6rem 0 .3rem;'>⚠️ Warning Signs Detected</p>",
        unsafe_allow_html=True,
    )
    found_any = False
    for cat, label in CATEGORY_LABELS.items():
        hits = cats[cat]
        if hits:
            found_any = True
            with st.expander(f"{label}  —  {len(hits)} match(es)"):
                for h in hits:
                    st.markdown(
                        f"<code style='background:#fff3cd;padding:2px 6px;"
                        f"border-radius:4px;'>{html.escape(h)}</code>",
                        unsafe_allow_html=True,
                    )

    if not found_any:
        st.success("No phishing signals detected in this message.")

    # ── Recommendations ───────────────────────────────────────────────────
    st.markdown(
        "<p style='font-size:.95rem;font-weight:600;margin:.6rem 0 .3rem;'>💡 Safety Recommendations</p>",
        unsafe_allow_html=True,
    )
    for tip in recommendations(risk, cats):
        st.markdown(f"- {tip}")

    # ── Disclaimer ────────────────────────────────────────────────────────
    st.markdown(
        "<p style='color:#57606a;font-size:.75rem;margin-top:.75rem;'>"
        "PhishGuard uses pattern-matching heuristics. It may produce false positives or miss "
        "novel attacks. Always verify suspicious messages through official channels.</p>",
        unsafe_allow_html=True,
    )

# ── Footer ─────────────────────────────────────────────────────────────────────
st.markdown(
    "<hr style='margin:.75rem 0 .4rem;'>"
    "<p style='text-align:center;color:#57606a;font-size:.75rem;margin:0;'>"
    "PhishGuard · Phishing Awareness Checker · For educational use only</p>",
    unsafe_allow_html=True,
)
