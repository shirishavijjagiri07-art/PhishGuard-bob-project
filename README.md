# 🛡️ PhishGuard – Phishing Awareness Checker

**IBM SkillsBuild Cybersecurity Project**
**Technology:** Python · Streamlit · Regex
**Category:** Cybersecurity Awareness Tool

---

## 📌 Problem Statement

Phishing is one of the most common and harmful forms of cybercrime today. Attackers send fake emails or messages that look legitimate to trick people into sharing passwords, one-time codes, banking details, or clicking dangerous links. Most people, especially those who are not tech-savvy, cannot easily tell the difference between a real message and a phishing attempt.

There is a need for a simple, easy-to-use tool that helps everyday users check whether a suspicious message they received might be a phishing attack — before they take any action on it.

---

## 🎯 Objectives

1. Build a beginner-friendly web application that analyses email and message text for phishing signals.
2. Detect six phishing and scam tactics: urgency, suspicious links, credential requests, financial requests, phishing keywords, and scam/prize/call-back fraud.
3. Produce a clear risk rating (LOW / MEDIUM / HIGH) and a numeric score out of 100.
4. Display specific warning signs found in the message so the user understands exactly what triggered the alert.
5. Provide practical safety recommendations based on what was detected.
6. Keep the tool entirely local — no user data is sent to any server.
7. Serve as an educational resource that increases phishing awareness.

---

## 🚀 Features

| Feature | Description |
|---|---|
| ⚡ Urgency detection | Spots pressure tactics like "act now", "expires", "final notice", "within 24 hours" |
| 🔗 Suspicious link scanner | Detects raw IP URLs, URL shorteners, typosquatted domains, and plain HTTP links |
| 🔑 OTP / Credential requests | Flags requests to share passwords, PINs, or one-time codes |
| 💳 Financial info requests | Identifies bank detail, card number, wire-transfer, and gift-card scams |
| 🚩 Phishing keywords | Catches classic scam phrases, spoofed brand names, and unusual activity notices |
| 🎰 Scam / Prize / Call-back fraud | Detects prize claims, lottery wins, money offers, promotional scams, and call-back requests |
| 📊 Risk score (0 – 100) | Weighted numeric score across all six categories, with guaranteed MEDIUM/HIGH floors for scam signals |
| 💡 Safety recommendations | Context-aware tips shown based on what was actually detected |
| 🔁 Sample loader | One-click button to load a built-in phishing example for demonstration |

---

## 🧑‍💻 Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.9+ | Core programming language |
| Streamlit | Web application framework (runs in the browser, no server needed) |
| `re` (regex) | Pattern matching engine for phishing signal detection |
| `html` (stdlib) | HTML escaping to safely display matched snippets |
| HTML / CSS | Inline styling for the risk cards, progress bar, and result layout |

No external APIs, databases, or cloud services are used. The entire application runs on the user's local machine.

---

## ⚙️ How the Application Works

The application follows four steps each time the Analyse button is clicked:

**Step 1 — Input**
The user pastes an email or message into the text area. The text is read exactly as typed — no preprocessing or modification.

**Step 2 — Pattern scanning**
The text is scanned against six sets of regular-expression patterns, one set per phishing category. All matching spans across every pattern in a category are collected, overlapping spans are merged, and one highlighted snippet per merged span is extracted (with 10 characters of context on each side). This ensures one piece of text that matches multiple patterns only appears once in the results.

**Step 3 — Scoring**
Each category has a maximum score contribution. The number of distinct matches in a category determines the percentage of that maximum that is added to the total:
- 1 match → 60% of the category maximum
- 2 matches → 80%
- 3 or more matches → 100%

The six category scores are summed and capped at 100. Two floor rules then apply:
- If any **scam** indicators are detected → score is raised to at least **30** (MEDIUM), even if no other categories fired.
- If scam indicators are detected **together with** urgency, suspicious links, OTP/password requests, or financial requests → score is raised to at least **60** (HIGH).

**Step 4 — Display**
The app shows the risk level (LOW / MEDIUM / HIGH), the numeric score, a progress bar, expandable panels for each category with the matched text snippets highlighted, and a set of safety recommendations tailored to what was found.

---

## 🔍 Phishing Indicators Checked

### ⚡ Urgency / Pressure Tactics (max 20 points)
Words and phrases designed to make the reader act without thinking:
`urgent`, `immediately`, `act now`, `expires`, `deadline`, `last chance`, `final notice`, `within 24 hours`, `today only`, `action required`, `account will be suspended`, `verify now`

### 🔗 Suspicious Links (max 25 points)
Link formats commonly used by attackers:
- Raw IP address URLs (e.g. `http://192.168.1.1/login`)
- Uncommon or free TLDs associated with phishing: `.tk`, `.xyz`, `.ru`
- URL shorteners: `bit.ly`, `tinyurl`, `t.co`, `ow.ly`, `is.gd`, `buff.ly`
- Typosquatted brand domains: `paypa1`, `amaz0n`, `g00gle`, `micros0ft`, `app1e`, `faceb00k`
- Phishing keyword paths on suspicious TLDs: `/login`, `/verify`, `/secure` on `.tk`, `.xyz`, etc.
- Plain HTTP links (not HTTPS)

### 🔑 OTP / Password / Credential Requests (max 25 points)
Phrases that ask the user to share sensitive authentication information:
`enter your OTP`, `provide your PIN`, `share your password`, `do not share your OTP`, `your verification code`, `update your password`, `reset your password`, `confirm your credentials`

### 💳 Financial Information Requests (max 20 points)
Phrases associated with financial fraud:
`bank account`, `account number`, `routing number`, `credit card`, `card number`, `CVV`, `wire transfer`, `gift card`, `you have won`, `claim your prize`, `unclaimed funds`, `pay a fee`

### 🚩 Phishing Keywords (max 10 points)
Classic scam and phishing language:
`phishing`, `malware`, `suspicious activity`, `unauthorized access`, `account compromised`, `click here to verify`, `open the attachment`, `download the file`, `we noticed unusual`, `kindly update`, `dear customer`, `congratulations you`, Nigerian prince / royalty fund transfer patterns

### 🎰 Scam / Prize / Call-back Fraud (max 30 points — with risk floor)
Indicators of prize scams, lottery fraud, money offers, promotional traps, and call-back fraud:
- Prize / winner / lottery claims: `you have won`, `you are a winner`, `lucky winner`, `prize`, `lottery`, `jackpot`, `claim your prize`, `winner announcement`
- Money offers: `free money`, `earn easy money`, `make money fast`, `guaranteed income`, `million dollars transfer`, `cash prize`
- Promotional scams: `exclusive offer`, `limited time offer`, `100% free`, `absolutely free`, `double your money`, `get rich quick`, `this is not a scam`, `work from home earn`
- Call-back requests: `call us now`, `call this number`, `phone me back`, `WhatsApp us`, `text me back` followed by a phone number

**Floor rules (guaranteed minimum risk):**
- Any scam signal alone → at least **MEDIUM** risk (score raised to 30 if below).
- Scam signal + urgency, suspicious links, OTP/credential request, or financial request → at least **HIGH** risk (score raised to 60 if below).

---

## 📊 Risk Scoring

### Score bands

| Score | Risk Level | Meaning |
|---|---|---|
| 0 – 29 | 🟢 LOW | No significant phishing signals. Message is likely safe. |
| 30 – 59 | 🟡 MEDIUM | Some suspicious elements detected. Proceed with caution. |
| 60 – 100 | 🔴 HIGH | Multiple phishing indicators. Do not act on this message. |

### Score calculation

| Category | Max points | Weight reasoning |
|---|---|---|
| Suspicious links | 25 | Links are the most direct attack vector |
| OTP / Credential requests | 25 | Direct credential theft is high severity |
| Urgency / Pressure | 20 | Urgency is a primary manipulation tactic |
| Financial requests | 20 | Financial fraud causes direct harm |
| Scam / Prize / Call-back | 30 | Broad scam signals; floor rules ensure correct minimum rating |
| Phishing keywords | 10 | Supporting signal — context alone is lower weight |

Within each category: **1 match = 60%**, **2 matches = 80%**, **3+ matches = 100%** of the maximum. Total is capped at 100.

**Score floors applied after totalling:**
- Scam hits present → `score = max(score, 30)`
- Scam hits + any of urgency / links / OTP / financial → `score = max(score, 60)`

---

## 🛠️ Installation & Usage

### Requirements

- Python 3.9 or later
- pip (Python package manager)

### Step 1 — Download the project

```bash
git clone https://github.com/your-username/PhishGuard.git
cd PhishGuard
```

Or download the ZIP from GitHub and extract it.

### Step 2 — (Recommended) Create a virtual environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Run the app

```bash
streamlit run app.py
```

The app opens automatically in your browser at `http://localhost:8501`.

### How to use it

1. Paste any suspicious email or message into the text area.
2. Click **🔍 Analyse Message**.
3. Read the **Risk Level** and **Phishing Score**.
4. Expand each **Warning Signs** panel to see exactly what was flagged.
5. Follow the **Safety Recommendations** shown at the bottom.
6. Use **Load sample ↓** to instantly try a built-in phishing example.

---

## 📁 Project Structure

```
PhishGuard/
├── app.py            ← Main Streamlit application (detection logic + UI)
├── requirements.txt  ← Python dependencies (streamlit only)
├── README.md         ← This documentation file
└── report.html       ← Static sample phishing analysis report (standalone HTML)
```

---

## 🧪 Testing Results

Five types of messages were tested to verify correct behaviour:

### Test 1 — Phishing sample (HIGH risk expected)

**Input:**
> Dear Customer, We have noticed suspicious activity on your account. Your account will be suspended within 24 hours unless you verify immediately. Click here to verify: http://paypa1-secure.tk/verify. Enter your OTP and password to confirm your identity.

**Result:** Score **60 / 100** · Risk **HIGH** ✅

| Category | Hits detected |
|---|---|
| Urgency | "suspended within 24 hours", "verify immediately", "account will be suspended" |
| Suspicious links | `http://paypa1-secure.tk/verify` (typosquatted domain + .tk TLD + plain HTTP) |
| OTP / Credentials | "Enter your OTP and password" |
| Financial | None |
| Keywords | "suspicious activity", "dear customer", "click here to verify" |
| Scam | None |

---

### Test 2 — Normal message (LOW risk expected)

**Input:**
> Hi John, just wanted to follow up on our meeting Thursday. Let me know if the time works. Best, Sarah

**Result:** Score **0 / 100** · Risk **LOW** ✅

No phishing signals detected. The safe fallback recommendation was shown.

---

### Test 3 — Empty input

**Result:** Warning message displayed — "Please paste a message before analysing." No score or results shown. ✅

---

### Test 4 — Scam-only message (MEDIUM risk expected — floor rule)

**Input:**
> Congratulations! You have won a lottery prize. Call us now to claim your reward.

**Result:** Score **30 / 100** · Risk **MEDIUM** ✅

The raw score from pattern matching alone would be LOW, but the scam floor rule raises it to 30 (MEDIUM) because scam indicators were present.

| Category | Hits detected |
|---|---|
| Scam | "you have won", "lottery", "prize", "call us now", "claim your reward" |
| All other categories | None |

---

### Test 5 — Scam + urgency combined (HIGH risk expected — combined floor rule)

**Input:**
> URGENT: You are a lucky winner! You have won $1 million. Act now — limited time offer. Call this number immediately to claim your prize.

**Result:** Score **60 / 100** · Risk **HIGH** ✅

Scam indicators combined with urgency triggers the combined floor rule, raising the score to at least 60.

| Category | Hits detected |
|---|---|
| Urgency | "urgent", "act now", "immediately", "limited time offer" |
| Scam | "you are a lucky winner", "you have won", "million", "call this number", "claim your prize" |
| All other categories | None |

---

## ⚠️ Limitations

- **Pattern matching only:** PhishGuard uses regular expressions. It cannot understand context the way a human or an AI model can. A cleverly worded phishing message that avoids known phrases may not be detected.
- **No image or attachment scanning:** The tool only analyses plain text. Phishing attempts that use images, QR codes, or malicious attachments are out of scope.
- **English language only:** All detection patterns are written for English text. Messages in other languages will not be reliably detected.
- **False positives possible:** Legitimate messages that contain security-related phrases (e.g. a bank's genuine password reset email) may score higher than expected.
- **No sender verification:** The tool does not check email headers, sender addresses, or DNS records. It only analyses message body text.
- **Not a replacement for professional security tools:** PhishGuard is an awareness and educational tool, not an enterprise-grade anti-phishing solution.

---

## 🤝 Ethical Usage

PhishGuard is built for **educational and awareness purposes only**.

- Use it to learn how phishing messages are structured.
- Use it to test whether a message you received might be suspicious before clicking any links.
- **Do not** use it to craft phishing messages. Understanding phishing patterns is for defence, not offence.
- All analysis runs locally on your machine. No message text is transmitted, stored, or logged anywhere.
- This tool does not guarantee the safety of any message. Always use your own judgement and consult your organisation's IT or security team when in doubt.

---

## 🔮 Future Improvements

The following enhancements could be added in a future version:

| Improvement | Description |
|---|---|
| URL reputation check | Integrate a public API (e.g. Google Safe Browsing) to check whether detected links are on known phishing blocklists |
| Email header analysis | Parse raw email headers to verify sender domain, SPF/DKIM records, and Reply-To mismatches |
| Multi-language support | Add detection patterns for phishing in other languages |
| AI / ML model | Train a text classifier on labelled phishing datasets for higher accuracy and context awareness |
| Browser extension | Package the detection logic as a browser extension that analyses emails directly in Gmail or Outlook |
| Export report | Allow the user to download the analysis result as a PDF or HTML report |
| History log | Store previous scans in a local session log so users can compare messages |

---

## ✅ Conclusion

PhishGuard demonstrates how a simple Python application can be used to raise cybersecurity awareness and help users identify phishing messages. By scanning six categories of phishing and scam signals — urgency tactics, suspicious links, credential requests, financial requests, phishing keywords, and scam/prize/call-back fraud — the tool produces a clear risk score and actionable safety advice that anyone can understand and act on.

The project was built with beginner-friendliness in mind: it requires only one dependency (Streamlit), runs entirely on the local machine, and uses only Python's built-in `re` and `html` standard library modules for its core logic. No cloud services, no databases, and no user data collection.

Phishing awareness is one of the most effective defences against cybercrime. PhishGuard is a small but practical step toward making that awareness accessible to everyone.

---

## 📄 License

This project is released for educational use as part of the IBM SkillsBuild Cybersecurity programme. Feel free to study, modify, and share it for non-commercial educational purposes.
