"""
КОНТУР — AI-powered Telegram air threat parser
Uses Gemini 1.5 Flash for deep message analysis.
Runs via GitHub Actions every 3 minutes.
"""

import asyncio
import json
import os
import re
import sys
import time
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from typing import Optional

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError, ChannelPrivateError
import google.generativeai as genai

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("kontur")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

API_ID     = int(os.environ["TG_API_ID"])
API_HASH   = os.environ["TG_API_HASH"]
SESSION    = os.environ["TG_SESSION"]
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")

# Messages per channel per run
LIMIT_PER_CHANNEL = 20

# Keep alerts for N hours
ALERT_TTL_HOURS = 8

# Channels to monitor (username or numeric ID)
CHANNELS: list[str] = [
    "ukraeromil",        # Повітряні Сили ЗСУ (офіційний)
    "kpszsu",            # Командування ПС ЗСУ
    "air_alert_ua",      # Повітряна тривога Україна
    "ppo_ua",            # ППО радар
    "monitor1654",       # monitor 1654 | Харків
    "rynd_monitors",     # Ринда моніторить
    "eradar_ua",         # єРадар
    "rocketalert",       # Радар ракет
    "UkraineNow",        # Ukraine Now
    "spravdi",           # Спротив / Спразді
    "dsszzi",            # ДССЗЗІ
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatAlert:
    id: str                        # channel_msgid
    channel: str                   # channel username
    channel_title: str             # human-readable title
    ts: float                      # unix timestamp
    date_str: str                  # HH:MM dd.MM
    text: str                      # raw message (truncated)

    # AI-extracted fields
    is_threat: bool
    all_clear: bool
    threat_type: str               # shahed | rocket | ballistic | cruise | unknown
    threat_subtype: str            # e.g. shahed-136, x-101, kinzhal
    regions: list[str]             # affected regions/cities
    direction: Optional[str]       # movement direction if known
    count: Optional[int]           # number of objects
    destroyed: Optional[int]       # number destroyed (if report)
    severity: str                  # critical | high | medium | low
    summary_ua: str                # short Ukrainian summary ≤80 chars
    detail_ua: str                 # full Ukrainian analysis ≤300 chars
    ai_confidence: str             # high | medium | low
    tags: list[str]                # extra tags: [реактивний, балістичний, масований]


CHANNEL_TITLES = {
    "ukraeromil":   "Повітряні Сили ЗСУ",
    "kpszsu":       "Командування ПС ЗСУ",
    "air_alert_ua": "Повітряна тривога",
    "ppo_ua":       "ППО радар",
    "monitor1654":  "monitor 1654 | Харків",
    "rynd_monitors":"Ринда моніторить",
    "eradar_ua":    "єРадар",
    "rocketalert":  "Радар ракет",
    "UkraineNow":   "Ukraine Now",
    "spravdi":      "Спротив",
    "dsszzi":       "ДССЗЗІ",
}

# ─────────────────────────────────────────────────────────────────────────────
# AI PROCESSING — GEMINI
# ─────────────────────────────────────────────────────────────────────────────

_gemini_model = None

def _get_model():
    global _gemini_model
    if _gemini_model is None:
        genai.configure(api_key=GEMINI_KEY)
        _gemini_model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config=genai.GenerationConfig(
                temperature=0.1,          # low = more deterministic
                top_p=0.8,
                max_output_tokens=1024,
                response_mime_type="application/json",
            ),
        )
    return _gemini_model

AI_SYSTEM_PROMPT = """
Ти — експертна система аналізу повідомлень про повітряні загрози для України.
Твоє завдання: аналізувати повідомлення з Telegram каналів моніторингу та витягувати
структуровану інформацію з максимальною точністю.

ТИПИ ЗАГРОЗ:
- shahed: БПЛА-камікадзе Shahed (Шахед), іранські дрони, "мопеди", "гірки"
- rocket: крилаті ракети (Х-101, Х-555, Х-59, Калібр, Онікс)
- ballistic: балістичні ракети (Іскандер-М, КН-23, Кинджал)
- missile: загальна ракетна загроза (якщо тип невідомий)
- unknown: незрозумілий тип загрози

РЕГІОНИ УКРАЇНИ (нормалізовані назви):
Київська, Харківська, Дніпропетровська, Одеська, Запорізька, Херсонська,
Миколаївська, Полтавська, Сумська, Чернігівська, Вінницька, Житомирська,
Черкаська, Кіровоградська, Хмельницька, Тернопільська, Рівненська, Волинська,
Івано-Франківська, Закарпатська, Чернівецька, Донецька, Луганська, Львівська,
Київ (місто)

ВАЖЛИВО:
- all_clear: true ТІЛЬКИ якщо явно написано "відбій", "загроза минула", "небезпека відсутня"
- is_threat: true якщо йдеться про АКТИВНУ загрозу або щойно підтверджену атаку
- severity критерії:
  * critical: масований удар 10+ об'єктів, балістика, Кинджал
  * high: 3-9 БПЛА або ракети, підтверджені влучання
  * medium: 1-2 БПЛА, попередження
  * low: інформаційне повідомлення
- detail_ua: розширений аналіз — що відбувається, куди рухається, наслідки
- ai_confidence: наскільки ти впевнений у класифікації

Відповідай ТІЛЬКИ валідним JSON без пояснень.
"""

AI_USER_PROMPT_TEMPLATE = """
Проаналізуй це повідомлення з Telegram каналу "{channel}":

---
{text}
---

Поверни JSON з такою структурою:
{{
  "is_threat": boolean,
  "all_clear": boolean,
  "threat_type": "shahed"|"rocket"|"ballistic"|"missile"|"unknown"|"none",
  "threat_subtype": "назва конкретного типу зброї або null",
  "regions": ["масив регіонів/міст що згадані, нормалізовані"],
  "direction": "напрямок руху або null",
  "count": число або null,
  "destroyed": число знищених або null,
  "severity": "critical"|"high"|"medium"|"low",
  "summary_ua": "короткий підсумок до 80 символів",
  "detail_ua": "детальний аналіз до 300 символів — що відбувається, де, наслідки",
  "ai_confidence": "high"|"medium"|"low",
  "tags": ["додаткові теги: масований, поодинокий, підтверджено, попередження, відбій тощо"]
}}
"""


def ai_analyze(text: str, channel: str) -> dict:
    """Deep AI analysis via Gemini. Returns structured dict."""
    if not GEMINI_KEY:
        log.warning("No GEMINI_API_KEY — using fallback parser")
        return _fallback_parse(text)

    try:
        model = _get_model()
        prompt = AI_USER_PROMPT_TEMPLATE.format(
            channel=CHANNEL_TITLES.get(channel, channel),
            text=text[:2000],  # Gemini context limit safety
        )

        # Include system context in the prompt
        full_prompt = AI_SYSTEM_PROMPT + "\n\n" + prompt

        response = model.generate_content(full_prompt)
        raw = response.text.strip()

        # Strip markdown fences if model returns them despite json mime type
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        result = json.loads(raw)

        # Validate required keys
        required = ["is_threat", "all_clear", "threat_type", "regions", "severity", "summary_ua"]
        for k in required:
            if k not in result:
                raise ValueError(f"Missing key: {k}")

        log.info(f"  AI → {result.get('threat_type','?')} | {result.get('severity','?')} | {result.get('summary_ua','')[:50]}")
        return result

    except Exception as e:
        log.warning(f"  AI error ({type(e).__name__}): {e} — using fallback")
        return _fallback_parse(text)


def _fallback_parse(text: str) -> dict:
    """Keyword-based fallback when Gemini is unavailable."""
    t = text.lower()

    shahed_kw    = ["бпла", "шахед", "shahed", "дрон", "uav", "мопед", "гірка"]
    rocket_kw    = ["ракет", "крилат", "калібр", "kaliber", "х-101", "х-555", "х-59", "онікс"]
    ballistic_kw = ["балістич", "іскандер", "кинджал", "kinzhal", "кн-23"]
    clear_kw     = ["відбій", "загроза минула", "небезпека відсутня", "скасовано тривогу"]
    threat_kw    = ["бпла", "шахед", "ракет", "балістич", "крилат", "загроза", "тривога", "атак", "удар"]

    is_threat = any(k in t for k in threat_kw)
    all_clear = any(k in t for k in clear_kw)
    if all_clear:
        is_threat = False

    threat_type = "unknown"
    if any(k in t for k in ballistic_kw):
        threat_type = "ballistic"
    elif any(k in t for k in rocket_kw):
        threat_type = "rocket"
    elif any(k in t for k in shahed_kw):
        threat_type = "shahed"

    # Count extraction
    count = None
    m = re.search(r"(\d+)\s*(бпла|шахед|ракет|дрон)", t)
    if m:
        count = int(m.group(1))

    # Region extraction
    regions_map = {
        "київ":             "Київська",
        "харків":           "Харківська",
        "харківськ":        "Харківська",
        "львів":            "Львівська",
        "одес":             "Одеська",
        "дніпр":            "Дніпропетровська",
        "запоріж":          "Запорізька",
        "херсон":           "Херсонська",
        "миколаїв":         "Миколаївська",
        "полтав":           "Полтавська",
        "сум":              "Сумська",
        "чернігів":         "Чернігівська",
        "вінниц":           "Вінницька",
        "житомир":          "Житомирська",
        "черкас":           "Черкаська",
        "кіровоград":       "Кіровоградська",
        "хмельниц":         "Хмельницька",
        "тернопіл":         "Тернопільська",
        "рівн":             "Рівненська",
        "волин":            "Волинська",
        "луцьк":            "Волинська",
        "івано-франків":    "Івано-Франківська",
        "ужгород":          "Закарпатська",
        "чернівц":          "Чернівецька",
        "донецьк":          "Донецька",
        "луганськ":         "Луганська",
    }
    regions = []
    for key, region in regions_map.items():
        if key in t and region not in regions:
            regions.append(region)

    severity = "low"
    if is_threat:
        if threat_type == "ballistic":
            severity = "critical"
        elif count and count >= 10:
            severity = "critical"
        elif count and count >= 3:
            severity = "high"
        else:
            severity = "medium"

    return {
        "is_threat": is_threat,
        "all_clear": all_clear,
        "threat_type": threat_type if is_threat else "none",
        "threat_subtype": None,
        "regions": regions,
        "direction": None,
        "count": count,
        "destroyed": None,
        "severity": severity,
        "summary_ua": text[:80] if is_threat else "",
        "detail_ua": text[:300] if is_threat else "",
        "ai_confidence": "low",
        "tags": ["fallback"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# DATA PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

DATA_DIR       = "data"
ALERTS_FILE    = os.path.join(DATA_DIR, "alerts.json")
STATS_FILE     = os.path.join(DATA_DIR, "stats.json")
HISTORY_FILE   = os.path.join(DATA_DIR, "history.json")


def load_existing() -> tuple[list[dict], set[str]]:
    """Load existing alerts and seen IDs."""
    if not os.path.exists(ALERTS_FILE):
        return [], set()
    try:
        with open(ALERTS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=ALERT_TTL_HOURS)).timestamp()
        kept = [a for a in data.get("alerts", []) if a.get("ts", 0) > cutoff]
        seen = {a["id"] for a in data.get("alerts", [])}  # seen = ALL, kept = recent only
        return kept, seen
    except Exception as e:
        log.warning(f"Could not load existing data: {e}")
        return [], set()


def save_alerts(alerts: list[dict]):
    """Write alerts.json and stats.json."""
    os.makedirs(DATA_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts  = datetime.now(timezone.utc).timestamp()

    # Sort descending by time
    alerts.sort(key=lambda x: x.get("ts", 0), reverse=True)
    alerts = alerts[:300]  # hard cap

    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "updated":    now_iso,
            "updated_ts": now_ts,
            "total":      len(alerts),
            "alerts":     alerts,
        }, f, ensure_ascii=False, indent=2)
    log.info(f"Saved {len(alerts)} alerts → {ALERTS_FILE}")

    # ── Stats ─────────────────────────────────────────────────────────────────
    one_hour_ago = now_ts - 3600
    active = [a for a in alerts if a.get("ts", 0) > one_hour_ago and not a.get("all_clear")]

    threat_counts: dict[str, int] = {}
    regions_active: set[str] = set()
    total_count = 0

    for a in active:
        tt = a.get("threat_type", "unknown")
        threat_counts[tt] = threat_counts.get(tt, 0) + 1
        regions_active.update(a.get("regions", []))
        total_count += a.get("count") or 1

    # Severity breakdown
    severity_counts = {s: 0 for s in ["critical", "high", "medium", "low"]}
    for a in active:
        s = a.get("severity", "low")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    # Latest all_clear
    clears = [a for a in alerts if a.get("all_clear")]
    latest_clear = clears[0].get("ts") if clears else None

    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "updated":              now_iso,
            "active_last_hour":     len(active),
            "threat_counts":        threat_counts,
            "severity_counts":      severity_counts,
            "regions_under_threat": sorted(regions_active),
            "total_objects":        total_count,
            "latest_all_clear_ts":  latest_clear,
        }, f, ensure_ascii=False, indent=2)
    log.info(f"Saved stats → {STATS_FILE}")

    # ── History (daily buckets) ────────────────────────────────────────────────
    history: dict[str, dict] = {}
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = {}

    for a in alerts:
        day = datetime.fromtimestamp(a["ts"], tz=timezone.utc).strftime("%Y-%m-%d")
        if day not in history:
            history[day] = {"shaheds": 0, "rockets": 0, "ballistics": 0, "all_clear": 0}
        tt = a.get("threat_type", "unknown")
        if tt == "shahed":         history[day]["shaheds"]    += a.get("count") or 1
        elif tt == "rocket":       history[day]["rockets"]    += a.get("count") or 1
        elif tt == "ballistic":    history[day]["ballistics"] += a.get("count") or 1
        if a.get("all_clear"):     history[day]["all_clear"]  += 1

    # Keep last 30 days
    days_sorted = sorted(history.keys(), reverse=True)
    history = {d: history[d] for d in days_sorted[:30]}

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM PARSER
# ─────────────────────────────────────────────────────────────────────────────

async def parse_channels() -> int:
    """Main parsing coroutine. Returns number of new alerts found."""
    client = TelegramClient(StringSession(SESSION), API_ID, API_HASH)
    await client.start()
    log.info("Telegram client connected")

    existing_alerts, seen_ids = load_existing()
    new_alerts: list[dict] = []
    new_count = 0

    for channel in CHANNELS:
        log.info(f"Fetching @{channel}…")
        try:
            entity = await client.get_entity(channel)

            async for msg in client.iter_messages(entity, limit=LIMIT_PER_CHANNEL):
                if not msg.text or not msg.text.strip():
                    continue

                msg_id = f"{channel}_{msg.id}"
                if msg_id in seen_ids:
                    continue

                log.info(f"  Processing msg {msg.id}: {msg.text[:60].strip()!r}")

                # ── AI analysis ──────────────────────────────────────────────
                parsed = ai_analyze(msg.text, channel)

                # Skip non-threat, non-all_clear messages
                if not parsed.get("is_threat") and not parsed.get("all_clear"):
                    continue

                # Format timestamp
                msg_ts = msg.date.replace(tzinfo=timezone.utc).timestamp()
                date_str = datetime.fromtimestamp(msg_ts, tz=timezone.utc).strftime("%H:%M %d.%m")

                alert = {
                    # Identity
                    "id":             msg_id,
                    "channel":        channel,
                    "channel_title":  CHANNEL_TITLES.get(channel, channel),
                    "ts":             msg_ts,
                    "date_str":       date_str,
                    "text":           msg.text[:600],

                    # AI extracted
                    "is_threat":      parsed.get("is_threat", False),
                    "all_clear":      parsed.get("all_clear", False),
                    "threat_type":    parsed.get("threat_type", "unknown"),
                    "threat_subtype": parsed.get("threat_subtype"),
                    "regions":        parsed.get("regions", []),
                    "direction":      parsed.get("direction"),
                    "count":          parsed.get("count"),
                    "destroyed":      parsed.get("destroyed"),
                    "severity":       parsed.get("severity", "medium"),
                    "summary_ua":     parsed.get("summary_ua", ""),
                    "detail_ua":      parsed.get("detail_ua", ""),
                    "ai_confidence":  parsed.get("ai_confidence", "low"),
                    "tags":           parsed.get("tags", []),
                }

                new_alerts.append(alert)
                seen_ids.add(msg_id)
                new_count += 1

                emoji = "🚨" if alert["is_threat"] else "✅"
                log.info(f"  {emoji} [{alert['severity']}] {alert['summary_ua'][:60]}")

                # Small delay to avoid Gemini rate limits
                if GEMINI_KEY:
                    await asyncio.sleep(0.5)

        except ChannelPrivateError:
            log.warning(f"  @{channel} is private/not found — skipping")
        except FloodWaitError as e:
            log.warning(f"  Flood wait {e.seconds}s on @{channel} — skipping rest")
            break
        except Exception as e:
            log.error(f"  Error on @{channel}: {type(e).__name__}: {e}")

    await client.disconnect()
    log.info("Telegram client disconnected")

    all_alerts = new_alerts + existing_alerts
    save_alerts(all_alerts)

    log.info(f"Done — new: {new_count}, kept: {len(existing_alerts)}, total: {len(all_alerts)}")
    return new_count


# ─────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start = time.time()
    try:
        new = asyncio.run(parse_channels())
        elapsed = time.time() - start
        log.info(f"Finished in {elapsed:.1f}s  |  new alerts: {new}")
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        log.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
