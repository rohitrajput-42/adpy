import re
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

app = FastAPI(
    title="Competitor Ad Pixel & Buyer Intent Spy API",
    description="Detects active paid ad networks (Meta, TikTok, Google Ads, LinkedIn), pixel IDs, and sales intent scores in <400ms.",
    version="1.0.0"
)

# Enable CORS for RapidAPI playground and third-party dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScriptAndTagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self._inside_script = False
        self._current_script = []

    def handle_starttag(self, tag: str, attrs: list):
        attrs_dict = dict(attrs)
        if tag == "script":
            self._inside_script = True
            if "src" in attrs_dict:
                self.script_srcs.append(attrs_dict["src"])

    def handle_endtag(self, tag: str):
        if tag == "script":
            self._inside_script = False
            script_text = "".join(self._current_script).strip()
            if script_text:
                self.inline_scripts.append(script_text)
            self._current_script = []

    def handle_data(self, data: str):
        if self._inside_script:
            self._current_script.append(data)


# --- Pixel ID Extraction & Network Signatures ---
PIXEL_EXTRACTORS = {
    "Meta Ads": {
        "id_patterns": [
            r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]\)",
            r"connect\.facebook\.net/.*/fbevents\.js.*id=(\d{10,20})",
            r"facebook\.com/tr\?id=(\d{10,20})"
        ],
        "presence_patterns": [r"fbevents\.js", r"fbq\("]
    },
    "Google Ads": {
        "id_patterns": [
            r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](AW-\d{7,15})['\"]\)",
            r"googleadservices\.com/pagead/conversion/(\d{7,15})",
            r"conversion_id\s*=\s*['\"]?(\d{7,15})"
        ],
        "presence_patterns": [r"googleadservices\.com", r"googletagmanager\.com/gtag/js\?id=AW-"]
    },
    "TikTok Ads": {
        "id_patterns": [
            r"ttq\.load\(\s*['\"]([A-Z0-9]{12,25})['\"]\)",
            r"analytics\.tiktok\.com/i18n/pixel/sdk\.js\?sdkid=([A-Z0-9]{12,25})"
        ],
        "presence_patterns": [r"analytics\.tiktok\.com", r"ttq\.page\("]
    },
    "LinkedIn Ads": {
        "id_patterns": [
            r"_linkedin_partner_id\s*=\s*['\"]?(\d{5,12})['\"]?",
            r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js\?id=(\d{5,12})"
        ],
        "presence_patterns": [r"snap\.licdn\.com/li\.lms-analytics", r"_linkedin_data_partner_ids"]
    },
    "Twitter/X Ads": {
        "id_patterns": [
            r"twq\(\s*['\"]config['\"]\s*,\s*['\"]([a-z0-9]{4,10})['\"]\)",
            r"twq\(\s*['\"]init['\"]\s*,\s*['\"]([a-z0-9]{4,10})['\"]\)"
        ],
        "presence_patterns": [r"static\.ads-twitter\.com", r"twq\("]
    },
    "Pinterest Ads": {
        "id_patterns": [
            r"pintrk\(\s*['\"]load['\"]\s*,\s*['\"](\d{10,18})['\"]",
            r"pintrk\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,18})['\"]"
        ],
        "presence_patterns": [r"s\.pinimg\.com/ct/core\.js", r"pintrk\("]
    }
}

OTHER_TRACKING_SIGNATURES = {
    "tag_managers": {
        "Google Tag Manager": [r"googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)"],
        "Adobe Launch": [r"assets\.adobedtm\.com/launch-"]
    },
    "analytics_crm": {
        "Google Analytics 4": [r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](G-[A-Z0-9]+)['\"]\)"],
        "HubSpot": [r"js\.hs-scripts\.com/(\d{5,12})\.js"],
        "Klaviyo": [r"static\.klaviyo\.com/onsite/js/klaviyo\.js\?company_id=([A-Za-z0-9]+)"],
        "Segment": [r"cdn\.segment\.com/analytics\.js/v1/([A-Za-z0-9]+)"],
        "Hotjar": [r"static\.hotjar\.com/c/hotjar-(\d+)\.js"]
    }
}


def scan_website_ad_intelligence(url: str) -> Dict:
    parsed_domain = urllib.parse.urlparse(url).netloc
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                raise HTTPException(status_code=400, detail="Target URL did not return HTML content.")
            html_body = resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch website: {str(e)}")

    # Parse external scripts and inline blocks
    parser = ScriptAndTagCollector()
    try:
        parser.feed(html_body)
    except Exception:
        pass

    corpus = " ".join(parser.script_srcs + parser.inline_scripts + [html_body[:30000]])

    active_networks = []
    pixel_ids = {}

    # 1. Scan Paid Ad Pixels & IDs
    for network, rules in PIXEL_EXTRACTORS.items():
        found_id = None
        for pattern in rules["id_patterns"]:
            match = re.search(pattern, corpus, re.IGNORECASE)
            if match:
                found_id = match.group(1)
                break

        network_detected = found_id is not None or any(
            re.search(pat, corpus, re.IGNORECASE) for pat in rules["presence_patterns"]
        )

        if network_detected:
            active_networks.append(network)
            if found_id:
                clean_key = network.lower().replace(" ", "_").replace("/", "_") + "_id"
                pixel_ids[clean_key] = found_id

    # 2. Scan Tag Managers and CRM/Analytics
    detected_tag_managers = []
    for tm_name, patterns in OTHER_TRACKING_SIGNATURES["tag_managers"].items():
        for pat in patterns:
            match = re.search(pat, corpus, re.IGNORECASE)
            if match:
                detected_tag_managers.append(tm_name)
                break

    detected_crm = []
    for tool_name, patterns in OTHER_TRACKING_SIGNATURES["analytics_crm"].items():
        for pat in patterns:
            match = re.search(pat, corpus, re.IGNORECASE)
            if match:
                detected_crm.append(tool_name)
                break

    # 3. Calculate Intent & Ad Spend Profile
    is_running_ads = len(active_networks) > 0
    score = 0
    if is_running_ads:
        score += 40
        score += min(len(active_networks) * 15, 30)  # Multi-channel scaling bonus
    if "Google Tag Manager" in detected_tag_managers:
        score += 15
    if detected_crm:
        score += 15

    intent_score = min(100, score)

    if intent_score >= 70:
        spend_profile = "AGGRESSIVE_SCALE"
    elif intent_score >= 40:
        spend_profile = "MODERATE_ACQUISITION"
    elif intent_score > 0:
        spend_profile = "TESTING_OR_ORGANIC"
    else:
        spend_profile = "ORGANIC_ONLY"

    return {
        "domain": parsed_domain,
        "is_running_paid_traffic": is_running_ads,
        "ad_spend_profile": spend_profile,
        "lead_intent_score": intent_score,
        "active_ad_networks": active_networks,
        "extracted_pixel_ids": pixel_ids,
        "tracking_infrastructure": {
            "tag_managers": detected_tag_managers,
            "analytics_and_crm": detected_crm
        }
    }


class IntentRequest(BaseModel):
    url: HttpUrl

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/api/v1/detect-ad-intent")
def detect_ad_intent(payload: IntentRequest):
    data = scan_website_ad_intelligence(str(payload.url))
    return {
        "success": True,
        "data": data
    }