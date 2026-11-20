"""OIW webpage text extraction and spaCy analysis feature.

Adapted from the web_sourcery2.py script for local HTTP use.
"""
# Future annotations allow type hints to refer to types without
# requiring every annotation to be evaluated immediately.
from __future__ import annotations
# Standard-library imports used for dependency checks, URL/IP validation,
# network access, regular expressions, concurrency control and timestamps.
import importlib.metadata
import importlib.util
import ipaddress
import re
import socket
import threading
import time
from collections import Counter, defaultdict
from urllib.parse import unquote, urljoin, urlsplit
# Third-party library used to parse and validate telephone numbers
# internationally, rather than accepting every number-shaped text string.
import phonenumbers
from phonenumbers import PhoneNumberFormat
# Configuration limits and concurrency controls for webpage analysis.
# MAX_BODY_SIZE is retained as a small-body limit setting; the page download
# itself is governed by MAX_PAGE_BYTES below.
WEB_ANALYSIS_MAX_BODY_SIZE = 8 * 1024
WEB_ANALYSIS_MAX_PAGE_BYTES = 4 * 1024 * 1024
WEB_ANALYSIS_MAX_TEXT_CHARS = 160_000
WEB_ANALYSIS_MAX_REDIRECTS = 4
WEB_ANALYSIS_TIMEOUT = (5, 18)
WEB_ANALYSIS_LOCK = threading.RLock()
WEB_ANALYSIS_SEMAPHORE = threading.BoundedSemaphore(1)
_WEB_NLP = None
_WEB_SPACY = None
# A dedicated exception lets the API layer return a useful message and
# an appropriate HTTP status instead of exposing an internal traceback.
class WebAnalysisError(Exception):
    """A safe, user-facing webpage-analysis error with an HTTP status."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
# Reports whether spaCy and its English model appear to be installed.
# It deliberately checks availability without loading the comparatively
# large NLP model, so the UI can check status quickly.

def web_analysis_install_status() -> dict:
    """Check optional spaCy/model availability without loading the model."""
    try:
        spacy_version = importlib.metadata.version("spacy")
    except importlib.metadata.PackageNotFoundError:
        return {"installed": False, "modelInstalled": False, "spacyVersion": None}
    try:
        model_installed = importlib.util.find_spec("en_core_web_sm") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        model_installed = False
            # Return a JSON-serialisable dictionary. The frontend can display these
    # fields in separate result panels and include them in an exported report.
    return {
        "installed": True,
        "modelInstalled": model_installed,
        "spacyVersion": spacy_version,
    }
# Validates a submitted URL before any network request is made.
# This is an important SSRF safeguard: the analyser is intended to fetch
# public websites, not localhost, private networks or internal services.

def _validate_public_web_url(value: object) -> str:
    """Accept public HTTP(S) URLs only; reject local/private destinations."""
    if not isinstance(value, str) or not value:
        raise WebAnalysisError("Enter a webpage URL.")
    if value != value.strip():
        raise WebAnalysisError("The URL has leading or trailing whitespace. Correct it and try again.")
    if len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise WebAnalysisError("The URL is too long or contains invalid control characters.")
    # Parse the URL and access .port here because malformed port values can
    # raise ValueError; that is converted into a user-facing validation error.
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise WebAnalysisError("The URL is malformed.") from None

    if parsed.scheme.lower() not in {"http", "https"}:
        raise WebAnalysisError("Only public HTTP and HTTPS webpages can be analysed.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise WebAnalysisError("Enter a valid URL without embedded username or password credentials.")
    if parsed.fragment:
        # Fragments are not sent to the server and can cause confusing duplicates.
        raise WebAnalysisError("Remove the #fragment from the URL and try again.")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if port not in (None, default_port):
        raise WebAnalysisError("Non-standard website ports are not supported.")
    # Remove a trailing DNS dot, then resolve the hostname so the code can
    # reject destinations that point at private, reserved or non-public IPs.
    hostname = parsed.hostname.rstrip(".")
    if not hostname or hostname.casefold() in {"localhost", "localhost.localdomain"}:
        raise WebAnalysisError("Localhost and private network addresses cannot be analysed.")

    try:
        try:
            literal_ip = ipaddress.ip_address(hostname)
            resolved = {literal_ip}
        except ValueError:
            records = socket.getaddrinfo(
                hostname,
                default_port,
                type=socket.SOCK_STREAM,
            )
            resolved = {
                ipaddress.ip_address(record[4][0].split("%", 1)[0])
                for record in records
            }
    except (OSError, ValueError):
        raise WebAnalysisError("The website hostname could not be resolved.", 502) from None

    if not resolved or any(not address.is_global for address in resolved):
        raise WebAnalysisError(
            "The URL resolves to a private, reserved or non-public network address. It has been blocked."
        )
    return value

# Fetches the webpage as bytes and returns both the page and final URL.
# Redirects are handled manually so every new destination is validated
# before the next request is sent.
def _download_public_html(url: str) -> tuple[bytes, str]:
    """Download a bounded HTML page while revalidating every redirect target."""
    try:
        import requests
    except ImportError:
        raise WebAnalysisError(
            "The webpage-analysis dependencies are missing. Install requirements-web-analysis.txt.",
            503,
        ) from None
    # A session reuses connection settings. trust_env=False prevents ambient
    # proxy environment variables from silently changing where requests go.
    current_url = _validate_public_web_url(url)
    session = requests.Session()
    # Ignore machine-level proxy environment variables for this local research fetch.
    session.trust_env = False
    headers = {
        "User-Agent": "OIW-Webpage-Analyser/0.3.4",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
        # Follow only a bounded number of redirects. Each target is revalidated
        # to reduce the risk of a public URL redirecting to an internal address.
    try:
        for redirect_count in range(WEB_ANALYSIS_MAX_REDIRECTS + 1):
            _validate_public_web_url(current_url)
            try:
                response = session.get(
                    current_url,
                    headers=headers,
                    timeout=WEB_ANALYSIS_TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.exceptions.Timeout:
                raise WebAnalysisError("The website request timed out.", 504) from None
            except requests.exceptions.RequestException:
                raise WebAnalysisError("Unable to connect to the requested website.", 502) from None

            with response:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if not location:
                        raise WebAnalysisError("The website returned an invalid redirect.", 502)
                    if redirect_count >= WEB_ANALYSIS_MAX_REDIRECTS:
                        raise WebAnalysisError("The website exceeded the redirect limit.", 502)
                    current_url = urljoin(current_url, location)
                    continue

                if response.status_code >= 400:
                    raise WebAnalysisError(
                        f"The website returned HTTP {response.status_code}.", 502
                    )

                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type not in {"text/html", "application/xhtml+xml"}:
                    raise WebAnalysisError(
                        "The URL did not return an HTML webpage. Only HTML pages are supported.", 415
                    )

                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > WEB_ANALYSIS_MAX_PAGE_BYTES:
                            raise WebAnalysisError("The webpage is larger than the 4 MB download limit.", 413)
                    except ValueError:
                        pass
                # Stream the response in chunks and enforce the byte limit while reading.
                # Checking only Content-Length would be insufficient because it can be
                # absent or inaccurate.
                chunks = []
                byte_count = 0
                try:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        byte_count += len(chunk)
                        if byte_count > WEB_ANALYSIS_MAX_PAGE_BYTES:
                            raise WebAnalysisError("The webpage is larger than the 4 MB download limit.", 413)
                        chunks.append(chunk)
                except requests.exceptions.Timeout:
                    raise WebAnalysisError("The webpage download timed out.", 504) from None
                except requests.exceptions.RequestException:
                    raise WebAnalysisError("The webpage download was interrupted.", 502) from None

                page_bytes = b"".join(chunks)
                return page_bytes, current_url

        raise WebAnalysisError("The webpage could not be downloaded.", 502)
    finally:
        session.close()
    # Always close the HTTP session, including when validation or download fails.
# Converts downloaded HTML into readable text. The Boolean result indicates
# whether the extracted text had to be truncated to the configured limit.
def _extract_page_text(page_bytes: bytes) -> tuple[str, bool]:
    """Strip non-content elements and extract readable text, following the supplied script."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise WebAnalysisError(
            "BeautifulSoup is missing. Install requirements-web-analysis.txt.", 503
        ) from None

    soup = BeautifulSoup(page_bytes, "html.parser")
    for element in soup(["script", "style", "noscript", "svg", "iframe", "template"]):
        element.decompose()

    extracted = soup.get_text(separator="\n", strip=True)
    lines = [re.sub(r"\s+", " ", line).strip() for line in extracted.splitlines()]
    text = "\n".join(line for line in lines if line)
    truncated = len(text) > WEB_ANALYSIS_MAX_TEXT_CHARS
    return text[:WEB_ANALYSIS_MAX_TEXT_CHARS], truncated

# Lazily load spaCy and the en_core_web_sm model the first time analysis
# is requested. Caching avoids repeatedly loading the model into memory.
def _load_web_nlp():
    """Load the same spaCy English small model as the supplied script, on demand."""
    global _WEB_NLP, _WEB_SPACY
    with WEB_ANALYSIS_LOCK:
        if _WEB_NLP is not None and _WEB_SPACY is not None:
            return _WEB_NLP, _WEB_SPACY
        try:
            import spacy
        except ImportError:
            raise WebAnalysisError(
                "spaCy is not installed. Run: python -m pip install -r requirements-web-analysis.txt",
                503,
            ) from None
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            raise WebAnalysisError(
                "The spaCy English model is missing. Run: python -m spacy download en_core_web_sm",
                503,
            ) from None
        nlp.max_length = WEB_ANALYSIS_MAX_TEXT_CHARS + 1000
        _WEB_NLP = nlp
        _WEB_SPACY = spacy
        return _WEB_NLP, _WEB_SPACY
# Normalises entity labels for grouping, for example by removing a trailing
# possessive apostrophe, while retaining the original spelling separately.

def _normalise_web_entity(entity: str) -> str:
    entity = entity.strip()
    entity = re.sub(r"(?i)(?:['’]s|['’])$", "", entity)
    return entity.strip()
# Runs the NLP stage and returns three datasets: named entities, recurring
# noun-phrase themes, and frequently occurring keywords.

def _analyse_web_text(text: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Return spaCy entities, recurring noun-phrase themes and keyword frequencies."""
    nlp, spacy = _load_web_nlp()
    doc = nlp(text)

    entity_counts = defaultdict(Counter)
    entity_variations = defaultdict(Counter)
    for ent in doc.ents:
        if ent.label_ == "CARDINAL":
            continue
        original_name = ent.text.strip()
        entity_name = _normalise_web_entity(original_name)
        if not entity_name:
            continue
        entity_counts[entity_name][ent.label_] += 1
        entity_variations[entity_name][original_name] += 1

    entities = []
    for entity_name, types in entity_counts.items():
        for entity_type, count in types.items():
            entities.append({
                "entity": entity_name,
                "type": entity_type,
                "description": spacy.explain(entity_type) or entity_type,
                "count": count,
                "variations": dict(entity_variations[entity_name]),
            })
    entities.sort(key=lambda item: (item["type"], item["entity"].lower()))

    keyword_counts = Counter()
    for token in doc:
        if token.is_alpha and not token.is_stop and len(token.text) > 2:
            keyword = token.lemma_.lower()
            if keyword:
                keyword_counts[keyword] += 1
    keywords = [
        {"keyword": keyword, "count": count}
        for keyword, count in keyword_counts.most_common(50)
    ]

    # The supplied script ranks keywords. For a more useful theme view, this
    # integration also surfaces repeated two-or-more-word spaCy noun phrases.
    theme_counts = Counter()
    for chunk in doc.noun_chunks:
        terms = [
            token.lemma_.lower()
            for token in chunk
            if token.is_alpha and not token.is_stop
        ]
        phrase = " ".join(terms).strip()
        if len(terms) >= 2 and len(phrase) >= 5:
            theme_counts[phrase] += 1
    themes = [
        {"theme": theme, "count": count}
        for theme, count in theme_counts.most_common(20)
        if count >= 2
    ]

    return entities, themes, keywords

# Email and telephone extraction -------------------------------------------------
# National-format telephone numbers are interpreted using this default region.
# Numbers with an explicit international prefix (for example +1 or +33) are
# parsed according to that prefix and are not restricted to this region.
EMAIL_PATTERN = re.compile(
    r"(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
    re.IGNORECASE,
)

# This deliberately finds candidate number strings; phonenumbers performs the
# country-aware parsing and validation to filter dates, IDs and other noise.
PHONE_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w])(?:\+|00)?\s*\(?\d"
    r"(?:[\d\s()./\-]{4,30}\d)"
    r"(?:\s*(?:ext\.?|x)\s*\d{1,6})?(?!\w)",
    re.IGNORECASE,
)
# Extracts and deduplicates email addresses and valid phone numbers.
# Numbers without an international prefix are interpreted using the
# supplied default region (GB by default).

def extract_contact_identifiers(
    text: str,
    default_region: str = "GB",
    email_candidates: list[str] | None = None,
    phone_candidates: list[str] | None = None,
) -> dict:
    """Extract deduplicated email addresses and valid international phone numbers.

    Explicit international prefixes such as +1, +33 and +44 are recognised
    independently of default_region. Numbers without a country code are
    interpreted using default_region (GB by default).
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(default_region, str) or not re.fullmatch(r"[A-Za-z]{2}", default_region):
        raise ValueError("default_region must be a two-letter ISO region code, such as GB or US")

    email_results = {}
    email_source = text
    if email_candidates:
        email_source += "\\n" + "\\n".join(email_candidates)

    for match in EMAIL_PATTERN.finditer(email_source):
        original = match.group(0).rstrip(".,;:!?)\"]}")
        if not original:
            continue
        key = original.casefold()
        if key not in email_results:
            email_results[key] = {
                "email": original,
                "count": 0,
                "originalFormats": [],
            }
        item = email_results[key]
        item["count"] += 1
        if original not in item["originalFormats"]:
            item["originalFormats"].append(original)

    phone_results = {}
    phone_source = text
    if phone_candidates:
        phone_source += "\\n" + "\\n".join(phone_candidates)

    for match in PHONE_CANDIDATE_PATTERN.finditer(phone_source):
        candidate = match.group(0).strip()
        try:
            parsed = phonenumbers.parse(candidate, default_region)
        except phonenumbers.NumberParseException:
            continue
        if not phonenumbers.is_valid_number(parsed):
            continue

        e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        international = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        region_code = phonenumbers.region_code_for_number(parsed)

        if e164 not in phone_results:
            phone_results[e164] = {
                "international": international,
                "national": national,
                "e164": e164,
                "region": region_code,
                "count": 0,
                "originalFormats": [],
            }
        item = phone_results[e164]
        item["count"] += 1
        if candidate not in item["originalFormats"]:
            item["originalFormats"].append(candidate)

    emails = sorted(email_results.values(), key=lambda item: item["email"].casefold())
    phones = sorted(phone_results.values(), key=lambda item: item["e164"])
    return {
        "emails": emails,
        "phones": phones,
        "uniqueEmails": len(emails),
        "uniquePhones": len(phones),
        "totalEmailOccurrences": sum(item["count"] for item in emails),
        "totalPhoneOccurrences": sum(item["count"] for item in phones),
    }

# Reads anchor href values to find contact details that may not appear in
# the visible page text, such as addresses hidden behind mailto: or tel: links.

def _extract_contact_links(page_bytes: bytes) -> tuple[list[str], list[str]]:
    """Extract email and telephone targets from mailto: and tel: links."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        raise WebAnalysisError(
            "BeautifulSoup is missing. Install requirements-web-analysis.txt.",
            503,
        ) from None

    soup = BeautifulSoup(page_bytes, "html.parser")
    email_candidates = []
    phone_candidates = []

    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href", "")).strip()
        if not href:
            continue

        parsed = urlsplit(href)
        scheme = parsed.scheme.lower()

        if scheme == "mailto":
            # A mailto target can contain multiple recipients and query parameters.
            recipient_text = unquote(parsed.path)
            for recipient in re.split(r"[,;]", recipient_text):
                recipient = recipient.strip()
                if recipient:
                    email_candidates.append(recipient)

        elif scheme == "tel":
            telephone = unquote(parsed.path).strip()
            if telephone:
                phone_candidates.append(telephone)

    return email_candidates, phone_candidates
# Main entry point called by the OIW backend/API. It coordinates fetching,
# text extraction, NLP analysis and contact extraction, then builds the
# structured result object consumed by the frontend.
def analyse_webpage(url: str) -> dict:
    """Complete webpage extraction and NLP analysis for the OIW web interface."""
    if not WEB_ANALYSIS_SEMAPHORE.acquire(blocking=False):
        raise WebAnalysisError("A webpage analysis is already running. Wait for it to finish.", 429)
    try:
        page_bytes, final_url = _download_public_html(url)
        text, truncated = _extract_page_text(page_bytes)
        if not text.strip():
            raise WebAnalysisError("No readable webpage text could be extracted.", 422)
        entities, themes, keywords = _analyse_web_text(text)
        linked_emails, linked_phones = _extract_contact_links(page_bytes)
        contacts = extract_contact_identifiers(
            text,
            default_region="GB",
            email_candidates=linked_emails,
            phone_candidates=linked_phones,
        )
        return {
            "sourceUrl": url,
            "finalUrl": final_url,
            "collectedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "totalCharacters": len(text),
            "totalWords": len(text.split()),
            "uniqueEntities": len(entities),
            "uniqueKeywords": len(keywords),
            "truncated": truncated,
            "entities": entities,
            "themes": themes,
            "keywords": keywords,
            "emails": contacts["emails"],
            "phones": contacts["phones"],
            "uniqueEmails": contacts["uniqueEmails"],
            "uniquePhones": contacts["uniquePhones"],
            "totalEmailOccurrences": contacts["totalEmailOccurrences"],
            "totalPhoneOccurrences": contacts["totalPhoneOccurrences"],
            "extractedText": text,
        }
    finally:
        WEB_ANALYSIS_SEMAPHORE.release()
    # Release the single-analysis lock even if fetching or analysis raises an
    # exception, otherwise later requests would remain blocked indefinitely.