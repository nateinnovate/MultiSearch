"""OSINT Investigation Workstation - local browser-based search launcher."""

from __future__ import annotations
# Standard-library modules provide command-line parsing, JSON/config files,
# filesystem operations, validation, random IDs, threading and browser launch.
import argparse
import importlib.metadata
import json
import os
import re
import secrets
import threading
import time
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
# The separate webpage_analyser.py module performs webpage fetching and NLP.
# These imports provide its request-size limit, custom error and API functions.
from webpage_analyser import (
    WEB_ANALYSIS_MAX_BODY_SIZE,
    WebAnalysisError,
    analyse_webpage,
    web_analysis_install_status,
)

# Application paths and runtime settings. ROOT is the folder containing app.py.
APP_VERSION = "0.4"
ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
CONFIG = ROOT / "config"
PROVIDERS_FILE = CONFIG / "providers.json"
# Bind to loopback only: this server is intended for use on this computer,
# not for access by other computers on the network.
HOST = "127.0.0.1"
PORT = 8765
APP_URL = f"http://{HOST}:{PORT}/"
MAX_CONFIG_SIZE = 256 * 1024
CONFIG_LOCK = threading.RLock()
# Holehe jobs and their results are kept in RAM, not written to disk.
# Locks protect shared job data because HTTP handlers and worker threads overlap.
# Limits cap the number of retained jobs and concurrent checks.
# Holehe runs are transient: identifiers and results stay in memory only.
HOLEHE_LOCK = threading.RLock()
HOLEHE_JOBS: dict[str, dict] = {}
HOLEHE_MAX_JOBS = 25
HOLEHE_JOB_TTL_SECONDS = 60 * 60
HOLEHE_MAX_CONCURRENT_RUNS = 1
HOLEHE_MODULE_CONCURRENCY = 8
HOLEHE_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)
# Allowed search-identifier types and the controlled provider categories.
IDENTIFIER_TYPES = {"username", "email", "phone", "name", "domain", "ip"}
CATEGORIES = {
    "Search engines",
    "Identity intelligence",
    "Email intelligence",
    "Username research",
    "Telephone intelligence",
    "Infrastructure",
}
# BROWSER STARTUP: check common Windows paths for Chrome. Return None if it
# is not installed in those locations so the default browser can be used.#

def find_chrome() -> str | None:
    candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path.home() / "AppData/Local/Google/Chrome/Application/chrome.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None
# Wait for the server to start, then open OIW in Chrome or the default browser.
# A browser-launch failure is caught so it does not bring down the server.

def launch_browser() -> None:
    time.sleep(2)
    chrome = find_chrome()
    try:
        if chrome:
            import subprocess

            print(f"Chrome detected: {chrome}")
            subprocess.Popen([chrome, "--new-window", APP_URL])
        else:
            print("Chrome not found. Opening the default browser.")
            webbrowser.open_new_tab(APP_URL)
    except Exception as error:  # Browser launch must not stop the local server.
        print(f"Browser launch error: {error}")
        print(f"Open manually: {APP_URL}")
# PROVIDER VALIDATION: allow only well-formed HTTPS URLs with a hostname.
# Automatic search templates must contain {query}; credentials and fragments
# are rejected. The placeholder is replaced temporarily for URL parsing.

def validate_url(url: object, require_query: bool = False) -> bool:
    if not isinstance(url, str) or not url or len(url) > 2048:
        return False
    if any(ord(char) < 32 for char in url):
        return False
    if require_query and "{query}" not in url:
        return False
    candidate = url.replace("{query}", "oiw-validation-test")
    try:
        parsed = urlsplit(candidate)
        # Accessing .port also detects malformed port numbers.
        _ = parsed.port
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except ValueError:
        return False
# Validate the complete provider configuration before loading or saving it.
# Checks include provider IDs, duplicate IDs, names, categories, supported
# identifier types, enabled flags, URL templates and Holehe-specific rules.

def validate_config(config: object) -> dict:
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object.")

    providers = config.get("providers")
    if not isinstance(providers, list):
        raise ValueError("Missing providers array.")
    if len(providers) > 200:
        raise ValueError("Maximum of 200 providers allowed.")

    seen_ids: set[str] = set()
    for provider in providers:
        if not isinstance(provider, dict):
            raise ValueError("Invalid provider entry.")

        provider_id = provider.get("id")
        name = provider.get("name")
        category = provider.get("category")
        types = provider.get("types")
        enabled = provider.get("enabled")

        if not isinstance(provider_id, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,63}", provider_id
        ):
            raise ValueError("Invalid or missing provider ID.")
        if provider_id in seen_ids:
            raise ValueError(f"Duplicate provider ID: {provider_id}")
        seen_ids.add(provider_id)

        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise ValueError("Invalid provider name.")
        if category not in CATEGORIES:
            raise ValueError(f"Invalid provider category: {category}")
        if (
            not isinstance(types, list)
            or not types
            or any(not isinstance(item, str) for item in types)
        ):
            raise ValueError(f"Invalid identifier types for {name}.")
        if len(types) != len(set(types)):
            raise ValueError(f"Duplicate identifier types for {name}.")
        if not set(types).issubset(IDENTIFIER_TYPES):
            raise ValueError(f"Unsupported identifier type for {name}.")
        if not isinstance(enabled, bool):
            raise ValueError(f"Invalid enabled setting for {name}.")

        templates = provider.get("urlTemplates", {})
        if not isinstance(templates, dict):
            raise ValueError(f"Invalid URL templates for {name}.")
        integration = provider.get("integration")
        if integration is not None and integration != "holehe":
            raise ValueError(f"Unsupported local integration for {name}.")

        if integration == "holehe":
            if types != ["email"]:
                raise ValueError("The local Holehe integration supports email identifiers only.")
            if templates or provider.get("manualUrl"):
                raise ValueError("A local Holehe integration cannot also define website URLs.")
        else:
            for identifier, template in templates.items():
                if identifier not in IDENTIFIER_TYPES or identifier not in types:
                    raise ValueError(f"Invalid template identifier for {name}.")
                if not validate_url(template, require_query=True):
                    raise ValueError(f"Invalid HTTPS search template for {name}.")

            manual_url = provider.get("manualUrl")
            if manual_url is not None and not validate_url(manual_url):
                raise ValueError(f"Invalid manual URL for {name}.")
            if not templates and not manual_url:
                raise ValueError(f"{name} needs a search template, manual URL, or supported integration.")

        clipboard = provider.get("clipboard", False)
        if not isinstance(clipboard, bool):
            raise ValueError(f"Invalid clipboard setting for {name}.")
        if integration == "holehe" and clipboard:
            raise ValueError("Clipboard mode is not used by the local Holehe integration.")

    return config
# Read providers.json under a lock and validate its contents. Invalid JSON or
# invalid settings are treated as configuration errors, not silently reset.

def load_config() -> dict:
    if not PROVIDERS_FILE.exists():
        raise SystemExit("ERROR: providers.json not found.")
    try:
        with CONFIG_LOCK, PROVIDERS_FILE.open("r", encoding="utf-8") as file:
            config = json.load(file)
        return validate_config(config)
    except (json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"Provider configuration error: {error}") from error
# Validate first, then write a temporary file and atomically replace the old
# configuration. This reduces the risk of leaving a partially-written JSON file.

def save_config(config: object) -> dict:
    validated = validate_config(config)
    encoded = json.dumps(validated, indent=2, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_CONFIG_SIZE:
        raise ValueError("Configuration file is too large.")

    CONFIG.mkdir(parents=True, exist_ok=True)
    temporary_file = PROVIDERS_FILE.with_name("providers.json.tmp")
    with CONFIG_LOCK:
        try:
            with temporary_file.open("wb") as file:
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_file, PROVIDERS_FILE)
        finally:
            if temporary_file.exists():
                temporary_file.unlink()
    return validated
# HOLEHE: report whether the optional Python package is installed and its version.
# This check does not perform an email lookup.

def holehe_install_status() -> dict:
    """Report whether the optional upstream Holehe package is installed."""
    try:
        version = importlib.metadata.version("holehe")
        return {"installed": True, "version": version}
    except importlib.metadata.PackageNotFoundError:
        return {"installed": False, "version": None}
    except Exception:
        return {"installed": False, "version": None}
# Validate the email without normalising it. Leading/trailing spaces are rejected
# rather than stripped, so the value passed to Holehe remains exactly as entered.

def _validate_exact_holehe_email(value: object) -> str:
    """Validate an email without changing any character in the supplied value."""
    if not isinstance(value, str):
        raise ValueError("An email address is required.")
    if value != value.strip():
        raise ValueError(
            "The email contains leading or trailing whitespace. "
            "Remove it manually; OIW will not alter the supplied address."
        )
    if len(value) > 254 or not HOLEHE_EMAIL_RE.fullmatch(value):
        raise ValueError(
            "Enter a valid email address for Holehe. The supplied value will not be modified."
        )
    return value

# Mask the local part of an email address before showing job information in the UI.
def _mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    if not separator or not local:
        return "Hidden"
    return f"{local[0]}***@{domain}"
# Remove expired completed jobs and trim older completed jobs if the job table
# exceeds its maximum size. The caller must already hold HOLEHE_LOCK.

def _prune_holehe_jobs_locked() -> None:
    cutoff = time.time() - HOLEHE_JOB_TTL_SECONDS
    expired = [
        run_id for run_id, job in HOLEHE_JOBS.items()
        if job.get("updated_at", job.get("created_at", 0)) < cutoff
        and job.get("status") not in {"queued", "running"}
    ]
    for run_id in expired:
        HOLEHE_JOBS.pop(run_id, None)

    if len(HOLEHE_JOBS) > HOLEHE_MAX_JOBS:
        completed = sorted(
            (
                (run_id, job.get("updated_at", job.get("created_at", 0)))
                for run_id, job in HOLEHE_JOBS.items()
                if job.get("status") not in {"queued", "running"}
            ),
            key=lambda item: item[1],
        )
        for run_id, _ in completed[: max(0, len(HOLEHE_JOBS) - HOLEHE_MAX_JOBS)]:
            HOLEHE_JOBS.pop(run_id, None)
# Build the limited job-status object sent to the browser. The raw email and
# unfiltered upstream module responses are deliberately not exposed.

def _public_holehe_job(job: dict) -> dict:
    """Return only the fields needed by the results page; never expose the raw email."""
    return {
        "runId": job["run_id"],
        "status": job["status"],
        "emailMasked": job["email_masked"],
        "createdAt": job["created_at"],
        "startedAt": job.get("started_at"),
        "completedAt": job.get("completed_at"),
        "progress": {
            "completed": job.get("completed", 0),
            "total": job.get("total", 0),
        },
        "summary": job.get("summary"),
        "results": job.get("results", []),
        "error": job.get("error"),
        "settings": {
            "passwordRecoveryChecks": "excluded_using_upstream_no_password_recovery_mode"
        },
    }
# Reduce raw Holehe responses to a site name and simple outcome. Extra module
# fields, including recovery-contact details, are omitted from returned results.

def _safe_holehe_results(raw_results: list[dict]) -> tuple[list[dict], dict]:
    """Keep only site name and outcome; omit recovery contacts and extra module data."""
    results = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        if item.get("rateLimit") is True:
            result_status = "rate_limited"
        elif item.get("error") is True:
            result_status = "error"
        elif item.get("exists") is True:
            result_status = "registered"
        elif item.get("exists") is False:
            result_status = "not_found"
        else:
            result_status = "unknown"

        site = item.get("domain") or item.get("name") or "Unknown module"
        results.append({"site": str(site)[:160], "status": result_status})

    results.sort(key=lambda item: item["site"].casefold())
    summary = {
        "checked": len(results),
        "registered": sum(item["status"] == "registered" for item in results),
        "notFound": sum(item["status"] == "not_found" for item in results),
        "rateLimited": sum(item["status"] == "rate_limited" for item in results),
        "errors": sum(item["status"] in {"error", "unknown"} for item in results),
    }
    return results, summary
# Run Holehe Python modules directly instead of its CLI. Trio coordinates async
# checks, httpx supplies the HTTP client, and a limiter caps parallel modules.

def _execute_holehe(email: str, run_id: str) -> tuple[list[dict], int]:
    """Run Holehe's documented Python modules without invoking its auto-updating CLI."""
    import httpx
    import trio
    from holehe import core
    from types import SimpleNamespace

    # Keep the user's target exactly as entered. Do not strip, lowercase,
    # normalize Unicode, change dots/plus-tags, substitute characters, or
    # generate address variants. Each upstream module receives this same string.
    email = _validate_exact_holehe_email(email)

    # Use the module selection corresponding to Holehe's upstream
    # --no-password-recovery option. This avoids invoking the CLI's updater.
    modules = core.import_submodules("holehe.modules")
    functions = core.get_functions(modules, SimpleNamespace(nopasswordrecovery=True))
    if not functions:
        raise RuntimeError("Holehe did not expose any check modules.")

    with HOLEHE_LOCK:
        job = HOLEHE_JOBS.get(run_id)
        if job:
            job["total"] = len(functions)
            job["updated_at"] = time.time()

    raw_results: list[dict] = []
    limiter = trio.CapacityLimiter(HOLEHE_MODULE_CONCURRENCY)

    async def run_one(function, client):
        async with limiter:
            try:
                # Pass the exact same immutable Python string to every module.
                # Holehe's own documented embedding pattern uses this signature.
                await function(email, client, raw_results)
            except Exception:
                module_name = getattr(function, "__name__", "unknown")
                raw_results.append({
                    "name": module_name,
                    "domain": module_name,
                    "rateLimit": False,
                    "error": True,
                    "exists": False,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None,
                })
            finally:
                with HOLEHE_LOCK:
                    job = HOLEHE_JOBS.get(run_id)
                    if job:
                        job["completed"] = job.get("completed", 0) + 1
                        job["updated_at"] = time.time()

    async def run_all():
        async with httpx.AsyncClient(timeout=10) as client:
            async with trio.open_nursery() as nursery:
                for function in functions:
                    nursery.start_soon(run_one, function, client)

    trio.run(run_all)
    return raw_results, len(functions)
# Background worker for one Holehe run. It updates the job status and stores
# sanitised results or a generic operational error message.

def _run_holehe_job(run_id: str, email: str) -> None:
    with HOLEHE_LOCK:
        job = HOLEHE_JOBS.get(run_id)
        if not job:
            return
        job["status"] = "running"
        job["started_at"] = time.time()
        job["updated_at"] = time.time()

    try:
        raw_results, total = _execute_holehe(email, run_id)
        safe_results, summary = _safe_holehe_results(raw_results)
        with HOLEHE_LOCK:
            job = HOLEHE_JOBS.get(run_id)
            if job:
                job.update({
                    "status": "completed",
                    "completed_at": time.time(),
                    "updated_at": time.time(),
                    "total": total,
                    "completed": total,
                    "results": safe_results,
                    "summary": summary,
                    "error": None,
                    "email": None,
                })
    except Exception as error:
        # Keep operational errors useful without returning tracebacks or identifier data.
        if isinstance(error, ImportError) or error.__class__.__name__ == "ModuleNotFoundError":
            message = "Holehe or one of its dependencies is missing. Install it using the setup instructions."
        else:
            message = f"Holehe could not complete this run ({error.__class__.__name__}). Check the installation and network connection."
        with HOLEHE_LOCK:
            job = HOLEHE_JOBS.get(run_id)
            if job:
                job.update({
                    "status": "failed",
                    "completed_at": time.time(),
                    "updated_at": time.time(),
                    "error": message,
                    "email": None,
                })
# HTTP SERVER: serve static frontend files and implement OIW JSON API endpoints.
# The server binds to the local machine only (see HOST above).

class OIWHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND), **kwargs)
    # Add browser security/privacy headers to every response, including a
    # restrictive Content Security Policy and disabled caching.
    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        super().end_headers()
    # Suppress default access logs because request paths can contain identifiers.
    def log_message(self, format: str, *args) -> None:
        # Do not write request paths or potentially identifying query values to logs.
        return
    # Common helper to send a JSON response with the correct HTTP and content headers.
    def send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    # Check the Host and Origin headers for state-changing API requests. This is
    # a browser-side request-origin defence, not a replacement for OS-level security.
    def valid_request_origin(self) -> bool:
        host = self.headers.get("Host", "").lower()
        allowed_hosts = {f"{HOST}:{PORT}", f"localhost:{PORT}"}
        if host not in allowed_hosts:
            return False

        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urlsplit(origin)
            return (
                parsed.scheme == "http"
                and parsed.hostname in {HOST, "localhost"}
                and parsed.port == PORT
                and parsed.path == ""
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            return False
    # GET API routes return provider settings, dependency status, or a Holehe job.
    # Any other GET path is handled as a static frontend file by the parent class.
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in {"/api/providers", "/config/providers.json"}:
            try:
                self.send_json(200, load_config())
            except Exception:
                self.send_json(500, {"error": "Unable to load provider configuration."})
            return

        if path == "/api/holehe/status":
            self.send_json(200, holehe_install_status())
            return

        if path == "/api/web-analysis/status":
            self.send_json(200, web_analysis_install_status())
            return

        run_match = re.fullmatch(r"/api/holehe/runs/([A-Za-z0-9_-]{12,80})", path)
        if run_match:
            run_id = run_match.group(1)
            with HOLEHE_LOCK:
                _prune_holehe_jobs_locked()
                job = HOLEHE_JOBS.get(run_id)
                public_job = _public_holehe_job(job) if job else None
            if public_job is None:
                self.send_json(404, {"error": "Holehe run not found or expired."})
            else:
                self.send_json(200, public_job)
            return

        super().do_GET()
    # Receive a size-limited JSON URL request and delegate fetching/NLP to
    # webpage_analyser.py. Known analysis errors become JSON responses.
    def _handle_web_analysis_post(self) -> None:
        if not self.valid_request_origin():
            self.send_error(403, "Invalid request origin")
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_error(415, "JSON required")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid content length")
            return
        if length <= 0 or length > WEB_ANALYSIS_MAX_BODY_SIZE:
            self.send_error(413, "Invalid request size")
            return
        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise WebAnalysisError("Request body must be a JSON object.")
            result = analyse_webpage(payload.get("url"))
            self.send_json(200, result)
        except WebAnalysisError as error:
            self.send_json(error.status_code, {"error": str(error)})
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "The request body is not valid JSON."})
        except Exception as error:
            self.send_json(500, {"error": f"Webpage analysis failed ({error.__class__.__name__})."})
    # POST starts webpage analysis or queues a Holehe run. Method, origin,
    # content type and request size are checked before processing the body.
    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/web-analysis":
            self._handle_web_analysis_post()
            return
        if path != "/api/holehe/runs":
            self.send_error(404)
            return
        if not self.valid_request_origin():
            self.send_error(403, "Invalid request origin")
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_error(415, "JSON required")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid content length")
            return
        if length <= 0 or length > 4096:
            self.send_error(413, "Invalid request size")
            return

        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object.")
            # Validation returns the original value unchanged.
            email = _validate_exact_holehe_email(payload.get("email"))

            install = holehe_install_status()
            if not install["installed"]:
                self.send_json(
                    503,
                    {
                        "error": "Holehe is not installed in this Python environment.",
                        "installCommand": "python -m pip install -r requirements-holehe.txt",
                    },
                )
                return

            run_id = secrets.token_urlsafe(24)
            now = time.time()
            with HOLEHE_LOCK:
                _prune_holehe_jobs_locked()
                active = any(
                    job.get("status") in {"queued", "running"}
                    for job in HOLEHE_JOBS.values()
                )
                if active and HOLEHE_MAX_CONCURRENT_RUNS <= 1:
                    self.send_json(429, {"error": "A Holehe run is already active. Wait for it to finish before starting another."})
                    return
                HOLEHE_JOBS[run_id] = {
                    "run_id": run_id,
                    "status": "queued",
                    "email": email,
                    "email_masked": _mask_email(email),
                    "created_at": now,
                    "updated_at": now,
                    "started_at": None,
                    "completed_at": None,
                    "completed": 0,
                    "total": 0,
                    "results": [],
                    "summary": None,
                    "error": None,
                }

            worker = threading.Thread(
                target=_run_holehe_job,
                args=(run_id, email),
                daemon=True,
                name=f"OIW-Holehe-{run_id[:8]}",
            )
            worker.start()
            self.send_json(202, {"runId": run_id, "status": "queued"})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except Exception:
            self.send_json(500, {"error": "Unable to start the Holehe run."})
    # PUT replaces provider configuration after JSON parsing and validation.
    # The updated settings are persisted before a success response is sent.
    def do_PUT(self) -> None:
        if self.path.split("?", 1)[0] != "/api/providers":
            self.send_error(404)
            return
        if not self.valid_request_origin():
            self.send_error(403, "Invalid request origin")
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_error(415, "JSON required")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid content length")
            return
        if length <= 0 or length > MAX_CONFIG_SIZE:
            self.send_error(413, "Invalid configuration size")
            return

        try:
            body = self.rfile.read(length)
            config = json.loads(body.decode("utf-8"))
            saved = save_config(config)
            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Provider configuration saved.",
                    "count": len(saved["providers"]),
                },
            )
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            self.send_json(400, {"success": False, "error": str(error)})
        except Exception:
            self.send_json(500, {"success": False, "error": "Unable to save provider configuration."})
# STARTUP: parse options, check required folders/files, load provider settings,
# report optional NLP readiness, start the local HTTP server and open the browser.

def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT Investigation Workstation")
    parser.add_argument("--no-browser", action="store_true", help="Do not open Chrome automatically")
    args = parser.parse_args()

    print("\nChecking application...")
    if not FRONTEND.is_dir():
        raise SystemExit(f"ERROR: frontend directory missing: {FRONTEND}")
    if not (FRONTEND / "index.html").is_file():
        raise SystemExit("ERROR: frontend/index.html missing.")
    if not (FRONTEND / "app.js").is_file() or not (FRONTEND / "styles.css").is_file():
        raise SystemExit("ERROR: frontend/app.js or frontend/styles.css missing.")
    if not CONFIG.is_dir():
        raise SystemExit("ERROR: config directory missing.")

    config = load_config()
    print(f"Providers loaded: {len(config['providers'])}")
    analysis_status = web_analysis_install_status()
    if analysis_status["installed"] and analysis_status["modelInstalled"]:
        print(f"Webpage NLP: spaCy {analysis_status['spacyVersion']} and en_core_web_sm available")
    else:
        print("Webpage NLP: optional dependencies/model not fully installed")

    try:
        server = ThreadingHTTPServer((HOST, PORT), OIWHandler)
    except OSError as error:
        raise SystemExit(f"Unable to start server: {error}") from error
    server.daemon_threads = True

    print("\n" + "=" * 55)
    print(" OSINT INVESTIGATION WORKSTATION")
    print(f" Version {APP_VERSION}")
    print("=" * 55)
    print(f"PROJECT: {ROOT}")
    print(f"FRONTEND: {FRONTEND}")
    print(f"CONFIG: {PROVIDERS_FILE}")
    print(f"ADDRESS: {APP_URL}")
    print("=" * 55)
    print("SERVER STATUS: RUNNING")
    print("NETWORK ACCESS: LOCAL COMPUTER ONLY")
    print("PRESS CTRL+C TO EXIT")
    print("=" * 55)

    if not args.no_browser:
        threading.Thread(target=launch_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down OIW...")
    finally:
        server.server_close()
        print("Server stopped.")
# Only start the server when app.py is run directly (for example, python app.py).
# Importing this module elsewhere will not automatically launch the application.

if __name__ == "__main__":
    main()
