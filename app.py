"""
OSINT Investigation Workstation
Version: 0.3.0

Local browser-based OSINT search launcher
with integrated Provider Manager.
"""

import argparse
import json
import re
import threading
import time
import webbrowser
import os

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit


# ==================================================
# CONFIGURATION
# ==================================================

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
CONFIG = ROOT / "config"
PROVIDERS_FILE = CONFIG / "providers.json"

HOST = "127.0.0.1"
PORT = 8765
APP_URL = f"http://{HOST}:{PORT}/"

MAX_CONFIG_SIZE = 256 * 1024

IDENTIFIER_TYPES = {
    "username",
    "email",
    "phone",
    "name",
    "domain",
    "ip"
}

CATEGORIES = {
    "Search engines",
    "Identity intelligence",
    "Email intelligence",
    "Username research",
    "Telephone intelligence",
    "Infrastructure"
}


# ==================================================
# CHROME DETECTION
# ==================================================

def find_chrome():

    possible_paths = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path.home() / "AppData/Local/Google/Chrome/Application/chrome.exe"
    ]

    for path in possible_paths:
        if path.is_file():
            return str(path)

    return None


# ==================================================
# BROWSER LAUNCH
# ==================================================

def launch_browser():

    time.sleep(2)

    chrome = find_chrome()

    try:

        if chrome:

            import subprocess

            print(f"Chrome detected: {chrome}")

            subprocess.Popen([
                chrome,
                "--new-window",
                APP_URL
            ])

        else:

            print("Chrome not found. Opening default browser.")

            webbrowser.open_new_tab(APP_URL)

    except Exception as error:

        print(f"Browser launch error: {error}")
        print(f"Open manually: {APP_URL}")


# ==================================================
# CONFIGURATION VALIDATION
# ==================================================

def validate_url(url, require_query=False):

    if not isinstance(url, str):
        return False

    if not url or len(url) > 2048:
        return False

    if require_query and "{query}" not in url:
        return False

    test_url = url.replace("{query}", "oiw-validation-test")

    try:

        parsed = urlsplit(test_url)

        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
        )

    except ValueError:

        return False


def validate_config(config):

    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object.")

    providers = config.get("providers")

    if not isinstance(providers, list):
        raise ValueError("Missing providers array.")

    if len(providers) > 200:
        raise ValueError("Maximum of 200 providers allowed.")

    seen_ids = set()

    for provider in providers:

        if not isinstance(provider, dict):
            raise ValueError("Invalid provider entry.")

        provider_id = provider.get("id")
        name = provider.get("name")
        category = provider.get("category")
        types = provider.get("types")
        enabled = provider.get("enabled")

        if not isinstance(provider_id, str):
            raise ValueError("Provider ID is required.")

        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", provider_id):
            raise ValueError(f"Invalid provider ID: {provider_id}")

        if provider_id in seen_ids:
            raise ValueError(f"Duplicate provider ID: {provider_id}")

        seen_ids.add(provider_id)

        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise ValueError("Invalid provider name.")

        if category not in CATEGORIES:
            raise ValueError(f"Invalid provider category: {category}")

        if not isinstance(types, list) or not types:
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

        for identifier, template in templates.items():

            if identifier not in IDENTIFIER_TYPES:
                raise ValueError(f"Invalid template identifier for {name}.")

            if identifier not in types:
                raise ValueError(
                    f"Template type {identifier} is not supported by {name}."
                )

            if not validate_url(template, require_query=True):
                raise ValueError(f"Invalid HTTPS search template for {name}.")

        manual_url = provider.get("manualUrl")

        if manual_url is not None and not validate_url(manual_url):
            raise ValueError(f"Invalid manual URL for {name}.")

        if not templates and not manual_url:
            raise ValueError(
                f"{name} needs a search template or manual URL."
            )

        clipboard = provider.get("clipboard", False)

        if not isinstance(clipboard, bool):
            raise ValueError(f"Invalid clipboard setting for {name}.")

    return config


# ==================================================
# LOAD CONFIGURATION
# ==================================================

def load_config():

    if not PROVIDERS_FILE.exists():
        raise SystemExit("ERROR: providers.json not found.")

    try:

        with PROVIDERS_FILE.open("r", encoding="utf-8") as file:
            config = json.load(file)

        return validate_config(config)

    except (json.JSONDecodeError, ValueError) as error:

        raise SystemExit(f"Provider configuration error: {error}")


# ==================================================
# SAVE CONFIGURATION
# ==================================================

def save_config(config):

    validate_config(config)

    data = json.dumps(
        config,
        indent=2,
        ensure_ascii=False
    ).encode("utf-8")

    if len(data) > MAX_CONFIG_SIZE:
        raise ValueError("Configuration file is too large.")

    CONFIG.mkdir(parents=True, exist_ok=True)

    temporary_file = PROVIDERS_FILE.with_name(
        "providers.json.tmp"
    )

    try:

        with temporary_file.open("wb") as file:

            file.write(data)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_file, PROVIDERS_FILE)

    finally:

        if temporary_file.exists():
            temporary_file.unlink()


# ==================================================
# HTTP HANDLER
# ==================================================

class OIWHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):

        super().__init__(
            *args,
            directory=str(FRONTEND),
            **kwargs
        )

    def end_headers(self):

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "Referrer-Policy",
            "no-referrer"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )

        super().end_headers()

    def log_message(self, format, *args):
        pass

    def send_json(self, status, data):

        body = json.dumps(data).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)

    def valid_request_origin(self):

        origin = self.headers.get("Origin")

        if origin and origin != APP_URL.rstrip("/"):
            return False

        host = self.headers.get("Host", "")

        return host in (
            f"{HOST}:{PORT}",
            f"localhost:{PORT}"
        )

    def do_GET(self):

        path = self.path.split("?")[0]

        if path == "/api/providers":

            try:

                config = load_config()

                self.send_json(200, config)

            except Exception as error:

                self.send_json(
                    500,
                    {"error": str(error)}
                )

            return

        if path == "/config/providers.json":

            try:

                data = PROVIDERS_FILE.read_bytes()

                self.send_response(200)

                self.send_header(
                    "Content-Type",
                    "application/json; charset=utf-8"
                )

                self.send_header(
                    "Content-Length",
                    str(len(data))
                )

                self.end_headers()

                self.wfile.write(data)

            except OSError:

                self.send_error(404, "Configuration not found")

            return

        super().do_GET()

    def do_PUT(self):

        if self.path.split("?")[0] != "/api/providers":
            self.send_error(404)
            return

        if not self.valid_request_origin():
            self.send_error(403, "Invalid request origin")
            return

        content_type = self.headers.get(
            "Content-Type", ""
        ).split(";")[0].strip().lower()

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

            save_config(config)

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Provider configuration saved.",
                    "count": len(config["providers"])
                }
            )

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:

            self.send_json(
                400,
                {"success": False, "error": str(error)}
            )

        except Exception as error:

            self.send_json(
                500,
                {"success": False, "error": str(error)}
            )


# ==================================================
# MAIN
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description="OSINT Investigation Workstation"
    )

    parser.add_argument(
        "--no-browser",
        action="store_true"
    )

    args = parser.parse_args()

    print("\nChecking application...")

    if not FRONTEND.is_dir():
        raise SystemExit("ERROR: frontend directory missing.")

    if not CONFIG.is_dir():
        raise SystemExit("ERROR: config directory missing.")

    config = load_config()

    print(f"Providers loaded: {len(config['providers'])}")

    try:

        server = ThreadingHTTPServer(
            (HOST, PORT),
            OIWHandler
        )

    except OSError as error:

        raise SystemExit(f"Unable to start server: {error}")

    server.daemon_threads = True

    print("\n" + "=" * 55)
    print(" OSINT INVESTIGATION WORKSTATION")
    print(" Version 0.3.0")
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

        threading.Thread(
            target=launch_browser,
            daemon=True
        ).start()

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nShutting down OIW...")

    finally:

        server.server_close()
        print("Server stopped.")


if __name__ == "__main__":
    main()