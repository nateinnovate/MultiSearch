"""
OSINT Investigation Workstation
Version: 0.2.1

Local browser-based OSINT search launcher.
"""

import argparse
import json
import threading
import time
import webbrowser

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent

FRONTEND = ROOT / "frontend"
CONFIG = ROOT / "config"
PROVIDERS_FILE = CONFIG / "providers.json"

HOST = "127.0.0.1"
PORT = 8765

APP_URL = f"http://{HOST}:{PORT}/"


# --------------------------------------------------
# CHROME DETECTION
# --------------------------------------------------

def find_chrome():

    possible_paths = [

        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),

        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),

        Path.home() /
        "AppData/Local/Google/Chrome/Application/chrome.exe"

    ]

    for path in possible_paths:

        if path.is_file():
            return str(path)

    return None


# --------------------------------------------------
# BROWSER LAUNCHER
# --------------------------------------------------

def launch_browser():

    time.sleep(2)

    chrome_path = find_chrome()

    try:

        if chrome_path:

            print(f"Chrome detected: {chrome_path}")

            browser = webbrowser.get(
                f'"{chrome_path}" %s'
            )

            browser.open_new_tab(APP_URL)

        else:

            print("Chrome not found in standard locations.")
            print("Opening default browser instead.")

            webbrowser.open_new_tab(APP_URL)

    except webbrowser.Error as error:

        print(f"Browser launch error: {error}")
        print(f"Please open manually: {APP_URL}")


# --------------------------------------------------
# PROVIDER CONFIGURATION VALIDATION
# --------------------------------------------------

def validate_providers():

    if not PROVIDERS_FILE.is_file():

        raise SystemExit(
            f"ERROR: Provider configuration missing: {PROVIDERS_FILE}"
        )

    try:

        with PROVIDERS_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            config = json.load(file)

    except json.JSONDecodeError as error:

        raise SystemExit(
            f"ERROR: Invalid providers.json: {error}"
        )

    providers = config.get("providers")

    if not isinstance(providers, list):

        raise SystemExit(
            "ERROR: providers.json must contain a providers array."
        )

    if not providers:

        raise SystemExit(
            "ERROR: No providers configured."
        )

    provider_ids = set()

    for provider in providers:

        required = ["id", "name", "category", "types", "enabled"]

        for field in required:

            if field not in provider:

                raise SystemExit(
                    f"ERROR: Provider is missing field '{field}'."
                )

        if provider["id"] in provider_ids:

            raise SystemExit(
                f"ERROR: Duplicate provider ID: {provider['id']}"
            )

        provider_ids.add(provider["id"])

        if not isinstance(provider["types"], list):

            raise SystemExit(
                f"ERROR: Invalid identifier types for {provider['name']}"
            )

        if not isinstance(provider["enabled"], bool):

            raise SystemExit(
                f"ERROR: Invalid enabled setting for {provider['name']}"
            )

        templates = provider.get("urlTemplates", {})

        if not isinstance(templates, dict):

            raise SystemExit(
                f"ERROR: Invalid URL templates for {provider['name']}"
            )

        for identifier, template in templates.items():

            if not isinstance(template, str) or "{query}" not in template:

                raise SystemExit(
                    f"ERROR: Invalid URL template for "
                    f"{provider['name']} ({identifier})"
                )

            if not template.startswith("https://"):

                raise SystemExit(
                    f"ERROR: Only HTTPS templates are allowed "
                    f"for {provider['name']}"
                )

        manual_url = provider.get("manualUrl")

        if manual_url and not manual_url.startswith("https://"):

            raise SystemExit(
                f"ERROR: Invalid manual URL for {provider['name']}"
            )

    print(f"Provider configuration validated: {len(providers)} providers")

    return config


# --------------------------------------------------
# HTTP REQUEST HANDLER
# --------------------------------------------------

class OIWHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):

        super().__init__(
            *args,
            directory=str(FRONTEND),
            **kwargs
        )

    def do_GET(self):

        path = self.path.split("?")[0]

        print(f"REQUEST: {path}")

        # Provider configuration endpoint
        if path == "/config/providers.json":

            try:

                data = PROVIDERS_FILE.read_bytes()

                # Ensure configuration is valid JSON.
                json.loads(data)

                self.send_response(200)

                self.send_header(
                    "Content-Type",
                    "application/json; charset=utf-8"
                )

                self.send_header(
                    "Content-Length",
                    str(len(data))
                )

                self.send_header(
                    "Cache-Control",
                    "no-store"
                )

                self.end_headers()

                self.wfile.write(data)

                print("CONFIGURATION: SUCCESS")

                return

            except FileNotFoundError:

                self.send_error(
                    404,
                    "Provider configuration not found"
                )

                return

            except (OSError, json.JSONDecodeError) as error:

                print(f"CONFIGURATION ERROR: {error}")

                self.send_error(
                    500,
                    "Unable to read provider configuration"
                )

                return

        # Normal frontend files
        super().do_GET()

    def log_message(self, format, *args):

        # Avoid logging search terms in request URLs.
        pass

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

        super().end_headers()


# --------------------------------------------------
# APPLICATION STARTUP
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="OSINT Investigation Workstation"
    )

    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start without automatically opening a browser"
    )

    args = parser.parse_args()

    print("\nChecking application directories...")

    if not FRONTEND.is_dir():

        raise SystemExit(
            f"ERROR: Frontend directory missing: {FRONTEND}"
        )

    if not CONFIG.is_dir():

        raise SystemExit(
            f"ERROR: Configuration directory missing: {CONFIG}"
        )

    print("Frontend directory: OK")
    print("Configuration directory: OK")

    validate_providers()

    # Start local HTTP server
    try:

        server = ThreadingHTTPServer(
            (HOST, PORT),
            OIWHandler
        )

    except OSError as error:

        raise SystemExit(
            f"ERROR: Unable to start server on port {PORT}: {error}"
        )

    server.daemon_threads = True

    # Startup information
    print("\n" + "=" * 55)
    print(" OSINT INVESTIGATION WORKSTATION")
    print(" Version 0.2.1")
    print("=" * 55)

    print(f"PROJECT: {ROOT}")
    print(f"FRONTEND: {FRONTEND}")
    print(f"CONFIG: {PROVIDERS_FILE}")
    print(f"ADDRESS: {APP_URL}")

    print("=" * 55)
    print("SERVER STATUS: RUNNING")
    print("NETWORK ACCESS: LOCAL COMPUTER ONLY")
    print("PRESS CTRL+C TO EXIT")
    print("=" * 55 + "\n")

    # Launch browser
    if not args.no_browser:

        browser_thread = threading.Thread(
            target=launch_browser,
            daemon=True
        )

        browser_thread.start()

    else:

        print("Automatic browser launching disabled.")

    # Run application
    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nShutting down OSINT Workstation...")

    finally:

        server.shutdown()
        server.server_close()

        print("Server stopped.")
        print("Goodbye.")


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    main()