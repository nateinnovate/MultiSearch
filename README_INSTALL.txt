OSINT INVESTIGATION WORKSTATION v0.3.4
WEBPAGE TEXT & ENTITY ANALYSIS
================================

WHAT IS NEW
-----------
A standalone Webpage Text & Entity Analysis panel has been added below the
existing Search Platforms panel. It does not change provider selection,
identifier searches, or the local Holehe integration.

The new panel:
- accepts a public HTTP or HTTPS webpage URL;
- downloads HTML and removes script, style, noscript, SVG, iframe and template
  elements before extracting text;
- uses spaCy en_core_web_sm for named-entity recognition and keyword lemmas;
- adds recurring multi-word noun phrases as indicative themes;
- displays extracted text, entities, themes and keywords in OIW;
- lets the user download a text report from the browser.

The original supplied script's automatic server-side report creation and
os.startfile() behaviour have been replaced with an explicit browser download.
The extracted page and analysis are held in memory during the request and are
not automatically saved by OIW.

INSTALLATION
------------
1. Stop OIW with Ctrl+C.
2. Back up your project folder and config/providers.json.
3. Create/switch to a development branch before replacing files.
4. Extract this package into a temporary folder.
5. Copy/replace these files into the existing MultiSearch folder:

   app.py
   webpage_analyser.py
   frontend/app.js
   frontend/index.html
   frontend/styles.css
   frontend/holehe-results.html
   frontend/holehe-results.js
   requirements-holehe.txt
   requirements-web-analysis.txt
   tests/test_holehe_exact_input.py
   tests/test_web_analysis.py

IMPORTANT: This package intentionally does NOT include config/providers.json.
Keep your existing config/providers.json so the providers you have added remain.

6. Install the webpage-analysis dependencies in the same Python environment
   used to start OIW:

   python -m pip install -r requirements-web-analysis.txt

7. Install the spaCy English small model:

   python -m spacy download en_core_web_sm

8. If you also use the local Holehe provider, make sure its dependencies remain
   installed:

   python -m pip install -r requirements-holehe.txt

9. Run static checks:

   python -m py_compile .\app.py
   node --check .\frontend\app.js
   node --check .\frontend\holehe-results.js
   python -m unittest discover -s tests -v

10. Start OIW:

   python .\app.py

Open http://127.0.0.1:8765/ in Chrome. The new webpage analysis feature appears
below Search Platforms.

SECURITY AND PRIVACY
--------------------
- OIW remains bound to 127.0.0.1.
- The URL fetcher allows only HTTP/HTTPS and public network destinations.
- DNS-resolved private, loopback, link-local, reserved and non-global addresses
  are blocked. Redirect targets are revalidated. Non-standard ports are blocked.
- Automatic redirects are disabled; OIW handles and validates up to four.
- Only HTML/XHTML pages are accepted; downloads are limited to 4 MB.
- Extracted text is limited to 160,000 characters for NLP processing.
- The spaCy model loads only when needed; missing optional dependencies do not
  prevent the main OIW application from starting.
- Analysis results and extracted page text are not stored by the backend. The
  report is only downloaded when the user selects Download text report.
- The remote website receives a normal HTTP GET from the computer running OIW.
  Consider whether you are authorised to access and analyse the page.

THEME INTERPRETATION
--------------------
The supplied script calculates named-entity frequencies and the 50 most
frequent non-stopword lemmas. It does not implement a separate topic-modeling
or summarisation algorithm. OIW preserves those outputs and additionally
surfaces repeated two-or-more-word spaCy noun phrases as indicative themes.
These are heuristic recurring phrases, not a human-verified summary.

LIMITATIONS
-----------
- This extracts server-delivered HTML. Pages that rely on JavaScript rendering,
  login sessions, paywalls, or anti-bot challenges may yield little or no text.
- spaCy en_core_web_sm is an English model; results on other languages may be
  incomplete or inaccurate.
- Entity recognition and noun-phrase themes are probabilistic NLP outputs and
  should be verified against the source page.
