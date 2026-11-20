import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import socket

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webpage_analyser as web


class FakeToken:
    def __init__(self, text, lemma=None, is_alpha=True, is_stop=False):
        self.text = text
        self.lemma_ = lemma or text.lower()
        self.is_alpha = is_alpha
        self.is_stop = is_stop


class FakeEntity:
    def __init__(self, text, label):
        self.text = text
        self.label_ = label


class FakeDoc:
    def __init__(self):
        self.ents = [FakeEntity("Example Organisation", "ORG")]
        self.tokens = [
            FakeToken("investigation"),
            FakeToken("research"),
            FakeToken("organisation"),
        ]
        self.noun_chunks = [
            [FakeToken("public" , is_stop=True), FakeToken("records") , FakeToken("search")],
            [FakeToken("public", is_stop=True), FakeToken("records"), FakeToken("search")],
        ]

    def __iter__(self):
        return iter(self.tokens)


class FakeNLP:
    max_length = 1_000_000

    def __call__(self, text):
        return FakeDoc()


class FakeSpacy:
    @staticmethod
    def explain(label):
        return "Organisation" if label == "ORG" else label


class WebAnalysisTests(unittest.TestCase):
    def test_rejects_loopback_ip(self):
        with self.assertRaises(web.WebAnalysisError):
            web._validate_public_web_url("http://127.0.0.1/")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(web.WebAnalysisError):
            web._validate_public_web_url("file:///C:/Windows/win.ini")

    def test_rejects_url_whitespace_without_rewriting(self):
        with self.assertRaises(web.WebAnalysisError):
            web._validate_public_web_url(" https://example.com/")

    @patch.object(web.socket, "getaddrinfo")
    def test_rejects_hostname_resolving_to_private_address(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443))
        ]
        with self.assertRaises(web.WebAnalysisError):
            web._validate_public_web_url("https://example.test/")

    @patch.object(web.socket, "getaddrinfo")
    def test_accepts_hostname_resolving_to_public_address(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        value = "https://example.test/article"
        self.assertEqual(web._validate_public_web_url(value), value)

    def test_extracts_text_and_removes_script_style_and_svg(self):
        html = b"""<html><head><style>bad style</style><script>bad script</script></head>
        <body><h1>Example page</h1><p>Useful text here.</p><svg>hidden</svg></body></html>"""
        text, truncated = web._extract_page_text(html)
        self.assertIn("Example page", text)
        self.assertIn("Useful text here.", text)
        self.assertNotIn("bad style", text)
        self.assertNotIn("bad script", text)
        self.assertNotIn("hidden", text)
        self.assertFalse(truncated)

    def test_analyser_returns_entities_themes_and_keywords(self):
        with patch.object(web, "_load_web_nlp", return_value=(FakeNLP(), FakeSpacy)):
            entities, themes, keywords = web._analyse_web_text("test content")
        self.assertEqual(entities[0]["entity"], "Example Organisation")
        self.assertEqual(entities[0]["type"], "ORG")
        self.assertEqual(themes[0], {"theme": "records search", "count": 2})
        self.assertTrue(any(item["keyword"] == "investigation" for item in keywords))


if __name__ == "__main__":
    unittest.main(verbosity=2)
