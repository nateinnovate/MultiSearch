"""Regression tests for exact Holehe target-address pass-through."""

from __future__ import annotations

import asyncio
import sys
import types
import unittest
from unittest.mock import patch

import app


class ExactEmailValidationTests(unittest.TestCase):
    def test_preserves_case_dots_and_plus_tag_exactly(self):
        supplied = "Mixed.Case+Research.Tag@Example.COM"
        self.assertIs(app._validate_exact_holehe_email(supplied), supplied)

    def test_rejects_outer_whitespace_instead_of_trimming_it(self):
        with self.assertRaisesRegex(ValueError, "leading or trailing whitespace"):
            app._validate_exact_holehe_email(" Mixed.Case@example.com ")

    def test_rejects_non_email_values_without_rewriting_them(self):
        with self.assertRaises(ValueError):
            app._validate_exact_holehe_email("Mixed.Case at Example dot com")


class ExactEmailModulePassThroughTests(unittest.TestCase):
    def test_same_string_is_passed_to_the_upstream_module(self):
        supplied = "Mixed.Case+Research.Tag@Example.COM"
        received: list[str] = []
        raw_result = {
            "name": "sample",
            "domain": "sample.example",
            "rateLimit": False,
            "error": False,
            "exists": True,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        }

        async def sample_module(email, client, output):
            received.append(email)
            output.append(raw_result)

        # Minimal Trio-compatible test doubles. No Internet requests are made.
        class FakeLimiter:
            def __init__(self, _capacity):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class FakeNursery:
            def __init__(self):
                self.tasks = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                await asyncio.gather(*self.tasks)
                return False

            def start_soon(self, function, *args):
                self.tasks.append(asyncio.create_task(function(*args)))

        fake_trio = types.ModuleType("trio")
        fake_trio.CapacityLimiter = FakeLimiter
        fake_trio.open_nursery = FakeNursery
        fake_trio.run = lambda async_function: asyncio.run(async_function())

        class FakeAsyncClient:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeAsyncClient

        fake_core = types.ModuleType("holehe.core")
        fake_core.import_submodules = lambda _package: {
            "holehe.modules.sample.sample": object()
        }
        fake_core.get_functions = lambda _modules, _args: [sample_module]

        fake_holehe = types.ModuleType("holehe")
        fake_holehe.__path__ = []
        fake_holehe.core = fake_core

        run_id = "exact-email-test-run"
        app.HOLEHE_JOBS[run_id] = {
            "status": "running",
            "completed": 0,
            "total": 0,
        }
        try:
            with patch.dict(sys.modules, {
                "httpx": fake_httpx,
                "trio": fake_trio,
                "holehe": fake_holehe,
                "holehe.core": fake_core,
            }):
                results, total = app._execute_holehe(supplied, run_id)

            self.assertEqual(received, [supplied])
            self.assertEqual(total, 1)
            self.assertEqual(results[0]["domain"], "sample.example")
        finally:
            app.HOLEHE_JOBS.pop(run_id, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
