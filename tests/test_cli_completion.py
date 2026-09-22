"""Tests for interactive tab completion and inline suggestions."""

from __future__ import annotations

import asyncio
import unittest

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

from app.cli.completion import NexaAutoSuggest, NexaCompleter, current_token


def completions(text: str) -> list[str]:
    completer = NexaCompleter()
    document = Document(text, len(text))
    return [c.text for c in completer.get_completions(document, CompleteEvent())]


def suggestion(text: str) -> str | None:
    completer = NexaCompleter()
    document = Document(text, len(text))
    result = NexaAutoSuggest(completer).get_suggestion(None, document)
    return result.text if result else None


class CurrentTokenTests(unittest.TestCase):
    def test_token_after_boolean_operator(self) -> None:
        self.assertEqual(current_token('app="Vue.js" && ser'), "ser")

    def test_token_inside_quoted_value(self) -> None:
        self.assertEqual(current_token('status="2'), 'status="2')

    def test_token_after_command(self) -> None:
        self.assertEqual(current_token("clean "), "")


class CommandCompletionTests(unittest.TestCase):
    def test_prefix_completes_command(self) -> None:
        self.assertEqual(completions("ov"), ["overview"])

    def test_ambiguous_prefix_lists_all(self) -> None:
        # Commands that take arguments insert a trailing space.
        self.assertEqual(completions("clean"), ["clean ", "clean! "])

    def test_command_booking_prefix(self) -> None:
        self.assertIn("services", completions("serv"))

    def test_empty_input_lists_commands(self) -> None:
        self.assertIn("overview", completions(""))


class FieldCompletionTests(unittest.TestCase):
    def test_query_command_offers_fields(self) -> None:
        result = completions("clean ")
        self.assertIn("app=", result)
        self.assertIn("status=", result)

    def test_group_offers_field_and_subcommand(self) -> None:
        result = completions("clean gr")
        self.assertIn("group=", result)
        self.assertIn("group ", result)

    def test_field_after_operator(self) -> None:
        self.assertEqual(completions('app="Vue.js" && st'), ["status="])

    def test_id_command_has_no_completions(self) -> None:
        self.assertEqual(completions("inspect "), [])


class PromptQueryFieldTests(unittest.TestCase):
    """A bare query at the prompt must complete its fields, not only commands."""

    def test_exact_field_name_leads_with_the_field(self) -> None:
        self.assertEqual(completions("app"), ["app=", "apps"])

    def test_plain_field_names_complete(self) -> None:
        for field in ("title", "server", "ip", "host", "url", "port", "cdn", "waf"):
            self.assertEqual(completions(field), [f"{field}="], field)

    def test_ambiguous_prefix_lists_command_and_field(self) -> None:
        self.assertEqual(completions("ser"), ["services", "server="])

    def test_command_only_prefix_still_completes_command(self) -> None:
        self.assertEqual(completions("ov"), ["overview"])

    def test_value_completion_at_prompt(self) -> None:
        self.assertEqual(completions("status=2"), ["200"])
        self.assertEqual(completions("alive="), ["true", "false"])

    def test_operator_completion_after_complete_term(self) -> None:
        result = completions('app="Vue.js" ')
        self.assertIn("&&", result)
        self.assertIn("||", result)

    def test_field_without_known_values_yields_nothing(self) -> None:
        self.assertEqual(completions("ip="), [])
        self.assertEqual(completions("app="), [])


class FieldValueTests(unittest.TestCase):
    def test_status_values(self) -> None:
        self.assertEqual(completions("clean status=")[0], "200")
        self.assertIn("404", completions("clean status="))

    def test_status_value_prefix(self) -> None:
        self.assertEqual(completions("clean status=2"), ["200"])

    def test_quoted_value_keeps_quote(self) -> None:
        self.assertEqual(completions('clean status="2'), ['200"'])

    def test_alive_values(self) -> None:
        self.assertEqual(completions("clean alive="), ["true", "false"])

    def test_unknown_values_are_omitted(self) -> None:
        self.assertEqual(completions("clean app="), [])


class AutoSuggestTests(unittest.TestCase):
    def test_completes_command_inline(self) -> None:
        self.assertEqual(suggestion("ov"), "erview")

    def test_completes_field_inline(self) -> None:
        self.assertEqual(suggestion("clean st"), "atus=")

    def test_completes_prompt_field_inline(self) -> None:
        self.assertEqual(suggestion("ti"), "tle=")
        self.assertEqual(suggestion("app"), "=")

    def test_no_hint_for_complete_word(self) -> None:
        self.assertIsNone(suggestion("overview"))

    def test_no_hint_for_empty_token(self) -> None:
        self.assertIsNone(suggestion("clean "))


class InteractiveKeyBindingTests(unittest.IsolatedAsyncioTestCase):
    """Drive a real PromptSession to prove Tab and the → hint actually work."""

    async def _prompt(self, steps: list[tuple[str, str]]) -> str:
        completer = NexaCompleter()
        with create_pipe_input() as pipe:
            session = PromptSession(
                completer=completer,
                auto_suggest=NexaAutoSuggest(completer),
                complete_style=CompleteStyle.MULTI_COLUMN,
                input=pipe,
                output=DummyOutput(),
            )
            task = asyncio.ensure_future(session.prompt_async())
            for keys, expected in steps:
                pipe.send_text(keys)
                await self._wait_for(session, expected)
            pipe.send_text("\n")
            return await asyncio.wait_for(task, timeout=10)

    async def _wait_for(self, session, expected: str) -> None:
        for _ in range(300):
            if session.default_buffer.text == expected:
                return
            await asyncio.sleep(0.01)
        self.fail(f"buffer never reached {expected!r}")

    async def test_tab_completes_command(self) -> None:
        self.assertEqual(await self._prompt([("ov", "ov"), ("\t", "overview")]), "overview")

    async def test_right_arrow_accepts_inline_hint(self) -> None:
        self.assertEqual(await self._prompt([("ov", "ov"), ("\x1b[C", "overview")]), "overview")

    async def test_tab_completes_query_field(self) -> None:
        self.assertEqual(
            await self._prompt([("clean st", "clean st"), ("\t", "clean status=")]),
            "clean status=",
        )


if __name__ == "__main__":
    unittest.main()
