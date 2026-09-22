"""Tab completion and inline suggestions for the interactive ``nexa use`` shell.

Two independent behaviours are provided:

* :class:`NexaCompleter` powers the Tab menu (commands, query fields, and common
  field values).
* :class:`NexaAutoSuggest` renders the first match as dim inline text while you
  type, so ``ov`` hints ``erview`` the way a shell hints ``whoami`` for ``who``.
  The right arrow key accepts the hint (prompt_toolkit's default binding).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document


@dataclass(frozen=True)
class Entry:
    name: str
    insert: str
    meta: str = ""


COMMANDS: tuple[Entry, ...] = (
    Entry("overview", "overview", "优先目标 + 来源覆盖"),
    Entry("services", "services", "HTTP 服务列表"),
    Entry("apps", "apps", "组件/技术统计（等价 components/techs）"),
    Entry("assets", "assets", "主机资产列表"),
    Entry("groups", "groups", "重复模板组"),
    Entry("group", "group ", "查看某个组：group <id>"),
    Entry("noise", "noise", "降噪/清理候选"),
    Entry("outliers", "outliers", "大型模板组内的异常资产"),
    Entry("interesting", "interesting", "值得关注的资产"),
    Entry("inspect", "inspect ", "查看服务分类与证据：inspect <service_id>"),
    Entry("why", "why ", "同 inspect：why <service_id>"),
    Entry("sources", "sources", "来源计数"),
    Entry("coverage", "coverage", "来源覆盖"),
    Entry("evidence", "evidence", "来源证据明细"),
    Entry("clean", "clean ", "预览清理：clean <query>"),
    Entry("clean!", "clean! ", "执行清理：clean! <query>"),
    Entry("drop", "drop ", "预览删除：drop <query>"),
    Entry("drop!", "drop! ", "执行删除：drop! <query>"),
    Entry("help", "help", "显示帮助"),
    Entry("exit", "exit", "退出目标工作区"),
)

QUERY_FIELDS: tuple[Entry, ...] = (
    Entry("app", "app=", "技术组件，如 app=\"Vue.js\""),
    Entry("host", "host=", "主机名/子域名"),
    Entry("ip", "ip=", "资产 IP"),
    Entry("url", "url=", "服务 URL 片段"),
    Entry("title", "title=", "网页标题"),
    Entry("server", "server=", "Server 指纹"),
    Entry("header", "header=", "响应头键或值"),
    Entry("status", "status=", "HTTP 状态码"),
    Entry("port", "port=", "服务端口"),
    Entry("scheme", "scheme=", "协议：http / https"),
    Entry("source", "source=", "资产来源，如 subfinder"),
    Entry("cname", "cname=", "CNAME"),
    Entry("favicon", "favicon=", "favicon hash"),
    Entry("cdn", "cdn=", "CDN 标签"),
    Entry("waf", "waf=", "WAF 标签"),
    Entry("alive", "alive=", "存活状态：true / false"),
    Entry("category", "category=", "降噪分类，如 admin"),
    Entry("noise", "noise=", "噪声分"),
    Entry("value", "value=", "发现价值分"),
    Entry("tier", "tier=", "优先级层级"),
    Entry("group", "group=", "模板组 ID"),
    Entry("group", "group ", "按模板组操作：group <id>"),
)

FIELD_VALUES: dict[str, tuple[str, ...]] = {
    "status": ("200", "301", "302", "401", "403", "404", "500"),
    "alive": ("true", "false"),
    "scheme": ("http", "https"),
    "category": ("admin", "api", "auth", "docs", "redirect", "error", "normal", "shop-template"),
}

# Commands whose remaining arguments are a Nexa query expression.
QUERY_COMMANDS = frozenset({"clean", "clean!", "drop", "drop!"})
# Commands that take a numeric id and therefore have nothing to complete.
ID_COMMANDS = frozenset({"inspect", "why"})

_TAIL_RE = re.compile(r"[^\s&|]*$")


def current_token(text: str) -> str:
    """Return the whitespace/operator-delimited token under the cursor."""

    match = _TAIL_RE.search(text)
    return match.group(0) if match else ""


def _split_field(token: str) -> tuple[str, str, str] | None:
    """Split ``field=value`` / ``field!=value`` into (field, operator, raw value)."""

    for operator in ("!=", "="):
        if operator in token:
            field, _, raw = token.partition(operator)
            return field.strip().lower(), operator, raw
    return None


def _value_completions(token: str):
    split = _split_field(token)
    if not split:
        return
    field, _operator, raw = split
    values = FIELD_VALUES.get(field)
    if not values:
        return
    quote = raw[:1] if raw[:1] in {'"', "'"} else ""
    typed = raw[1:] if quote else raw
    for value in values:
        if not value.lower().startswith(typed.lower()):
            continue
        suffix = quote if quote else ""
        yield value + suffix, len(typed)


class NexaCompleter(Completer):
    """Complete interactive commands, query fields and common field values.

    A bare query is a first-class input at this prompt (``app="Vue.js" &&
    status=200``), so query fields are offered at the command position too --
    typing ``app`` lists both the ``apps`` command and the ``app=`` field.
    """

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        text = document.text_before_cursor
        token = current_token(text)
        prefix = text[: len(text) - len(token)]
        command_position = not prefix.strip()

        # A term that already has an operator is unambiguously a query term.
        if _split_field(token):
            for value, consumed in _value_completions(token):
                yield Completion(value, start_position=-consumed, display=value)
            return

        if command_position:
            # No '=' yet, so the token may be a command or the start of a field.
            # An exact field name (``app``, ``title``, ``server``...) wins so the
            # common query case is one keystroke away; otherwise commands lead.
            seen: set[str] = set()
            lowered = token.lower()
            exact_fields = tuple(entry for entry in QUERY_FIELDS if entry.name.lower() == lowered)
            yield from _entries(exact_fields, token, seen)
            yield from _entries(COMMANDS, token, seen)
            yield from _entries(QUERY_FIELDS, token, seen)
            return

        first = text.split(None, 1)[0]
        if first in ID_COMMANDS:
            return
        if not token and "=" in prefix:
            yield from _operator_completions()
        yield from _entries(QUERY_FIELDS, token)


def _operator_completions():
    for operator, meta in (("&&", "并且 and"), ("||", "或者 or")):
        yield Completion(operator, start_position=0, display=operator, display_meta=meta)


def _entries(entries: tuple[Entry, ...], token: str, seen: set[str] | None = None):
    if seen is None:
        seen = set()
    for entry in entries:
        if not entry.name.lower().startswith(token.lower()):
            continue
        if entry.insert in seen:
            continue
        seen.add(entry.insert)
        yield Completion(
            entry.insert,
            start_position=-len(token),
            display=entry.name,
            display_meta=entry.meta,
        )


class NexaAutoSuggest(AutoSuggest):
    """Inline (fish-style) hint for the first completion of the current token."""

    def __init__(self, completer: Completer) -> None:
        self._completer = completer

    def get_suggestion(self, buffer, document: Document) -> Suggestion | None:
        token = current_token(document.text_before_cursor)
        if not token:
            return None
        for completion in self._completer.get_completions(document, CompleteEvent(completion_requested=False)):
            candidate = completion.text
            if candidate.lower().startswith(token.lower()) and len(candidate) > len(token):
                return Suggestion(candidate[len(token):])
            return None
        return None
