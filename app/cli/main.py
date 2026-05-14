from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.history import InMemoryHistory
import typer
from rich.console import Console
from rich.table import Table

from app.config import get_settings
from app.database import create_session, init_db
from app.pipelines.recon import (
    ReconSummary,
    collect_target_sync,
)
from app.providers.base import OnlineAssetResult, OnlineSearchMeta
from app.providers.search import search_online_assets
from app.query import QuerySyntaxError, SearchRow, list_target_rows, search_target_assets
from app.repositories import TargetRepository
from app.risk import RiskAssetSummary, analyze_target_risk, preview_target_risk, top_risk_assets
from app.schemas.target import TargetCreate
from app.tooling import ToolResolver
from scripts.bootstrap_tools import bootstrap_tools

app = typer.Typer(help="Nexa attack surface intelligence CLI.", no_args_is_help=True)
console = Console()


HELP_GROUPS: list[dict[str, object]] = [
    {
        "name_en": "Project",
        "name_zh": "项目",
        "commands": [
            ("init", "Initialize the SQLite database.", "初始化 SQLite 数据库。"),
            ("tools", "Show bundled tool installation status.", "查看内置工具安装状态。"),
        ],
    },
    {
        "name_en": "Targets",
        "name_zh": "目标",
        "commands": [
            ("add-target", "Create or update a target.", "创建或更新赏金目标。"),
            ("target", "Show or scan a target by id/name.", "按 ID/名称查看或扫描目标。"),
            ("use", "Enter interactive target search mode.", "进入目标交互式搜索界面。"),
            ("targets", "List targets.", "列出所有目标。"),
            ("show-target", "Show one target.", "查看单个目标详情。"),
            ("delete-target", "Delete a target by name.", "按名称删除目标。"),
            ("del-target", "Alias of delete-target.", "delete-target 的短别名。"),
        ],
    },
    {
        "name_en": "Scanning and Analysis",
        "name_zh": "扫描与分析",
        "commands": [
            (
                "scan-http",
                "Probe existing assets with httpx.",
                "使用 httpx 探测已有资产。",
            ),
            (
                "collect-target",
                "Run target collection pipeline with subfinder/oneforall/httpx.",
                "运行 subfinder/oneforall/httpx 目标自动梳理流水线。",
            ),
            (
                "online-search",
                "Search enabled FOFA/Hunter/Shodan/ZoomEye providers.",
                "调用已启用的 FOFA/Hunter/Shodan/ZoomEye 测绘接口。",
            ),
        ],
    },
]


def _print_help(language: str) -> None:
    is_zh = language == "zh"
    title = "Nexa 命令帮助" if is_zh else "Nexa Command Help"
    usage = "用法: nexa [--help | --help-en | --help-zh] COMMAND [ARGS]..." if is_zh else (
        "Usage: nexa [--help | --help-en | --help-zh] COMMAND [ARGS]..."
    )
    console.print(f"[bold]{title}[/bold]")
    console.print(usage)
    console.print()
    console.print(
        "默认 [bold]--help[/bold] 输出英文 Typer 帮助；[bold]--help-zh[/bold] 输出中文分组帮助。"
        if is_zh
        else "Default [bold]--help[/bold] prints the standard English Typer help; "
        "[bold]--help-en[/bold] prints this grouped English help."
    )
    console.print()

    for group in HELP_GROUPS:
        group_name = str(group["name_zh"] if is_zh else group["name_en"])
        table = Table(title=group_name)
        table.add_column("命令" if is_zh else "Command")
        table.add_column("说明" if is_zh else "Description")
        for command, description_en, description_zh in group["commands"]:
            table.add_row(command, description_zh if is_zh else description_en)
        console.print(table)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    help_zh: bool = typer.Option(
        False,
        "--help-zh",
        help="Show grouped Chinese help.",
        is_eager=True,
    ),
    help_en: bool = typer.Option(
        False,
        "--help-en",
        help="Show grouped English help.",
        is_eager=True,
    ),
) -> None:
    """Nexa attack surface intelligence CLI."""

    if help_zh:
        _print_help("zh")
        raise typer.Exit()
    if help_en:
        _print_help("en")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        return


def _require_target(session, target_name: str):
    target = TargetRepository(session).get_by_name(target_name)
    if not target or target.id is None:
        raise typer.BadParameter(f"target not found: {target_name}")
    return target


def _require_target_ref(session, target_ref: str):
    target = TargetRepository(session).get_by_ref(target_ref)
    if not target or target.id is None:
        raise typer.BadParameter(f"target not found: {target_ref}")
    return target


def _print_recon_summary(summary: ReconSummary) -> None:
    table = Table(title=f"Nexa Summary: {summary.target}")
    table.add_column("Stage")
    table.add_column("Count", justify="right")
    table.add_column("Error")
    for result in summary.collector_results:
        table.add_row(result.name, str(result.count), result.error or "")
    table.add_row("assets upserted", str(summary.assets_seen), "")
    table.add_row("services upserted", str(summary.services_seen), "")
    table.add_row("alive assets", str(summary.alive_assets), "")
    console.print(table)


def _print_target_detail(target_obj) -> None:
    console.print_json(data=target_obj.model_dump(mode="json"))


def _print_search_rows(rows: list[SearchRow], title: str) -> None:
    table = Table(title=title)
    table.add_column("Host")
    table.add_column("IP")
    table.add_column("URL")
    table.add_column("Status", justify="right")
    table.add_column("Title")
    table.add_column("Server")
    table.add_column("App/Tech")
    table.add_column("CDN")
    table.add_column("WAF")
    for row in rows:
        service = row.service
        table.add_row(
            row.asset.host,
            row.asset.ip or "",
            service.url if service else "",
            str(service.status_code) if service and service.status_code is not None else "",
            service.title if service and service.title else "",
            service.server if service and service.server else "",
            ", ".join(service.technologies) if service and service.technologies else "",
            service.cdn if service and service.cdn else "",
            service.waf if service and service.waf else "",
        )
    console.print(table)


def _print_asset_rows(rows: list[SearchRow], title: str) -> None:
    table = Table(title=title)
    table.add_column("ID", justify="right")
    table.add_column("Host")
    table.add_column("IP")
    table.add_column("Source")
    table.add_column("Alive")
    seen: set[int] = set()
    for row in rows:
        if row.asset.id in seen:
            continue
        if row.asset.id is not None:
            seen.add(row.asset.id)
        table.add_row(
            str(row.asset.id or ""),
            row.asset.host,
            row.asset.ip or "",
            row.asset.source,
            "yes" if row.asset.is_alive else "no",
        )
    console.print(table)


def _scan_target(
    target_ref: str,
    use_subfinder: bool | None,
    use_oneforall: bool | None,
    use_httpx: bool | None,
    use_online: bool | None,
    strict: bool,
) -> None:
    resolved_subfinder, resolved_oneforall, resolved_httpx, resolved_online = _resolve_scan_tools(
        use_subfinder,
        use_oneforall,
        use_httpx,
        use_online,
    )
    with create_session() as session:
        target_obj = _require_target_ref(session, target_ref)
        with console.status("[cyan]Starting scan pipeline...[/cyan]", spinner="dots") as status:
            summary = collect_target_sync(
                session,
                target_obj,
                use_subfinder=resolved_subfinder,
                use_oneforall=resolved_oneforall,
                run_httpx=resolved_httpx,
                use_online_providers=resolved_online,
                continue_on_error=not strict,
                progress_callback=lambda message: status.update(f"[cyan]{message}[/cyan]"),
            )
    _print_recon_summary(summary)


def _resolve_scan_tools(
    use_subfinder: bool | None,
    use_oneforall: bool | None,
    use_httpx: bool | None,
    use_online: bool | None,
) -> tuple[bool, bool, bool, bool]:
    defaults = get_settings().scan_tool_defaults
    return (
        defaults.subfinder if use_subfinder is None else use_subfinder,
        defaults.oneforall if use_oneforall is None else use_oneforall,
        defaults.httpx if use_httpx is None else use_httpx,
        defaults.online_providers if use_online is None else use_online,
    )


@app.command()
def init(
    bootstrap: bool = typer.Option(False, "--bootstrap-tools", help="Download bundled tools without prompting."),
    skip_tools: bool = typer.Option(False, "--skip-tools", help="Do not check or download bundled tools."),
) -> None:
    """Initialize the SQLite database."""

    init_db()
    config_path = get_settings().ensure_app_config()
    console.print("[green]Database initialized.[/green]")
    console.print(f"[green]Config ready:[/green] {config_path}")
    if not skip_tools:
        _maybe_bootstrap_tools(force=bootstrap)


def _maybe_bootstrap_tools(force: bool = False) -> None:
    resolver = ToolResolver()
    missing = [status for status in resolver.statuses() if not status.installed]
    if not missing:
        console.print("[green]Bundled tools are installed.[/green]")
        return

    missing_names = ", ".join(status.name for status in missing)
    console.print(f"[yellow]Missing bundled tools:[/yellow] {missing_names}")
    should_download = force or typer.confirm("Download bundled tools now?", default=False)
    if not should_download:
        console.print("[yellow]Skipped bundled tool bootstrap.[/yellow]")
        return

    try:
        with console.status("[cyan]Downloading bundled tools...[/cyan]", spinner="dots"):
            bootstrap_tools(root=get_settings().project_root)
    except Exception as exc:
        console.print(f"[red]Bundled tool bootstrap failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print("[green]Bundled tool bootstrap completed.[/green]")


@app.command("tools")
def tools_status() -> None:
    """Show bundled tool installation status."""

    resolver = ToolResolver()
    table = Table(title=f"Bundled Tools: {resolver.tools_dir}")
    table.add_column("Tool")
    table.add_column("Kind")
    table.add_column("Installed")
    table.add_column("Path")
    table.add_column("Note")
    for status in resolver.statuses():
        table.add_row(
            status.name,
            status.kind,
            "yes" if status.installed else "no",
            str(status.path),
            status.note,
        )
    console.print(table)


@app.command("online-search")
def online_search(
    query: str = typer.Argument(..., help='Provider query, e.g. domain="example.com".'),
    provider: str = typer.Option(
        "all",
        "--provider",
        "-p",
        help="Provider: all, fofa, hunter_qianxin, shodan, zoomeye.",
    ),
    limit: int = typer.Option(30, "--limit", "-l", min=1, help="Maximum results."),
    debug: bool = typer.Option(False, "--debug", help="Show provider response metadata."),
) -> None:
    """Search enabled online cyberspace mapping providers."""

    settings = get_settings()
    try:
        results, errors, metas = search_online_assets(
            query=query,
            configs=settings.provider_configs,
            provider_name=provider,
            limit=limit,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    _print_online_results(results, f"Online Search: {query}")
    if debug:
        _print_online_metas(metas)
    for error in errors:
        console.print(f"[yellow]{error}[/yellow]")


def _print_online_results(results: list[OnlineAssetResult], title: str) -> None:
    table = Table(title=title)
    table.add_column("Provider")
    table.add_column("Host")
    table.add_column("IP")
    table.add_column("Port", justify="right")
    table.add_column("URL")
    table.add_column("Title")
    table.add_column("Server")
    for row in results:
        table.add_row(
            row.provider,
            row.host,
            row.ip,
            str(row.port or ""),
            row.url,
            row.title,
            row.server,
        )
    console.print(table)


def _print_online_metas(metas: list[OnlineSearchMeta]) -> None:
    table = Table(title="Provider Metadata")
    table.add_column("Provider")
    table.add_column("Total", justify="right")
    table.add_column("Returned", justify="right")
    table.add_column("Message")
    for meta in metas:
        table.add_row(
            meta.provider,
            str(meta.total) if meta.total is not None else "",
            str(meta.returned),
            meta.message,
        )
    console.print(table)


def _print_risk_summaries(rows: list[RiskAssetSummary], title: str) -> None:
    table = Table(title=title)
    table.add_column("#", justify="right")
    table.add_column("Target")
    table.add_column("Score", justify="right")
    table.add_column("Level")
    table.add_column("Reasons")
    for index, row in enumerate(rows, start=1):
        target = row.service.url if row.service else row.asset.host
        table.add_row(
            str(index),
            target,
            str(row.total_score),
            row.risk_level,
            "\n".join(row.reasons[:3]),
        )
    console.print(table)


def _render_markdown_top(rows: list[RiskAssetSummary], title: str) -> str:
    lines = [f"# {title}", ""]
    for index, row in enumerate(rows, start=1):
        target = row.service.url if row.service else row.asset.host
        lines.extend(
            [
                f"{index}. {target}",
                f"   Score: {row.total_score}",
                f"   Risk Level: {row.risk_level}",
                "   Reasons:",
            ]
        )
        lines.extend(f"   - {reason}" for reason in row.reasons)
        lines.append("   Recommended:")
        lines.extend(f"   - {step}" for step in row.recommended_next_steps)
        lines.append("")
    return "\n".join(lines)


@app.command("add-target")
def add_target(
    name: str,
    root_domain: str | None = typer.Option(None, help="Root domain, defaults to name."),
    program_name: str | None = typer.Option(None, help="Bug bounty/SRC program name."),
    scope_type: str = typer.Option("in-scope", help="Scope type label."),
) -> None:
    """Create or update a target."""

    init_db()
    with create_session() as session:
        target = TargetRepository(session).create(
            TargetCreate(
                name=name,
                root_domain=root_domain,
                program_name=program_name,
                scope_type=scope_type,
            )
        )
    console.print(f"[green]Target saved:[/green] {target.name} (id={target.id})")


@app.command("targets")
def list_targets() -> None:
    """List targets."""

    init_db()
    with create_session() as session:
        targets = TargetRepository(session).list()

    table = Table(title="Targets")
    table.add_column("ID", justify="right")
    table.add_column("Name")
    table.add_column("Root Domain")
    table.add_column("Program")
    table.add_column("Scope")
    for target in targets:
        table.add_row(
            str(target.id),
            target.name,
            target.root_domain,
            target.program_name or "",
            target.scope_type,
        )
    console.print(table)


@app.command("show-target")
def show_target(name: str) -> None:
    """Show one target."""

    init_db()
    with create_session() as session:
        target = TargetRepository(session).get_by_name(name)
        if not target:
            raise typer.BadParameter(f"target not found: {name}")
    console.print_json(data=target.model_dump(mode="json"))


@app.command("target", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def target_command(
    ctx: typer.Context,
    target_ref: str = typer.Argument(..., help="Target id or name, e.g. 1 or jd.com."),
    scan: bool = typer.Option(False, "--scan", help="Run subdomain collection and httpx probing."),
    subfinder: bool | None = typer.Option(None, "--subfinder/--no-subfinder", help="Override subfinder config."),
    oneforall: bool | None = typer.Option(None, "--oneforall/--no-oneforall", help="Override OneForAll config."),
    httpx: bool | None = typer.Option(None, "--httpx/--no-httpx", help="Override httpx config."),
    online: bool | None = typer.Option(None, "--online/--no-online", help="Override online provider config."),
    strict: bool = typer.Option(False, "--strict", help="Stop on first collector error."),
) -> None:
    """Show or scan a target by id/name."""

    init_db()
    if ctx.args:
        _print_target_extra_arg_hint(target_ref, ctx.args)
        raise typer.Exit(code=2)
    if scan:
        _scan_target(target_ref, subfinder, oneforall, httpx, online, strict)
        return
    with create_session() as session:
        target_obj = _require_target_ref(session, target_ref)
        _print_target_detail(target_obj)


def _print_target_extra_arg_hint(target_ref: str, args: list[str]) -> None:
    requested = " ".join(args)
    if requested in {"assets", "services"}:
        console.print(
            f"[yellow]'{requested}' is available inside interactive mode.[/yellow]\n"
            f"Run: [bold]nexa use {target_ref}[/bold]\n"
            f"Then type: [bold]{requested}[/bold]"
        )
        return
    console.print(
        f"[red]Unexpected target argument:[/red] {requested}\n"
        f"Run [bold]nexa use {target_ref}[/bold] for target-scoped asset/service queries."
    )


@app.command("use")
def use_target(
    target_ref: str = typer.Argument(..., help="Target id or name, e.g. 1 or jd.com."),
    query: str | None = typer.Option(None, "--query", "-q", help='Run one query and exit, e.g. app="Vue.js".'),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum rows to show per query."),
) -> None:
    """Enter interactive target search mode."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target_ref)
        if query is not None:
            rows = search_target_assets(session, target_obj.id, query, limit=limit)
            _print_search_rows(rows, f'{target_obj.name}: {query or "*"}')
            return

        console.print(
            f"[bold green]Using target[/bold green] {target_obj.id}: {target_obj.name}\n"
            'Query examples: app="Vue.js", ip="127.0.0.1", app="vue.js" && server="nginx"\n'
            "Commands: help, assets, services, exit"
        )
        prompt = HTML(f'<ansicyan><b>{target_obj.name}</b></ansicyan> <ansigreen><b>&gt;</b></ansigreen> ')
        prompt_session = PromptSession(history=InMemoryHistory())
        while True:
            try:
                text = prompt_session.prompt(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
            if text.lower() in {"exit", "quit", "q"}:
                break
            if text.lower() == "help":
                console.print(
                    'Supported fields: app, tech, ip, host, url, title, server, cdn, waf, '
                    'status, port, scheme, source, cname, favicon, alive\n'
                    'Operators: =, !=. Boolean logic: &&, ||.\n'
                    'Examples: app="Vue.js"; server="nginx" && status=200; '
                    'app="vue" || title="admin"'
                )
                continue
            try:
                if text.lower() == "assets":
                    _print_asset_rows(list_target_rows(session, target_obj.id), f"{target_obj.name}: assets")
                    continue
                if text.lower() == "services":
                    rows = [row for row in list_target_rows(session, target_obj.id) if row.service is not None]
                    _print_search_rows(rows[:limit], f"{target_obj.name}: services")
                    continue
                rows = search_target_assets(session, target_obj.id, text, limit=limit)
                _print_search_rows(rows, f'{target_obj.name}: {text or "*"}')
            except QuerySyntaxError as exc:
                console.print(f"[red]Query error:[/red] {exc}")


@app.command("del-target")
@app.command("delete-target")
def delete_target(name: str) -> None:
    """Delete a target by name."""

    init_db()
    with create_session() as session:
        deleted = TargetRepository(session).delete_by_name(name)
    if not deleted:
        raise typer.BadParameter(f"target not found: {name}")
    console.print(f"[yellow]Target deleted:[/yellow] {name}")


@app.command("scan-http")
def scan_http(
    target: str = typer.Option(..., help="Target name."),
    strict: bool = typer.Option(False, "--strict", help="Stop on collector errors."),
) -> None:
    """Probe existing assets with httpx."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        summary = collect_target_sync(
            session,
            target_obj,
            use_subfinder=False,
            use_oneforall=False,
            run_httpx=True,
            use_online_providers=False,
            continue_on_error=not strict,
        )
    _print_recon_summary(summary)


@app.command("collect-target")
def collect_target_command(
    target: str = typer.Option(..., help="Target name or root domain."),
    subfinder: bool | None = typer.Option(None, "--subfinder/--no-subfinder", help="Override subfinder config."),
    oneforall: bool | None = typer.Option(None, "--oneforall/--no-oneforall", help="Override OneForAll config."),
    httpx: bool | None = typer.Option(None, "--httpx/--no-httpx", help="Override httpx config."),
    online: bool | None = typer.Option(None, "--online/--no-online", help="Override online provider config."),
    strict: bool = typer.Option(False, "--strict", help="Stop on first collector error."),
) -> None:
    """Run target collection pipeline with subfinder/oneforall/httpx."""

    init_db()
    resolved_subfinder, resolved_oneforall, resolved_httpx, resolved_online = _resolve_scan_tools(
        subfinder,
        oneforall,
        httpx,
        online,
    )
    with create_session() as session:
        target_repo = TargetRepository(session)
        target_obj = target_repo.get_by_name(target) or target_repo.create(TargetCreate(name=target))
        with console.status("[cyan]Starting scan pipeline...[/cyan]", spinner="dots") as status:
            summary = collect_target_sync(
                session,
                target_obj,
                use_subfinder=resolved_subfinder,
                use_oneforall=resolved_oneforall,
                run_httpx=resolved_httpx,
                use_online_providers=resolved_online,
                continue_on_error=not strict,
                progress_callback=lambda message: status.update(f"[cyan]{message}[/cyan]"),
            )
    _print_recon_summary(summary)


@app.command("analyze", hidden=True)
def analyze(target: str = typer.Option(..., help="Target id or name.")) -> None:
    """Experimental: run risk analysis for a target."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        count = analyze_target_risk(session, target_obj.id)
    console.print(f"[green]Risk analysis completed:[/green] {count} findings")


@app.command("top", hidden=True)
def top(target: str = typer.Option(..., help="Target id or name."), limit: int = typer.Option(30)) -> None:
    """Experimental: show high-value assets."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        rows = top_risk_assets(session, target_obj.id, limit=limit)
        if not rows:
            rows = preview_target_risk(session, target_obj.id, limit=limit)
    _print_risk_summaries(rows, f"High-value Assets: {target_obj.name}")


@app.command("export", hidden=True)
def export(
    target: str = typer.Option(..., help="Target id or name."),
    format: str = typer.Option("markdown", "--format", help="Export format: markdown."),
    limit: int = typer.Option(30, "--limit", help="Maximum assets to export."),
) -> None:
    """Experimental: export high-value assets."""

    if format.lower() not in {"markdown", "md"}:
        raise typer.BadParameter("only markdown export is supported now")
    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        rows = top_risk_assets(session, target_obj.id, limit=limit)
        if not rows:
            rows = preview_target_risk(session, target_obj.id, limit=limit)
    console.print(_render_markdown_top(rows, f"高价值资产 Top {limit}: {target_obj.name}"))


if __name__ == "__main__":
    app()
