from pathlib import Path

from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.history import InMemoryHistory
import typer
from rich.console import Console
from rich.table import Table

from app.database import create_session, init_db
from app.pipelines.recon import (
    ReconSummary,
    collect_target_sync,
    import_httpx_file,
    import_subdomain_file,
)
from app.query import QuerySyntaxError, SearchRow, list_target_rows, search_target_assets
from app.repositories import AssetRepository, ServiceRepository, TargetRepository
from app.schemas.asset import AssetCreate
from app.schemas.service import ServiceCreate
from app.schemas.target import TargetCreate
from app.tooling import ToolResolver

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
        ],
    },
    {
        "name_en": "Assets",
        "name_zh": "资产",
        "commands": [
            ("add-asset", "Create or update an asset.", "创建或更新子域名/主机资产。"),
            ("assets", "List assets for a target.", "列出目标下的资产。"),
            ("delete-asset", "Delete an asset by host.", "按主机名删除资产。"),
        ],
    },
    {
        "name_en": "Services",
        "name_zh": "服务",
        "commands": [
            ("add-service", "Create or update an HTTP service.", "创建或更新 HTTP/HTTPS 服务。"),
            ("services", "List HTTP services for a target.", "列出目标下的 HTTP/HTTPS 服务。"),
            ("delete-service", "Delete a service by id.", "按 ID 删除服务。"),
        ],
    },
    {
        "name_en": "Import and Analysis",
        "name_zh": "导入与分析",
        "commands": [
            (
                "import-subdomains",
                "Import subfinder/oneforall/custom subdomain output.",
                "导入 subfinder/oneforall/自定义子域名结果。",
            ),
            (
                "import-httpx",
                "Import httpx JSON/JSONL output.",
                "导入 httpx JSON/JSONL 结果。",
            ),
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
                "analyze",
                "Reserved: run fingerprint and risk analysis.",
                "预留：执行指纹识别和风险分析。",
            ),
            ("top", "Reserved: show high-value assets.", "预留：展示高价值资产列表。"),
            ("export", "Reserved: export high-value assets.", "预留：导出高价值资产结果。"),
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


def _require_asset(session, host: str):
    asset = AssetRepository(session).get_by_host(host)
    if not asset or asset.id is None:
        raise typer.BadParameter(f"asset not found: {host}")
    return asset


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


def _scan_target(target_ref: str, use_subfinder: bool, use_oneforall: bool, use_httpx: bool, strict: bool) -> None:
    with create_session() as session:
        target_obj = _require_target_ref(session, target_ref)
        summary = collect_target_sync(
            session,
            target_obj,
            use_subfinder=use_subfinder,
            use_oneforall=use_oneforall,
            run_httpx=use_httpx,
            continue_on_error=not strict,
        )
    _print_recon_summary(summary)


@app.command()
def init() -> None:
    """Initialize the SQLite database."""

    init_db()
    console.print("[green]Database initialized.[/green]")


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


@app.command("target")
def target_command(
    target_ref: str = typer.Argument(..., help="Target id or name, e.g. 1 or jd.com."),
    scan: bool = typer.Option(False, "--scan", help="Run subdomain collection and httpx probing."),
    subfinder: bool = typer.Option(True, "--subfinder/--no-subfinder", help="Run subfinder."),
    oneforall: bool = typer.Option(True, "--oneforall/--no-oneforall", help="Run bundled OneForAll."),
    httpx: bool = typer.Option(True, "--httpx/--no-httpx", help="Run httpx after asset collection."),
    strict: bool = typer.Option(False, "--strict", help="Stop on first collector error."),
) -> None:
    """Show or scan a target by id/name."""

    init_db()
    if scan:
        _scan_target(target_ref, subfinder, oneforall, httpx, strict)
        return
    with create_session() as session:
        target_obj = _require_target_ref(session, target_ref)
        _print_target_detail(target_obj)


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


@app.command("delete-target")
def delete_target(name: str) -> None:
    """Delete a target by name."""

    init_db()
    with create_session() as session:
        deleted = TargetRepository(session).delete_by_name(name)
    if not deleted:
        raise typer.BadParameter(f"target not found: {name}")
    console.print(f"[yellow]Target deleted:[/yellow] {name}")


@app.command("add-asset")
def add_asset(
    target: str = typer.Option(..., help="Target name."),
    host: str = typer.Option(..., help="Hostname or URL."),
    asset_type: str = typer.Option("subdomain", help="Asset type."),
    source: str = typer.Option("manual", help="Asset source."),
    ip: str | None = typer.Option(None, help="Resolved IP."),
    cname: str | None = typer.Option(None, help="CNAME record."),
    alive: bool = typer.Option(False, "--alive", help="Mark asset as alive."),
) -> None:
    """Create or update an asset."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        asset = AssetRepository(session).upsert(
            AssetCreate(
                target_id=target_obj.id,
                host=host,
                asset_type=asset_type,
                source=source,
                ip=ip,
                cname=cname,
                is_alive=alive,
            )
        )
    console.print(f"[green]Asset saved:[/green] {asset.host} (id={asset.id})")


@app.command("assets")
def list_assets(
    target: str = typer.Option(..., help="Target name."),
    alive_only: bool = typer.Option(False, "--alive-only", help="Only list alive assets."),
) -> None:
    """List assets for a target."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        assets = AssetRepository(session).list_by_target(target_obj.id, alive_only=alive_only)

    table = Table(title=f"Assets: {target}")
    table.add_column("ID", justify="right")
    table.add_column("Host")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("IP")
    table.add_column("Alive")
    for asset in assets:
        table.add_row(
            str(asset.id),
            asset.host,
            asset.asset_type,
            asset.source,
            asset.ip or "",
            "yes" if asset.is_alive else "no",
        )
    console.print(table)


@app.command("delete-asset")
def delete_asset(host: str) -> None:
    """Delete an asset by host."""

    init_db()
    with create_session() as session:
        deleted = AssetRepository(session).delete_by_host(host)
    if not deleted:
        raise typer.BadParameter(f"asset not found: {host}")
    console.print(f"[yellow]Asset deleted:[/yellow] {host}")


@app.command("add-service")
def add_service(
    host: str = typer.Option(..., help="Existing asset host."),
    url: str = typer.Option(..., help="Service URL."),
    status_code: int | None = typer.Option(None, help="HTTP status code."),
    title: str | None = typer.Option(None, help="HTML title."),
    server: str | None = typer.Option(None, help="Server header."),
    cdn: str | None = typer.Option(None, help="CDN fingerprint."),
    waf: str | None = typer.Option(None, help="WAF fingerprint."),
) -> None:
    """Create or update an HTTP service."""

    init_db()
    with create_session() as session:
        asset = _require_asset(session, host)
        service = ServiceRepository(session).upsert(
            ServiceCreate(
                asset_id=asset.id,
                url=url,
                status_code=status_code,
                title=title,
                server=server,
                cdn=cdn,
                waf=waf,
            )
        )
        asset.is_alive = True
        session.add(asset)
        session.commit()
    console.print(f"[green]Service saved:[/green] {service.url} (id={service.id})")


@app.command("services")
def list_services(target: str = typer.Option(..., help="Target name.")) -> None:
    """List HTTP services for a target."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        services = ServiceRepository(session).list_by_target(target_obj.id)

    table = Table(title=f"Services: {target}")
    table.add_column("ID", justify="right")
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Server")
    table.add_column("CDN")
    table.add_column("WAF")
    for service in services:
        table.add_row(
            str(service.id),
            service.url,
            str(service.status_code or ""),
            service.title or "",
            service.server or "",
            service.cdn or "",
            service.waf or "",
        )
    console.print(table)


@app.command("delete-service")
def delete_service(service_id: int) -> None:
    """Delete a service by id."""

    init_db()
    with create_session() as session:
        deleted = ServiceRepository(session).delete(service_id)
    if not deleted:
        raise typer.BadParameter(f"service not found: {service_id}")
    console.print(f"[yellow]Service deleted:[/yellow] {service_id}")


@app.command("import-subdomains")
def import_subdomains(
    target: str = typer.Option(..., help="Target name."),
    file: Path = typer.Option(..., exists=True, readable=True, help="Subdomain result file."),
    source: str = typer.Option("subfinder", help="Source parser: subfinder, oneforall, or custom."),
) -> None:
    """Import subfinder/oneforall/custom subdomain output."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        count = import_subdomain_file(session, target_obj, file, source)
    console.print(f"[green]Imported assets:[/green] {count}")


@app.command("import-httpx")
def import_httpx(
    target: str = typer.Option(..., help="Target name."),
    file: Path = typer.Option(..., exists=True, readable=True, help="httpx JSONL output file."),
) -> None:
    """Import httpx JSON/JSONL output."""

    init_db()
    with create_session() as session:
        target_obj = _require_target(session, target)
        count = import_httpx_file(session, target_obj, file)
    console.print(f"[green]Imported services:[/green] {count}")


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
            continue_on_error=not strict,
        )
    _print_recon_summary(summary)


@app.command("collect-target")
def collect_target_command(
    target: str = typer.Option(..., help="Target name or root domain."),
    subfinder: bool = typer.Option(True, "--subfinder/--no-subfinder", help="Run subfinder."),
    oneforall: bool = typer.Option(True, "--oneforall/--no-oneforall", help="Run bundled OneForAll."),
    httpx: bool = typer.Option(True, "--httpx/--no-httpx", help="Run httpx after asset collection."),
    strict: bool = typer.Option(False, "--strict", help="Stop on first collector error."),
) -> None:
    """Run target collection pipeline with subfinder/oneforall/httpx."""

    init_db()
    with create_session() as session:
        target_repo = TargetRepository(session)
        target_obj = target_repo.get_by_name(target) or target_repo.create(TargetCreate(name=target))
        summary = collect_target_sync(
            session,
            target_obj,
            use_subfinder=subfinder,
            use_oneforall=oneforall,
            run_httpx=httpx,
            continue_on_error=not strict,
        )
    _print_recon_summary(summary)


@app.command("analyze")
def analyze(target: str = typer.Option(...)) -> None:
    """Reserved: run fingerprint and risk analysis."""

    _ = target
    console.print("[yellow]Not implemented in MVP step 1. Planned for step 3.[/yellow]")


@app.command("top")
def top(target: str = typer.Option(...), limit: int = typer.Option(30)) -> None:
    """Reserved: show high-value assets."""

    _ = (target, limit)
    console.print("[yellow]Not implemented in MVP step 1. Planned for step 3.[/yellow]")


@app.command("export")
def export(target: str = typer.Option(...), format: str = typer.Option("markdown")) -> None:
    """Reserved: export high-value assets."""

    _ = (target, format)
    console.print("[yellow]Not implemented in MVP step 1. Planned for step 3.[/yellow]")


if __name__ == "__main__":
    app()
