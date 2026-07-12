import sys

from prompt_toolkit import HTML, PromptSession
from prompt_toolkit.history import InMemoryHistory
import typer
from rich.box import SIMPLE_HEAVY
from rich.console import Console
from rich.table import Table

from app.config import get_settings
from app.database import create_session, init_db
from app.intel import CveExploitClient, CveExploitResult
from app.noise import (
    ClassificationView,
    GroupView,
    classify_target_assets,
    get_service_classification,
    list_asset_groups,
    list_group_assets,
    list_interesting_assets,
    list_noisy_assets,
    list_outliers,
)
from app.pipelines.recon import (
    ReconSummary,
    collect_target_sync,
)
from app.providers.base import OnlineAssetResult, OnlineSearchMeta
from app.providers.search import search_online_assets
from app.prune import PrunePreview, preview_prune, preview_prune_group, prune_group, prune_query
from app.query import AppSummary, QuerySyntaxError, SearchRow, list_target_apps, list_target_rows, search_target_assets
from app.repositories import AssetEvidenceRepository, AssetSeedRepository, TargetRepository
from app.risk import RiskAssetSummary, analyze_target_risk, preview_target_risk, top_risk_assets
from app.noise_rules import load_noise_rules
from app.schemas.target import TargetCreate
from app.tooling import ToolResolver
from app.web_runtime import WebBuildError, ensure_frontend_bundle
from scripts.bootstrap_tools import bootstrap_tools

app = typer.Typer(help="Nexa attack surface intelligence CLI.", no_args_is_help=True)
seed_app = typer.Typer(help="Manage manual high-value asset seeds.", no_args_is_help=True)
app.add_typer(seed_app, name="seed")
console = Console()


HELP_GROUPS: list[dict[str, object]] = [
    {
        "name_en": "Project",
        "name_zh": "项目",
        "commands": [
            ("init", "Initialize the SQLite database.", "初始化 SQLite 数据库。"),
            ("tools", "Show bundled tool installation status.", "查看内置工具安装状态。"),
            ("noise-rules", "Show loaded noise rule configuration.", "查看当前加载的噪声规则配置。"),
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
            ("seed", "Manage manual high-value asset seeds.", "管理手动回灌的高价值资产线索。"),
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
                "Search enabled FOFA/Hunter/Shodan/ZoomEye/360 Quake providers.",
                "调用已启用的 FOFA/Hunter/Shodan/ZoomEye/360 Quake 测绘接口。",
            ),
            (
                "web",
                "Start the integrated Web workspace and API server.",
                "一条命令启动集成式 Web 管理台与 API 服务。",
            ),
            (
                "cve-poc",
                "Check public GitHub PoC metadata for a CVE.",
                "查询某个 CVE 是否存在公开 GitHub PoC 元数据。",
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


def _print_recon_diff(summary: ReconSummary) -> None:
    diff = summary.diff
    table = Table(title=f"Scan Diff: {summary.target}")
    table.add_column("Type")
    table.add_column("New", justify="right")
    table.add_column("Samples")
    table.add_row("assets", str(len(diff.new_assets)), ", ".join(diff.new_assets[:5]))
    table.add_row("services", str(len(diff.new_services)), ", ".join(diff.new_services[:5]))
    table.add_row("technologies", str(len(diff.new_technologies)), ", ".join(diff.new_technologies[:8]))
    table.add_row("sources", str(len(diff.new_sources)), ", ".join(diff.new_sources[:8]))
    console.print(table)


def _print_source_coverage(source_counts: dict[str, int], title: str) -> None:
    table = Table(title=title)
    table.add_column("Source")
    table.add_column("Evidence", justify="right")
    for source, count in list(source_counts.items())[:20]:
        table.add_row(source, str(count))
    console.print(table)


def _print_noise_summary(summary, target_name: str) -> None:
    table = Table(title=f"Asset Noise Reduction: {target_name}")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    table.add_row("groups", str(summary.groups))
    table.add_row("classifications", str(summary.classifications))
    table.add_row("high-noise groups", str(summary.high_noise_groups))
    table.add_row("outliers", str(summary.outliers))
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


def _print_service_rows(rows: list[SearchRow], title: str) -> None:
    table = Table(title=title)
    table.add_column("ID", justify="right")
    table.add_column("URL")
    table.add_column("Status", justify="right")
    table.add_column("Port", justify="right")
    table.add_column("Title")
    table.add_column("Server")
    table.add_column("App/Tech")
    table.add_column("CDN")
    table.add_column("WAF")
    for row in rows:
        service = row.service
        if not service:
            continue
        table.add_row(
            str(service.id or ""),
            service.url,
            str(service.status_code) if service.status_code is not None else "",
            str(service.port) if service.port is not None else "",
            service.title or "",
            service.server or "",
            ", ".join(service.technologies) if service.technologies else "",
            service.cdn or "",
            service.waf or "",
        )
    console.print(table)


def _print_app_summaries(rows: list[AppSummary], title: str) -> None:
    table = Table(title=title)
    table.add_column("App / Technology")
    table.add_column("Services", justify="right")
    table.add_column("Assets", justify="right")
    table.add_column("Sample Hosts")
    for row in rows:
        table.add_row(
            row.name,
            str(row.service_count),
            str(row.asset_count),
            ", ".join(row.sample_hosts),
        )
    console.print(table)


def _print_group_views(rows: list[GroupView], title: str) -> None:
    table = Table(title=title)
    table.add_column("ID", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Template")
    table.add_column("Sample")
    table.add_column("Open")
    for row in rows:
        group = row.group
        service = row.service
        sample = service.url if service else group.sample_hosts[0] if group.sample_hosts else ""
        table.add_row(
            str(group.id or ""),
            str(group.count),
            _group_template_label(group),
            sample,
            f"group {group.id}" if group.id is not None else "",
        )
    console.print(table)


def _print_classification_views(rows: list[ClassificationView], title: str) -> None:
    table = Table(title=title)
    table.add_column("Host")
    table.add_column("URL")
    table.add_column("Status", justify="right")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Score", justify="right")
    table.add_column("Group", justify="right")
    for row in rows:
        service = row.service
        table.add_row(
            row.asset.host,
            service.url if service else "",
            str(service.status_code) if service and service.status_code is not None else "-",
            service.title if service and service.title else "",
            row.classification.category,
            f"{row.classification.noise_score}/{row.classification.discovery_value}",
            str(row.group.count) if row.group else "-",
        )
    console.print(table)


def _print_interesting_views(rows: list[ClassificationView], title: str) -> None:
    table = Table(title=title)
    table.add_column("ID", justify="right")
    table.add_column("URL")
    table.add_column("Status", justify="right")
    table.add_column("Title")
    table.add_column("App/Tech")
    table.add_column("Category")
    table.add_column("Score", justify="right")
    table.add_column("Why")
    for row in rows:
        service = row.service
        table.add_row(
            str(service.id) if service and service.id is not None else "",
            service.url if service else row.asset.host,
            str(service.status_code) if service and service.status_code is not None else "",
            service.title if service and service.title else "",
            ", ".join(service.technologies[:3]) if service and service.technologies else "",
            row.classification.category,
            f"{row.classification.discovery_value}/{row.classification.noise_score}",
            "; ".join(_reason_zh(reason) for reason in row.classification.reasons[:3]),
        )
    console.print(table)


def _print_why_view(row: ClassificationView, evidence_rows) -> None:
    service = row.service
    if not service:
        console.print("[yellow]No service detail available.[/yellow]")
        return
    console.print(f"[bold]Service[/bold]: {service.url}")
    console.print(f"[bold]Asset[/bold]: {row.asset.host}")
    console.print(
        f"[bold]Category[/bold]: {row.classification.category}  "
        f"[bold]Discovery/Noise[/bold]: {row.classification.discovery_value}/{row.classification.noise_score}"
    )
    if row.group:
        console.print(f"[bold]Group[/bold]: {row.group.id} count={row.group.count}")
    if row.classification.reasons:
        console.print("[bold]Reasons[/bold]")
        for reason in row.classification.reasons:
            console.print(f"- {_reason_zh(reason)}")
    if evidence_rows:
        console.print("[bold]Evidence Sources[/bold]")
        for evidence in evidence_rows[:8]:
            source = f"{evidence.source}:{evidence.provider}" if evidence.provider else evidence.source
            console.print(f"- {source} {evidence.raw_url or evidence.raw_host or ''}")
    headers = _interesting_headers(service.response_headers)
    if headers:
        console.print("[bold]Headers[/bold]")
        for key, value in headers.items():
            console.print(f"- {key}: {value}")


def _interesting_headers(headers: dict) -> dict[str, str]:
    interesting = {}
    wanted = {
        "server",
        "x-powered-by",
        "x-nextjs-cache",
        "vary",
        "location",
        "content-security-policy",
        "set-cookie",
    }
    for key, value in headers.items():
        normalized = str(key).lower()
        if normalized in wanted or normalized.startswith("x-"):
            interesting[str(key)] = str(value)[:200]
    return interesting


def _reason_zh(reason: str) -> str:
    """Translate legacy English classifications already stored in SQLite."""

    exact = {
        "very large repeated service template": "超大规模重复服务模板",
        "repeated service template": "重复服务模板",
        "redirect template": "重定向模板",
        "common error/status template": "常见错误页或状态码模板",
        "generic title": "通用或空标题",
        "redirect service": "服务仅返回重定向",
        "numeric or short host label": "主机标签过短或主要由数字组成",
        "api documentation or graphql signal": "发现 API 文档或 GraphQL 特征",
        "rare template group": "属于少见服务模板",
        "single-source discovery": "目前仅由单一来源发现",
        "shop template": "命中店铺套用模板",
        "high-value-looking asset inside a large template group": "大型模板组中出现疑似高价值异常资产",
    }
    if reason in exact:
        return exact[reason]
    prefixes = {
        "large repeated group count=": "大规模重复资产组，服务数：",
        "repeated group count=": "重复资产组，服务数：",
        "common low-signal status=": "低信息量 HTTP 状态码：",
        "high-value hostname keywords: ": "主机名包含高价值关键词：",
        "category=": "识别分类：",
    }
    for prefix, translated in prefixes.items():
        if reason.startswith(prefix):
            return translated + reason[len(prefix):]
    return reason


def _print_prune_preview(preview: PrunePreview, title: str) -> None:
    console.print(
        f"[yellow]{title}[/yellow] "
        f"matched services={preview.service_count}, assets={preview.asset_count}"
    )
    _print_search_rows(preview.rows, "Matched sample")
    console.print("[dim]Use drop! <query> to delete these matched rows.[/dim]")


def _print_seed_rows(rows, title: str) -> None:
    table = Table(title=title)
    table.add_column("ID", justify="right")
    table.add_column("Host")
    table.add_column("Source")
    table.add_column("Note")
    for row in rows:
        table.add_row(str(row.id or ""), row.host, row.source, row.note or "")
    console.print(table)


def _print_evidence_rows(rows, title: str) -> None:
    table = Table(title=title, box=SIMPLE_HEAVY, show_lines=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Host", overflow="ellipsis")
    table.add_column("URL", overflow="ellipsis")
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Title", overflow="ellipsis")
    for row in rows:
        source = f"{row.source}:{row.provider}" if row.provider else row.source
        table.add_row(
            source,
            row.raw_host or "",
            row.raw_url or "",
            str(row.confidence),
            row.title or "",
        )
    console.print(table)


def _print_source_counts(counts: dict[str, int], title: str) -> None:
    table = Table(title=title)
    table.add_column("Source")
    table.add_column("Evidence", justify="right")
    for source, count in counts.items():
        table.add_row(source, str(count))
    console.print(table)


def _print_interactive_help() -> None:
    command_table = Table(title="交互命令 / Interactive Commands", box=SIMPLE_HEAVY, show_lines=False)
    command_table.add_column("命令 / Command", no_wrap=True)
    command_table.add_column("说明 / Description")
    command_table.add_column("示例 / Example", no_wrap=True)
    command_table.add_row(
        "overview",
        "一次查看优先目标与来源覆盖，不再分别执行 interesting、sources、coverage。\nShow prioritized targets and source coverage together.",
        "overview",
    )
    command_table.add_row(
        "services",
        "列出 HTTP/HTTPS 服务、状态码、标题、Server、组件。\nList HTTP services, status, title, server and tech.",
        "services",
    )
    command_table.add_row(
        "apps",
        "汇总已识别组件名，辅助 app= 查询。\nAggregate detected app/technology names.",
        "apps",
    )
    command_table.add_row(
        "inspect <service_id>",
        "查看服务分类原因、响应头与来源证据。\nInspect classification, headers and source evidence.",
        "inspect 123",
    )
    command_table.add_row(
        "clean",
        "查看噪声资产；clean group <id> 或 clean <query> 可预览删除范围。\nReview noise or preview cleanup by group/query.",
        'clean title="旗舰店 - 京东"',
    )
    command_table.add_row(
        "clean! <query>",
        "确认后执行清理；支持 clean! group <id>。\nExecute cleanup after reviewing the preview.",
        'clean! group 4',
    )
    command_table.add_row("help", "显示帮助。\nShow this help.", "help")
    command_table.add_row("exit", "退出当前目标工作区。\nLeave the target workspace.", "exit")
    console.print(command_table)

    query_table = Table(title="查询语法 / Query Syntax", box=SIMPLE_HEAVY, show_lines=False)
    query_table.add_column("字段 / Field", no_wrap=True)
    query_table.add_column("说明 / Meaning")
    query_table.add_column("示例 / Example", no_wrap=True)
    query_table.add_row("app / tech", "技术组件名。\nDetected technology.", 'app="Vue.js"')
    query_table.add_row("host", "主机名/子域名。\nHostname/subdomain.", 'host="api"')
    query_table.add_row("ip", "资产 IP。\nResolved asset IP.", 'ip="127.0.0.1"')
    query_table.add_row("url", "服务 URL。\nService URL.", 'url="/admin"')
    query_table.add_row("title", "网页标题。\nHTTP title.", 'title="后台"')
    query_table.add_row("server", "Server 指纹。\nServer header/provider value.", 'server="nginx"')
    query_table.add_row("header", "响应头键或值。\nResponse header key or value.", 'header="X-Nextjs-Cache"')
    query_table.add_row("status", "HTTP 状态码。\nHTTP status code.", "status=200")
    query_table.add_row("port", "服务端口。\nService port.", "port=443")
    query_table.add_row("cdn / waf", "CDN/WAF 标签。\nDetected CDN/WAF labels.", 'cdn!="cloudflare"')
    query_table.add_row("source", "资产来源。\nAsset source.", 'source="online"')
    query_table.add_row("alive", "资产存活状态。\nAsset alive state.", "alive=true")
    query_table.add_row("category", "降噪分类。\nNoise/category label.", 'category="shop-template"')
    console.print(query_table)
    console.print("[dim]操作符 / Operators: =, !=. 布尔逻辑 / Boolean logic: &&, ||.[/dim]")


def _compact(value: str, limit: int) -> str:
    normalized = " ".join(str(value).split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 1)] + "…"


def _table_width(preferred: int) -> int:
    return max(80, min(preferred, console.size.width))


def _signal_labels(reasons: list[str]) -> str:
    labels = []
    mapping = {
        "very large repeated service template": "huge-template",
        "repeated service template": "repeated",
        "redirect template": "redirect",
        "common error/status template": "error-template",
        "generic title": "generic-title",
        "超大规模重复服务模板": "超大模板",
        "重复服务模板": "重复模板",
        "重定向模板": "重定向",
        "常见错误页或状态码模板": "错误页模板",
        "通用或空标题": "通用标题",
    }
    for reason in reasons:
        label = mapping.get(reason)
        if not label:
            if reason.startswith("large repeated group"):
                label = "large-group"
            elif reason.startswith("high-value hostname"):
                label = "keyword"
            elif reason.startswith("category="):
                label = reason
            elif reason.startswith("rare template"):
                label = "rare-group"
            elif reason.startswith("single-source"):
                label = "single-source"
            elif reason.startswith("common low-signal"):
                label = "low-signal-status"
            elif reason.startswith("numeric or short"):
                label = "short-host"
            else:
                label = _compact(reason, 18)
        if label not in labels:
            labels.append(label)
    return ", ".join(labels[:4])


def _group_template_label(group: GroupView | object) -> str:
    status_code = getattr(group, "status_code", None)
    title = getattr(group, "title", None) or "(empty title)"
    server = getattr(group, "server", None) or "-"
    parts = [
        f"status={status_code}" if status_code is not None else "status=-",
        f"title={title}",
        f"server={server}",
    ]
    return " | ".join(parts)


def _parse_group_id(text: str) -> int:
    return _parse_numeric_arg(text, "group")


def _parse_numeric_arg(text: str, command: str) -> int:
    parts = text.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].strip().isdigit():
        raise ValueError(f"usage: {command} <id>")
    return int(parts[1].strip())


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
            status.update("[cyan]Classifying asset groups and noise...[/cyan]")
            noise_summary = classify_target_assets(session, target_obj.id)
    _print_recon_summary(summary)
    _print_recon_diff(summary)
    _print_source_coverage(summary.source_counts, f"Source Coverage: {target_obj.name}")
    _print_noise_summary(noise_summary, target_obj.name)


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
    settings = get_settings()
    config_path = settings.ensure_app_config()
    noise_rules_path = settings.ensure_noise_rules_config()
    console.print("[green]Database initialized.[/green]")
    console.print(f"[green]Config ready:[/green] {config_path}")
    console.print(f"[green]Noise rules ready:[/green] {noise_rules_path}")
    if not skip_tools:
        _maybe_bootstrap_tools(force=bootstrap)


@app.command("noise-rules")
def noise_rules_status() -> None:
    """Show loaded noise rule configuration."""

    settings = get_settings()
    path = settings.config_dir / "noise_rules.json"
    rules = load_noise_rules()
    table = Table(title=f"Noise Rules: {path if path.exists() else settings.config_dir / 'noise_rules.example.json'}")
    table.add_column("Section")
    table.add_column("Count", justify="right")
    table.add_row("high_value_keywords", str(len(rules.high_value_keywords)))
    table.add_row("doc_keywords", str(len(rules.doc_keywords)))
    table.add_row("generic_titles", str(len(rules.generic_titles)))
    table.add_row("category_rules", str(len(rules.category_rules)))
    console.print(table)

    category_table = Table(title="Category Rules")
    category_table.add_column("Name")
    category_table.add_column("Category")
    category_table.add_column("Noise", justify="right")
    category_table.add_column("Value", justify="right")
    category_table.add_column("Reason")
    for rule in rules.category_rules:
        category_table.add_row(
            rule.name,
            rule.category,
            str(rule.noise_delta),
            str(rule.value_delta),
            rule.reason,
        )
    console.print(category_table)


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
        help="Provider: all, fofa, hunter_qianxin, shodan, zoomeye, quake_360.",
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


@app.command("web")
def web_server(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Enable uvicorn reload."),
    rebuild: bool = typer.Option(False, "--rebuild", help="Force rebuilding the Web frontend."),
) -> None:
    """Start the integrated Nexa Web workspace and API server."""

    init_db()
    settings = get_settings()
    try:
        with console.status("[cyan]Preparing Nexa Web frontend...[/cyan]"):
            built = ensure_frontend_bundle(settings.resource_root, rebuild=rebuild)
    except WebBuildError as exc:
        console.print(f"[red]Nexa Web frontend is unavailable:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    try:
        import uvicorn
    except ImportError as exc:
        raise typer.BadParameter("uvicorn is required to start Nexa Web") from exc
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    base_url = f"http://{display_host}:{port}"
    if built:
        console.print("[green]Nexa Web frontend built successfully.[/green]")
    console.print(f"[bold green]Nexa Web:[/bold green] {base_url}")
    console.print(f"[green]API documentation:[/green] {base_url}/docs")
    console.print("[dim]Press Ctrl+C to stop the Web workspace.[/dim]")
    if reload and not getattr(sys, "frozen", False):
        application = "app.main:app"
    else:
        from app.main import app as application

    uvicorn.run(
        application,
        host=host,
        port=port,
        reload=reload and not getattr(sys, "frozen", False),
    )


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


def _print_cve_exploit_result(result: CveExploitResult) -> None:
    title = f"{result.cve_id}: public GitHub PoC"
    if result.error:
        console.print(f"[yellow]{title} lookup failed:[/yellow] {result.error}")
        return
    table = Table(title=title)
    table.add_column("Name")
    table.add_column("Stars", justify="right")
    table.add_column("Lang")
    table.add_column("Updated")
    table.add_column("URL")
    table.add_column("Description")
    for item in result.items:
        table.add_row(
            item.name,
            str(item.stars) if item.stars is not None else "",
            item.language,
            item.updated_at,
            item.url,
            item.description,
        )
    console.print(table)
    if not result.items:
        console.print("[dim]No public PoC metadata returned by configured source.[/dim]")


@app.command("cve-poc")
def cve_poc(cve_id: str = typer.Argument(..., help="CVE id, e.g. CVE-2024-12345.")) -> None:
    """Check public GitHub PoC metadata for a CVE."""

    settings = get_settings()
    try:
        result = CveExploitClient(settings.cve_exploit_intel).lookup(cve_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    _print_cve_exploit_result(result)


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
    if requested in {
        "assets",
        "services",
        "apps",
        "components",
        "techs",
        "groups",
        "group",
        "noise",
        "outliers",
        "interesting",
        "why",
        "sources",
        "coverage",
        "evidence",
        "drop",
    }:
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
            "Commands: help, overview, services, apps, inspect <id>, clean, exit"
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
                _print_interactive_help()
                continue
            try:
                if text.lower() == "overview":
                    rows = list_interesting_assets(session, target_obj.id, limit=limit)
                    _print_interesting_views(rows, f"{target_obj.name}: prioritized services")
                    counts = AssetEvidenceRepository(session).source_counts(target_obj.id)
                    _print_source_coverage(counts, f"{target_obj.name}: source coverage")
                    continue
                if text.lower() == "assets":
                    _print_asset_rows(list_target_rows(session, target_obj.id), f"{target_obj.name}: assets")
                    continue
                if text.lower() == "services":
                    rows = [row for row in list_target_rows(session, target_obj.id) if row.service is not None]
                    _print_service_rows(rows[:limit], f"{target_obj.name}: services")
                    continue
                if text.lower() in {"apps", "components", "techs"}:
                    rows = list_target_apps(session, target_obj.id, limit=limit)
                    _print_app_summaries(rows, f"{target_obj.name}: apps")
                    continue
                if text.lower() == "groups":
                    rows = list_asset_groups(session, target_obj.id, limit=limit)
                    _print_group_views(rows, f"{target_obj.name}: asset groups")
                    continue
                if text.lower().startswith("group "):
                    group_id = _parse_group_id(text)
                    rows = list_group_assets(session, target_obj.id, group_id, limit=limit)
                    _print_search_rows(
                        [SearchRow(asset=row.asset, service=row.service) for row in rows],
                        f"{target_obj.name}: group {group_id}",
                    )
                    continue
                if text.lower() == "noise":
                    rows = list_noisy_assets(session, target_obj.id, limit=limit)
                    _print_classification_views(rows, f"{target_obj.name}: noisy assets")
                    continue
                if text.lower() == "outliers":
                    rows = list_outliers(session, target_obj.id, limit=limit)
                    _print_classification_views(rows, f"{target_obj.name}: outliers")
                    continue
                if text.lower() == "interesting":
                    rows = list_interesting_assets(session, target_obj.id, limit=limit)
                    _print_interesting_views(rows, f"{target_obj.name}: interesting")
                    continue
                if text.lower().startswith("why "):
                    service_id = _parse_numeric_arg(text, "why")
                    row = get_service_classification(session, target_obj.id, service_id)
                    if not row:
                        console.print(f"[yellow]service not found in target: {service_id}[/yellow]")
                        continue
                    evidence_rows = AssetEvidenceRepository(session).list_by_target(target_obj.id, limit=500)
                    evidence_rows = [
                        evidence for evidence in evidence_rows
                        if evidence.service_id == service_id or evidence.asset_id == row.asset.id
                    ]
                    _print_why_view(row, evidence_rows)
                    continue
                if text.lower().startswith("inspect "):
                    service_id = _parse_numeric_arg(text, "inspect")
                    row = get_service_classification(session, target_obj.id, service_id)
                    if not row:
                        console.print(f"[yellow]service not found in target: {service_id}[/yellow]")
                        continue
                    evidence_rows = AssetEvidenceRepository(session).list_by_target(target_obj.id, limit=500)
                    evidence_rows = [
                        evidence for evidence in evidence_rows
                        if evidence.service_id == service_id or evidence.asset_id == row.asset.id
                    ]
                    _print_why_view(row, evidence_rows)
                    continue
                if text.lower() == "sources":
                    counts = AssetEvidenceRepository(session).source_counts(target_obj.id)
                    _print_source_counts(counts, f"{target_obj.name}: evidence sources")
                    continue
                if text.lower() == "coverage":
                    counts = AssetEvidenceRepository(session).source_counts(target_obj.id)
                    _print_source_coverage(counts, f"{target_obj.name}: source coverage")
                    continue
                if text.lower() == "evidence":
                    rows = AssetEvidenceRepository(session).list_by_target(target_obj.id, limit=limit)
                    _print_evidence_rows(rows, f"{target_obj.name}: evidence")
                    continue
                if text.lower() == "clean":
                    rows = list_noisy_assets(session, target_obj.id, limit=limit)
                    _print_classification_views(rows, f"{target_obj.name}: cleanup candidates")
                    continue
                if text.lower().startswith("clean! "):
                    prune_expr = text[7:].strip()
                    if prune_expr.lower().startswith("group "):
                        group_id = _parse_numeric_arg(prune_expr, "group")
                        result = prune_group(session, target_obj.id, group_id)
                    else:
                        result = prune_query(session, target_obj.id, prune_expr)
                    classify_target_assets(session, target_obj.id)
                    console.print(
                        f"[yellow]Deleted services={result.services_deleted}, "
                        f"assets={result.assets_deleted}[/yellow]"
                    )
                    continue
                if text.lower().startswith("clean "):
                    prune_expr = text[6:].strip()
                    if prune_expr.lower().startswith("group "):
                        group_id = _parse_numeric_arg(prune_expr, "group")
                        preview = preview_prune_group(session, target_obj.id, group_id, limit=limit)
                    else:
                        preview = preview_prune(session, target_obj.id, prune_expr, limit=limit)
                    _print_prune_preview(preview, f"{target_obj.name}: cleanup preview")
                    continue
                if text.lower().startswith("drop! "):
                    prune_expr = text[6:].strip()
                    if prune_expr.lower().startswith("group "):
                        group_id = _parse_numeric_arg(prune_expr, "group")
                        result = prune_group(session, target_obj.id, group_id)
                        classify_target_assets(session, target_obj.id)
                        console.print(
                            f"[yellow]Deleted group={group_id} services={result.services_deleted}, "
                            f"assets={result.assets_deleted}[/yellow]"
                        )
                        continue
                    result = prune_query(session, target_obj.id, prune_expr)
                    classify_target_assets(session, target_obj.id)
                    console.print(
                        f"[yellow]Deleted services={result.services_deleted}, "
                        f"assets={result.assets_deleted}[/yellow]"
                    )
                    continue
                if text.lower().startswith("drop "):
                    prune_expr = text[5:].strip()
                    if prune_expr.lower().startswith("group "):
                        group_id = _parse_numeric_arg(prune_expr, "group")
                        preview = preview_prune_group(session, target_obj.id, group_id, limit=limit)
                        _print_prune_preview(preview, f"{target_obj.name}: drop group {group_id} preview")
                        continue
                    preview = preview_prune(session, target_obj.id, prune_expr, limit=limit)
                    _print_prune_preview(preview, f"{target_obj.name}: drop preview")
                    continue
                rows = search_target_assets(session, target_obj.id, text, limit=limit)
                _print_search_rows(rows, f'{target_obj.name}: {text or "*"}')
            except QuerySyntaxError as exc:
                console.print(f"[red]Query error:[/red] {exc}")
            except ValueError as exc:
                console.print(f"[red]Command error:[/red] {exc}")


@seed_app.command("add")
def seed_add(
    target: str = typer.Option(..., "--target", "-t", help="Target id or name."),
    host: str = typer.Argument(..., help="High-value host to feed back into Nexa."),
    note: str | None = typer.Option(None, "--note", "-n", help="Optional note."),
) -> None:
    """Add or update a manual asset seed."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        seed = AssetSeedRepository(session).upsert(target_obj.id, host, note=note)
    console.print(f"[green]Seed saved:[/green] {seed.host} (target={target_obj.name})")


@seed_app.command("list")
def seed_list(target: str = typer.Option(..., "--target", "-t", help="Target id or name.")) -> None:
    """List manual asset seeds."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        rows = AssetSeedRepository(session).list_by_target(target_obj.id)
    _print_seed_rows(rows, f"{target_obj.name}: seeds")


@seed_app.command("del")
def seed_delete(
    target: str = typer.Option(..., "--target", "-t", help="Target id or name."),
    host: str = typer.Argument(..., help="Seed host to delete."),
) -> None:
    """Delete a manual asset seed."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        deleted = AssetSeedRepository(session).delete(target_obj.id, host)
    if not deleted:
        raise typer.BadParameter(f"seed not found: {host}")
    console.print(f"[yellow]Seed deleted:[/yellow] {host}")


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
            use_passive_sources=False,
            use_expanders=False,
            continue_on_error=not strict,
        )
        noise_summary = classify_target_assets(session, target_obj.id)
    _print_recon_summary(summary)
    _print_recon_diff(summary)
    _print_source_coverage(summary.source_counts, f"Source Coverage: {target_obj.name}")
    _print_noise_summary(noise_summary, target_obj.name)


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
            status.update("[cyan]Classifying asset groups and noise...[/cyan]")
            noise_summary = classify_target_assets(session, target_obj.id)
    _print_recon_summary(summary)
    _print_recon_diff(summary)
    _print_source_coverage(summary.source_counts, f"Source Coverage: {target_obj.name}")
    _print_noise_summary(noise_summary, target_obj.name)


@app.command("classify", hidden=True)
def classify(
    target: str = typer.Option(..., help="Target id or name."),
) -> None:
    """Group assets and calculate noise classifications."""

    init_db()
    with create_session() as session:
        target_obj = _require_target_ref(session, target)
        summary = classify_target_assets(session, target_obj.id)
    _print_noise_summary(summary, target_obj.name)


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
