import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const PROVIDERS = ["fofa", "hunter_qianxin", "shodan", "zoomeye", "quake_360"];
const WORKSPACES = [
  { key: "overview", label: "总览", caption: "优先目标", views: [["interesting", "值得关注"]] },
  { key: "inventory", label: "资产", caption: "服务与来源", views: [["services", "HTTP 服务"], ["assets", "主机"], ["evidence", "来源证据"]] },
  { key: "technology", label: "技术", caption: "组件指纹", views: [["apps", "组件统计"]] },
  { key: "cleanup", label: "降噪", caption: "模板与异常", views: [["noise", "清理候选"], ["groups", "重复模板"], ["outliers", "组内异常"]] }
];
const PAGE_SIZE = 50;

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(payload?.detail || response.statusText);
  }
  return payload;
}

function App() {
  const [targets, setTargets] = useState([]);
  const [selected, setSelected] = useState(null);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");

  async function refresh() {
    const [targetRows, appSummary] = await Promise.all([api("/targets"), api("/summary")]);
    setTargets(targetRows);
    setSummary(appSummary);
    if (!selected && targetRows.length) setSelected(targetRows[0]);
    if (selected) {
      const fresh = targetRows.find((item) => item.id === selected.id);
      if (fresh) setSelected(fresh);
    }
  }

  useEffect(() => {
    refresh().catch((err) => setError(err.message));
  }, []);

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">N</span>
          <div>
            <h1>Nexa</h1>
            <p>授权 SRC / Bug bounty 前期资产情报工作台</p>
          </div>
        </div>
        <div className="meta">
          <span>{summary?.targets ?? 0} targets</span>
          <span>{summary?.config_path || "config/nexa.toml"}</span>
        </div>
      </header>

      {error && <div className="notice danger">{error}</div>}

      <div className="layout">
        <TargetPanel
          targets={targets}
          selected={selected}
          onSelect={setSelected}
          onRefresh={refresh}
          onError={setError}
        />
        <Workspace target={selected} onError={setError} onRefreshTargets={refresh} />
        <SidePanel target={selected} onError={setError} />
      </div>
    </main>
  );
}

function TargetPanel({ targets, selected, onSelect, onRefresh, onError }) {
  const [form, setForm] = useState({ name: "", program_name: "", scope_type: "in-scope" });

  async function saveTarget(event) {
    event.preventDefault();
    try {
      await api("/targets", { method: "POST", body: JSON.stringify(form) });
      setForm({ name: "", program_name: "", scope_type: "in-scope" });
      await onRefresh();
    } catch (err) {
      onError(err.message);
    }
  }

  async function removeTarget(target) {
    if (!window.confirm(`删除目标 ${target.name} 及其资产？`)) return;
    try {
      await api(`/targets/${target.id}`, { method: "DELETE" });
      await onRefresh();
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <section className="panel target-panel">
      <div className="section-title">
        <h2>Targets</h2>
        <button onClick={onRefresh}>刷新</button>
      </div>
      <form className="target-form" onSubmit={saveTarget}>
        <input
          value={form.name}
          onChange={(event) => setForm({ ...form, name: event.target.value })}
          placeholder="jd.com"
          required
        />
        <input
          value={form.program_name}
          onChange={(event) => setForm({ ...form, program_name: event.target.value })}
          placeholder="Program"
        />
        <button type="submit">添加</button>
      </form>
      <div className="target-list">
        {targets.map((target) => (
          <button
            key={target.id}
            className={selected?.id === target.id ? "target active" : "target"}
            onClick={() => onSelect(target)}
          >
            <span>{target.name}</span>
            <small>#{target.id} {target.program_name || "no program"}</small>
            <i onClick={(event) => { event.stopPropagation(); removeTarget(target); }}>删除</i>
          </button>
        ))}
      </div>
    </section>
  );
}

function Workspace({ target, onError, onRefreshTargets }) {
  const [view, setView] = useState("interesting");
  const [query, setQuery] = useState("*");
  const [rows, setRows] = useState([]);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [job, setJob] = useState(null);
  const [dropQuery, setDropQuery] = useState("");
  const [dropPreview, setDropPreview] = useState(null);
  const [whyPanel, setWhyPanel] = useState(null);
  const [groupPreview, setGroupPreview] = useState(null);
  const activeWorkspace = WORKSPACES.find((item) => item.views.some(([key]) => key === view)) || WORKSPACES[0];

  useEffect(() => {
    if (target) loadView(view, page).catch((err) => onError(err.message));
  }, [target?.id, view, page]);

  useEffect(() => {
    if (!job || ["completed", "failed"].includes(job.status)) return undefined;
    const timer = setInterval(async () => {
      try {
        const updated = await api(`/jobs/${job.id}`);
        setJob(updated);
        if (updated.status === "completed") {
          await onRefreshTargets();
          await loadView(view, page);
        }
      } catch (err) {
        onError(err.message);
      }
    }, 1500);
    return () => clearInterval(timer);
  }, [job?.id, job?.status, view]);

  function switchView(nextView) {
    setView(nextView);
    setPage(0);
    setWhyPanel(null);
    setGroupPreview(null);
  }

  async function loadView(nextView, nextPage = page) {
    if (!target) return;
    setLoading(true);
    try {
      const offset = nextPage * PAGE_SIZE;
      const path = nextView === "search"
        ? `/targets/${target.id}/search?q=${encodeURIComponent(query)}`
        : `/targets/${target.id}/${nextView}`;
      const data = await api(`${path}${path.includes("?") ? "&" : "?"}limit=${PAGE_SIZE}&offset=${offset}`);
      setRows(Array.isArray(data) ? data : []);
    } finally {
      setLoading(false);
    }
  }

  async function runSearch(event) {
    event.preventDefault();
    setView("search");
    setPage(0);
    await loadView("search", 0);
  }

  async function startScan() {
    if (!target) return;
    const created = await api(`/targets/${target.id}/scan`, {
      method: "POST",
      body: JSON.stringify({})
    });
    setJob(created);
  }

  async function previewDrop(event) {
    event.preventDefault();
    const preview = await api(`/targets/${target.id}/drop`, {
      method: "POST",
      body: JSON.stringify({ query: dropQuery, execute: false, limit: 20 })
    });
    setDropPreview(preview);
  }

  async function executeDrop() {
    if (!dropPreview || !window.confirm(`确认删除 ${dropPreview.service_count} 个服务？`)) return;
    await api(`/targets/${target.id}/drop`, {
      method: "POST",
      body: JSON.stringify({ query: dropQuery, execute: true })
    });
    setDropPreview(null);
    await loadView(view, page);
  }

  async function showWhy(row) {
    const serviceId = row.service?.id;
    if (!serviceId) return;
    try {
      setGroupPreview(null);
      setWhyPanel(await api(`/targets/${target.id}/services/${serviceId}/why`));
    } catch (err) {
      onError(err.message);
    }
  }

  async function previewDeleteGroup(groupId) {
    try {
      const preview = await api(`/targets/${target.id}/drop-group`, {
        method: "POST",
        body: JSON.stringify({ group_id: groupId, execute: false, limit: 20 })
      });
      setGroupPreview(preview);
    } catch (err) {
      onError(err.message);
    }
  }

  async function deletePreviewedGroup() {
    const groupId = whyPanel?.classification?.classification?.group_id;
    if (!groupId || !groupPreview) return;
    if (!window.confirm(`确认删除同组噪声资产？services=${groupPreview.service_count}, assets=${groupPreview.asset_count}`)) return;
    try {
      await api(`/targets/${target.id}/drop-group`, {
        method: "POST",
        body: JSON.stringify({ group_id: groupId, execute: true })
      });
      setWhyPanel(null);
      setGroupPreview(null);
      await loadView(view, page);
    } catch (err) {
      onError(err.message);
    }
  }

  if (!target) {
    return <section className="panel empty">先添加或选择一个 target。</section>;
  }

  return (
    <section className="panel workspace">
      <div className="section-title workspace-heading">
        <div>
          <span className="eyebrow">CURRENT TARGET</span>
          <h2>{target.name}</h2>
          <p>#{target.id} · {target.root_domain} · {target.program_name || "独立目标"}</p>
        </div>
        <button className="primary" onClick={startScan}>开始扫描</button>
      </div>

      <nav className="workspace-nav" aria-label="目标工作区">
        {WORKSPACES.map((item) => (
          <button
            key={item.key}
            className={activeWorkspace.key === item.key ? "active" : ""}
            onClick={() => switchView(item.views[0][0])}
          >
            <strong>{item.label}</strong>
            <span>{item.caption}</span>
          </button>
        ))}
      </nav>

      <form className="querybar" onSubmit={runSearch}>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder='app="Vue.js" && status=200' />
        <button type="submit">查询</button>
      </form>

      {activeWorkspace.views.length > 1 && <div className="tabs secondary-tabs">
        {activeWorkspace.views.map(([key, label]) => (
          <button key={key} className={view === key ? "active" : ""} onClick={() => switchView(key)}>
            {label}
          </button>
        ))}
      </div>}

      <ResultTable view={view} rows={rows} loading={loading} onAction={showWhy} />

      <Pagination
        page={page}
        count={rows.length}
        onPrev={() => setPage(Math.max(0, page - 1))}
        onNext={() => setPage(page + 1)}
      />

      {whyPanel && (
        <WhyPanel
          data={whyPanel}
          groupPreview={groupPreview}
          onClose={() => { setWhyPanel(null); setGroupPreview(null); }}
          onPreviewGroup={previewDeleteGroup}
          onDeleteGroup={deletePreviewedGroup}
        />
      )}

      <form className="dropbar" onSubmit={previewDrop}>
        <input value={dropQuery} onChange={(event) => setDropQuery(event.target.value)} placeholder='title="旗舰店 - 京东"' />
        <button type="submit">预览泛删除</button>
        {dropPreview && <button type="button" className="danger-button" onClick={executeDrop}>确认删除</button>}
      </form>
      {dropPreview && (
        <p className="hint">命中 services={dropPreview.service_count}, assets={dropPreview.asset_count}</p>
      )}

      {job && <JobPanel job={job} />}
    </section>
  );
}

function ResultTable({ view, rows, loading, onAction }) {
  const columns = useMemo(() => columnsFor(view, onAction), [view, onAction]);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {loading && <tr><td colSpan={columns.length}>加载中...</td></tr>}
          {!loading && rows.length === 0 && <tr><td colSpan={columns.length}>暂无数据</td></tr>}
          {!loading && rows.map((row, index) => (
            <tr key={`${view}-${index}`}>
              {columns.map((column) => <td key={column.key}>{column.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function columnsFor(view, onAction) {
  if (view === "assets") {
    return [
      col("id", "ID", (row) => row.asset?.id),
      col("host", "Host", (row) => row.asset?.host),
      col("ip", "IP", (row) => row.asset?.ip || "-"),
      col("source", "Source", (row) => row.asset?.source),
      col("alive", "Alive", (row) => row.asset?.is_alive ? "yes" : "no")
    ];
  }
  if (view === "apps") {
    return [
      col("name", "App", (row) => row.name),
      col("services", "Services", (row) => row.service_count),
      col("assets", "Assets", (row) => row.asset_count),
      col("samples", "Samples", (row) => (row.sample_hosts || []).join(", "))
    ];
  }
  if (view === "groups") {
    return [
      col("id", "Group", (row) => row.group?.id),
      col("count", "Count", (row) => row.group?.count),
      col("level", "噪声等级", (row) => noiseLevelZh(row.group?.noise_level)),
      col("sample", "Sample", (row) => linkUrl(row.service?.url) || row.asset?.host || "-"),
      col("template", "Template", (row) => `${row.group?.status_code || "-"} · ${row.group?.title || "(empty)"}`),
      col("reasons", "判定原因", (row) => (row.group?.reasons || []).map(reasonZh).join("；"))
    ];
  }
  if (["interesting", "noise", "outliers"].includes(view)) {
    const baseColumns = [
      col("service", "Service", (row) => linkUrl(row.service?.url) || row.asset?.host),
      col("status", "Status", (row) => row.service?.status_code || "-"),
      col("title", "Title", (row) => row.service?.title || "-"),
      col("category", "分类", (row) => categoryZh(row.classification?.category)),
      col("score", "价值 / 噪声", (row) => `${row.classification?.discovery_value}/${row.classification?.noise_score}`),
      col("why", "判断依据", (row) => (row.classification?.reasons || []).slice(0, 3).map(reasonZh).join("；"))
    ];
    if (view === "noise") {
      baseColumns.push(col("actions", "操作", (row) => (
        <button className="text-button" onClick={() => onAction(row)}>查看原因与清理</button>
      )));
    }
    return baseColumns;
  }
  if (view === "evidence") {
    return [
      col("source", "Source", (row) => row.provider ? `${row.source}:${row.provider}` : row.source),
      col("host", "Host", (row) => row.raw_host || "-"),
      col("url", "URL", (row) => linkUrl(row.raw_url) || "-"),
      col("confidence", "Conf", (row) => row.confidence),
      col("title", "Title", (row) => row.title || "-")
    ];
  }
  return [
    col("url", "URL", (row) => linkUrl(row.service?.url) || row.asset?.host),
    col("status", "Status", (row) => row.service?.status_code || "-"),
    col("title", "Title", (row) => row.service?.title || "-"),
    col("server", "Server", (row) => row.service?.server || "-"),
    col("tech", "App/Tech", (row) => (row.service?.technologies || []).join(", ")),
    col("ip", "IP", (row) => row.asset?.ip || "-")
  ];
}

function col(key, label, render) {
  return { key, label, render };
}

function linkUrl(value) {
  if (!value) return "";
  const text = String(value);
  if (!/^https?:\/\//i.test(text)) return text;
  return <a className="url-link" href={text} target="_blank" rel="noreferrer">{text}</a>;
}

function noiseLevelZh(value) {
  return ({ high: "高", medium: "中", low: "低" })[value] || value || "-";
}

function categoryZh(value) {
  return ({
    "shop-template": "店铺模板", docs: "接口文档", admin: "管理后台", auth: "认证入口",
    api: "API 服务", redirect: "重定向", error: "错误页", normal: "普通服务"
  })[value] || value || "-";
}

function reasonZh(reason) {
  const exact = {
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
    "high-value-looking asset inside a large template group": "大型模板组中出现疑似高价值异常资产"
  };
  if (exact[reason]) return exact[reason];
  const prefixes = [
    ["large repeated group count=", "大规模重复资产组，服务数："],
    ["repeated group count=", "重复资产组，服务数："],
    ["common low-signal status=", "低信息量 HTTP 状态码："],
    ["high-value hostname keywords: ", "主机名包含高价值关键词："],
    ["category=", "识别分类："]
  ];
  const match = prefixes.find(([prefix]) => String(reason).startsWith(prefix));
  return match ? match[1] + String(reason).slice(match[0].length) : reason;
}

function Pagination({ page, count, onPrev, onNext }) {
  return (
    <div className="pagination">
      <span>第 {page + 1} 页 · 本页 {count} 条</span>
      <div>
        <button disabled={page === 0} onClick={onPrev}>上一页</button>
        <button disabled={count < PAGE_SIZE} onClick={onNext}>下一页</button>
      </div>
    </div>
  );
}

function WhyPanel({ data, groupPreview, onClose, onPreviewGroup, onDeleteGroup }) {
  const row = data.classification;
  const classification = row?.classification || {};
  const service = row?.service || {};
  const asset = row?.asset || {};
  const groupId = classification.group_id;
  return (
    <div className="why-panel">
      <div className="section-title">
        <div>
          <h2>分类说明</h2>
          <p>{service.url || asset.host}</p>
        </div>
        <button onClick={onClose}>关闭</button>
      </div>
      <div className="why-grid">
        <span>资产分类</span><b>{categoryZh(classification.category)}</b>
        <span>价值 / 噪声</span><b>{classification.discovery_value}/{classification.noise_score}</b>
        <span>模板组</span><b>{groupId || "-"}</b>
      </div>
      <div className="why-reasons">
        {(classification.reasons || []).map((reason, index) => <p key={index}>{reasonZh(reason)}</p>)}
      </div>
      {groupId && (
        <div className="danger-zone">
          <button className="danger-button" onClick={() => onPreviewGroup(groupId)}>预览删除同组噪声</button>
          {groupPreview && (
            <>
              <span>命中 services={groupPreview.service_count}, assets={groupPreview.asset_count}</span>
              <button className="danger-button" onClick={onDeleteGroup}>确认删除同组</button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function JobPanel({ job }) {
  return (
    <div className="job">
      <strong>扫描任务：{job.status}</strong>
      <div className="job-log">
        {(job.progress || []).slice(-12).map((line, index) => <p key={index}>{line}</p>)}
      </div>
      {job.result && (
        <div className="job-result">
          assets={job.result.assets_seen} services={job.result.services_seen} alive={job.result.alive_assets}
        </div>
      )}
      {job.error && <div className="notice danger">{job.error}</div>}
    </div>
  );
}

function SidePanel({ target, onError }) {
  return (
    <aside className="side">
      <OnlinePanel target={target} onError={onError} />
      <ProviderPanel onError={onError} />
    </aside>
  );
}

function OnlinePanel({ target, onError }) {
  const [query, setQuery] = useState(target ? `domain.suffix="${target.root_domain}"` : 'domain.suffix="example.com"');
  const [provider, setProvider] = useState("hunter_qianxin");
  const [translations, setTranslations] = useState({});
  const [results, setResults] = useState([]);

  useEffect(() => {
    if (target) setQuery(`domain.suffix="${target.root_domain}"`);
  }, [target?.id]);

  async function translate() {
    try {
      setTranslations(await api("/providers/translate", {
        method: "POST",
        body: JSON.stringify({ query, providers: PROVIDERS })
      }));
    } catch (err) {
      onError(err.message);
    }
  }

  async function search(event) {
    event.preventDefault();
    try {
      const data = await api("/online-search", {
        method: "POST",
        body: JSON.stringify({ query, provider, limit: 30 })
      });
      setResults(data.results || []);
      setTranslations({});
      if (data.errors?.length) onError(data.errors.join("; "));
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <section className="panel">
      <div className="section-title">
        <h2>Online Search</h2>
        <button onClick={translate}>转换</button>
      </div>
      <form className="stack" onSubmit={search}>
        <select value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="all">all enabled</option>
          {PROVIDERS.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
        <input value={query} onChange={(event) => setQuery(event.target.value)} />
        <button type="submit">查询</button>
      </form>
      {Object.keys(translations).length > 0 && (
        <div className="translation">
          {Object.entries(translations).map(([name, value]) => <p key={name}><b>{name}</b>: {value}</p>)}
        </div>
      )}
      <div className="mini-list">
        {results.slice(0, 8).map((row, index) => (
          <p key={index}><b>{row.provider}</b> {row.url || row.host} <span>{row.title}</span></p>
        ))}
      </div>
    </section>
  );
}

function ProviderPanel({ onError }) {
  const [providers, setProviders] = useState([]);
  const [editing, setEditing] = useState(null);

  async function load() {
    setProviders(await api("/config/providers"));
  }

  useEffect(() => {
    load().catch((err) => onError(err.message));
  }, []);

  async function saveProvider(event) {
    event.preventDefault();
    try {
      const payload = { ...editing };
      if (!payload.api_key) delete payload.api_key;
      await api(`/config/providers/${editing.name}`, {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      setEditing(null);
      await load();
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <section className="panel">
      <div className="section-title">
        <h2>Providers</h2>
        <button onClick={load}>刷新</button>
      </div>
      <div className="provider-list">
        {providers.map((item) => (
          <button key={item.name} onClick={() => setEditing({ ...item, api_key: "" })}>
            <span>{item.name}</span>
            <small>{item.enabled ? "enabled" : "disabled"} · key {item.api_key_set ? "set" : "empty"}</small>
          </button>
        ))}
      </div>
      {editing && (
        <form className="provider-form" onSubmit={saveProvider}>
          <label><input type="checkbox" checked={Boolean(editing.enabled)} onChange={(event) => setEditing({ ...editing, enabled: event.target.checked })} /> enabled</label>
          <input value={editing.email || ""} onChange={(event) => setEditing({ ...editing, email: event.target.value })} placeholder="email (FOFA)" />
          <input value={editing.api_key || ""} onChange={(event) => setEditing({ ...editing, api_key: event.target.value })} placeholder="new api key" />
          <input value={editing.base_url || ""} onChange={(event) => setEditing({ ...editing, base_url: event.target.value })} placeholder="base url" />
          <button type="submit">保存 {editing.name}</button>
        </form>
      )}
    </section>
  );
}

createRoot(document.getElementById("root")).render(<App />);
