/* smbgui full frontend */
const state = {
  host: null,
  port: 445,
  share: null,
  path: "",
  username: "",
  password: "",
  domain: "",
  hash: null,
  guest: false,
  use_kerberos: false,
  aes_key: "",
  kdc_host: "",
  dc_ip: "",
  ccache: "",
  cred_fp: null,
  session_id: null,
  sid: null, // opaque UI session — secrets stay server-side after connect
  selected: [], // multi-select [{name,is_dir,size}]
  entries: [],
  sortCol: "name",
  sortAsc: true,
  filter: "",
  sessions: {}, // session_id -> auth snapshot
};

let ws = null;

/** GET query params — never put passwords/hashes/aes keys in the URL. */
function authParams() {
  const p = new URLSearchParams();
  p.set("port", String(state.port || 445));
  if (state.sid) p.set("sid", state.sid);
  // Cookie smbgui_sid is sent automatically with credentials: 'include'
  return p;
}

/** POST JSON body — prefer sid after connect; include secrets only when needed. */
function authBody() {
  const body = {
    port: state.port || 445,
  };
  if (state.sid) {
    body.sid = state.sid;
    return body;
  }
  return {
    ...body,
    username: state.username || "",
    password: state.password || "",
    domain: state.domain || "",
    hash: state.hash || null,
    guest: !!state.guest,
    use_kerberos: !!state.use_kerberos,
    aes_key: state.aes_key || "",
    kdc_host: state.kdc_host || "",
    dc_ip: state.dc_ip || "",
    ccache: state.ccache || "",
  };
}

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "include", ...opts });
  const ctype = res.headers.get("content-type") || "";
  if (ctype.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error?.message || res.statusText);
    return data;
  }
  if (!res.ok) throw new Error(res.statusText);
  return res;
}

function setStatus(msg, right = "") {
  document.getElementById("statusLeft").textContent = msg;
  document.getElementById("statusRight").textContent = right;
}

function fmtSize(n) {
  if (n == null || n === "") return "";
  n = Number(n);
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

function fmtTime(epoch) {
  if (!epoch) return "";
  try { return new Date(epoch * 1000).toLocaleString(); } catch { return ""; }
}

function escapeHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function promptModal(title, initial = "") {
  return new Promise((resolve) => {
    const bg = document.getElementById("modal");
    const input = document.getElementById("modalInput");
    document.getElementById("modalTitle").textContent = title;
    input.value = initial;
    bg.classList.add("show");
    input.focus();
    const ok = () => { cleanup(); resolve(input.value); };
    const cancel = () => { cleanup(); resolve(null); };
    function cleanup() {
      bg.classList.remove("show");
      document.getElementById("modalOk").onclick = null;
      document.getElementById("modalCancel").onclick = null;
    }
    document.getElementById("modalOk").onclick = ok;
    document.getElementById("modalCancel").onclick = cancel;
    input.onkeydown = (e) => {
      if (e.key === "Enter") ok();
      if (e.key === "Escape") cancel();
    };
  });
}

function connectWs() {
  if (ws && ws.readyState <= 1) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/progress`);
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === "progress") showProgress(msg);
    } catch (_) {}
  };
  ws.onclose = () => setTimeout(connectWs, 2000);
}

function showProgress(msg) {
  const wrap = document.getElementById("progressWrap");
  wrap.classList.remove("hidden");
  const pct = msg.percent || 0;
  document.getElementById("progressFill").style.width = `${pct}%`;
  document.getElementById("progressLabel").textContent =
    `${msg.action} ${msg.path || ""} ${pct}% ${msg.message || ""} ${msg.status || ""}`;
  if (msg.status === "done" || msg.status === "error") {
    setTimeout(() => wrap.classList.add("hidden"), 2500);
  }
}

async function refreshLog() {
  try {
    const data = await api("/api/log?limit=80");
    document.getElementById("log").innerHTML = data.entries.map((e) => {
      const t = new Date(e.ts * 1000).toLocaleTimeString();
      return `<div class="log-entry ${e.ok ? "" : "bad"}"><span class="ts">${t}</span> [${e.source}] ${escapeHtml(e.action)} ${escapeHtml(e.host||"")} ${escapeHtml(e.detail||"")}${e.error?" — "+escapeHtml(e.error):""}</div>`;
    }).join("");
  } catch (_) {}
}

function updateAddressBar() {
  if (!state.host) { document.getElementById("addressBar").value = ""; return; }
  const p = state.path ? `\\${state.path.replace(/\//g, "\\")}` : "";
  document.getElementById("addressBar").value = `\\\\${state.host}\\${state.share || ""}${p}`;
}

function renderHostSwitcher() {
  const sel = document.getElementById("hostSwitcher");
  const ids = Object.keys(state.sessions);
  sel.innerHTML = ids.length
    ? ids.map((id) => {
        const s = state.sessions[id];
        const label = `${s.display_user || s.username}@${s.host}:${s.port}`;
        return `<option value="${id}" ${id === state.session_id ? "selected" : ""}>${escapeHtml(label)}</option>`;
      }).join("")
    : `<option value="">no sessions</option>`;
}

function renderShares(shares) {
  const el = document.getElementById("shares");
  state._shares = shares || [];
  el.innerHTML = (shares || []).map((s) => {
    const badges = [];
    if (s.is_admin) badges.push('<span class="badge admin">admin</span>');
    else if (s.is_hidden) badges.push('<span class="badge admin">hidden</span>');
    if (s.is_ipc) badges.push('<span class="badge ipc">IPC</span>');
    if (s.drive_letter) badges.push(`<span class="badge">${s.drive_letter}:</span>`);
    const nb = s.browsable === false ? "nonbrowse" : "";
    return `<div class="share-item ${state.share === s.name ? "active" : ""} ${nb}" data-share="${escapeHtml(s.name)}" data-browsable="${s.browsable === false ? 0 : 1}">${escapeHtml(s.name)} ${badges.join(" ")}${s.remark ? ` <span class="meta">— ${escapeHtml(s.remark)}</span>` : ""}</div>`;
  }).join("");
  el.querySelectorAll(".share-item").forEach((node) => {
    node.onclick = () => {
      const name = node.getAttribute("data-share");
      const browsable = node.getAttribute("data-browsable") !== "0";
      if (!browsable) {
        setStatus(`${name} is not a filesystem share (IPC$ = named pipes only)`);
        return;
      }
      state.share = name;
      state.path = "";
      state.selected = [];
      renderShares(shares);
      listPath("");
    };
  });
}

function sortedFilteredEntries() {
  let ents = [...state.entries];
  const f = (state.filter || "").toLowerCase();
  if (f) ents = ents.filter((e) => e.name.toLowerCase().includes(f));
  const col = state.sortCol;
  ents.sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    let av = a[col], bv = b[col];
    if (col === "name") { av = (av || "").toLowerCase(); bv = (bv || "").toLowerCase(); }
    if (av < bv) return state.sortAsc ? -1 : 1;
    if (av > bv) return state.sortAsc ? 1 : -1;
    return 0;
  });
  return ents;
}

function isSelected(name) {
  return state.selected.some((s) => s.name === name);
}

function renderFiles(entries, meta = {}) {
  state.entries = entries || state.entries;
  const tbody = document.getElementById("files");
  document.getElementById("searchResults").classList.add("hidden");
  document.querySelector("table.files").classList.remove("hidden");
  const rows = [];
  if (state.path) {
    rows.push(`<tr data-up="1"><td></td><td class="name-cell dir">..</td><td></td><td></td><td></td></tr>`);
  }
  for (const e of sortedFilteredEntries()) {
    const cls = e.is_dir ? "dir" : "";
    const sel = isSelected(e.name) ? "selected" : "";
    const attrs = e.attributes ? `0x${Number(e.attributes).toString(16)}` : "";
    rows.push(`<tr class="${sel}" data-name="${encodeURIComponent(e.name)}" data-dir="${e.is_dir?1:0}" data-size="${e.size||0}">
      <td><input type="checkbox" class="rowchk" ${isSelected(e.name)?"checked":""} /></td>
      <td class="name-cell ${cls}">${e.is_dir ? "📁 " : "📄 "}${escapeHtml(e.name)}</td>
      <td>${e.is_dir ? "" : fmtSize(e.size)}</td>
      <td>${fmtTime(e.mtime)}</td>
      <td class="meta">${attrs}</td>
    </tr>`);
  }
  tbody.innerHTML = rows.join("");

  tbody.querySelectorAll("tr").forEach((tr) => {
    const chk = tr.querySelector(".rowchk");
    if (chk) {
      chk.onclick = (ev) => {
        ev.stopPropagation();
        const name = decodeURIComponent(tr.getAttribute("data-name"));
        const is_dir = tr.getAttribute("data-dir") === "1";
        const size = Number(tr.getAttribute("data-size") || 0);
        if (chk.checked) {
          if (!isSelected(name)) state.selected.push({ name, is_dir, size });
        } else {
          state.selected = state.selected.filter((s) => s.name !== name);
        }
        tr.classList.toggle("selected", chk.checked);
      };
    }
    tr.onclick = (ev) => {
      if (ev.target.classList.contains("rowchk")) return;
      if (tr.getAttribute("data-up")) {
        const parts = state.path.split("/").filter(Boolean);
        parts.pop();
        listPath(parts.join("/"));
        return;
      }
      const name = decodeURIComponent(tr.getAttribute("data-name"));
      const is_dir = tr.getAttribute("data-dir") === "1";
      const size = Number(tr.getAttribute("data-size") || 0);
      if (ev.ctrlKey || ev.metaKey) {
        if (isSelected(name)) state.selected = state.selected.filter((s) => s.name !== name);
        else state.selected.push({ name, is_dir, size });
        renderFiles(state.entries, meta);
        return;
      }
      state.selected = [{ name, is_dir, size }];
      renderFiles(state.entries, meta);
      if (is_dir) {
        const next = state.path ? `${state.path}/${name}` : name;
        listPath(next);
      } else {
        previewFile(name);
      }
    };
    tr.ondblclick = () => {
      if (tr.getAttribute("data-up")) return;
      const name = decodeURIComponent(tr.getAttribute("data-name"));
      const is_dir = tr.getAttribute("data-dir") === "1";
      if (is_dir) {
        const next = state.path ? `${state.path}/${name}` : name;
        listPath(next);
      } else downloadSelected();
    };
  });

  const badges = [];
  if (meta.from_cache) badges.push(`<span class="badge cache">cache</span>`);
  else if (meta.refreshed_at || meta.fetched_at) badges.push(`<span class="badge wire">wire</span>`);
  if (meta.stale) badges.push(`<span class="badge stale">stale</span>`);
  document.getElementById("badges").innerHTML = badges.join(" ");
  document.getElementById("listMeta").textContent = meta.refreshed_at ? `refreshed at ${meta.refreshed_at}` : "";
  updateAddressBar();
}

async function loadBookmarks() {
  try {
    const data = await api("/api/bookmarks");
    document.getElementById("bookmarks").innerHTML = (data.bookmarks || []).map((b) =>
      `<div class="bm-item" data-id="${b.id}" title="${escapeHtml(b.notes||"")}">★ ${escapeHtml(b.label)}
        <button data-del="${b.id}" class="ghost" style="float:right;padding:0 4px">✕</button></div>`
    ).join("") || `<span class="meta">none</span>`;
    document.getElementById("bookmarks").querySelectorAll(".bm-item").forEach((node) => {
      node.onclick = async (ev) => {
        if (ev.target.getAttribute("data-del")) {
          await api(`/api/bookmarks/${ev.target.getAttribute("data-del")}`, { method: "DELETE" });
          loadBookmarks();
          return;
        }
        const id = node.getAttribute("data-id");
        const bm = data.bookmarks.find((x) => x.id === id);
        if (!bm) return;
        // navigate if same host connected
        if (state.host === bm.host) {
          state.share = bm.share;
          listPath(bm.path || "");
        } else {
          document.getElementById("connStr").value =
            `${bm.domain ? bm.domain + "\\" : ""}${bm.username || "user"}@${bm.host}:${bm.port || 445}`;
          setStatus(`bookmark loaded — fill password and Connect: ${bm.label}`);
        }
      };
    });
    document.getElementById("recent").innerHTML = (data.recent || []).map((r) =>
      `<div class="bm-item" data-recent="1">${escapeHtml(r.label || r.host)}</div>`
    ).join("") || `<span class="meta">none</span>`;
    document.getElementById("recent").querySelectorAll(".bm-item").forEach((node, i) => {
      node.onclick = () => {
        const r = data.recent[i];
        document.getElementById("connStr").value =
          `${r.domain ? r.domain + "\\" : ""}${r.username}@${r.host}:${r.port}`;
        if (r.auth_mode === "kerberos") document.getElementById("useKerb").checked = true;
      };
    });
  } catch (_) {}
}

async function connect(ev) {
  ev?.preventDefault();
  const conn = document.getElementById("connStr").value.trim();
  const hash = document.getElementById("hash").value.trim() || null;
  const guest = document.getElementById("guest").checked;
  const use_kerberos = document.getElementById("useKerb").checked;
  const aes_key = document.getElementById("aesKey").value.trim();
  const kdc_host = document.getElementById("kdcHost").value.trim();
  const dc_ip = document.getElementById("dcIp").value.trim();
  const ccache = document.getElementById("ccache").value.trim();
  if (!conn && !guest) { setStatus("connection string required"); return; }
  setStatus("connecting…");
  try {
    const body = {
      connection: conn || undefined,
      hash, guest, use_kerberos, aes_key, kdc_host, dc_ip, ccache,
    };
    const data = await api("/api/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    state.host = data.host;
    state.port = data.port;
    state.cred_fp = data.cred_fp;
    state.session_id = data.session_id;
    state.sid = data.sid || null;
    state.guest = !!data.guest;
    state.hash = hash;
    state.use_kerberos = !!data.use_kerberos;
    state.aes_key = aes_key;
    state.kdc_host = kdc_host;
    state.dc_ip = dc_ip;
    state.ccache = ccache;
    const m = (conn || "").match(/^(?:([^\\/@]+)\\)?([^:@]+)(?::(.*))?@(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/);
    if (m) {
      state.domain = m[1] || "";
      state.username = m[2] || "";
      state.password = hash || use_kerberos ? (m[3] || "") : (m[3] || "");
      if (hash && !use_kerberos) state.password = "";
    }
    if (guest) { state.username = "Guest"; state.password = ""; state.hash = null; }
    state.sessions[data.session_id] = {
      host: data.host,
      port: data.port,
      sid: data.sid,
      display_user: data.user,
      cred_fp: data.cred_fp,
      session_id: data.session_id,
    };
    renderHostSwitcher();
    renderShares(data.shares || []);
    state.share = ((data.shares || []).find((s) => s.browsable !== false) || (data.shares || [])[0] || {}).name || null;
    state.path = "";
    setStatus(`connected as ${data.user} @ ${data.host}:${data.port} [${data.auth_mode}]`, `cached: ${data.cached_listings}`);
    if (state.share) await listPath("", true);
    await refreshLog();
    await loadBookmarks();
  } catch (e) {
    setStatus("connect failed: " + e.message);
  }
}

function switchSession() {
  const id = document.getElementById("hostSwitcher").value;
  const s = state.sessions[id];
  if (!s) return;
  Object.assign(state, {
    host: s.host, port: s.port, username: s.username || "", password: s.password || "",
    domain: s.domain || "", hash: s.hash || null, guest: !!s.guest, use_kerberos: !!s.use_kerberos,
    aes_key: s.aes_key || "", kdc_host: s.kdc_host || "", dc_ip: s.dc_ip || "", ccache: s.ccache || "",
    cred_fp: s.cred_fp, session_id: s.session_id, sid: s.sid || null, share: null, path: "", selected: [],
  });
  // reload shares
  api(`/api/shares?${authParams().toString()}&host=${encodeURIComponent(state.host)}`).then((data) => {
    renderShares(data.shares || []);
    if (data.shares?.[0]) { state.share = data.shares[0].name; listPath(""); }
  }).catch((e) => setStatus(e.message));
}

async function listPath(path, useCache = true) {
  if (!state.host || !state.share) return;
  state.path = path || "";
  state.selected = [];
  setStatus(`listing ${state.share}/${state.path}…`);
  try {
    const p = authParams();
    p.set("host", state.host);
    p.set("share", state.share);
    p.set("path", state.path);
    p.set("use_cache", useCache ? "true" : "false");
    const data = await api(`/api/list?${p.toString()}`);
    renderFiles(data.entries || [], data);
    setStatus(`listed ${state.share}/${state.path}`, `${data.from_cache ? "cache" : "wire"}${data.stale ? " stale" : ""}`);
    await refreshLog();
  } catch (e) {
    setStatus("list failed: " + e.message);
  }
}

async function doRefresh({ all = false, recursive = false } = {}) {
  if (!state.host) return;
  setStatus(recursive ? "recursive refresh…" : all ? "refresh all…" : "refresh…");
  try {
    const body = { host: state.host, share: state.share, path: state.path, all, recursive, max_depth: 8, max_dirs: 2000, ...authBody() };
    const data = await api("/api/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (data.job_id && ws && ws.readyState === 1) ws.send(JSON.stringify({ subscribe: data.job_id }));
    if (all && data.shares) renderShares(data.shares);
    if (data.entries) renderFiles(data.entries, data);
    else await listPath(state.path, false);
    setStatus(recursive ? `recursive refresh dirs=${data.dirs_refreshed}` : "refreshed", data.refreshed_at || "");
    await refreshLog();
  } catch (e) {
    setStatus("refresh failed: " + e.message);
  }
}

async function previewFile(name) {
  const path = state.path ? `${state.path}/${name}` : name;
  const p = authParams();
  p.set("host", state.host); p.set("share", state.share); p.set("path", path); p.set("preview", "true");
  const el = document.getElementById("preview");
  el.innerHTML = `<span class="meta">loading…</span>`;
  try {
    const res = await fetch(`/api/file?${p.toString()}`);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data?.error?.message || res.statusText);
    }
    const ctype = res.headers.get("content-type") || "";
    const buf = await res.arrayBuffer();
    if (ctype.startsWith("image/")) {
      const url = URL.createObjectURL(new Blob([buf], { type: ctype }));
      el.innerHTML = `<img src="${url}" alt="${escapeHtml(name)}" />`;
    } else {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(buf);
      const looksBinary = /[\x00-\x08]/.test(text.slice(0, 200));
      el.innerHTML = looksBinary
        ? `<span class="meta">${escapeHtml(name)} · ${fmtSize(buf.byteLength)} · binary</span>`
        : `<pre>${escapeHtml(text)}</pre>`;
    }
    await refreshLog();
  } catch (e) {
    el.innerHTML = `<span class="meta">preview failed: ${escapeHtml(e.message)}</span>`;
  }
}

function selectedPaths() {
  return state.selected.map((s) => ({
    path: state.path ? `${state.path}/${s.name}` : s.name,
    is_dir: s.is_dir,
  }));
}

async function downloadSelected() {
  if (!state.selected.length) return;
  if (state.selected.length === 1 && !state.selected[0].is_dir) {
    const path = state.path ? `${state.path}/${state.selected[0].name}` : state.selected[0].name;
    const p = authParams();
    p.set("host", state.host); p.set("share", state.share); p.set("path", path);
    window.location.href = `/api/file?${p.toString()}`;
    return;
  }
  // bulk zip
  const res = await fetch("/api/bulk", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host: state.host, share: state.share, paths: selectedPaths(), action: "download_zip", ...authBody() }),
  });
  if (!res.ok) { setStatus("bulk download failed"); return; }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "selection.zip";
  a.click();
}

async function zipFolder() {
  if (!state.host || !state.share) return;
  const p = authParams();
  p.set("host", state.host); p.set("share", state.share); p.set("path", state.path || "");
  window.location.href = `/api/zip?${p.toString()}`;
}

async function uploadFiles(fileList) {
  for (const file of fileList) {
    const fd = new FormData();
    fd.append("host", state.host);
    fd.append("share", state.share);
    fd.append("path", state.path || "");
    fd.append("port", String(state.port || 445));
    // Prefer opaque session cookie — avoid putting secrets in multipart when sid is set
    if (!state.sid) {
      fd.append("username", state.username || "");
      fd.append("password", state.password || "");
      fd.append("domain", state.domain || "");
      if (state.hash) fd.append("hash", state.hash);
      if (state.guest) fd.append("guest", "true");
      if (state.use_kerberos) fd.append("use_kerberos", "true");
      if (state.aes_key) fd.append("aes_key", state.aes_key);
      if (state.kdc_host) fd.append("kdc_host", state.kdc_host);
      if (state.dc_ip) fd.append("dc_ip", state.dc_ip);
      if (state.ccache) fd.append("ccache", state.ccache);
    }
    fd.append("file", file);
    setStatus(`uploading ${file.name}…`);
    try {
      const data = await api("/api/upload", { method: "POST", body: fd });
      if (data.job_id && ws && ws.readyState === 1) ws.send(JSON.stringify({ subscribe: data.job_id }));
    } catch (e) {
      setStatus("upload failed: " + e.message);
      return;
    }
  }
  await doRefresh({});
}

async function mkdir() {
  const name = await promptModal("New folder name");
  if (!name) return;
  const path = state.path ? `${state.path}/${name}` : name;
  await api("/api/mkdir", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: state.host, share: state.share, path, ...authBody() }) });
  await doRefresh({});
}

async function renameSelected() {
  if (state.selected.length !== 1) return;
  const neu = await promptModal("Rename to", state.selected[0].name);
  if (!neu) return;
  const oldPath = state.path ? `${state.path}/${state.selected[0].name}` : state.selected[0].name;
  const newPath = state.path ? `${state.path}/${neu}` : neu;
  await api("/api/rename", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: state.host, share: state.share, path: oldPath, new_path: newPath, ...authBody() }) });
  await doRefresh({});
}

async function deleteSelected() {
  if (!state.selected.length) return;
  if (!confirm(`Delete ${state.selected.length} item(s)?`)) return;
  const body = { host: state.host, share: state.share, paths: selectedPaths(), action: "delete", ...authBody() };
  await api("/api/bulk", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  await doRefresh({});
}

async function copyOrMove(action) {
  if (state.selected.length !== 1 || state.selected[0].is_dir) {
    setStatus("select a single file for copy/move");
    return;
  }
  const dest = await promptModal(`${action} to path (share-relative)`, state.path ? `${state.path}/` : "");
  if (!dest) return;
  const src = state.path ? `${state.path}/${state.selected[0].name}` : state.selected[0].name;
  await api("/api/copy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host: state.host, src_share: state.share, src_path: src,
      dst_share: state.share, dst_path: dest, action, ...authBody(),
    }),
  });
  await doRefresh({});
}

async function showProps() {
  if (state.selected.length !== 1) return;
  const path = state.path ? `${state.path}/${state.selected[0].name}` : state.selected[0].name;
  const p = authParams();
  p.set("host", state.host); p.set("share", state.share); p.set("path", path);
  try {
    const data = await api(`/api/properties?${p.toString()}`);
    document.getElementById("preview").innerHTML = `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  } catch (e) {
    setStatus("props failed: " + e.message);
  }
}

async function addBookmark() {
  if (!state.host) return;
  const label = await promptModal("Bookmark label", `${state.host}/${state.share}/${state.path}`);
  if (!label) return;
  await api("/api/bookmarks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      label, host: state.host, port: state.port, share: state.share || "",
      path: state.path || "", username: state.username, domain: state.domain,
    }),
  });
  await loadBookmarks();
}

async function doSearch() {
  const q = document.getElementById("searchQ").value.trim();
  if (!q || !state.host) return;
  const p = authParams();
  p.set("host", state.host); p.set("q", q);
  if (state.share) p.set("share", state.share);
  const data = await api(`/api/search?${p.toString()}`);
  const el = document.getElementById("searchResults");
  document.querySelector("table.files").classList.add("hidden");
  el.classList.remove("hidden");
  el.innerHTML = `<div class="meta">${data.hits.length} FTS hit(s)</div>` + data.hits.map((h) => {
    const full = h.fullpath || `${h.share}/${h.path}/${h.name}`;
    return `<div class="tree-item" data-share="${h.share}" data-path="${h.path}" data-name="${escapeHtml(h.name)}" data-dir="${h.is_dir?1:0}">${escapeHtml(full)}</div>`;
  }).join("");
  el.querySelectorAll(".tree-item").forEach((node) => {
    node.onclick = () => {
      state.share = node.getAttribute("data-share");
      const path = node.getAttribute("data-path") || "";
      const isDir = node.getAttribute("data-dir") === "1";
      const name = node.getAttribute("data-name");
      if (isDir) listPath(path ? `${path}/${name}` : name);
      else listPath(path).then(() => previewFile(name));
    };
  });
  await refreshLog();
}

function goAddress() {
  const raw = document.getElementById("addressBar").value.trim();
  // \\host\share\path
  const m = raw.replace(/\//g, "\\").match(/^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$/);
  if (!m) { setStatus("address must look like \\\\host\\share\\path"); return; }
  const host = m[1], share = m[2], path = (m[3] || "").replace(/\\/g, "/");
  if (state.host && state.host.toLowerCase() !== host.toLowerCase()) {
    setStatus(`host ${host} not active — connect first`);
    return;
  }
  state.share = share;
  listPath(path);
}

async function cacheStatus() {
  const data = await api(`/api/cache/status?host=${encodeURIComponent(state.host || "")}`);
  document.getElementById("cacheStatus").textContent = JSON.stringify(data, null, 2);
}

// events
document.getElementById("connForm").addEventListener("submit", connect);
document.getElementById("btnKerbMore").onclick = () => document.getElementById("kerbPanel").classList.toggle("hidden");
document.getElementById("hostSwitcher").onchange = switchSession;
document.getElementById("btnRefresh").onclick = () => doRefresh({});
document.getElementById("btnRefreshRec").onclick = () => doRefresh({ recursive: true });
document.getElementById("btnRefreshAll").onclick = () => doRefresh({ all: true });
document.getElementById("btnGo").onclick = goAddress;
document.getElementById("addressBar").addEventListener("keydown", (e) => { if (e.key === "Enter") goAddress(); });
document.getElementById("btnUpload").onclick = () => document.getElementById("fileInput").click();
document.getElementById("fileInput").onchange = (e) => { if (e.target.files?.length) uploadFiles([...e.target.files]); e.target.value = ""; };
document.getElementById("btnMkdir").onclick = () => mkdir().catch((e) => setStatus(e.message));
document.getElementById("btnRename").onclick = () => renameSelected().catch((e) => setStatus(e.message));
document.getElementById("btnDelete").onclick = () => deleteSelected().catch((e) => setStatus(e.message));
document.getElementById("btnDownload").onclick = () => downloadSelected().catch((e) => setStatus(e.message));
document.getElementById("btnZip").onclick = zipFolder;
document.getElementById("btnCopy").onclick = () => copyOrMove("copy").catch((e) => setStatus(e.message));
document.getElementById("btnMove").onclick = () => copyOrMove("move").catch((e) => setStatus(e.message));
document.getElementById("btnProps").onclick = () => showProps();
document.getElementById("btnBookmark").onclick = () => addBookmark().catch((e) => setStatus(e.message));
document.getElementById("btnSearch").onclick = () => doSearch().catch((e) => setStatus(e.message));
document.getElementById("searchQ").addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
document.getElementById("filterBox").oninput = (e) => { state.filter = e.target.value; renderFiles(state.entries); };
document.getElementById("sortCol").onchange = (e) => { state.sortCol = e.target.value; renderFiles(state.entries); };
document.getElementById("btnSortDir").onclick = () => { state.sortAsc = !state.sortAsc; renderFiles(state.entries); };
document.getElementById("selectAll").onchange = (e) => {
  if (e.target.checked) state.selected = state.entries.map((x) => ({ name: x.name, is_dir: x.is_dir, size: x.size }));
  else state.selected = [];
  renderFiles(state.entries);
};
document.getElementById("btnCacheStatus").onclick = () => cacheStatus().catch((e) => setStatus(e.message));
document.getElementById("btnCacheExport").onclick = () => {
  if (!state.host) return;
  window.location.href = `/api/cache/export?host=${encodeURIComponent(state.host)}`;
};
document.getElementById("btnCacheClear").onclick = async () => {
  if (!state.host || !confirm("Clear cache for host?")) return;
  await api("/api/cache/clear", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: state.host }) });
  cacheStatus();
};
document.getElementById("btnTtl").onclick = async () => {
  const ttl = Number(document.getElementById("ttlInput").value || 300);
  await api("/api/cache/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ttl }) });
  setStatus(`TTL set to ${ttl}s`);
};
document.getElementById("cacheImport").onchange = async (e) => {
  const f = e.target.files?.[0];
  if (!f || !state.host) return;
  const fd = new FormData();
  fd.append("host", state.host);
  fd.append("file", f);
  await api("/api/cache/import", { method: "POST", body: fd });
  setStatus("cache imported");
  cacheStatus();
};

// drag and drop upload
const dz = document.getElementById("dropzone");
dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
dz.addEventListener("drop", (e) => {
  e.preventDefault();
  dz.classList.remove("dragover");
  if (e.dataTransfer.files?.length) uploadFiles([...e.dataTransfer.files]);
});

document.addEventListener("keydown", (e) => {
  if (e.key === "F5") { e.preventDefault(); doRefresh({}); }
  if (e.key === "Delete" && state.selected.length) deleteSelected();
  if (e.key === "Enter" && state.selected.length === 1) {
    const s = state.selected[0];
    if (s.is_dir) listPath(state.path ? `${state.path}/${s.name}` : s.name);
  }
  if (e.key === "Backspace" && !["INPUT","TEXTAREA"].includes(document.activeElement.tagName)) {
    if (state.path) {
      const parts = state.path.split("/").filter(Boolean); parts.pop();
      listPath(parts.join("/"));
    }
  }
});

connectWs();
refreshLog();
loadBookmarks();
setInterval(refreshLog, 5000);


async function exportListing() {
  if (!state.host || !state.share) return;
  const fmt = document.getElementById("exportFmt")?.value || "csv";
  const recursive = confirm("Export recursively (whole subtree, bounded)?\nOK = recursive, Cancel = current folder only");
  const p = authParams();
  p.set("host", state.host);
  p.set("share", state.share);
  p.set("path", state.path || "");
  p.set("format", fmt);
  p.set("recursive", recursive ? "true" : "false");
  window.location.href = `/api/export/listing?${p.toString()}`;
  setTimeout(refreshLog, 800);
}

document.getElementById("btnExport")?.addEventListener("click", () => exportListing().catch((e) => setStatus(e.message)));
document.getElementById("showHidden")?.addEventListener("change", async () => {
  if (!state.host) return;
  const show = document.getElementById("showHidden").checked;
  try {
    const p = authParams();
    p.set("host", state.host);
    p.set("show_hidden", show ? "true" : "false");
    p.set("use_cache", "false");
    const data = await api(`/api/shares?${p.toString()}`);
    renderShares(data.shares || []);
  } catch (e) {
    setStatus(e.message);
  }
});


// --- Reliability / proxy / background jobs ---
document.getElementById("btnRelMore")?.addEventListener("click", () => {
  document.getElementById("reliabilityPanel").classList.toggle("hidden");
  loadReliability();
});
document.getElementById("btnJobs")?.addEventListener("click", async () => {
  document.getElementById("jobsPanel").classList.toggle("hidden");
  refreshJobs();
});

async function loadReliability() {
  try {
    const d = await api("/api/reliability");
    document.getElementById("relConnectTimeout").value = d.connect_timeout ?? 3600;
    document.getElementById("relIoTimeout").value = d.io_timeout ?? 0;
    document.getElementById("relMaxRetries").value = d.max_retries ?? 10;
    document.getElementById("relBaseDelay").value = d.base_delay ?? 2;
    document.getElementById("relMaxDelay").value = d.max_delay ?? 600;
    document.getElementById("relRetry").checked = !!d.retry_enabled;
    document.getElementById("relReconnect").checked = !!d.auto_reconnect;
    document.getElementById("relResume").checked = !!d.resume_enabled;
    if (d.proxy) {
      document.getElementById("proxyType").value = d.proxy.proxy_type || "socks5";
      document.getElementById("proxyHost").value = d.proxy.host || "";
      document.getElementById("proxyPort").value = d.proxy.port || "";
      document.getElementById("proxyUser").value = d.proxy.username || "";
    }
  } catch (e) { setStatus(e.message); }
}

document.getElementById("btnSaveRel")?.addEventListener("click", async () => {
  const body = {
    connect_timeout: Number(document.getElementById("relConnectTimeout").value),
    io_timeout: Number(document.getElementById("relIoTimeout").value),
    max_retries: Number(document.getElementById("relMaxRetries").value),
    base_delay: Number(document.getElementById("relBaseDelay").value),
    max_delay: Number(document.getElementById("relMaxDelay").value),
    retry_enabled: document.getElementById("relRetry").checked,
    auto_reconnect: document.getElementById("relReconnect").checked,
    resume_enabled: document.getElementById("relResume").checked,
    proxy: {
      enabled: !!document.getElementById("proxyHost").value.trim(),
      proxy_type: document.getElementById("proxyType").value,
      host: document.getElementById("proxyHost").value.trim(),
      port: Number(document.getElementById("proxyPort").value || 1080),
      username: document.getElementById("proxyUser").value,
      password: document.getElementById("proxyPass").value,
    },
  };
  await api("/api/reliability", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  setStatus("reliability settings saved");
});

function proxyFields() {
  const host = document.getElementById("proxyHost")?.value.trim() || "";
  if (!host) return {};
  return {
    proxy_type: document.getElementById("proxyType").value,
    proxy_host: host,
    proxy_port: Number(document.getElementById("proxyPort").value || 1080),
    proxy_user: document.getElementById("proxyUser").value || "",
    proxy_pass: document.getElementById("proxyPass").value || "",
  };
}

// Patch connect body to include proxy
const _origConnect = connect;
connect = async function(ev) {
  ev?.preventDefault();
  // stash proxy into connection by temporarily wrapping api for connect only
  const conn = document.getElementById("connStr").value.trim();
  const hash = document.getElementById("hash").value.trim() || null;
  const guest = document.getElementById("guest").checked;
  const use_kerberos = document.getElementById("useKerb").checked;
  const aes_key = document.getElementById("aesKey").value.trim();
  const kdc_host = document.getElementById("kdcHost").value.trim();
  const dc_ip = document.getElementById("dcIp").value.trim();
  const ccache = document.getElementById("ccache").value.trim();
  if (!conn && !guest) { setStatus("connection string required"); return; }
  setStatus("connecting…");
  try {
    const body = {
      connection: conn || undefined, hash, guest, use_kerberos, aes_key, kdc_host, dc_ip, ccache,
      ...proxyFields(),
      connect_timeout: Number(document.getElementById("relConnectTimeout")?.value || 3600),
    };
    const data = await api("/api/connect", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    state.host = data.host; state.port = data.port; state.cred_fp = data.cred_fp;
    state.session_id = data.session_id; state.sid = data.sid || null; state.guest = !!data.guest; state.hash = hash;
    state.use_kerberos = !!data.use_kerberos; state.aes_key = aes_key; state.kdc_host = kdc_host;
    state.dc_ip = dc_ip; state.ccache = ccache;
    Object.assign(state, proxyFields());
    const m = (conn || "").match(/^(?:([^\\/@]+)\\)?([^:@]+)(?::(.*))?@(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/);
    if (m) { state.domain = m[1] || ""; state.username = m[2] || ""; state.password = m[3] || ""; if (hash && !use_kerberos) state.password = ""; }
    if (guest) { state.username = "Guest"; state.password = ""; state.hash = null; }
    state.sessions[data.session_id] = { host: data.host, port: data.port, sid: data.sid, display_user: data.user, cred_fp: data.cred_fp, session_id: data.session_id, ...proxyFields() };
    renderHostSwitcher();
    renderShares(data.shares || []);
    state.share = ((data.shares || []).find((s) => s.browsable !== false) || (data.shares || [])[0] || {}).name || null;
    state.path = "";
    setStatus(`connected as ${data.user} @ ${data.host}:${data.port} [${data.auth_mode}]`, `cached: ${data.cached_listings}`);
    if (state.share) await listPath("", true);
    await refreshLog(); await loadBookmarks();
  } catch (e) { setStatus("connect failed: " + e.message); }
};

async function refreshJobs() {
  try {
    const d = await api("/api/jobs");
    document.getElementById("jobsList").textContent = JSON.stringify(d.jobs, null, 2);
  } catch (e) { setStatus(e.message); }
}

async function bgDownloadSelected() {
  if (!state.selected.length || state.selected[0].is_dir) return;
  const path = state.path ? `${state.path}/${state.selected[0].name}` : state.selected[0].name;
  const data = await api("/api/transfer/download", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host: state.host, share: state.share, path, ...authBody(), ...proxyFields() }),
  });
  setStatus(`download job ${data.job_id} started — poll Jobs / WebSocket`);
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({ subscribe: data.job_id }));
  refreshJobs();
}

// Prefer background download for Download button when reliability resume enabled
const _oldDl = downloadSelected;
downloadSelected = async function() {
  try { await bgDownloadSelected(); } catch (e) { setStatus(e.message); await _oldDl(); }
};


// --- Live operator activity strip ---
let statusWs = null;
let statusPollTimer = null;

function applyActivity(ev) {
  if (!ev) return;
  const bar = document.getElementById("operatorStatus");
  if (!bar) return;
  const sev = ev.severity || "info";
  const busy = ev.busy ? "1" : "0";
  bar.setAttribute("data-severity", sev);
  bar.setAttribute("data-busy", busy);
  document.getElementById("opState").textContent = ev.state || "idle";
  document.getElementById("opMsg").textContent = ev.message || "";
  document.getElementById("opHost").textContent = ev.host ? `@ ${ev.host}` : "";
  const ts = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : "—";
  document.getElementById("opUpdated").textContent = `updated ${ts}`;
  const wrap = document.getElementById("opProgressWrap");
  if (ev.progress != null && ev.progress !== undefined && !Number.isNaN(Number(ev.progress))) {
    wrap.classList.remove("hidden");
    document.getElementById("opProgressFill").style.width = `${Math.min(100, Number(ev.progress))}%`;
    document.getElementById("opProgressPct").textContent = `${Number(ev.progress).toFixed(0)}%`;
  } else {
    wrap.classList.add("hidden");
  }
  // mirror into legacy statusLeft briefly
  if (ev.message) setStatus(ev.message, ev.state || "");
}

async function fetchStatusSnapshot() {
  try {
    const d = await api("/api/status");
    applyActivity(d);
  } catch (_) {}
}

function connectStatusWs() {
  if (statusWs && statusWs.readyState <= 1) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  statusWs = new WebSocket(`${proto}://${location.host}/ws/status`);
  statusWs.onopen = () => {
    if (statusPollTimer) { clearInterval(statusPollTimer); statusPollTimer = null; }
  };
  statusWs.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === "status" || msg.state) applyActivity(msg);
      if (msg.type === "ping" && msg.status) applyActivity(msg.status);
    } catch (_) {}
  };
  statusWs.onclose = () => {
    statusWs = null;
    if (!statusPollTimer) statusPollTimer = setInterval(fetchStatusSnapshot, 3000);
    setTimeout(connectStatusWs, 2000);
  };
  statusWs.onerror = () => { try { statusWs.close(); } catch (_) {} };
}

connectStatusWs();
fetchStatusSnapshot();
