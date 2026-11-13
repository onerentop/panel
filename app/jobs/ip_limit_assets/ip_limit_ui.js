/* PasarGuard 同时在线 IP 限制 —— 面板注入脚本（由 /api/ip-limit/ui.js 提供，插件自动注入到 dashboard HTML）
 *
 * 1. 包装 window.fetch，从面板自己的请求里拿到 Authorization 头（不依赖 token 的存储方式）
 * 2. 侧边栏加「IP 限制」入口（找不到侧边栏时退回右下角悬浮按钮），点击打开管理面板
 * 3. 用户编辑弹窗里，在 HWID 限制字段下面插入「同时在线 IP 上限」（只在编辑已有用户时出现，独立保存）
 */
(function () {
  "use strict";
  if (window.__ipLimitLoaded) return;
  window.__ipLimitLoaded = true;

  var API = "/api/ip-limit";
  var auth = { header: null };

  // ---------- 1. 抓取面板的鉴权头 ----------
  function grab(h) {
    try {
      if (!h) return;
      var v = null;
      if (typeof Headers !== "undefined" && h instanceof Headers) v = h.get("Authorization");
      else if (Array.isArray(h)) h.forEach(function (p) { if (String(p[0]).toLowerCase() === "authorization") v = p[1]; });
      else Object.keys(h).forEach(function (k) { if (k.toLowerCase() === "authorization") v = h[k]; });
      if (v && /^Bearer\s+\S+/.test(v) && !/Bearer\s+(null|undefined)$/.test(v)) auth.header = v;
    } catch (e) { /* ignore */ }
  }
  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      if (input && typeof Request !== "undefined" && input instanceof Request) grab(input.headers);
      if (init && init.headers) grab(init.headers);
    } catch (e) { /* ignore */ }
    return origFetch.apply(this, arguments);
  };
  var origSet = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (String(k).toLowerCase() === "authorization") grab({ Authorization: v });
    return origSet.apply(this, arguments);
  };

  function api(method, path, body) {
    var headers = { "Content-Type": "application/json" };
    if (auth.header) headers.Authorization = auth.header;
    return origFetch(API + path, { method: method, headers: headers, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) {
        return r.text().then(function (t) {
          var data = null;
          try { data = t ? JSON.parse(t) : null; } catch (e) { data = t; }
          if (!r.ok) throw new Error((data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : ("HTTP " + r.status));
          return data;
        });
      });
  }

  // ---------- 小工具 ----------
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "class") e.className = attrs[k];
      else if (k === "style") e.style.cssText = attrs[k];
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), attrs[k]);
      else e.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      if (c == null) return;
      e.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    });
    return e;
  }
  function fmtAgo(ts, now) {
    if (!ts) return "-";
    var s = Math.max(0, Math.round(now - ts));
    if (s < 60) return s + " 秒前";
    if (s < 3600) return Math.floor(s / 60) + " 分钟前";
    if (s < 86400) return Math.floor(s / 3600) + " 小时前";
    return Math.floor(s / 86400) + " 天前";
  }
  function fmtLeft(s) {
    if (s < 60) return s + " 秒";
    return Math.floor(s / 60) + " 分 " + (s % 60) + " 秒";
  }
  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    function p(n) { return n < 10 ? "0" + n : "" + n; }
    return p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  var ACTION_TEXT = {
    "ban": "封禁", "dry-ban": "封禁（演练，未下发）", "unban-expired": "到期解封", "unban-manual": "手动解封",
    "unban-nolimit": "取消限制后解封", "unban-disabled": "停用后全部解封"
  };
  function actionText(a) {
    if (ACTION_TEXT[a]) return ACTION_TEXT[a];
    if (a.indexOf("limit=") === 0) return "上限改为 " + a.slice(6);
    if (a.indexOf("settings ") === 0) return "修改设置 " + a.slice(9);
    return a;
  }
  var NODE_STATUS = { ok: "正常", rotate: "已换代", cleanup: "已收尾", unban: "已解封", skip: "跳过", error: "错误", offline: "离线" };

  // ---------- 样式 ----------
  var css = "" +
    "#iplimit-overlay{position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.45);display:flex;justify-content:center;align-items:flex-start;overflow:auto;padding:24px 12px}" +
    "#iplimit-panel{width:min(1100px,100%);border-radius:12px;padding:20px;box-shadow:0 10px 40px rgba(0,0,0,.35)}" +
    "#iplimit-panel table{width:100%;border-collapse:collapse;font-size:13px}" +
    "#iplimit-panel th,#iplimit-panel td{padding:6px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--border,rgba(127,127,127,.25))}" +
    "#iplimit-panel th{font-weight:600;opacity:.8;white-space:nowrap}" +
    "#iplimit-panel .ipl-tag{display:inline-block;padding:1px 6px;margin:1px 2px;border-radius:6px;font-family:ui-monospace,monospace;font-size:12px;border:1px solid var(--border,rgba(127,127,127,.35))}" +
    "#iplimit-panel .ipl-ban{border-color:#dc2626;color:#dc2626}" +
    "#iplimit-panel .ipl-over{color:#dc2626;font-weight:600}" +
    "#iplimit-panel input[type=number]{width:72px;padding:2px 6px;border-radius:6px;border:1px solid var(--border,rgba(127,127,127,.4));background:transparent;color:inherit}" +
    "#iplimit-panel button.ipl-btn{padding:3px 10px;border-radius:6px;border:1px solid var(--border,rgba(127,127,127,.4));background:transparent;color:inherit;cursor:pointer;font-size:12px}" +
    "#iplimit-panel button.ipl-btn:hover{opacity:.75}" +
    "#iplimit-panel .ipl-sec{margin-top:18px}" +
    "#iplimit-panel .ipl-muted{opacity:.65;font-size:12px}" +
    "#iplimit-panel .ipl-banner{padding:8px 12px;border-radius:8px;margin:10px 0;font-size:13px}" +
    "#iplimit-panel .ipl-warn{background:rgba(234,179,8,.15);border:1px solid rgba(234,179,8,.5)}" +
    "#iplimit-panel .ipl-err{background:rgba(220,38,38,.12);border:1px solid rgba(220,38,38,.5)}" +
    "#iplimit-fab{position:fixed;right:16px;bottom:16px;z-index:55;padding:8px 14px;border-radius:999px;cursor:pointer;font-size:13px;box-shadow:0 4px 16px rgba(0,0,0,.25)}" +
    ".iplimit-field-hint{font-size:12px;opacity:.7;margin-top:4px}";
  function injectCss() {
    if (document.getElementById("iplimit-css")) return;
    document.head.appendChild(el("style", { id: "iplimit-css" }, [css]));
  }

  // ---------- 2. 管理面板 ----------
  var panelState = { timer: null, data: null, editing: {} };

  function openPanel() {
    injectCss();
    closePanel();
    var panel = el("div", { id: "iplimit-panel", class: "bg-background text-foreground border" });
    var overlay = el("div", { id: "iplimit-overlay", onclick: function (e) { if (e.target === overlay) closePanel(); } }, [panel]);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", escClose);
    renderPanel();
    refresh();
    panelState.timer = setInterval(refresh, 5000);
  }
  function escClose(e) { if (e.key === "Escape") closePanel(); }
  function closePanel() {
    var o = document.getElementById("iplimit-overlay");
    if (o) o.remove();
    if (panelState.timer) clearInterval(panelState.timer);
    panelState.timer = null;
    document.removeEventListener("keydown", escClose);
  }
  function refresh() {
    if (!auth.header) { renderPanel("还没拿到登录凭据：请在面板里随便点一下（例如刷新用户列表）后再打开本页。"); return; }
    api("GET", "/state").then(function (d) { panelState.data = d; renderPanel(); })
      .catch(function (e) { renderPanel("加载失败：" + e.message); });
  }

  function settingsBox(s) {
    function num(key, label, unit) {
      var inp = el("input", { type: "number", value: s[key], min: 1 });
      return el("label", { style: "margin-right:14px;white-space:nowrap" }, [label + " ", inp, " " + unit,
        el("button", { class: "ipl-btn", style: "margin-left:4px", onclick: function () { saveSettings(obj(key, +inp.value)); } }, ["保存"])]);
    }
    function obj(k, v) { var o = {}; o[k] = v; return o; }
    var enabled = el("input", { type: "checkbox" }); enabled.checked = !!s.enabled;
    enabled.addEventListener("change", function () { saveSettings({ enabled: enabled.checked ? 1 : 0 }); });
    var dry = el("input", { type: "checkbox" }); dry.checked = !!s.dry_run;
    dry.addEventListener("change", function () {
      if (!dry.checked && !confirm("关闭演练模式后，超限的新 IP 会被真正拦截。确定？")) { dry.checked = true; return; }
      saveSettings({ dry_run: dry.checked ? 1 : 0 });
    });
    return el("div", { class: "ipl-sec" }, [
      el("div", { style: "font-weight:600;margin-bottom:6px" }, ["全局设置"]),
      el("div", { style: "display:flex;flex-wrap:wrap;gap:8px 0;align-items:center;font-size:13px" }, [
        el("label", { style: "margin-right:14px" }, [enabled, " 启用限制"]),
        el("label", { style: "margin-right:14px" }, [dry, " 演练模式（只记录，不拦截）"]),
        num("interval", "检查周期", "秒"),
        num("ban_ttl", "封禁时长", "秒"),
        num("offline_grace", "下线判定", "秒")
      ]),
      el("div", { class: "ipl-muted", style: "margin-top:4px" }, ["下线判定：某个 IP 超过这么久没被任何节点报告，就不再占用名额。手机切换网络时旧 IP 会在这段时间后释放。"])
    ]);
  }
  function saveSettings(p) {
    api("PUT", "/settings", p).then(refresh).catch(function (e) { alert("保存失败：" + e.message); refresh(); });
  }
  function savePolicy(uid, v, after) {
    return api("PUT", "/policy/" + uid, { ip_limit: v }).then(function (r) { if (after) after(r); refresh(); return r; });
  }
  function unban(uid, ip) {
    var q = ip ? ("?ip=" + encodeURIComponent(ip)) : "";
    api("DELETE", "/ban/" + uid + q).then(refresh).catch(function (e) { alert("解封失败：" + e.message); });
  }

  function usersTable(d) {
    var nodeName = {};
    (d.nodes || []).forEach(function (n) { nodeName[n.id] = n.name; });
    var rows = d.users.map(function (u) {
      var limitInp = el("input", { type: "number", min: 0, value: u.ip_limit || 0, title: "0 = 不限制" });
      var save = el("button", { class: "ipl-btn", onclick: function () {
        savePolicy(u.id, +limitInp.value || 0).catch(function (e) { alert("保存失败：" + e.message); });
      } }, ["保存"]);
      var cnt = u.online.length;
      var over = u.ip_limit > 0 && cnt > u.ip_limit;
      return el("tr", null, [
        el("td", null, [el("div", { style: "font-weight:600" }, [u.username]), el("div", { class: "ipl-muted" }, ["#" + u.id + " · " + u.status])]),
        el("td", { class: over ? "ipl-over" : "" }, [cnt + " / " + (u.ip_limit > 0 ? u.ip_limit : "不限")]),
        el("td", null, u.online.length ? u.online.map(function (o) {
          return el("div", null, [el("span", { class: "ipl-tag" }, [o.ip]), " ",
            el("span", { class: "ipl-muted" }, [o.nodes.map(function (n) { return nodeName[n] || ("#" + n); }).join("、") +
              (o.first_seen ? " · 首次 " + fmtAgo(o.first_seen, d.now) : "")])]);
        }) : [el("span", { class: "ipl-muted" }, ["离线"])]),
        el("td", null, u.bans.length ? u.bans.map(function (b) {
          return el("div", null, [el("span", { class: "ipl-tag ipl-ban" }, [b.ip]), " ",
            el("span", { class: "ipl-muted" }, ["剩 " + fmtLeft(b.remaining)]), " ",
            el("button", { class: "ipl-btn", onclick: function () { unban(u.id, b.ip); } }, ["解封"])]);
        }) : [el("span", { class: "ipl-muted" }, ["-"])]),
        el("td", { style: "white-space:nowrap" }, [limitInp, " ", save])
      ]);
    });
    return el("div", { class: "ipl-sec" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, ["用户", "在线 / 上限", "在线 IP（节点 · 首次出现）", "被拦截的 IP", "同时在线 IP 上限"].map(function (h) { return el("th", null, [h]); }))]),
        el("tbody", null, rows)
      ])
    ]);
  }
  function nodesBox(d) {
    if (!d.nodes || !d.nodes.length) return null;
    return el("div", { class: "ipl-sec" }, [
      el("div", { style: "font-weight:600;margin-bottom:6px" }, ["节点下发状态"]),
      el("div", { style: "display:flex;flex-wrap:wrap;gap:6px" }, d.nodes.map(function (n) {
        var bad = n.status === "error" || n.status === "skip";
        return el("span", { class: "ipl-tag" + (bad ? " ipl-ban" : ""), title: n.reason || "" },
          [n.name + "：" + (NODE_STATUS[n.status] || n.status || "-") + (n.gen ? " · g" + n.gen : "") + (n.reason ? " · " + n.reason : "")]);
      }))
    ]);
  }
  function eventsBox(d) {
    var ev = (d.events || []).slice(0, 40);
    return el("div", { class: "ipl-sec" }, [
      el("div", { style: "font-weight:600;margin-bottom:6px" }, ["最近事件"]),
      ev.length ? el("table", null, [el("tbody", null, ev.map(function (e) {
        return el("tr", null, [el("td", { class: "ipl-muted", style: "white-space:nowrap" }, [fmtTime(e.ts)]),
          el("td", null, [e.user_id ? e.username : "全局"]), el("td", null, [e.ip === "*" ? "" : el("span", { class: "ipl-tag" }, [e.ip])]),
          el("td", null, [actionText(e.action)])]);
      }))]) : el("div", { class: "ipl-muted" }, ["暂无"])
    ]);
  }

  function renderPanel(msg) {
    var panel = document.getElementById("iplimit-panel");
    if (!panel) return;
    var d = panelState.data;
    var active = document.activeElement;
    if (active && panel.contains(active) && active.tagName === "INPUT" && active.type === "number") return; // 正在输入时不刷新
    panel.innerHTML = "";
    panel.appendChild(el("div", { style: "display:flex;justify-content:space-between;align-items:center" }, [
      el("div", null, [el("div", { style: "font-size:18px;font-weight:700" }, ["同时在线 IP 限制"]),
        el("div", { class: "ipl-muted" }, ["按订阅限制同时在线的不同 IP 数：先连上的 IP 保留，超出的新 IP 会被拦截一段时间。数据每 5 秒刷新。"])]),
      el("button", { class: "ipl-btn", onclick: closePanel }, ["关闭"])
    ]));
    if (msg) panel.appendChild(el("div", { class: "ipl-banner ipl-err" }, [msg]));
    if (!d) return;
    if (d.last_error) panel.appendChild(el("div", { class: "ipl-banner ipl-err" }, ["后台任务出错：" + d.last_error]));
    if (!d.settings.enabled) panel.appendChild(el("div", { class: "ipl-banner ipl-warn" }, ["限制已停用：不判定、不拦截。"]));
    else if (d.settings.dry_run) panel.appendChild(el("div", { class: "ipl-banner ipl-warn" }, ["演练模式：只记录会被拦截的 IP，不会真的拦截。确认判定没问题后，在下方关闭演练模式。"]));
    panel.appendChild(el("div", { class: "ipl-muted" }, ["上次检查：" + (d.last_tick ? fmtAgo(d.last_tick, d.now) : "尚未运行")]));
    panel.appendChild(settingsBox(d.settings));
    panel.appendChild(usersTable(d));
    var nb = nodesBox(d); if (nb) panel.appendChild(nb);
    panel.appendChild(eventsBox(d));
  }

  // ---------- 侧边栏入口 ----------
  function ensureEntry() {
    if (document.getElementById("iplimit-nav") || document.getElementById("iplimit-fab")) return;
    var menu = document.querySelector('[data-sidebar="content"] [data-sidebar="menu"]') || document.querySelector('[data-sidebar="menu"]');
    var items = menu ? menu.querySelectorAll(':scope > [data-sidebar="menu-item"], :scope > li') : [];
    if (menu && items.length) {
      var tpl = items[items.length - 1];
      var li = tpl.cloneNode(true);
      li.id = "iplimit-nav";
      var a = li.querySelector("a,button") || li;
      if (a.tagName === "A") a.removeAttribute("href");
      a.removeAttribute("data-active");
      a.setAttribute("data-active", "false");
      var label = null;
      a.querySelectorAll("span").forEach(function (s) { if (!label && s.textContent.trim()) label = s; });
      if (label) label.textContent = "IP 限制"; else a.textContent = "IP 限制";
      var svg = a.querySelector("svg");
      if (svg) svg.outerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6"/></svg>';
      li.addEventListener("click", function (e) { e.preventDefault(); e.stopPropagation(); openPanel(); }, true);
      tpl.parentNode.appendChild(li);
      return;
    }
    if (location.pathname.indexOf("/login") >= 0) return;
    if (!document.querySelector("#root *")) return;
    injectCss();
    document.body.appendChild(el("button", { id: "iplimit-fab", class: "bg-primary text-primary-foreground", onclick: openPanel }, ["IP 限制"]));
  }

  // ---------- 3. 用户编辑弹窗字段 ----------
  var usersCache = { at: 0, map: {} };
  function userIdByName(name) {
    var now = Date.now();
    if (now - usersCache.at < 15000 && usersCache.map[name]) return Promise.resolve(usersCache.map[name]);
    return api("GET", "/state").then(function (d) {
      usersCache = { at: now, map: {} };
      d.users.forEach(function (u) { usersCache.map[u.username] = u; });
      return usersCache.map[name];
    });
  }
  function findHwidField(dialog) {
    var inp = dialog.querySelector('input[name="hwid_limit"]');
    if (inp) return inp;
    var labels = dialog.querySelectorAll("label");
    for (var i = 0; i < labels.length; i++) {
      if (/hwid/i.test(labels[i].textContent)) {
        var id = labels[i].getAttribute("for");
        var target = id ? dialog.querySelector("#" + CSS.escape(id)) : null;
        return target || labels[i].parentElement.querySelector("input") || labels[i];
      }
    }
    return null;
  }
  function enhanceDialogs() {
    document.querySelectorAll('[role="dialog"]').forEach(function (dialog) {
      if (dialog.querySelector(".iplimit-field")) return;
      var userInp = dialog.querySelector('input[name="username"]');
      var hwid = findHwidField(dialog);
      if (!userInp || !hwid) return;
      var username = (userInp.value || "").trim();
      if (!username) return; // 新建用户还没填名字；名字对不上已有用户时 load() 会提示先保存
      var box = hwid.closest('[class*="space-y"], .grid > div, [data-slot="form-item"]') || hwid.parentElement;
      var inp = el("input", { type: "number", min: 0, placeholder: "0 = 不限制",
        class: "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm" });
      var hint = el("div", { class: "iplimit-field-hint" }, ["同一个订阅最多同时在线的不同 IP 数；超出的新 IP 会被拦截。改完点「保存上限」，与表单的保存按钮相互独立。"]);
      var btn = el("button", { type: "button", class: "inline-flex items-center justify-center rounded-md border border-input bg-background px-3 text-sm h-10 whitespace-nowrap" }, ["保存上限"]);
      var wrap = el("div", { class: "iplimit-field space-y-2", style: "margin-top:8px" }, [
        el("label", { class: "text-sm font-medium" }, ["同时在线 IP 上限"]),
        el("div", { style: "display:flex;gap:8px" }, [inp, btn]), hint
      ]);
      box.parentNode.insertBefore(wrap, box.nextSibling);
      var uid = null;
      function load() {
        userIdByName(username).then(function (u) {
          if (!u) { hint.textContent = "新建用户请先保存，之后再编辑时设置 IP 上限。"; inp.disabled = true; btn.disabled = true; return; }
          uid = u.id; inp.value = u.ip_limit || 0;
          hint.textContent = "当前在线 " + u.online.length + " 个 IP；0 = 不限制。改完点「保存上限」（与表单的保存相互独立）。";
        }).catch(function (e) { hint.textContent = "读取失败：" + e.message; });
      }
      btn.addEventListener("click", function (e) {
        e.preventDefault(); e.stopPropagation();
        if (uid == null) return;
        btn.disabled = true;
        savePolicy(uid, +inp.value || 0, function (r) { hint.textContent = "已保存：上限 " + (r.ip_limit || "不限制"); usersCache.at = 0; })
          .catch(function (err) { hint.textContent = "保存失败：" + err.message; })
          .then(function () { btn.disabled = false; });
      });
      inp.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); btn.click(); } });
      if (auth.header) load(); else { hint.textContent = "正在获取登录凭据…"; setTimeout(load, 1500); }
    });
  }

  // ---------- 启动 ----------
  var pending = false;
  function tick() {
    pending = false;
    try { ensureEntry(); enhanceDialogs(); } catch (e) { console.warn("[ip-limit]", e); }
  }
  function boot() {
    new MutationObserver(function () { if (!pending) { pending = true; setTimeout(tick, 150); } })
      .observe(document.body, { childList: true, subtree: true });
    tick();
  }
  if (document.body) boot(); else document.addEventListener("DOMContentLoaded", boot);
  window.ipLimitOpen = openPanel;
})();

