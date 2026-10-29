/* sshweb browser client. No framework; talks to the gateway via /api and the /ws protocol v1.
 *
 * Tabs: each tab owns an xterm.js instance and its own WebSocket bound to one terminal session.
 * The list of tabs (target, name, session id) is saved on the server (/api/workspace), so
 * signing in again (in any browser) restores them: tabs whose session is still running are
 * re-attached; tabs whose session ended start a fresh session for the same target when opened.
 */
(function () {
  "use strict";

  const PROTOCOL_VERSION = 1;
  const $ = (id) => document.getElementById(id);
  const prefs = loadPrefs();
  // OpsAPI task link: https://<this gateway>/#launch=<ticket>. The fragment never reaches
  // proxies or logs. The server verifies the ticket after the user signs in with their key, or
  // signs them in with it when the link carries `login` and the terminal allows it. The page
  // reads the payload only to say which task is waiting and whether to try that (unverified).
  const launchTicket = (function () {
    const m = /(?:^#|&)launch=([^&]+)/.exec(location.hash || "");
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (_) { return null; }
  })();
  let launchHandled = false;
  let autoLoginTried = false;
  function launchClaims() {
    try {
      const b64 = launchTicket.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (_) { return null; }
  }
  function launchPreview() {
    const c = launchClaims();
    return c ? { number: c.num, title: String(c.title || "") } : null;
  }

  // ---------- small utilities ----------
  function loadPrefs() {
    try {
      return Object.assign({ theme: "dark", fontSize: 14, optionMeta: true }, JSON.parse(localStorage.getItem("sshweb.prefs") || "{}"));
    } catch (_) {
      return { theme: "dark", fontSize: 14, optionMeta: true };
    }
  }
  function savePrefs() {
    try { localStorage.setItem("sshweb.prefs", JSON.stringify(prefs)); } catch (_) { /* private mode */ }
  }
  function toast(msg, kind) {
    const el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    $("toasts").appendChild(el);
    setTimeout(() => el.remove(), kind === "error" ? 8000 : 4000);
  }
  function setStatus(text, kind) {
    $("status-text").textContent = text;
    $("status-dot").className = "dot " + (kind || "");
  }
  function show(view) {
    for (const v of ["login", "term", "settings"]) $("view-" + v).classList.toggle("hidden", v !== view);
    const authed = view !== "login";
    for (const id of ["btn-logout", "btn-settings", "who"]) $(id).classList.toggle("hidden", !authed);
    $("btn-settings").classList.toggle("hidden", !authed || view === "settings");
    $("btn-terminal-view").classList.toggle("hidden", view !== "settings");
    if (view === "term" && active) setTimeout(() => active.fit(), 0);
  }
  async function api(method, path, body, headers) {
    const opts = { method, credentials: "same-origin", headers: Object.assign({}, headers) };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(path, opts);
    let data = {};
    try { data = await r.json(); } catch (_) { /* empty */ }
    if (!r.ok) {
      const err = new Error(data.message || r.statusText);
      err.status = r.status;
      err.code = data.error;
      throw err;
    }
    return data;
  }
  const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform || "");
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied", "ok");
    } catch (_) {
      toast("Couldn't copy here; press " + (IS_MAC ? "⌘C" : "Ctrl+Insert") + " instead", "error");
    }
  }
  function shellQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  function newId() {
    const a = new Uint8Array(9);
    crypto.getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // ---------- theme ----------
  const THEMES = {
    dark: { background: "#0d1013", foreground: "#e3e6ea", cursor: "#e3e6ea", selectionBackground: "#3a4a63" },
    light: {
      background: "#ffffff", foreground: "#1d2228", cursor: "#1d2228", selectionBackground: "#b6cdf5",
      black: "#1d2228", white: "#8b939e", brightWhite: "#5f6873", yellow: "#9a6700", brightYellow: "#7d5300",
    },
  };
  function applyTheme() {
    document.documentElement.setAttribute("data-theme", prefs.theme);
    for (const t of tabs) t.applyPrefs();
  }

  // ---------- tabs ----------
  const tabs = [];
  let active = null;
  let me = null;

  class Tab {
    constructor(spec) {
      this.id = spec.id || newId();
      this.target = spec.target;         // {kind:"local", shell?, cwd?} | {kind:"remote", profile}
      this.name = spec.name || null;     // user label
      this.sessionId = spec.session_id || null; // session to attach to / currently bound
      this.title = this.defaultTitle();  // server title once known
      this.ws = null;
      this.live = false;                 // socket open and bound to a session
      this.manualClose = false;
      this.retries = 0;
      this.retryTimer = null;
      this.pending = null;
      this.started = false;              // has this tab tried to connect yet?
      this.restartNote = false;          // print "new session" note on next open
      this.launch = spec.launch || null; // OpsAPI launch id for the first open only
      this.task = spec.task || null;     // OpsAPI task shown in the banner (this page only)
      this.state = { text: "Not connected", kind: "" };

      this.el = document.createElement("div");
      this.el.className = "terminal hidden";
      $("terminals").appendChild(this.el);
      this.term = new window.Terminal({
        cursorBlink: true,
        fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
        fontSize: prefs.fontSize,
        scrollback: 5000,
        macOptionIsMeta: !!prefs.optionMeta,
        // ⌥ Option+drag (Shift+drag elsewhere) selects text even while a program that uses the
        // mouse (Claude Code, vim, less, tmux) is running.
        macOptionClickForcesSelection: true,
        rightClickSelectsWord: false,
        theme: THEMES[prefs.theme],
      });
      this.fitAddon = new window.FitAddon.FitAddon();
      this.term.loadAddon(this.fitAddon);
      this.term.open(this.el);
      // Right-click on a selection copies it. Caught on the press, before xterm sees it: in a program
      // that uses the mouse xterm would send the press to the program and clear the selection. Without
      // a selection the browser's own menu (Paste) shows as usual.
      let copiedOnPress = false;
      this.el.addEventListener("mousedown", (e) => {
        copiedOnPress = e.button === 2 && this.term.hasSelection();
        if (!copiedOnPress) return;
        e.preventDefault();
        e.stopPropagation();
        copyText(this.term.getSelection());
      }, true);
      this.el.addEventListener("contextmenu", (e) => {
        if (!copiedOnPress && !this.term.hasSelection()) return;
        e.preventDefault();
        e.stopPropagation();
        if (!copiedOnPress) copyText(this.term.getSelection());
        copiedOnPress = false;
      }, true);
      // Keystrokes are only sent while bound to a live session; anything typed while
      // disconnected is dropped, never queued, so nothing is replayed after a reconnect.
      this.term.onData((data) => { if (this.live) this.send({ type: "input", data }); });
      this.term.onBinary((data) => { if (this.live) this.send({ type: "input", data, binary: true }); });
      this.term.onResize(({ cols, rows }) => { if (this.live) this.send({ type: "resize", cols, rows }); });
      this.term.attachCustomKeyEventHandler((e) => shortcut(e));

      this.tabEl = document.createElement("div");
      this.tabEl.className = "tab";
      this.tabEl.setAttribute("role", "tab");
      this.dotEl = document.createElement("span");
      this.dotEl.className = "dot";
      this.labelEl = document.createElement("span");
      this.labelEl.className = "label";
      const close = document.createElement("button");
      close.className = "close";
      close.textContent = "×";
      close.title = "Close tab (ends the session)";
      close.addEventListener("click", (ev) => { ev.stopPropagation(); closeTab(this, true); });
      this.tabEl.append(this.dotEl, this.labelEl, close);
      this.tabEl.addEventListener("click", () => activate(this));
      this.tabEl.addEventListener("dblclick", () => renameTab(this));
      $("tabs").appendChild(this.tabEl);
      this.renderLabel();
    }

    defaultTitle() {
      if (this.target.kind === "remote") {
        const p = me && me.remote.profiles.find((x) => x.id === this.target.profile);
        return p ? p.name : this.target.profile;
      }
      return me ? "This Mac (" + me.host + ")" : "This Mac";
    }
    label() { return this.name || this.title; }
    renderLabel() {
      this.labelEl.textContent = this.label();
      this.tabEl.title = this.name ? this.name + " — " + this.title : this.title;
      this.dotEl.className = "dot " + this.state.kind;
      if (this === active) updateChrome();
    }
    setState(text, kind) {
      this.state = { text, kind };
      this.renderLabel();
    }
    applyPrefs() {
      this.term.options.theme = THEMES[prefs.theme];
      this.term.options.fontSize = prefs.fontSize;
      this.term.options.macOptionIsMeta = !!prefs.optionMeta;
      if (this === active) this.fit();
    }
    fit() {
      if (this.el.classList.contains("hidden") || $("view-term").classList.contains("hidden")) return;
      try { this.fitAddon.fit(); } catch (_) { /* not laid out yet */ }
    }
    send(msg) {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
    }

    /** Attach to the saved session if any, otherwise open a new one for the target. */
    start() {
      this.started = true;
      this.retries = 0;
      if (this.sessionId) this.connect({ attach: this.sessionId });
      else this.connect({ open: this.target });
    }
    connect(pending) {
      this.disconnectSocket();
      this.pending = pending;
      this.manualClose = false;
      clearTimeout(this.retryTimer);
      this.setState("Connecting…", "warn");
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(proto + "//" + location.host + "/ws");
      ws.binaryType = "arraybuffer";
      this.ws = ws;
      ws.onopen = () => ws.send(JSON.stringify({ type: "hello", version: PROTOCOL_VERSION }));
      ws.onmessage = (ev) => {
        if (ws !== this.ws) return;
        if (typeof ev.data !== "string") {
          this.term.write(new Uint8Array(ev.data));
          return;
        }
        let m;
        try { m = JSON.parse(ev.data); } catch (_) { return; }
        this.onMessage(m);
      };
      ws.onclose = () => {
        if (ws !== this.ws) return;
        this.ws = null;
        const wasLive = this.live;
        this.live = false;
        if (this.manualClose) return;
        if ((wasLive && this.sessionId) || this.pending) this.scheduleRetry();
        else this.setState("Disconnected", "");
      };
    }
    disconnectSocket() {
      if (this.ws) {
        this.manualClose = true;
        try { this.ws.close(); } catch (_) { /* ignore */ }
        this.ws = null;
      }
      this.live = false;
    }
    scheduleRetry() {
      this.retries += 1;
      if (this.retries > 8) {
        this.setState("Disconnected (gave up reconnecting)", "err");
        return;
      }
      const delay = Math.min(15000, 500 * Math.pow(2, this.retries - 1));
      this.setState("Connection lost; retrying in " + Math.round(delay / 1000) + "s…", "warn");
      clearTimeout(this.retryTimer);
      this.retryTimer = setTimeout(() => {
        this.connect(this.sessionId ? { attach: this.sessionId } : { open: this.target });
      }, delay);
    }
    /** Detach: the session keeps running on the server and the tab stays. */
    detach() {
      if (!this.live) return;
      this.send({ type: "detach" });
      this.disconnectSocket();
      this.setState("Disconnected (session kept running)", "");
      refreshSessions();
    }
    reconnect() {
      this.retries = 0;
      if (!this.sessionId) this.term.reset();
      this.start();
    }
    destroy() {
      clearTimeout(this.retryTimer);
      this.disconnectSocket();
      this.term.dispose();
      this.el.remove();
      this.tabEl.remove();
    }
    onMessage(m) {
      switch (m.type) {
        case "hello":
          if (!m.authenticated) { toLogin("Your login has expired. Please sign in again."); return; }
          if (this.pending && this.pending.attach) {
            this.send({ type: "attach", session_id: this.pending.attach, cols: this.term.cols, rows: this.term.rows });
          } else if (this.pending && this.pending.open) {
            const msg = { type: "open", target: this.pending.open, cols: this.term.cols, rows: this.term.rows };
            if (this.name) msg.name = this.name;
            if (this.launch) msg.launch = this.launch;
            this.send(msg);
          }
          break;
        case "session_opened": {
          const resumed = m.resumed;
          this.pending = null;
          this.launch = null; // used: later reconnects attach or open a plain shell here
          this.retries = 0;
          this.live = true;
          const changed = this.sessionId !== m.session_id;
          this.sessionId = m.session_id;
          this.title = m.title;
          if (m.name && !this.name) this.name = m.name;
          if (resumed) this.term.reset();
          if (this.restartNote) {
            this.term.write("\x1b[2m[previous session had ended — started a new one]\x1b[0m\r\n");
            this.restartNote = false;
          }
          this.setState(resumed ? "Resumed" : "Connected", "ok");
          if (this === active) { this.term.focus(); this.fit(); }
          this.send({ type: "resize", cols: this.term.cols, rows: this.term.rows });
          if (resumed && this.name && m.name !== this.name) {
            api("PATCH", "/api/sessions/" + encodeURIComponent(this.sessionId), { name: this.name }).catch(() => {});
          }
          if (changed) saveWorkspace();
          refreshSessions();
          break;
        }
        case "session_closed":
          this.live = false;
          this.sessionId = null;
          this.term.write("\r\n\x1b[2m[session closed: " + m.reason +
            (m.exit_code !== null && m.exit_code !== undefined ? ", exit code " + m.exit_code : "") +
            " — press Reconnect for a new session]\x1b[0m\r\n");
          this.setState("Session closed", "");
          this.disconnectSocket();
          saveWorkspace();
          refreshSessions();
          break;
        case "status":
          if (m.state === "detached") {
            // Another window took this session over; don't fight it with auto-retries.
            this.disconnectSocket();
            this.setState("Opened in another window — Reconnect to take it back", "");
            refreshSessions();
          }
          break;
        case "error":
          if (m.code === "no_such_session") {
            // The saved session is gone: start a fresh one for this tab's target.
            this.sessionId = null;
            this.restartNote = true;
            this.term.reset();
            this.connect({ open: this.target });
            return;
          }
          if (m.code === "session_expired" || m.code === "unauthenticated") {
            toLogin("Your login has expired or was revoked.");
            return;
          }
          if (this.pending && (m.code === "open_failed" || m.code === "forbidden")) {
            this.pending = null;
            this.launch = null;
            this.disconnectSocket();
            this.setState("Could not open: " + m.message, "err");
            this.term.write("\r\n\x1b[31m" + m.message + "\x1b[0m\r\n");
          }
          toast(this.label() + ": " + m.message, "error");
          break;
        default:
          break;
      }
    }
  }

  function updateChrome() {
    const t = active;
    $("term-title").textContent = t ? t.label() : "No tab";
    $("term-title").title = t ? (t.name ? t.title + " — double-click to rename" : "Double-click to rename") : "";
    document.title = t ? t.label() + " — sshweb" : "sshweb";
    if (t) setStatus(t.state.text + ": " + t.label(), t.state.kind);
    else setStatus(me ? "Signed in — open a tab" : "Not signed in", "");
    for (const id of ["btn-rename", "btn-clear", "btn-reconnect", "btn-detach", "btn-close"]) $(id).disabled = !t;
    $("empty").classList.toggle("hidden", tabs.length > 0 || !me);
    renderTaskBanner(t);
  }

  // Built with textContent and createElement only: nothing from a link is parsed as HTML.
  function renderTaskBanner(t) {
    const el = $("opsapi-banner");
    if (!el) return;
    el.textContent = "";
    const task = t && t.task;
    el.classList.toggle("hidden", !task);
    if (!task) return;
    const parts = [];
    parts.push("OpsAPI task " + (task.number ? "#" + task.number + " " : "") + task.title);
    if (task.agent) parts.push(task.agent + " in " + task.cwd);
    if (task.by) parts.push("opened by " + task.by);
    el.append(parts.join(" · "));
    if (/^https?:\/\//.test(task.url || "")) {
      const a = document.createElement("a");
      a.href = task.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = "Back to task";
      el.append(" · ", a);
    }
  }

  function activate(tab) {
    active = tab || null;
    for (const t of tabs) {
      t.el.classList.toggle("hidden", t !== active);
      t.tabEl.classList.toggle("active", t === active);
      t.tabEl.setAttribute("aria-selected", t === active ? "true" : "false");
    }
    updateChrome();
    if (active) {
      active.fit();
      active.term.focus();
      if (!active.started) active.start();
    }
    saveWorkspace();
  }

  function addTab(spec, makeActive) {
    if (tabs.length >= 16) { toast("At most 16 tabs", "error"); return null; }
    const t = new Tab(spec);
    tabs.push(t);
    if (makeActive) activate(t);
    else updateChrome();
    return t;
  }

  function closeTab(tab, endSession) {
    if (endSession && tab.sessionId) {
      if (!confirm("Close “" + tab.label() + "”? Its session will be ended and running programs terminated.")) return;
      if (tab.live) tab.send({ type: "close" });
      else api("DELETE", "/api/sessions/" + encodeURIComponent(tab.sessionId)).catch(() => {});
    }
    const i = tabs.indexOf(tab);
    tabs.splice(i, 1);
    tab.tabEl.remove();
    tab.el.classList.add("hidden");
    // Give the close message a moment to go out before dropping the socket.
    setTimeout(() => tab.destroy(), 300);
    if (active === tab) activate(tabs[Math.min(i, tabs.length - 1)] || null);
    else { updateChrome(); saveWorkspace(); }
    setTimeout(refreshSessions, 500);
  }

  function disposeAllTabs() {
    for (const t of tabs.splice(0)) t.destroy();
    active = null;
  }

  // ---------- workspace persistence ----------
  let saveTimer = null;
  let restoring = false;
  function saveWorkspace() {
    if (restoring || !me) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      const body = {
        tabs: tabs.map((t) => ({ id: t.id, target: t.target, name: t.name, session_id: t.sessionId })),
        active: active ? active.id : null,
      };
      try { await api("PUT", "/api/workspace", body); } catch (e) {
        if (e.status !== 401) toast("Could not save tabs: " + e.message, "error");
      }
    }, 400);
  }

  function targetAllowed(target) {
    if (!me) return false;
    if (target.kind === "local") return me.local.enabled;
    if (target.kind === "remote") return me.remote.profiles.some((p) => p.id === target.profile);
    return false;
  }

  async function restoreWorkspace() {
    let ws, live;
    try {
      [ws, live] = await Promise.all([api("GET", "/api/workspace"), api("GET", "/api/sessions")]);
    } catch (e) {
      toast("Could not load saved tabs: " + e.message, "error");
      return;
    }
    const alive = new Set(live.sessions.map((s) => s.id));
    restoring = true;
    let toActivate = null;
    for (const spec of ws.tabs) {
      if (!targetAllowed(spec.target)) continue; // access may have changed since
      const sessionAlive = !!spec.session_id && alive.has(spec.session_id);
      const t = addTab(Object.assign({}, spec, { session_id: sessionAlive ? spec.session_id : null }), false);
      if (!t) break;
      if (spec.session_id && !sessionAlive) t.restartNote = true;
      if (sessionAlive) t.start(); // re-attach running sessions right away
      if (spec.id === ws.active) toActivate = t;
    }
    restoring = false;
    // A task link is waiting: its tab opens next, so don't start a restored tab's shell for nothing.
    if (launchTicket && !launchHandled) updateChrome();
    else activate(toActivate || tabs[0] || null);
    if (tabs.length) toast("Restored " + tabs.length + " tab" + (tabs.length > 1 ? "s" : ""), "ok");
  }

  // ---------- renaming ----------
  async function renameTab(tab) {
    const v = window.prompt("Name this tab (leave empty to reset):", tab.name || "");
    if (v === null) return;
    const name = v.trim() || null;
    if (name && name.length > 64) { toast("Name must be at most 64 characters", "error"); return; }
    if (tab.sessionId) {
      try {
        const r = await api("PATCH", "/api/sessions/" + encodeURIComponent(tab.sessionId), { name: v });
        tab.name = r.name;
      } catch (e) {
        if (e.status !== 404) { toast(e.message, "error"); return; }
        tab.name = name;
      }
    } else {
      tab.name = name;
    }
    tab.renderLabel();
    saveWorkspace();
    refreshSessions();
  }

  // ---------- keyboard shortcuts ----------
  function shortcut(e) {
    if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey || !active) return true;
    const k = e.key.toLowerCase();
    if (k === "k") { active.term.clear(); e.preventDefault(); return false; }
    if (k === "u") { active.reconnect(); e.preventDefault(); return false; }
    if (k === "x") { active.detach(); e.preventDefault(); return false; }
    return true;
  }

  // ---------- session list ----------
  // `background`: the timer's refresh, which the server doesn't count as activity, so a page left
  // open still lets the login go idle. Typing in a terminal counts.
  async function refreshSessions(background) {
    if (!me) return;
    let data;
    const poll = background === true ? { "X-Sshweb-Poll": "1" } : undefined;
    try { data = await api("GET", "/api/sessions", undefined, poll); } catch (e) {
      if (e.status === 401) toLogin("Please sign in.");
      return;
    }
    const ul = $("session-list");
    ul.textContent = "";
    if (!data.sessions.length) {
      const li = document.createElement("li");
      li.className = "muted small";
      li.textContent = "No running sessions";
      li.style.cursor = "default";
      ul.appendChild(li);
      return;
    }
    for (const s of data.sessions) {
      const owner = tabs.find((t) => t.sessionId === s.id);
      const li = document.createElement("li");
      if (owner && owner === active) li.classList.add("current");
      const meta = document.createElement("div");
      meta.className = "meta";
      const name = document.createElement("div");
      name.className = "name";
      name.textContent = s.name || s.title;
      name.title = s.name ? s.name + " — " + s.title : s.title;
      const sub = document.createElement("div");
      sub.className = "small muted";
      sub.textContent = s.kind + " · " + s.cols + "×" + s.rows + " · idle " + s.idle_secs + "s";
      meta.append(name, sub);
      const badge = document.createElement("span");
      badge.className = "badge " + (owner ? "intab" : s.state);
      badge.textContent = owner ? "tab" : s.state;
      const x = document.createElement("button");
      x.className = "ghost small";
      x.textContent = "×";
      x.title = "End session";
      x.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (!confirm("End this session? Running programs will be terminated.")) return;
        try { await api("DELETE", "/api/sessions/" + encodeURIComponent(s.id)); } catch (e) { toast(e.message, "error"); }
        setTimeout(refreshSessions, 300);
      });
      li.append(meta, badge, x);
      li.title = owner ? "Show its tab" : "Open in a new tab";
      li.addEventListener("click", () => {
        if (owner) { activate(owner); return; }
        const target = s.kind === "remote" && s.profile ? { kind: "remote", profile: s.profile } : { kind: "local" };
        addTab({ target, name: s.name, session_id: s.id }, true);
      });
      ul.appendChild(li);
    }
  }

  // ---------- targets & settings ----------
  function renderTargets() {
    const sel = $("target");
    sel.textContent = "";
    if (me.local.enabled) sel.add(new Option("This Mac (" + me.host + ")", "local"));
    for (const p of me.remote.profiles) sel.add(new Option(p.name + " — " + p.user + "@" + p.host, "remote:" + p.id));
    const any = sel.options.length > 0;
    $("btn-connect").disabled = !any;
    $("btn-newtab").disabled = !any;
    if (!any) sel.add(new Option("No targets permitted", ""));
    const shell = $("shell");
    shell.textContent = "";
    for (const s of me.local.shells) shell.add(new Option(s, s, s === me.local.default_shell, s === me.local.default_shell));
    onTargetChange();

    const info = $("access-info");
    info.textContent = "";
    const rows = [
      ["User", me.user],
      ["Access", me.access],
      ["Key", me.key_fingerprint],
      ["Login expires", new Date(me.expires_unix * 1000).toLocaleString()],
      ["Max sessions", String(me.limits.max_per_user)],
      ["Sessions kept after the browser closes", Math.round(me.limits.detach_grace_secs / 60) + " min"],
    ];
    for (const [k, v] of rows) {
      const a = document.createElement("span"); a.className = "muted"; a.textContent = k;
      const b = document.createElement("span"); b.textContent = v;
      info.append(a, b);
    }
    const tb = $("profile-rows");
    tb.textContent = "";
    const all = [];
    if (me.local.enabled) all.push(["Local terminal", me.host + " (" + me.local.shells.join(", ") + ")"]);
    for (const p of me.remote.profiles) all.push([p.name + " (" + p.id + ")", p.user + "@" + p.host + ":" + p.port]);
    if (!all.length) all.push(["—", "No profiles permitted"]);
    for (const [a, b] of all) {
      const tr = document.createElement("tr");
      const t1 = document.createElement("td"); t1.textContent = a;
      const t2 = document.createElement("td"); t2.textContent = b;
      tr.append(t1, t2);
      tb.appendChild(tr);
    }
  }
  function onTargetChange() {
    const v = $("target").value;
    $("shell-row").classList.toggle("hidden", v !== "local");
    const p = me && me.remote.profiles.find((x) => "remote:" + x.id === v);
    $("target-info").textContent = p ? p.user + "@" + p.host + ":" + p.port : "";
  }
  $("target").addEventListener("change", onTargetChange);

  function selectedTarget() {
    const v = $("target").value;
    if (v === "local") {
      const shell = $("shell").value;
      return shell && shell !== me.local.default_shell ? { kind: "local", shell } : { kind: "local" };
    }
    if (v.startsWith("remote:")) return { kind: "remote", profile: v.slice(7) };
    return null;
  }

  function openNewTab() {
    const t = selectedTarget();
    if (t) addTab({ target: t }, true);
  }
  $("btn-connect").addEventListener("click", openNewTab);
  $("btn-newtab").addEventListener("click", openNewTab);
  $("btn-refresh").addEventListener("click", () => refreshSessions());
  $("btn-rename").addEventListener("click", () => { if (active) renameTab(active); });
  $("term-title").addEventListener("dblclick", () => { if (active) renameTab(active); });
  $("btn-clear").addEventListener("click", () => { if (active) { active.term.clear(); active.term.focus(); } });
  $("btn-reconnect").addEventListener("click", () => { if (active) active.reconnect(); });
  $("btn-detach").addEventListener("click", () => { if (active) active.detach(); });
  $("btn-close").addEventListener("click", () => { if (active) closeTab(active, true); });
  $("btn-theme").addEventListener("click", () => {
    prefs.theme = prefs.theme === "dark" ? "light" : "dark";
    $("set-theme").value = prefs.theme;
    savePrefs();
    applyTheme();
  });
  $("btn-settings").addEventListener("click", () => show("settings"));
  $("btn-terminal-view").addEventListener("click", () => show("term"));
  $("set-theme").addEventListener("change", (e) => { prefs.theme = e.target.value; savePrefs(); applyTheme(); });
  $("set-font").addEventListener("change", (e) => {
    const n = Math.min(28, Math.max(9, parseInt(e.target.value, 10) || 14));
    prefs.fontSize = n; e.target.value = n; savePrefs(); applyTheme();
  });
  $("set-meta").addEventListener("change", (e) => { prefs.optionMeta = e.target.checked; savePrefs(); applyTheme(); });
  $("btn-logout").addEventListener("click", async () => {
    if (!confirm("Log out? Sessions started from this login are ended; your tab list is kept.")) return;
    disposeAllTabs();
    try { await api("POST", "/api/auth/logout"); } catch (_) { /* ignore */ }
    toLogin("Signed out.");
  });

  let resizeTimer = null;
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (active) active.fit(); }, 60);
  }).observe($("terminals"));

  // ---------- login ----------
  let challenge = null;
  let expiryTimer = null;

  function toLogin(msg) {
    // Sessions keep running on the server (detached) and are re-attached after signing in.
    disposeAllTabs();
    me = null;
    show("login");
    updateChrome();
    setStatus("Not signed in", "");
    $("login-error").textContent = msg || "";
    const waiting = launchTicket && !launchHandled ? launchPreview() : null;
    $("login-launch").textContent = waiting
      ? "Sign in to start work on " + (waiting.number ? "#" + waiting.number + " " : "") + waiting.title + "."
      : "";
    $("login-launch").classList.toggle("hidden", !waiting);
    $("challenge-step").classList.add("hidden");
    ($("login-user").value ? $("login-file") : $("login-user")).focus();
  }

  // The usual way: pick the key file, type its passphrase; this page signs the challenge (keysign.js).
  $("form-keyfile").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("login-error").textContent = "";
    const user = $("login-user").value.trim();
    const file = $("login-file").files[0];
    if (!file) { $("login-error").textContent = "Pick your key file."; return; }
    $("btn-keyfile").disabled = true;
    $("keyfile-busy").textContent = "Opening your key…";
    try {
      const key = await window.KeySign.openKey(await file.text(), $("login-pass").value);
      $("keyfile-busy").textContent = "Signing in…";
      const ch = await api("POST", "/api/auth/challenge", { user });
      const signature = await window.KeySign.sign(key, ch.message, ch.namespace);
      await api("POST", "/api/auth/verify", { challenge_id: ch.challenge_id, signature });
    } catch (err) {
      $("login-error").textContent = err.code === "auth_failed"
        ? "That key doesn't belong to “" + user + "”. Check your user name and key file, or ask your manager for a new key."
        : err.message;
      return;
    } finally {
      $("btn-keyfile").disabled = false;
      $("keyfile-busy").textContent = "";
    }
    try { localStorage.setItem("sshweb.lastUser", user); } catch (_) { /* ignore */ }
    $("login-pass").value = "";
    await enter();
  });

  $("form-user").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("login-error").textContent = "";
    const user = $("login-user").value.trim();
    if (!user) { $("login-error").textContent = "Type your user name first."; $("login-user").focus(); return; }
    try {
      challenge = await api("POST", "/api/auth/challenge", { user });
    } catch (err) {
      $("login-error").textContent = err.message;
      return;
    }
    try { localStorage.setItem("sshweb.lastUser", user); localStorage.setItem("sshweb.keyPath", $("login-key").value); } catch (_) { /* ignore */ }
    const key = $("login-key").value.trim() || "~/.ssh/id_ed25519";
    const keyArg = key.startsWith("~/") ? "~/" + shellQuote(key.slice(2)) : shellQuote(key);
    $("sign-cmd").textContent = "printf '%s' " + shellQuote(challenge.message) +
      " | ssh-keygen -Y sign -n " + challenge.namespace + " -f " + keyArg + " | pbcopy";
    $("alt-cmd").textContent = "sshweb sign -f " + keyArg + " " + shellQuote(challenge.message);
    $("challenge-step").classList.remove("hidden");
    $("login-sig").value = "";
    $("login-sig").focus();
    clearInterval(expiryTimer);
    const tick = () => {
      const left = challenge.expires_unix - Math.floor(Date.now() / 1000);
      $("challenge-expiry").textContent = left > 0 ? "Challenge expires in " + left + "s" : "Challenge expired — request a new one";
      if (left <= 0) clearInterval(expiryTimer);
    };
    tick();
    expiryTimer = setInterval(tick, 1000);
  });

  $("btn-copy-cmd").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("sign-cmd").textContent);
      toast("Command copied", "ok");
    } catch (_) {
      const r = document.createRange();
      r.selectNodeContents($("sign-cmd"));
      const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      toast("Selected; press ⌘C to copy");
    }
  });

  $("form-sig").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!challenge) return;
    $("login-error").textContent = "";
    try {
      await api("POST", "/api/auth/verify", { challenge_id: challenge.challenge_id, signature: $("login-sig").value });
    } catch (err) {
      challenge = null;
      $("challenge-step").classList.add("hidden");
      $("login-error").textContent = err.message + (err.code === "auth_failed" ? " — request a new challenge and try again." : "");
      return;
    }
    clearInterval(expiryTimer);
    $("login-sig").value = "";
    challenge = null;
    await enter();
  });

  async function enter() {
    try {
      me = await api("GET", "/api/me");
    } catch (e) {
      me = null;
      if (e.status !== 401) { toLogin(e.message); return; }
      const auto = await autoLogin();
      if (auto === true) { await enter(); return; }
      toLogin(auto || "");
      return;
    }
    $("who").textContent = me.user;
    renderTargets();
    show("term");
    updateChrome();
    await restoreWorkspace();
    if (launchTicket && !launchHandled) await openLaunch();
    refreshSessions();
  }

  /** Sign in with a waiting OpsAPI link that asks for it (once). True when signed in; otherwise
   *  a one-line reason for the sign-in screen, or null when the link doesn't ask. */
  async function autoLogin() {
    if (!launchTicket || launchHandled || autoLoginTried) return null;
    autoLoginTried = true;
    const c = launchClaims();
    if (!c || !c.login) return null;
    setStatus("Signing you in from OpsAPI…", "");
    try {
      await api("POST", "/api/launch/login", { ticket: launchTicket });
      return true;
    } catch (e) {
      return "Couldn't sign you in automatically: " + e.message;
    }
  }

  /** Open the tab an OpsAPI task link asks for (after sign-in; the server checks everything). */
  async function openLaunch() {
    launchHandled = true;
    history.replaceState(null, "", location.pathname + location.search);
    let r;
    try {
      r = await api("POST", "/api/launch", { ticket: launchTicket });
    } catch (e) {
      toast("Couldn't open the task: " + e.message, "error");
      return;
    }
    const task = {
      number: r.task.number, title: r.task.title, url: r.task.url,
      by: r.by, agent: r.agent.name, cwd: r.cwd,
    };
    const target = { kind: "local", cwd: r.cwd };
    if (r.session_id) { // reload of a link that already opened a running session
      const t = tabs.find((x) => x.sessionId === r.session_id);
      if (t) { t.task = task; activate(t); return; }
      addTab({ target, name: r.name, session_id: r.session_id, task }, true);
      return;
    }
    if (r.used) {
      toast("This task link was already used, so the agent isn't started again. Opening the folder.", "");
      addTab({ target, name: r.name, task }, true);
      return;
    }
    addTab({ target, name: r.name, launch: r.launch, task }, true);
  }

  // ---------- init ----------
  $("set-theme").value = prefs.theme;
  $("set-font").value = prefs.fontSize;
  $("set-meta").checked = !!prefs.optionMeta;
  if (!IS_MAC) $("select-hint").textContent = $("select-hint").textContent.replace("⌥ Option", "Shift");
  $("select-hint").title = $("select-hint").textContent;
  document.documentElement.setAttribute("data-theme", prefs.theme);
  try {
    // A link from OpsAPI can name the user (?user=…), so people only pick their key file.
    const linked = new URLSearchParams(location.search).get("user");
    $("login-user").value = (linked && /^[a-z_][a-z0-9_.-]{0,31}$/.test(linked) ? linked : "") ||
      localStorage.getItem("sshweb.lastUser") || "";
    $("login-key").value = localStorage.getItem("sshweb.keyPath") || "~/.ssh/id_ed25519";
  } catch (_) { /* ignore */ }
  window.addEventListener("online", () => {
    for (const t of tabs) if (t.started && !t.ws && t.sessionId) t.reconnect();
  });
  setInterval(() => { if (me) refreshSessions(true); }, 15000);
  enter();
})();
