// Siftlog dashboard. No framework and no build step.
//
// Security rule for this file: everything shown here that came from a log
// (usernames, raw lines, addresses) is attacker-controlled. Data is only ever
// inserted as TEXT, through h() below, which uses text nodes. Never assign
// strings to markup-parsing properties, and never evaluate strings as code.
// A test checks this file for those APIs.
"use strict";

(function () {
  const TOKEN_KEY = "siftlog.token";
  const REFRESH_MS = 5000;
  const state = { tab: "overview", selected: null, rules: [], commandsLoaded: false, filtersBuilt: false };
  let memoryToken = "";

  // --- DOM helpers -----------------------------------------------------------

  const $ = (id) => document.getElementById(id);

  // h("td", {class: "num"}, 42) -> <td class="num">42</td>. Children become text nodes.
  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function replace(target, ...children) {
    target.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
    return target;
  }

  function when(iso) {
    if (!iso) return "";
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? String(iso) : date.toISOString().slice(0, 19).replace("T", " ") + " UTC";
  }

  const badge = (kind, value) => h("span", { class: `badge ${kind}-${value}` }, value);

  // The last three only come from a honeypot: a real sshd does not log what a user types.
  const EVENT_TYPES = [
    ["auth_failure", "Failed login"], ["auth_success", "Successful login"], ["invalid_user", "Unknown username"],
    ["connection", "Connection"], ["command", "Command"], ["file_transfer", "File transfer"],
  ];
  const typeName = (type) => (EVENT_TYPES.find(([value]) => value === type) || [type, type])[1];

  // What the "Log line" column shows. A honeypot's line is a long JSON record, so the
  // part a person wants is picked out of it; the full line is the cell's tooltip.
  // Every value here was typed by an attacker. It is returned as a string and shown as text.
  function logLine(event) {
    const extra = event.extra || {};
    const text = (value) => (typeof value === "string" ? value : "");
    if (event.source !== "cowrie") return event.raw;
    if (event.event_type === "command") return "$ " + text(extra.input);
    if (event.event_type === "connection") return "connected";
    if (event.event_type === "file_transfer") {
      // "written" has neither a name nor a URL: it is a file a shell command created, at destfile.
      const what = text(extra.filename) || text(extra.url) || text(extra.destfile);
      const failed = event.outcome === "failure" ? " failed" : "";
      return `${text(extra.direction) || "transfer"}${failed}: ${what}` + (text(extra.shasum) ? `  sha256 ${extra.shasum}` : "");
    }
    if (typeof extra.password === "string") return "password: " + extra.password;
    if (typeof extra.fingerprint === "string") return "key: " + extra.fingerprint;
    return event.raw;
  }

  const logCell = (event) => h("td", { class: "mono raw", title: event.raw }, logLine(event));

  function table(headers, rows, emptyText) {
    if (!rows.length) return h("p", { class: "muted" }, emptyText || "Nothing to show.");
    return h(
      "div",
      { class: "scroll" },
      h(
        "table",
        null,
        h("thead", null, h("tr", null, headers.map((head) => h("th", { class: head.num ? "num" : null }, head.label)))),
        h("tbody", null, rows)
      )
    );
  }

  // --- token -----------------------------------------------------------------

  function token() {
    try {
      return sessionStorage.getItem(TOKEN_KEY) || memoryToken;
    } catch (error) {
      return memoryToken;
    }
  }

  function setToken(value) {
    memoryToken = value;
    try {
      if (value) sessionStorage.setItem(TOKEN_KEY, value);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch (error) {
      /* storage unavailable: the in-memory copy still works for this page */
    }
  }

  // The server prints a link ending in #token=... The fragment never leaves the
  // browser. Keep the token for this tab and take it out of the address bar.
  function takeTokenFromAddress() {
    const match = window.location.hash.match(/^#token=([^&]+)/);
    if (!match) return;
    setToken(decodeURIComponent(match[1]));
    window.history.replaceState(null, "", window.location.pathname);
  }

  // --- talking to the API ----------------------------------------------------

  function showError(message) {
    const box = $("error");
    box.textContent = message || "";
    box.hidden = !message;
  }

  async function api(path, options) {
    const settings = Object.assign({}, options);
    settings.headers = Object.assign({ Authorization: `Bearer ${token()}` }, settings.headers);
    if (settings.body) settings.headers["Content-Type"] = "application/json";
    const response = await fetch(path, settings);
    if (response.status === 401) {
      showSignIn(token() ? "That token was not accepted. Copy the whole token and try again." : "");
      throw new Error("not signed in");
    }
    if (!response.ok) {
      let detail = response.statusText;
      try {
        detail = JSON.stringify((await response.json()).detail);
      } catch (error) {
        /* not JSON: keep the status text */
      }
      throw new Error(`${response.status} ${detail}`);
    }
    return response.json();
  }

  async function run(task) {
    try {
      await task();
      showError("");
      $("updated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      if (error.message !== "not signed in") showError(error.message);
    }
  }

  // --- sign in ---------------------------------------------------------------

  function showSignIn(message) {
    for (const name of ["overview", "alerts", "events", "commands"]) $(name).hidden = true;
    $("signin").hidden = false;
    $("signin-message").textContent = message || "";
    $("signin-message").hidden = !message;
  }

  $("signin-form").addEventListener("submit", (event) => {
    event.preventDefault();
    setToken($("token-input").value.trim());
    $("token-input").value = "";
    show(state.tab);
  });

  // --- tabs ------------------------------------------------------------------

  function show(tab) {
    state.tab = tab;
    $("signin").hidden = true;
    for (const button of $("tabs").querySelectorAll("button")) {
      if (button.dataset.tab === tab) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    for (const name of ["overview", "alerts", "events", "commands"]) $(name).hidden = name !== tab;
    if (!token()) return showSignIn("");
    refresh();
  }

  function refresh() {
    if (state.tab === "overview") return run(loadOverview);
    if (state.tab === "alerts") return run(loadAlerts);
    if (state.tab === "events") return run(loadEvents);
    return run(loadCommands);
  }

  for (const button of $("tabs").querySelectorAll("button")) {
    button.addEventListener("click", () => show(button.dataset.tab));
  }

  // --- overview --------------------------------------------------------------

  async function loadOverview() {
    const [stats, rules, honeypot] = await Promise.all([api("/stats"), api("/rules"), api("/honeypot")]);
    state.rules = rules;
    const status = stats.alerts.by_status;
    const card = (value, label) => h("div", { class: "card" }, h("div", { class: "value" }, value), h("div", { class: "label" }, label));

    const days = stats.alerts_over_time;
    const most = Math.max(1, ...days.map((d) => d.alerts));
    const dayBars = days.length
      ? h("div", { class: "bars" }, days.map((d) => [
          h("span", { class: "mono" }, d.day),
          h("div", { class: "bar", "data-width": d.alerts / most }),
          h("span", { class: "num" }, d.alerts),
        ]))
      : h("p", { class: "muted" }, "No alerts yet.");

    replace(
      $("overview"),
      h("div", { class: "cards" },
        card(stats.events.total.toLocaleString(), "Events stored"),
        card(status.open || 0, "Open alerts"),
        card(status.ack || 0, "Acknowledged"),
        card(status.closed || 0, "Closed"),
        card(stats.events.dead_letters, "Lines not understood")
      ),
      h("p", { class: "muted small" }, stats.events.first
        ? `Data from ${when(stats.events.first)} to ${when(stats.events.last)}.`
        : "No events stored yet. The Commands tab shows how to load some."),
      honeypotPanel(honeypot),
      h("div", { class: "columns" },
        h("div", { class: "panel" }, h("h2", null, "Alerts by rule"),
          table(
            [{ label: "Rule" }, { label: "Severity" }, { label: "Alerts", num: true }],
            rules.map((rule) => h("tr", { class: "clickable", onclick: () => openAlertsFor(rule.id) },
              h("td", null, rule.title, h("div", { class: "muted small mono" }, rule.id)),
              h("td", null, badge("sev", rule.severity)),
              h("td", { class: "num" }, rule.alerts)))
          )),
        h("div", { class: "panel" }, h("h2", null, "Busiest sources of failed logins"),
          h("p", { class: "muted small" }, "Worth a look even when no rule fired: a slow attacker shows up here first."),
          table(
            [{ label: "Address" }, { label: "Failures", num: true }],
            stats.top_sources.map((source) => h("tr", { class: "clickable", onclick: () => openEventsFor(source.src_ip) },
              h("td", { class: "mono" }, source.src_ip),
              h("td", { class: "num" }, source.failures.toLocaleString()))),
            "No failed logins stored."
          )),
        h("div", { class: "panel" }, h("h2", null, "Events by type"),
          table(
            [{ label: "Type" }, { label: "Events", num: true }],
            Object.entries(stats.events.by_type).sort((a, b) => b[1] - a[1]).map(([type, count]) =>
              h("tr", { class: "clickable", onclick: () => openEventsFor("", type) },
                h("td", null, typeName(type)),
                h("td", { class: "num" }, count.toLocaleString()))),
            "No events stored."
          )),
        h("div", { class: "panel" }, h("h2", null, "Alerts by day they started"), dayBars)
      )
    );
    // Bar widths are set through the style object, not a style attribute, so the
    // page's content security policy can forbid inline styles outright.
    for (const bar of $("overview").querySelectorAll(".bar")) {
      bar.style.width = Math.max(2, Number(bar.dataset.width) * 100) + "%";
    }
  }

  function honeypotPanel(status) {
    // Built with h() throughout: it skips missing pieces, where append() would print "null".
    if (!status.configured) {
      return h("div", { class: "panel" }, h("h2", null, "Honeypot"),
        h("p", { class: "muted" },
          "Not set up on this machine. Put its address in a file named siftlog.local.json in the project folder, for example ",
          h("code", null, '{"honeypot_host": "192.0.2.10"}'), ", then restart the server."));
    }
    const names = { honeypot: "Honeypot (port 22)", admin: "Your admin login" };
    const rows = status.checks.map((check) => h("tr", null,
      h("td", null, names[check.role] || check.role),
      h("td", { class: "mono" }, check.port),
      h("td", null, h("span", { class: "badge " + (check.open ? "st-closed" : "st-open") }, check.open ? "answering" : "no answer")),
      h("td", { class: "mono raw" }, check.banner)));
    const button = h("button", { type: "button" }, "Check now");
    const panel = h("div", { class: "panel" },
      h("h2", null, "Honeypot"),
      h("p", null, h("span", { class: "mono" }, status.host), " ",
        h("span", { class: "muted small" }, status.checked_at ? `checked ${when(status.checked_at)}` : "not checked yet")),
      rows.length ? table([{ label: "What" }, { label: "Port" }, { label: "State" }, { label: "It says it is" }], rows) : null,
      h("div", { class: "actions" }, button),
      h("p", { class: "muted small" },
        "Each check is a real connection, which the honeypot records like any other visitor, so it only runs when you ask."));
    button.addEventListener("click", () => run(async () => {
      button.disabled = true;
      button.textContent = "Checking…";
      panel.replaceWith(honeypotPanel(await api("/honeypot/check", { method: "POST" })));
    }));
    return panel;
  }

  // --- alerts ----------------------------------------------------------------

  function select(id, label, options) {
    const control = h("select", { id, onchange: () => run(loadAlerts) },
      options.map(([value, text]) => h("option", { value }, text)));
    return h("label", null, label, control);
  }

  function buildAlertFilters() {
    const ruleOptions = [["", "Any rule"]].concat(state.rules.map((rule) => [rule.id, rule.title]));
    replace($("alert-filters"),
      select("f-status", "Status", [["", "Any status"], ["open", "Open"], ["ack", "Acknowledged"], ["closed", "Closed"]]),
      select("f-severity", "Severity", [["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]),
      select("f-rule", "Rule", ruleOptions));
    state.filtersBuilt = true;
  }

  async function loadAlerts() {
    if (!state.filtersBuilt) {
      if (!state.rules.length) state.rules = await api("/rules");
      buildAlertFilters();
      if (state.pendingRule) $("f-rule").value = state.pendingRule;
      state.pendingRule = null;
    }
    const query = new URLSearchParams({ limit: "200" });
    for (const [param, id] of [["status", "f-status"], ["severity", "f-severity"], ["rule_id", "f-rule"]]) {
      if ($(id).value) query.set(param, $(id).value);
    }
    const page = await api("/alerts?" + query.toString());
    const rows = page.alerts.map((alert) => h("tr", {
      class: "clickable" + (alert.id === state.selected ? " selected" : ""),
      onclick: () => { state.selected = alert.id; run(async () => { await loadAlerts(); await openAlert(alert.id); }); },
    },
      h("td", null, badge("sev", alert.severity)),
      h("td", null, alert.title, h("div", { class: "muted small mono" }, alert.group_key)),
      h("td", { class: "nowrap" }, when(alert.last_seen)),
      h("td", { class: "num" }, alert.event_count.toLocaleString()),
      h("td", null, badge("st", alert.status))));
    replace($("alert-list"), h("div", { class: "panel" },
      h("h2", null, `${page.total} alert${page.total === 1 ? "" : "s"}`),
      table([{ label: "Severity" }, { label: "What and who" }, { label: "Last activity" }, { label: "Events", num: true }, { label: "Status" }],
        rows, "No alerts match. The Commands tab shows how to generate some.")));
    if (!state.selected) replace($("alert-detail"), h("div", { class: "panel muted" }, "Select an alert to see why it fired."));
  }

  async function openAlert(id) {
    const detail = await api(`/alerts/${encodeURIComponent(id)}?evidence_limit=200`);
    const note = h("input", { type: "text", placeholder: "Note (optional): what you found or did", maxlength: 2000, value: "" });
    const decide = (status) => run(async () => {
      await api(`/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ status, note: note.value }) });
      await loadAlerts();
      await openAlert(id);
    });
    const action = (status, label) => h("button", {
      type: "button", class: status === "ack" ? "primary" : null, disabled: detail.status === status, onclick: () => decide(status),
    }, label);

    replace($("alert-detail"), h("div", { class: "panel" },
      h("h2", null, detail.title),
      h("div", null, badge("sev", detail.severity), " ", badge("st", detail.status),
        detail.superseded ? h("span", { class: "muted small" }, " no longer produced by the current rules") : null),
      detail.summary ? h("p", { class: "note" }, detail.summary) : null,
      h("dl", { class: "facts" },
        h("dt", null, "Who"), h("dd", { class: "mono" }, detail.group_key),
        h("dt", null, "Rule"), h("dd", { class: "mono" }, detail.rule_id),
        h("dt", null, "First seen"), h("dd", null, when(detail.first_seen)),
        h("dt", null, "Last activity"), h("dd", null, when(detail.last_seen)),
        h("dt", null, "Events"), h("dd", null, detail.event_count.toLocaleString(),
          detail.distinct_count === null ? "" : ` (${detail.distinct_count} distinct)`),
        detail.mitre.length ? [h("dt", null, "MITRE ATT&CK"), h("dd", { class: "mono" }, detail.mitre.join(", "))] : null,
        detail.note ? [h("dt", null, "Latest note"), h("dd", null, detail.note)] : null),
      h("div", { class: "actions" }, note, action("ack", "Acknowledge"), action("closed", "Close"), action("open", "Reopen")),
      h("h3", null, "History"),
      detail.history.length
        ? table([{ label: "When" }, { label: "Change" }, { label: "By" }, { label: "Note" }],
            detail.history.map((entry) => h("tr", null,
              h("td", { class: "nowrap" }, when(entry.changed_at)),
              h("td", null, `${entry.old_status} → ${entry.new_status}`),
              h("td", null, entry.actor),
              h("td", null, entry.note))))
        : h("p", { class: "muted" }, "No decisions recorded yet."),
      h("h3", null, `Evidence: ${detail.evidence.length} of ${detail.evidence_total} events`),
      table([{ label: "When" }, { label: "Type" }, { label: "User" }, { label: "Address" }, { label: "Log line" }],
        detail.evidence.map((event) => h("tr", null,
          h("td", { class: "nowrap" }, when(event.timestamp)),
          h("td", null, typeName(event.event_type)),
          h("td", { class: "mono" }, event.username),
          h("td", { class: "mono" }, event.src_ip, event.geo && event.geo.city ? h("div", { class: "muted small" }, event.geo.city) : null),
          logCell(event))),
        "The evidence events are no longer stored.")));
  }

  function openAlertsFor(ruleId) {
    state.pendingRule = ruleId;
    if (state.filtersBuilt) $("f-rule").value = ruleId;
    show("alerts");
  }

  // --- events ----------------------------------------------------------------

  function buildEventFilters() {
    if ($("e-address")) return;
    const field = (id, label) => h("label", null, label, h("input", { id, type: "text", autocomplete: "off", spellcheck: "false" }));
    replace($("event-filters"),
      field("e-address", "Address"),
      field("e-user", "Username"),
      h("label", null, "Type", h("select", { id: "e-type" },
        [["", "Any type"]].concat(EVENT_TYPES).map(([value, text]) => h("option", { value }, text)))),
      h("label", { class: "inline" }, h("input", { id: "e-newest", type: "checkbox", checked: true }), "Newest first"),
      h("button", { type: "submit", class: "primary" }, "Search"));
    $("event-filters").addEventListener("submit", (event) => { event.preventDefault(); run(loadEvents); });
  }

  async function loadEvents() {
    buildEventFilters();
    const query = new URLSearchParams({ limit: "200", newest_first: $("e-newest").checked ? "true" : "false" });
    for (const [param, id] of [["src_ip", "e-address"], ["username", "e-user"], ["event_type", "e-type"]]) {
      const value = $(id).value.trim();
      if (value) query.set(param, value);
    }
    const page = await api("/events?" + query.toString());
    replace($("event-results"), h("div", { class: "panel" },
      h("h2", null, `Showing ${page.events.length.toLocaleString()} of ${page.total.toLocaleString()} matching events`),
      table([{ label: "When" }, { label: "Type" }, { label: "User" }, { label: "Address" }, { label: "Count", num: true }, { label: "Log line" }],
        page.events.map((event) => h("tr", null,
          h("td", { class: "nowrap" }, when(event.timestamp)),
          h("td", null, typeName(event.event_type)),
          h("td", { class: "mono" }, event.username),
          h("td", { class: "mono" }, event.src_ip),
          h("td", { class: "num" }, event.count),
          logCell(event))),
        "No events match.")));
  }

  function openEventsFor(address, type) {
    buildEventFilters();
    $("e-address").value = address;
    $("e-user").value = "";
    $("e-type").value = type || "";
    show("events");
  }

  // --- commands --------------------------------------------------------------

  async function loadCommands() {
    if (state.commandsLoaded) return;
    const groups = await api("/commands");
    const places = { mac: "On your Mac", honeypot: "On the honeypot" };
    replace($("commands"),
      h("p", { class: "muted" },
        "Copy a command and paste it into the right window. ", h("strong", null, "On your Mac"),
        " means a Terminal window with your normal prompt. ", h("strong", null, "On the honeypot"),
        " means after you have logged in and the prompt reads root@HoneyPot."),
      groups.map((group) => h("div", { class: "panel" },
        h("h2", null, group.title),
        group.about ? h("p", { class: "muted small" }, group.about) : null,
        group.commands.map((command) => {
          const copy = h("button", { type: "button", disabled: !command.ready, onclick: async () => {
            try {
              await navigator.clipboard.writeText(command.command);
              copy.textContent = "Copied";
            } catch (error) {
              copy.textContent = "Select and copy it by hand";
            }
            window.setTimeout(() => { copy.textContent = "Copy"; }, 1600);
          } }, "Copy");
          return h("div", { class: "command" },
            h("div", { class: "command-head" }, h("strong", null, command.title),
              h("span", { class: `badge where-${command.where}` }, places[command.where]), copy),
            h("pre", null, command.command),
            command.note ? h("p", { class: "muted small" }, command.note) : null,
            command.ready ? null : h("p", { class: "note small" },
              "Not ready to paste yet: set ", h("code", null, command.missing.join(", ")),
              " in siftlog.local.json and restart the server."));
        }))));
    state.commandsLoaded = true;
  }

  // --- start -----------------------------------------------------------------

  takeTokenFromAddress();
  show("overview");
  window.setInterval(() => {
    const live = state.tab === "overview" || state.tab === "alerts";
    if (live && $("auto").checked && document.visibilityState === "visible" && token() && $("signin").hidden) refresh();
  }, REFRESH_MS);
})();
