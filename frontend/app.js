// ProofTrail web UI: thin client over the JSON API in prooftrail/server.py.
// The session token lives in sessionStorage only, so closing the tab
// signs the browser out. No document content is ever rendered on the
// Verify tab: that view shows hashes, actors and timestamps only.
"use strict";

const $ = (id) => document.getElementById(id);

function token() {
  return sessionStorage.getItem("pt-token");
}

function setToken(value) {
  if (value) {
    sessionStorage.setItem("pt-token", value);
  } else {
    sessionStorage.removeItem("pt-token");
  }
  refreshAuthState();
}

function setStatus(message) {
  $("status").textContent = message;
}

function showError(error) {
  setStatus("Error: " + (error.message || error));
}

async function api(path, options) {
  const opts = options || {};
  const headers = { "Content-Type": "application/json" };
  const current = token();
  if (current) {
    headers["Authorization"] = "Bearer " + current;
  }
  const response = await fetch(path, {
    method: opts.method || "GET",
    headers: headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("request failed: " + response.status));
  }
  return data;
}

const SECTIONS = [
  "auth", "projects", "versions", "verify",
  "diff", "declarations", "export",
];

function showSection(name) {
  for (const section of SECTIONS) {
    $("section-" + section).hidden = section !== name;
  }
}

function refreshAuthState() {
  const signedIn = Boolean(token());
  $("auth-state").textContent = signedIn ? "Signed in." : "Not signed in.";
  $("button-logout").hidden = !signedIn;
  $("form-totp").hidden = true;
}

function refreshAuthState() {
  const signedIn = Boolean(token());
  $("auth-state").textContent = signedIn ? "Signed in." : "Not signed in.";
  $("button-logout").hidden = !signedIn;
  if (signedIn) {
    $("form-totp").hidden = true;
  }
}

// The pending second-factor token lives in memory only: it expires in
// five minutes and must never survive in storage.
let pendingTotpToken = null;

function onSubmit(id, handler) {
  $(id).addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await handler();
    } catch (error) {
      showError(error);
    }
  });
}

function initAuth() {
  onSubmit("form-register", async () => {
    await api("/api/users", {
      method: "POST",
      body: {
        username: $("register-username").value,
        name: $("register-name").value,
        password: $("register-password").value,
      },
    });
    $("register-password").value = "";
    setStatus("Registered. Sign in to continue.");
  });

  onSubmit("form-login", async () => {
    const result = await api("/api/sessions", {
      method: "POST",
      body: {
        username: $("login-username").value,
        password: $("login-password").value,
      },
    });
    $("login-password").value = "";
    if (result.totp_required) {
      pendingTotpToken = result.pending_token;
      $("form-totp").hidden = false;
      setStatus("Second factor required.");
      return;
    }
    pendingTotpToken = null;
    setToken(result.token);
    setStatus("Signed in.");
  });

  onSubmit("form-totp", async () => {
    const result = await api("/api/sessions/totp", {
      method: "POST",
      body: {
        pending_token: pendingTotpToken,
        code: $("totp-code").value,
      },
    });
    $("totp-code").value = "";
    pendingTotpToken = null;
    setToken(result.token);
    setStatus("Signed in.");
  });

  $("button-logout").addEventListener("click", async () => {
    try {
      await api("/api/sessions/revoke", { method: "POST" });
    } catch (error) {
      showError(error);
    }
    pendingTotpToken = null;
    setToken(null);
    setStatus("Signed out.");
  });
}

// The project every other tab acts on. It is set only by picking a
// project from the list, never guessed from a URL or a stored id.
let currentProjectId = null;

async function loadSection(section) {
  if (section === "projects") {
    await loadProjects();
  } else if (section === "versions") {
    await loadVersions();
  } else if (section === "verify") {
    await loadVerify();
  } else if (section === "diff") {
    await loadDiffOptions();
  } else if (section === "declarations") {
    await loadDeclarations();
  }
}

function renderList(elementId, items, render) {
  const list = $(elementId);
  list.innerHTML = "";
  for (const item of items) {
    const entry = document.createElement("li");
    entry.textContent = render(item);
    list.appendChild(entry);
  }
  if (items.length === 0) {
    const entry = document.createElement("li");
    entry.textContent = "None.";
    list.appendChild(entry);
  }
}

function fillVersionSelect(selectId, versions, includeBlank) {
  const select = $(selectId);
  select.innerHTML = "";
  if (includeBlank !== false) {
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "(latest vs parent)";
    select.appendChild(blank);
  }
  for (const version of versions) {
    const option = document.createElement("option");
    option.value = version.content_id;
    option.textContent = (version.label || version.content_id)
      + " — " + version.timestamp;
    select.appendChild(option);
  }
}

async function loadDeclarations() {
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  const base = "/api/projects/" + currentProjectId;
  const [versions, decls, cmap] = await Promise.all([
    api(base + "/versions"),
    api(base + "/declarations?limit=50&offset=0"),
    api(base + "/contributions?limit=50&offset=0"),
  ]);
  fillVersionSelect("declare-version", versions.versions, false);
  renderList("declaration-list", decls.declarations, (decl) =>
    decl.version_label + " — " + decl.tool + " — by " + decl.actor_id
    + (decl.prompt_summary ? " — " + decl.prompt_summary : ""));
  const coverage = Object.entries(cmap.coverage_pct)
    .map(([source, pct]) => source + ": " + pct + "%").join(", ");
  $("contribution-coverage").textContent = "Coverage over "
    + cmap.total_segments + " segments: " + coverage
    + (cmap.caveat ? " (" + cmap.caveat + ")" : "");
  renderList("contribution-segments", cmap.segments, (segment) =>
    segment.source + " — first seen in " + segment.first_seen_version
    + " — " + segment.text);
}

function initDeclarations() {
  onSubmit("form-declare", async () => {
    if (!currentProjectId) {
      setStatus("Pick a project on the Projects tab first.");
      return;
    }
    await api("/api/projects/" + currentProjectId + "/declarations", {
      method: "POST",
      body: {
        content_id: $("declare-version").value,
        tool: $("declare-tool").value,
        prompt_summary: $("declare-summary").value,
      },
    });
    $("declare-tool").value = "";
    $("declare-summary").value = "";
    setStatus("AI use declared.");
    await loadDeclarations();
  });
}

async function loadDiffOptions() {
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  const data = await api("/api/projects/" + currentProjectId + "/versions");
  fillVersionSelect("diff-from", data.versions);
  fillVersionSelect("diff-to", data.versions);
}

function initDiff() {
  $("button-diff").addEventListener("click", async () => {
    if (!currentProjectId) {
      setStatus("Pick a project on the Projects tab first.");
      return;
    }
    try {
      const params = new URLSearchParams();
      if ($("diff-from").value) {
        params.set("from", $("diff-from").value);
      }
      if ($("diff-to").value) {
        params.set("to", $("diff-to").value);
      }
      const query = params.toString();
      const data = await api("/api/projects/" + currentProjectId + "/diff"
        + (query ? "?" + query : ""));
      $("diff-summary").textContent = data.summary;
      renderList("diff-added", data.added, (line) => line);
      renderList("diff-removed", data.removed, (line) => line);
      setStatus("Diff shown.");
    } catch (error) {
      showError(error);
    }
  });
}

async function loadVerify() {
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  const base = "/api/projects/" + currentProjectId;
  const [page, people, recent] = await Promise.all([
    api(base + "/verify"),
    api(base + "/collaborators"),
    api(base + "/events?limit=20&offset=0"),
  ]);
  $("verify-valid").textContent = page.ledger_valid
    ? "Ledger valid: every version hash and signature checks out."
    : "Ledger problems: " + page.ledger_problems.join("; ");
  renderList("verify-chain", page.versions, (version) => {
    let line = (version.label || version.content_id) + " — "
      + version.content_id + " — by " + version.actor + " at "
      + version.timestamp;
    if (version.change) {
      line += " — " + JSON.stringify(version.change);
    }
    return line;
  });
  renderList("verify-self-approvals", page.self_approvals, (entry) =>
    (entry.approver || entry.actor || "?") + " approved own version "
    + (entry.content_id || ""));
  renderList("verify-contributors", people.collaborators, (person) =>
    person.name + (person.is_creator ? " (creator)" : ""));
  renderList("verify-events", recent.events, (event) =>
    event.type + " — " + (event.actor || "?") + " — " + event.timestamp);
  setStatus("Verification for " + page.title + " (" + recent.total
    + " ledger events).");
}

async function loadVersions() {
  const list = $("version-list");
  list.innerHTML = "";
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  const data = await api("/api/projects/" + currentProjectId + "/versions");
  for (const version of data.versions) {
    const item = document.createElement("li");
    item.textContent = (version.label || version.content_id) + " — "
      + version.timestamp + " — " + version.content_id
      + " (" + version.size + " bytes) ";
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", async () => {
      try {
        await api("/api/projects/" + currentProjectId + "/approvals", {
          method: "POST",
          body: { content_id: version.content_id },
        });
        setStatus("Version approved.");
      } catch (error) {
        showError(error);
      }
    });
    item.appendChild(approve);
    list.appendChild(item);
  }
  if (data.versions.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No versions yet. Upload one above.";
    list.appendChild(item);
  }
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(
      null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function initVersions() {
  onSubmit("form-upload", async () => {
    if (!currentProjectId) {
      setStatus("Pick a project on the Projects tab first.");
      return;
    }
    const file = $("upload-file").files[0];
    if (!file) {
      setStatus("Choose a file to upload.");
      return;
    }
    const result = await api(
      "/api/projects/" + currentProjectId + "/uploads", {
        method: "POST",
        body: {
          content_base64: toBase64(await file.arrayBuffer()),
          label: $("upload-label").value,
          filename: file.name,
          content_type: file.type || "application/octet-stream",
        },
      });
    $("upload-label").value = "";
    $("upload-file").value = "";
    setStatus(result.duplicate
      ? "Already the latest version: no duplicate was recorded."
      : "Version uploaded.");
    await loadVersions();
  });
}

async function loadProjects() {
  const data = await api("/api/projects?limit=50&offset=0");
  const list = $("project-list");
  list.innerHTML = "";
  for (const project of data.projects) {
    const item = document.createElement("li");
    item.textContent = project.title + " (" + project.versions
      + " versions, " + project.collaborators.length + " collaborators) ";
    const select = document.createElement("button");
    select.type = "button";
    select.textContent = "Select";
    select.addEventListener("click", () => {
      currentProjectId = project.project_id;
      $("versions-project").textContent = "Selected: " + project.title;
      showSection("versions");
      loadVersions().catch(showError);
    });
    item.appendChild(select);
    list.appendChild(item);
  }
  if (data.projects.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No projects yet. Create one above.";
    list.appendChild(item);
  }
}

function initProjects() {
  onSubmit("form-create-project", async () => {
    const result = await api("/api/projects", {
      method: "POST",
      body: { title: $("project-title").value },
    });
    $("project-title").value = "";
    setStatus("Project created.");
    await loadProjects();
    currentProjectId = result.project_id;
  });
}

function initNav() {
  for (const section of SECTIONS) {
    $("nav-" + section).addEventListener("click", () => {
      showSection(section);
      loadSection(section).catch(showError);
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initNav();
  initAuth();
  initProjects();
  initVersions();
  initDiff();
  initDeclarations();
  refreshAuthState();
  showSection("auth");
});
