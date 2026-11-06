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
  "diff", "declarations", "export", "bundle",
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
  // The second-factor form is only ever shown by the login handler
  // itself, so any token change (sign-in or sign-out) hides it again.
  $("form-totp").hidden = true;
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

  onSubmit("form-change-password", async () => {
    await api("/api/users/password", {
      method: "POST",
      body: {
        old_password: $("password-old").value,
        new_password: $("password-new").value,
      },
    });
    $("password-old").value = "";
    $("password-new").value = "";
    setStatus("Password changed. Your other sessions were signed out.");
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
  } else if (section === "export") {
    await loadExportSection();
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

async function loadExportSection() {
  const [mine, trail] = await Promise.all([
    api("/api/sessions"),
    api("/api/sessions/audit?limit=50&offset=0"),
  ]);
  const sessionList = $("session-list");
  sessionList.innerHTML = "";
  for (const session of mine.sessions) {
    let line = session.session_id + (session.current ? " (this session)" : "");
    const extras = [];
    if (session.remote_addr) {
      extras.push(session.remote_addr);
    }
    if (session.user_agent) {
      extras.push(session.user_agent);
    }
    // Sessions expire after 24 hours and after 30 idle minutes, so
    // the list shows when each one was created, last seen and when
    // it stops working — otherwise a stale session looks live.
    if (session.created_at) {
      extras.push("created " + session.created_at);
    }
    if (session.last_seen) {
      extras.push("last seen " + session.last_seen);
    }
    if (session.expires_at) {
      extras.push("expires " + session.expires_at);
    }
    if (extras.length) {
      line += " — " + extras.join(" — ");
    }
    const item = document.createElement("li");
    item.textContent = line + " ";
    // The current session is revoked by signing out instead: revoking
    // it here would leave a dead token in this tab's storage.
    if (!session.current) {
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke";
      revoke.addEventListener("click", async () => {
        try {
          await api("/api/sessions/revoke-one", {
            method: "POST",
            body: { session_id: session.session_id },
          });
          setStatus("Session revoked.");
          await loadExportSection();
        } catch (error) {
          showError(error);
        }
      });
      item.appendChild(revoke);
    }
    sessionList.appendChild(item);
  }
  if (mine.sessions.length === 0) {
    const item = document.createElement("li");
    item.textContent = "None.";
    sessionList.appendChild(item);
  }
  // Audit events carry their kind in "event", not "type": the old
  // render read event.type and showed "undefined" for every row.
  renderList("audit-list", trail.events, (event) =>
    event.event + " — " + event.timestamp
    + (event.detail ? " — " + event.detail : ""));
}

function initExport() {
  onSubmit("form-export", async () => {
    if (!currentProjectId) {
      setStatus("Pick a project on the Projects tab first.");
      return;
    }
    const claim = $("export-claim").value;
    const query = claim ? "?claim=" + encodeURIComponent(claim) : "";
    const bundle = await api(
      "/api/projects/" + currentProjectId + "/export" + query);
    $("export-output").textContent = JSON.stringify(bundle, null, 2);
    setStatus("Evidence bundle built. Copy or save the JSON above.");
  });
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

// Paging state for the ledger events on the Verify tab. Opening the
// tab resets to the first page; Load more appends the next page.
let eventOffset = 0;
const EVENT_PAGE = 20;

function renderEvents(events) {
  const list = $("verify-events");
  for (const event of events) {
    const entry = document.createElement("li");
    entry.textContent = event.type + " — " + (event.actor || "?")
      + " — " + event.timestamp;
    list.appendChild(entry);
  }
}

async function loadMoreEvents() {
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  const data = await api("/api/projects/" + currentProjectId
    + "/events?limit=" + EVENT_PAGE + "&offset=" + eventOffset);
  renderEvents(data.events);
  eventOffset += data.events.length;
  $("button-events-more").hidden = eventOffset >= data.total;
}

function initVerify() {
  $("button-events-more").addEventListener("click", async () => {
    try {
      await loadMoreEvents();
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
    api(base + "/events?limit=" + EVENT_PAGE + "&offset=0"),
  ]);
  eventOffset = 0;
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
  $("verify-events").innerHTML = "";
  renderEvents(recent.events);
  eventOffset = recent.events.length;
  $("button-events-more").hidden = eventOffset >= recent.total;
  setStatus("Verification for " + page.title + " (" + recent.total
    + " ledger events).");
}

// Paging state for the versions list. A fresh load (project select,
// upload) resets to the first page; Load more appends the next page.
let versionOffset = 0;
const VERSION_PAGE = 50;

async function loadVersions(reset) {
  const list = $("version-list");
  if (!currentProjectId) {
    setStatus("Pick a project on the Projects tab first.");
    return;
  }
  if (reset !== false) {
    list.innerHTML = "";
    versionOffset = 0;
  }
  const data = await api("/api/projects/" + currentProjectId
    + "/versions?limit=" + VERSION_PAGE + "&offset=" + versionOffset);
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
    // Download uses the stored filename, so the file a reviewer
    // saves is the file that was uploaded, not a bare hash.
    const download = document.createElement("button");
    download.type = "button";
    download.textContent = "Download";
    download.addEventListener("click", async () => {
      try {
        const data = await api("/api/projects/" + currentProjectId
          + "/versions/content?content_id=" + version.content_id);
        const binary = atob(data.content_base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        const blob = new Blob([bytes], {
          type: version.content_type || "application/octet-stream",
        });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = version.filename || version.content_id;
        anchor.click();
        URL.revokeObjectURL(url);
        setStatus("Version downloaded.");
      } catch (error) {
        showError(error);
      }
    });
    item.appendChild(download);
    list.appendChild(item);
  }
  versionOffset += data.versions.length;
  $("button-versions-more").hidden = versionOffset >= data.total;
  if (versionOffset === 0) {
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
  $("button-versions-more").addEventListener("click", async () => {
    try {
      await loadVersions(false);
    } catch (error) {
      showError(error);
    }
  });
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
  onSubmit("form-upload-text", async () => {
    if (!currentProjectId) {
      setStatus("Pick a project on the Projects tab first.");
      return;
    }
    const text = $("upload-text").value;
    if (!text) {
      setStatus("Paste some text first.");
      return;
    }
    // btoa only takes Latin-1, so text is UTF-8 encoded first:
    // pasted text with any characters must survive the round trip.
    const result = await api(
      "/api/projects/" + currentProjectId + "/uploads", {
        method: "POST",
        body: {
          content_base64: btoa(unescape(encodeURIComponent(text))),
          label: $("upload-text-label").value,
          filename: "",
          content_type: "text/plain",
        },
      });
    $("upload-text-label").value = "";
    $("upload-text").value = "";
    setStatus(result.duplicate
      ? "Already the latest version: no duplicate was recorded."
      : "Text version uploaded.");
    await loadVersions();
  });
}

// The project whose collaborators the Projects tab is managing.
// Separate from currentProjectId, which is the project other tabs act
// on, so managing collaborators never retargets the other tabs.
let manageProjectId = null;
let manageProjectTitle = null;

async function loadCollaborators() {
  const list = $("collaborator-list");
  list.innerHTML = "";
  if (!manageProjectId) {
    $("collaborator-project").textContent = "No project selected.";
    return;
  }
  $("collaborator-project").textContent = "Collaborators of "
    + manageProjectTitle + ":";
  const data = await api("/api/projects/" + manageProjectId
    + "/collaborators");
  for (const person of data.collaborators) {
    const item = document.createElement("li");
    item.textContent = person.name + (person.is_creator ? " (creator)" : "")
      + " ";
    if (!person.is_creator) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        try {
          await api("/api/projects/" + manageProjectId
            + "/collaborators/remove", {
              method: "POST",
              body: { username: person.actor_id },
            });
          setStatus("Collaborator removed.");
          await loadCollaborators();
        } catch (error) {
          showError(error);
        }
      });
      item.appendChild(remove);
    }
    list.appendChild(item);
  }
}

function initCollaborators() {
  onSubmit("form-add-collaborator", async () => {
    if (!manageProjectId) {
      setStatus("Pick a project's Collaborators button first.");
      return;
    }
    await api("/api/projects/" + manageProjectId + "/collaborators", {
      method: "POST",
      body: { username: $("collaborator-username").value },
    });
    $("collaborator-username").value = "";
    setStatus("Collaborator added.");
    await loadCollaborators();
  });
}

async function loadProjects() {
  const query = $("project-search").value.trim();
  const params = new URLSearchParams({ limit: "50", offset: "0" });
  if (query) {
    params.set("q", query);
  }
  const data = await api("/api/projects?" + params.toString());
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
    const manage = document.createElement("button");
    manage.type = "button";
    manage.textContent = "Collaborators";
    manage.addEventListener("click", () => {
      manageProjectId = project.project_id;
      manageProjectTitle = project.title;
      loadCollaborators().catch(showError);
    });
    item.appendChild(manage);
    const rename = document.createElement("button");
    rename.type = "button";
    rename.textContent = "Rename";
    rename.addEventListener("click", async () => {
      const title = prompt("New title for this project:", project.title);
      if (title === null || title.trim() === "") {
        return;
      }
      try {
        await api("/api/projects/" + project.project_id + "/rename", {
          method: "POST",
          body: { title: title.trim() },
        });
        setStatus("Project renamed.");
        await loadProjects();
      } catch (error) {
        showError(error);
      }
    });
    item.appendChild(rename);
    list.appendChild(item);
  }
  if (data.projects.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No projects yet. Create one above.";
    list.appendChild(item);
  }
}

function initProjects() {
  onSubmit("form-search-projects", async () => {
    await loadProjects();
  });
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

function initBundle() {
  onSubmit("form-bundle", async () => {
    let bundle;
    try {
      bundle = JSON.parse($("bundle-json").value);
    } catch (error) {
      setStatus("That is not valid JSON.");
      return;
    }
    const result = await api("/api/bundles/verify", {
      method: "POST",
      body: bundle,
    });
    $("bundle-result").textContent = result.valid
      ? "Bundle valid: its signatures and hashes check out."
      : "Bundle problems: " + result.problems.join("; ");
    setStatus(result.valid ? "Bundle verified." : "Bundle failed verification.");
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
  initCollaborators();
  initVerify();
  initBundle();
  initVersions();
  initDiff();
  initDeclarations();
  initExport();
  refreshAuthState();
  showSection("auth");
});
