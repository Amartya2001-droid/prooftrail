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
  }
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
  refreshAuthState();
  showSection("auth");
});
