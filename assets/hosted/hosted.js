(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const state = {
    config: null,
    token: null,
    me: null,
    workspaces: [],
    activeWorkspaceId: null,
    assets: [],
    projects: [],
    challengeAssetId: null,
    challenge: null
  };

  const authView = $("#auth-view");
  const workspaceView = $("#workspace-view");
  const authMessage = $("#auth-message");
  const workspaceMessage = $("#workspace-message");
  const challengeMessage = $("#challenge-message");

  function message(target, text, isError = false) {
    target.textContent = text || "";
    target.classList.toggle("error", Boolean(isError));
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[character]);
  }

  function setView(authenticated) {
    authView.classList.toggle("hidden", authenticated);
    workspaceView.classList.toggle("hidden", !authenticated);
    $("#signout").classList.toggle("hidden", !authenticated);
  }

  function clearSession() {
    sessionStorage.removeItem("vantage.access_token");
    sessionStorage.removeItem("vantage.access_expiry");
    sessionStorage.removeItem("vantage.oauth");
    state.token = null;
    state.me = null;
    state.workspaces = [];
    state.activeWorkspaceId = null;
    setView(false);
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
      clearSession();
      throw new Error("Your sign-in has expired. Please sign in again.");
    }
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : "The request could not be completed.";
      throw new Error(detail);
    }
    return data;
  }

  function base64url(bytes) {
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function randomValue() {
    return base64url(crypto.getRandomValues(new Uint8Array(32)));
  }

  async function sha256(value) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return base64url(new Uint8Array(digest));
  }

  function assertSafeEndpoint(value) {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new Error("The identity provider must use HTTPS outside local development.");
    }
    return url;
  }

  function providerEndpoints() {
    return {
      authorization: assertSafeEndpoint(state.config.authorization_endpoint),
      token: assertSafeEndpoint(state.config.token_endpoint)
    };
  }

  async function beginLogin() {
    message(authMessage, "Connecting to your identity provider…");
    const endpoints = providerEndpoints();
    const verifier = randomValue();
    const challenge = await sha256(verifier);
    const oauthState = randomValue();
    const redirectUri = state.config.redirect_uri;
    sessionStorage.setItem("vantage.oauth", JSON.stringify({
      verifier,
      state: oauthState,
      redirectUri,
      tokenEndpoint: endpoints.token.toString(),
      clientId: state.config.client_id
    }));
    const authorization = new URL(endpoints.authorization);
    authorization.searchParams.set("client_id", state.config.client_id);
    authorization.searchParams.set("redirect_uri", redirectUri);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("scope", state.config.scope);
    authorization.searchParams.set("state", oauthState);
    authorization.searchParams.set("code_challenge", challenge);
    authorization.searchParams.set("code_challenge_method", "S256");
    window.location.assign(authorization.toString());
  }

  async function completeLogin() {
    const params = new URLSearchParams(window.location.search);
    if (params.has("error")) {
      sessionStorage.removeItem("vantage.oauth");
      throw new Error(params.get("error_description") || params.get("error"));
    }
    if (!params.has("code")) return false;
    const raw = sessionStorage.getItem("vantage.oauth");
    if (!raw) throw new Error("The sign-in state is missing. Please start again.");
    const oauth = JSON.parse(raw);
    if (!params.get("state") || params.get("state") !== oauth.state) {
      sessionStorage.removeItem("vantage.oauth");
      throw new Error("The sign-in state did not match. Please start again.");
    }
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: oauth.clientId,
      code: params.get("code"),
      redirect_uri: oauth.redirectUri,
      code_verifier: oauth.verifier
    });
    const response = await fetch(assertSafeEndpoint(oauth.tokenEndpoint), {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const tokens = await response.json().catch(() => ({}));
    sessionStorage.removeItem("vantage.oauth");
    if (!response.ok || !tokens.access_token || tokens.token_type?.toLowerCase() !== "bearer") {
      throw new Error(tokens.error_description || "The identity provider did not issue a usable access token.");
    }
    state.token = tokens.access_token;
    sessionStorage.setItem("vantage.access_token", state.token);
    if (Number.isFinite(tokens.expires_in)) {
      sessionStorage.setItem("vantage.access_expiry", String(Date.now() + tokens.expires_in * 1000));
    }
    window.history.replaceState({}, document.title, "/app");
    return true;
  }

  async function loadIdentity() {
    const data = await api("/api/v2/me");
    state.me = data.user;
    state.workspaces = data.workspaces || [];
    state.activeWorkspaceId = state.workspaces.some(
      (item) => item.id === state.activeWorkspaceId
    ) ? state.activeWorkspaceId : data.personal_organization_id;
    if (!state.workspaces.some((item) => item.id === state.activeWorkspaceId)) {
      state.activeWorkspaceId = state.workspaces[0]?.id || null;
    }
    $("#welcome").textContent = state.me.display_name
      ? `Welcome back, ${state.me.display_name}.`
      : "Your security workspace is ready.";
    const select = $("#workspace-select");
    select.innerHTML = state.workspaces.map((item) =>
      `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)} · ${escapeHTML(item.role)}</option>`
    ).join("");
    if (state.activeWorkspaceId) select.value = state.activeWorkspaceId;
    setView(true);
    await loadWorkspace();
  }

  async function loadWorkspace() {
    if (!state.activeWorkspaceId) return;
    message(workspaceMessage, "Refreshing workspace…");
    const [assets, projects] = await Promise.all([
      api(`/api/v2/organizations/${state.activeWorkspaceId}/assets`),
      api(`/api/v2/organizations/${state.activeWorkspaceId}/projects`)
    ]);
    state.assets = assets.items || [];
    state.projects = projects.items || [];
    renderWorkspace();
    message(workspaceMessage, "");
  }

  function activeWorkspace() {
    return state.workspaces.find((item) => item.id === state.activeWorkspaceId);
  }

  function renderWorkspace() {
    const workspace = activeWorkspace();
    const verified = state.assets.filter((asset) => asset.ownership_verified).length;
    $("#metric-assets").textContent = String(state.assets.length);
    $("#metric-verified").textContent = String(verified);
    $("#metric-projects").textContent = String(state.projects.length);
    $("#metric-role").textContent = workspace?.role || "—";
    $("#metric-kind").textContent = workspace?.kind === "personal" ? "Personal workspace" : "Organization workspace";
    $("#asset-count").textContent = `${state.assets.length} assets`;
    $("#asset-list").innerHTML = state.assets.length ? state.assets.map((asset) => {
      const status = asset.ownership_verified
        ? '<span class="status-chip verified">VERIFIED</span>'
        : '<span class="status-chip">UNVERIFIED</span>';
      const action = asset.ownership_verified
        ? ""
        : `<button class="mini-button" type="button" data-action="challenge" data-asset="${escapeHTML(asset.id)}">Verify ownership</button>`;
      return `<article class="asset-row">
        <div><div class="asset-name">${escapeHTML(asset.display_name || asset.canonical_value)}</div>
        <div class="asset-meta">${escapeHTML(asset.canonical_value)} · DOMAIN</div></div>
        <div class="asset-actions">${status}${action}</div>
      </article>`;
    }).join("") : '<div class="empty-state">No domains registered yet. Add a domain you control to begin.</div>';
    $("#project-list").innerHTML = state.projects.length ? state.projects.map((project) =>
      `<div class="project-item"><span>${escapeHTML(project.name)}</span><code>${escapeHTML(project.slug)}</code></div>`
    ).join("") : '<div class="empty-state compact">No projects yet.</div>';
  }

  async function createOrganization(event) {
    event.preventDefault();
    const name = $("#org-name").value.trim();
    const slug = $("#org-slug").value.trim();
    try {
      const organization = await api("/api/v2/organizations", {
        method: "POST",
        body: JSON.stringify({ name, slug })
      });
      $("#organization-form").reset();
      await loadIdentity();
      state.activeWorkspaceId = organization.id;
      $("#workspace-select").value = organization.id;
      await loadWorkspace();
      message(workspaceMessage, `Created ${organization.name}.`);
    } catch (error) {
      message(workspaceMessage, error.message, true);
    }
  }

  async function createProject(event) {
    event.preventDefault();
    if (!state.activeWorkspaceId) return;
    try {
      await api(`/api/v2/organizations/${state.activeWorkspaceId}/projects`, {
        method: "POST",
        body: JSON.stringify({
          name: $("#project-name").value.trim(),
          slug: $("#project-slug").value.trim()
        })
      });
      $("#project-form").reset();
      await loadWorkspace();
      message(workspaceMessage, "Project created.");
    } catch (error) {
      message(workspaceMessage, error.message, true);
    }
  }

  async function createAsset(event) {
    event.preventDefault();
    if (!state.activeWorkspaceId) return;
    try {
      await api(`/api/v2/organizations/${state.activeWorkspaceId}/assets`, {
        method: "POST",
        body: JSON.stringify({
          domain: $("#domain-input").value.trim(),
          display_name: $("#domain-label").value.trim() || null
        })
      });
      $("#asset-form").reset();
      await loadWorkspace();
      message(workspaceMessage, "Domain registered. Verify ownership to establish control.");
    } catch (error) {
      message(workspaceMessage, error.message, true);
    }
  }

  async function createChallenge(assetId) {
    try {
      const challenge = await api(
        `/api/v2/organizations/${state.activeWorkspaceId}/assets/${assetId}/domain-verification`,
        { method: "POST" }
      );
      if (challenge.status === "verified") {
        await loadWorkspace();
        return;
      }
      state.challengeAssetId = assetId;
      state.challenge = challenge;
      $("#record-name").textContent = challenge.record_name;
      $("#record-value").textContent = challenge.record_value;
      $("#record-expiry").textContent = `Expires ${new Date(challenge.expires_at).toLocaleString()}.`;
      challengeMessage.textContent = "";
      $("#challenge-dialog").classList.remove("hidden");
    } catch (error) {
      message(workspaceMessage, error.message, true);
    }
  }

  async function verifyChallenge() {
    if (!state.challengeAssetId) return;
    $("#verify-domain").disabled = true;
    message(challengeMessage, "Checking the DNS TXT record…");
    try {
      const result = await api(
        `/api/v2/organizations/${state.activeWorkspaceId}/assets/${state.challengeAssetId}/domain-verification/verify`,
        { method: "POST" }
      );
      if (result.status === "verified") {
        $("#challenge-dialog").classList.add("hidden");
        await loadWorkspace();
        message(workspaceMessage, "Domain ownership verified. Active testing still requires a separate authorization scope.");
      } else {
        message(challengeMessage, "This challenge has expired. Create a new one.", true);
      }
    } catch (error) {
      message(challengeMessage, error.message, true);
    } finally {
      $("#verify-domain").disabled = false;
    }
  }

  async function initialize() {
    try {
      const configResponse = await fetch("/api/v2/auth/config");
      state.config = await configResponse.json();
      if (!state.config.configured) {
        $("#auth-config-warning").classList.remove("hidden");
        $("#signin").disabled = true;
        $("#signin").textContent = "Sign-in setup required";
      } else {
        $("#signin").addEventListener("click", () => {
          beginLogin().catch((error) => message(authMessage, error.message, true));
        });
      }

      const completed = await completeLogin();
      if (completed) {
        await loadIdentity();
        return;
      }
      const stored = sessionStorage.getItem("vantage.access_token");
      const expiry = Number(sessionStorage.getItem("vantage.access_expiry") || 0);
      if (stored && (!expiry || expiry > Date.now())) {
        state.token = stored;
        await loadIdentity();
      } else {
        clearSession();
      }
    } catch (error) {
      clearSession();
      message(authMessage, error.message, true);
    }
  }

  $("#signout").addEventListener("click", () => {
    clearSession();
    message(authMessage, "You have signed out of this VANTAGE browser session.");
  });
  $("#workspace-select").addEventListener("change", async (event) => {
    state.activeWorkspaceId = event.target.value;
    try { await loadWorkspace(); } catch (error) { message(workspaceMessage, error.message, true); }
  });
  $("#organization-form").addEventListener("submit", createOrganization);
  $("#project-form").addEventListener("submit", createProject);
  $("#asset-form").addEventListener("submit", createAsset);
  $("#verify-domain").addEventListener("click", verifyChallenge);
  $("#close-dialog").addEventListener("click", () => $("#challenge-dialog").classList.add("hidden"));
  $("#challenge-dialog").addEventListener("click", (event) => {
    if (event.target.id === "challenge-dialog") $("#challenge-dialog").classList.add("hidden");
  });
  document.addEventListener("click", (event) => {
    const action = event.target.closest("[data-action]");
    if (action?.dataset.action === "challenge") createChallenge(action.dataset.asset);
    const copy = event.target.closest("[data-copy]");
    if (copy) {
      const target = document.getElementById(copy.dataset.copy);
      if (!navigator.clipboard?.writeText) {
        message(challengeMessage, "Clipboard access is unavailable. Select and copy the value manually.", true);
        return;
      }
      navigator.clipboard.writeText(target.textContent).then(() => {
        copy.textContent = "Copied";
        window.setTimeout(() => { copy.textContent = "Copy"; }, 1200);
      }).catch(() => message(challengeMessage, "Clipboard access is unavailable. Select and copy the value manually.", true));
    }
  });

  initialize();
})();
