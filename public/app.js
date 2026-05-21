const zoomAuthorizeEndpoint = "https://zoom.us/oauth/authorize";
const redirectUri = `${window.location.origin}/`;

const state = {
  pkce: generatePkceMaterial()
};

const confidentialForm = document.querySelector("#confidential-form");
const pkceForm = document.querySelector("#pkce-form");
const confidentialAuthorizeEl = document.querySelector("#confidential-authorize");
const pkceAuthorizeEl = document.querySelector("#pkce-authorize");
const pkceMaterialEl = document.querySelector("#pkce-material");
const callbackParamsEl = document.querySelector("#callback-params");
const tokenResponseEl = document.querySelector("#token-response");
const redirectUriPreviewEl = document.querySelector("#redirect-uri-preview");

redirectUriPreviewEl.textContent = redirectUri;

function prettyPrint(target, value) {
  target.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  target.classList.toggle("empty", !value);
}

function formToObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function buildScopeParam(scope) {
  return scope?.trim() ? { scope: scope.trim() } : {};
}

function buildAuthorizeUrl(mode) {
  const isPkce = mode === "pkce";
  const formData = formToObject(isPkce ? pkceForm : confidentialForm);
  const stateToken = `${mode}:${formData.stateLabel?.trim() || "default"}:preview`;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: formData.clientId || "",
    redirect_uri: redirectUri,
    state: stateToken,
    ...buildScopeParam(formData.scope)
  });

  if (isPkce) {
    params.set("code_challenge", state.pkce.codeChallenge);
    params.set("code_challenge_method", "S256");
  }

  return `${zoomAuthorizeEndpoint}?${params.toString()}`;
}

function generateRandomString(length = 64) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from(bytes, (value) => charset[value % charset.length]).join("");
}

async function sha256(input) {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

function toBase64Url(bytes) {
  const string = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(string).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generatePkceMaterial() {
  return {
    codeVerifier: generateRandomString(96),
    codeChallenge: ""
  };
}

async function refreshPkceMaterial() {
  state.pkce.codeVerifier = generateRandomString(96);
  state.pkce.codeChallenge = toBase64Url(await sha256(state.pkce.codeVerifier));
  prettyPrint(pkceMaterialEl, state.pkce);
  renderAuthorizePreviews();
}

function renderAuthorizePreviews() {
  const confidentialData = formToObject(confidentialForm);
  const confidentialPreview = confidentialData.clientId
    ? buildAuthorizeUrl("confidential")
    : "Waiting for form values…";
  const pkceData = formToObject(pkceForm);
  const pkcePreview = pkceData.clientId ? buildAuthorizeUrl("pkce") : "Waiting for form values…";

  prettyPrint(confidentialAuthorizeEl, confidentialPreview);
  prettyPrint(pkceAuthorizeEl, pkcePreview);
}

function readCallbackParams() {
  const params = new URLSearchParams(window.location.search);
  return Object.fromEntries(params.entries());
}

async function exchangeCurrentCallback() {
  const callback = readCallbackParams();

  if (!callback.code) {
    prettyPrint(tokenResponseEl, { error: "No authorization code found in the current URL." });
    return;
  }

  prettyPrint(tokenResponseEl, { status: "Requesting token from local server…" });

  const sessionResponse = await fetch("/api/session/current");
  const sessionResult = await sessionResponse.json();
  if (!sessionResult.session) {
    prettyPrint(tokenResponseEl, {
      error: "No active server-side OAuth session found. Start a flow from this page first."
    });
    return;
  }

  const endpoint =
    sessionResult.session.mode === "pkce" ? "/api/exchange/pkce" : "/api/exchange/confidential";
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: callback.code,
      state: callback.state || ""
    })
  });

  const result = await response.json();
  prettyPrint(tokenResponseEl, result);
}

async function clearSession() {
  await fetch("/api/session/clear", { method: "POST" });
  window.history.replaceState({}, document.title, redirectUri);
  prettyPrint(callbackParamsEl, "No callback data yet.");
  prettyPrint(tokenResponseEl, "No token request yet.");
}

async function startOAuthSession(mode) {
  const form = mode === "pkce" ? pkceForm : confidentialForm;
  const formData = formToObject(form);
  const payload = {
    mode,
    clientId: formData.clientId || "",
    clientSecret: formData.clientSecret || "",
    scope: formData.scope || "",
    stateLabel: formData.stateLabel || "",
    redirectUri,
    codeVerifier: mode === "pkce" ? state.pkce.codeVerifier : "",
    codeChallenge: mode === "pkce" ? state.pkce.codeChallenge : ""
  };

  const response = await fetch("/api/session/start", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const result = await response.json();
  if (!response.ok) {
    prettyPrint(tokenResponseEl, result);
    return;
  }

  window.location.assign(result.authorizeUrl);
}

async function loadCurrentSessionMetadata() {
  const response = await fetch("/api/session/current");
  const result = await response.json();
  if (!result.session) {
    return;
  }

  if (result.session.mode === "confidential") {
    confidentialForm.elements.clientId.value = result.session.clientId || "";
    confidentialForm.elements.scope.value = result.session.scope || "";
  } else {
    pkceForm.elements.clientId.value = result.session.clientId || "";
    pkceForm.elements.scope.value = result.session.scope || "";
  }
}

function attachInputListeners(form) {
  form.addEventListener("input", () => {
    renderAuthorizePreviews();
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) {
    return;
  }

  const { action } = button.dataset;

  if (action === "generate-pkce") {
    button.disabled = true;
    await refreshPkceMaterial();
    button.disabled = false;
    return;
  }

  if (action === "authorize-confidential" || action === "authorize-pkce") {
    const mode = action.endsWith("pkce") ? "pkce" : "confidential";
    button.disabled = true;
    await startOAuthSession(mode);
    button.disabled = false;
    return;
  }

  if (action === "exchange-auto") {
    button.disabled = true;
    await exchangeCurrentCallback();
    button.disabled = false;
    return;
  }

  if (action === "clear-session") {
    button.disabled = true;
    await clearSession();
    button.disabled = false;
  }
});

attachInputListeners(confidentialForm);
attachInputListeners(pkceForm);
await refreshPkceMaterial();
await loadCurrentSessionMetadata();
renderAuthorizePreviews();

const callbackParams = readCallbackParams();
if (Object.keys(callbackParams).length > 0) {
  prettyPrint(callbackParamsEl, callbackParams);
  if (callbackParams.error) {
    prettyPrint(tokenResponseEl, {
      error: "Authorization callback returned an error.",
      details: callbackParams
    });
  } else if (callbackParams.code) {
    prettyPrint(tokenResponseEl, {
      status: "Authorization code detected. Use the exchange button to request tokens."
    });
  }
} else {
  prettyPrint(callbackParamsEl, "No callback data yet.");
  prettyPrint(tokenResponseEl, "No token request yet.");
}
