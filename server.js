import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DISCOVERY_URL = process.env.PINGONE_DISCOVERY_URL;
const EXPECTED_AUDIENCE = process.env.PINGONE_AUDIENCE || "https://orders-api";
const REQUIRED_SCOPE = process.env.PINGONE_REQUIRED_SCOPE || "orders.read";

if (!DISCOVERY_URL) {
  throw new Error("Missing PINGONE_DISCOVERY_URL");
}

let discoveryCache;
let jwks;

async function getDiscovery() {
  if (!discoveryCache) {
    const res = await fetch(DISCOVERY_URL);
    if (!res.ok) {
      throw new Error(`Failed to fetch discovery document: ${res.status}`);
    }
    discoveryCache = await res.json();
    jwks = createRemoteJWKSet(new URL(discoveryCache.jwks_uri));
  }
  return discoveryCache;
}

function getBearerToken(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  return auth.slice("Bearer ".length);
}

function hasScope(scopeString, requiredScope) {
  if (!scopeString) return false;
  return scopeString.split(" ").includes(requiredScope);
}

app.get("/health", async (_req, res) => {
  try {
    const discovery = await getDiscovery();
    res.json({
      ok: true,
      issuer: discovery.issuer,
      jwks_uri: discovery.jwks_uri,
      introspection_endpoint: discovery.introspection_endpoint,
      expectedAudience: EXPECTED_AUDIENCE,
      requiredScope: REQUIRED_SCOPE
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/protected", async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (!token) {
      return res.status(401).json({ ok: false, error: "Missing bearer token" });
    }

    const discovery = await getDiscovery();

    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: discovery.issuer,
      audience: EXPECTED_AUDIENCE
    });

    if (!hasScope(payload.scope, REQUIRED_SCOPE)) {
      return res.status(403).json({
        ok: false,
        error: `Missing required scope: ${REQUIRED_SCOPE}`,
        actualScope: payload.scope || null
      });
    }

    res.json({
      ok: true,
      message: "Token accepted",
      client: payload.client_id || payload.azp || "unknown",
      algorithm: protectedHeader.alg,
      claims: {
        iss: payload.iss,
        aud: payload.aud,
        sub: payload.sub || null,
        scope: payload.scope,
        exp: payload.exp
      }
    });
  } catch (err) {
    res.status(401).json({
      ok: false,
      error: "Token validation failed",
      detail: err.message
    });
  }
});

app.get("/debug/claims", async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (!token) {
      return res.status(401).json({ ok: false, error: "Missing bearer token" });
    }

    const discovery = await getDiscovery();
    const { payload } = await jwtVerify(token, jwks, {
      issuer: discovery.issuer,
      audience: EXPECTED_AUDIENCE
    });

    res.json({ ok: true, payload });
  } catch (err) {
    res.status(401).json({ ok: false, error: err.message });
  }
});

app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send(`
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>PingOne Gateway POC</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
      line-height: 1.5;
    }
    textarea {
      width: 100%;
      height: 160px;
      font-family: monospace;
      margin-bottom: 16px;
    }
    button {
      margin-right: 10px;
      margin-bottom: 10px;
      padding: 10px 14px;
      cursor: pointer;
    }
    pre {
      background: #f4f4f4;
      padding: 16px;
      overflow-x: auto;
      border-radius: 8px;
    }
  </style>
</head>
<body>
  <h1>PingOne Gateway POC</h1>
  <p>Paste a bearer token below, then call the API endpoints from the browser.</p>

  <label for="token"><strong>Access Token</strong></label>
  <textarea id="token" placeholder="Paste PingOne access token here"></textarea>

  <div>
    <button onclick="callApi('/health', false)">Health</button>
    <button onclick="callApi('/protected', true)">Protected</button>
    <button onclick="callApi('/debug/claims', true)">Claims</button>
  </div>

  <h2>Response</h2>
  <pre id="output">No request made yet.</pre>

  <script>
    async function callApi(path, needsToken) {
      const token = document.getElementById('token').value.trim();
      const headers = {};

      if (needsToken) {
        if (!token) {
          document.getElementById('output').textContent = 'Paste a token first.';
          return;
        }
        headers.Authorization = 'Bearer ' + token;
      }

      try {
        const response = await fetch(path, { headers });
        const text = await response.text();

        try {
          const json = JSON.parse(text);
          document.getElementById('output').textContent =
            JSON.stringify(json, null, 2);
        } catch {
          document.getElementById('output').textContent = text;
        }
      } catch (err) {
        document.getElementById('output').textContent = err.message;
      }
    }
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});