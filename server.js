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

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});