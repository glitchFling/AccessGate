import AccessGate from "./AccessGate.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Attach env/KV if you ever want to use AccessGate inside the Worker
    AccessGate.env = env;
    AccessGate.kv = env.ACCESSGATE_KV;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        }
      });
    }

    // --- DEBUG: prove AccessGate is imported ---
    if (path === "/debug/accessgate") {
      return json({
        imported: typeof AccessGate === "object",
        keys: Object.keys(AccessGate || {})
      });
    }

    // --- ROUTES ---

    // Issue a session ID (short‑lived)
    if (path === "/access/session" && method === "POST") {
      return handleSession(env);
    }

    // Issue a permanent ID (or reuse existing)
    if (path === "/access/issue" && method === "POST") {
      return handleIssue(request, env);
    }

    // Check if ID is blocked
    if (path === "/access/check" && method === "POST") {
      return handleBlockCheck(request, env);
    }

    // Block a user
    if (path === "/access/block" && method === "POST") {
      return handleBlockUser(request, env);
    }

    // Unblock a user
    if (path === "/access/unblock" && method === "POST") {
      return handleUnblockUser(request, env);
    }

    // Admin check
    if (path === "/access/is-admin" && method === "POST") {
      return handleAdminCheck(request, env);
    }

    // Default
    return new Response("AccessGate Worker Online", {
      headers: { "content-type": "text/plain" }
    });
  }
};

// -------------------------
// HANDLERS
// -------------------------

async function handleSession(env) {
  const id = crypto.randomUUID();
  await env.ACCESSGATE_KV.put(`session:${id}`, "1", { expirationTtl: 86400 });
  return json({ id });
}

async function handleIssue(request, env) {
  const body = await safeJson(request);
  const existing = body?.existingId;
  const id = existing || crypto.randomUUID();
  await env.ACCESSGATE_KV.put(`id:${id}`, "1");
  return json({ id });
}

async function handleBlockCheck(request, env) {
  const body = await safeJson(request);
  const id = body?.id || body?.uuid;
  if (!id) return json({ blocked: false });

  const blocked = await env.ACCESSGATE_KV.get(`blocked:${id}`);
  return json({ blocked: !!blocked });
}

async function handleBlockUser(request, env) {
  const body = await safeJson(request);
  const id = body?.id || body?.uuid;
  const reason = body?.reason || "manual";

  if (!id) return json({ error: "Missing id" }, 400);

  await env.ACCESSGATE_KV.put(`blocked:${id}`, reason);
  return json({ ok: true });
}

async function handleUnblockUser(request, env) {
  const body = await safeJson(request);
  const id = body?.id || body?.uuid;

  if (!id) return json({ error: "Missing id" }, 400);

  await env.ACCESSGATE_KV.delete(`blocked:${id}`);
  return json({ ok: true });
}

async function handleAdminCheck(request, env) {
  const token =
    request.headers.get("x-access-gate-token") ||
    request.headers.get("ACCESS_GATE_ADMIN_TOKEN") ||
    "";

  if (!token) return json({ isAdmin: false });

  const exists = await env.ACCESSGATE_KV.get(`admin:${token}`);
  return json({ isAdmin: !!exists });
}

// -------------------------
// HELPERS
// -------------------------

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

async function safeJson(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}
