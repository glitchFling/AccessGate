import AccessGate from "./AccessGate.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Attach KV + env to AccessGate
    AccessGate.env = env;
    AccessGate.kv = env.ACCESSGATE_KV;

    // Basic CORS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        }
      });
    }

    // ---- SESSION ----
    if (path === "/access/session") {
      const id = crypto.randomUUID();
      await env.ACCESSGATE_KV.put(`session:${id}`, "1", { expirationTtl: 86400 });
      return json({ id });
    }

    // ---- ISSUE ID ----
    if (path === "/access/issue") {
      const body = await safeJson(request);
      const existing = body?.existingId;
      const id = existing || crypto.randomUUID();
      await env.ACCESSGATE_KV.put(`id:${id}`, "1");
      return json({ id });
    }

    // ---- BLOCK CHECK ----
    if (path === "/access/check") {
      const body = await safeJson(request);
      const id = body?.id;
      const blocked = await env.ACCESSGATE_KV.get(`blocked:${id}`);
      return json({ blocked: !!blocked });
    }

    // ---- BLOCK USER ----
    if (path === "/access/block") {
      const body = await safeJson(request);
      const id = body?.id;
      await env.ACCESSGATE_KV.put(`blocked:${id}`, "1");
      return json({ ok: true });
    }

    // ---- UNBLOCK USER ----
    if (path === "/access/unblock") {
      const body = await safeJson(request);
      const id = body?.id;
      await env.ACCESSGATE_KV.delete(`blocked:${id}`);
      return json({ ok: true });
    }

    // ---- ADMIN CHECK ----
    if (path === "/access/is-admin") {
      const token = request.headers.get("x-access-gate-token") || "";
      const isAdmin = await env.ACCESSGATE_KV.get(`admin:${token}`);
      return json({ isAdmin: !!isAdmin });
    }

    return new Response("AccessGate Worker Online", {
      headers: { "content-type": "text/plain" }
    });
  }
};

// --- helpers ---
function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

async function safeJson(req) {
  try { return await req.json(); }
  catch { return {}; }
}
