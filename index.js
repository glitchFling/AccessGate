export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Define signUser INSIDE fetch so it can access 'masterKey' via closure
    const signUser = async (data) => {
      const enc = new TextEncoder();
      const input = enc.encode(masterKey + data);
      const digest = await crypto.subtle.digest("SHA-512", input);
      return [...new Uint8Array(digest)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    };

    try {
      const body = await request.json();
      const { userId, userKey } = body;

      if (!userId || !userKey) {
        return json({ authorized: false, error: "Missing userId or userKey" }, 400, corsHeaders);
      }

      const masterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      if (!masterKey) {
        return json({ authorized: false, error: "KV key 'uni-master-key' missing" }, 500, corsHeaders);
      }

      const masterDigest = await env.ACCESSGATE_KV.get("uni-master-key-hash");
      if (!masterDigest) {
        return json({ authorized: false, error: "KV key 'uni-master-key-hash' missing" }, 500, corsHeaders);
      }

      const userDigest = await sha512hex(userKey);

      if (!safeCompare(userDigest, masterDigest)) {
        return json({ authorized: false, error: "Unauthorized: key mismatch" }, 401, corsHeaders);
      }

      // Now this works with exactly 1 parameter
      const signature = await signUser(userId);

      return json({ ok: true, authorized: true, signature }, 200, corsHeaders);

    } catch (err) {
      return json({ authorized: false, error: err.message }, 400, corsHeaders);
    }
  }
};

function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function sha512hex(str) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-512", enc.encode(str));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}
