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

    try {
      const body = await request.json();
      const { userId, userKey } = body;

      if (!userId || !userKey) {
        return json({ authorized: false, error: "Missing userId or userKey" }, 400, corsHeaders);
      }

      // Raw UniMaster key (100k-bit)
      const masterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      if (!masterKey) {
        return json({ authorized: false, error: "KV key 'uni-master-key' missing" }, 500, corsHeaders);
      }

      // Precomputed SHA-512 digest of UniMaster key (must be stored manually in KV)
      const masterDigest = await env.ACCESSGATE_KV.get("uni-master-key-hash");
      if (!masterDigest) {
        return json({ authorized: false, error: "KV key 'uni-master-key-hash' missing" }, 500, corsHeaders);
      }

      // Hash incoming userKey
      const userDigest = await sha512hex(userKey);

      // Constant-time compare of 128-char digests
      if (!safeCompare(userDigest, masterDigest)) {
        return json({ authorized: false, error: "Unauthorized: key mismatch" }, 401, corsHeaders);
      }

      // Full-entropy signature using raw 100k-bit key
      const signature = await signUser(masterKey, userId);

      return json(
        { ok: true, authorized: true, signature },
        200,
        corsHeaders
      );

    } catch (err) {
      return json({ authorized: false, error: err.message }, 400, corsHeaders);
    }
  }
};

// -----------------------------
// CONSTANT-TIME STRING COMPARE
// -----------------------------
function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// -----------------------------
// SHA-512 HEX DIGEST
// -----------------------------
async function sha512hex(str) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-512", enc.encode(str));
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// -----------------------------
// FULL-ENTROPY SIGNATURE (SHA-512)
// -----------------------------
async function signUser(key, data) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-512", enc.encode(key + data));
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// -----------------------------
// JSON RESPONSE HELPER
// -----------------------------
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}
