export default {
  async fetch(request, env, ctx) {
    // 1. Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method !== "POST") {
      return new Response("AccessGate Online", { status: 200 });
    }

    try {
      const body = await request.json();
      const uniMasterKey = await env.GLITCHPROTECT_KV.get("uni-master-key");

      // ... (Your crypto logic here) ...
      const signature = "example_sig_123"; 

      // 2. Wrap your JSON response with CORS headers
      return json({ ok: true, signature });
    } catch (err) {
      return json({ error: "Invalid Request" }, 400);
    }
  }
};

/** 
 * Updated Helper: Adds "Allow All" CORS headers
 */
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*" // Allows any domain to read the response
    }
  });
}

/** 
 * Server-Side: Derive a User-Specific Key using SHA-256
 */
async function deriveUserKey(masterKey, userId) {
  const enc = new TextEncoder();
  const data = enc.encode(`${masterKey}:${userId}`);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hash));
}

/** 
 * Server-Side: Sign the payload using HMAC-SHA256
 */
async function signStory(masterKey, payload) {
  const enc = new TextEncoder();
  const keyData = enc.encode(masterKey);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const data = enc.encode(JSON.stringify(payload));
  const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return bytesToHex(new Uint8Array(sigBuf));
}

/** 
 * Helper: Convert binary buffer to Hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Precomputed SHA-512 digest of UniMaster key (must be stored manually in KV)
      const masterDigest = await env.ACCESSGATE_KV.get("uni-master-key-hash");
      if (!masterDigest) {
        return json({ authorized: false, error: "KV key 'uni-master-key-hash' missing" }, 500, corsHeaders);
      }
