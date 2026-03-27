export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // Handle Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const body = await request.json();
      const { userId, userKey } = body;

      // Validate input presence
      if (!userId || !userKey) {
        return json({ authorized: false, error: "Missing userId or userKey" }, 400, corsHeaders);
      }

      // 1. Fetch the 100k-bit Master Key
      const masterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      if (!masterKey) {
        return json({ authorized: false, error: "KV key 'uni-master-key' missing" }, 500, corsHeaders);
      }

      // 2. Fetch the precomputed SHA-512 hash of that key
      const masterDigest = await env.ACCESSGATE_KV.get("uni-master-key-hash");
      if (!masterDigest) {
        return json({ authorized: false, error: "KV key 'uni-master-key-hash' missing" }, 500, corsHeaders);
      }

      // 3. Hash the user's incoming key (Stay under 10ms CPU limit)
      const userDigest = await sha512hex(userKey);

      // 4. Constant-time compare the 128-character hashes
      if (!safeCompare(userDigest, masterDigest)) {
        return json({ authorized: false, error: "Unauthorized: key mismatch" }, 401, corsHeaders);
      }

      // 5. Generate the final high-entropy Admin signature
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

/** 
 * Constant-time comparison to prevent timing attacks 
 */
function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** 
 * Standard SHA-512 Hex generator 
 */
async function sha512hex(str) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-512", enc.encode(str));
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 
 * Signs the userId with the master key (pre-fetched or scoped)
 * Now only requires 1 parameter: data (userId)
 */
async function signUser(data) {
  // Option A: Fetch inside if not passed (though this adds a KV lookup)
  // const key = await env.ACCESSGATE_KV.get("uni-master-key"); 
  
  // Option B: Hardcoded/Env variable (if you move it to a secret)
  const key = env.MASTER_KEY_SECRET; 

  const enc = new TextEncoder();
  const input = enc.encode(key + data);
  const digest = await crypto.subtle.digest("SHA-512", input);
  
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 
 * Response helper 
 */
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}
