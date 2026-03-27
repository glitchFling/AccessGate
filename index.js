export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      const body = await request.json();
      const { userId, userKey } = body;

      if (!userId || !userKey) {
        return json({ authorized: false, error: "Missing fields" }, 400, corsHeaders);
      }

      // 1. Hash the user's incoming key to find the KV "address"
      const userDigest = await sha512hex(userKey);

      // 2. Look for a KV entry where the NAME is that hash string
      // If the key is wrong, the lookup address is wrong, and masterKey is null.
      const masterKey = await env.ACCESSGATE_KV.get(userDigest);

      if (!masterKey) {
        return json({ authorized: false, error: "Unauthorized" }, 401, corsHeaders);
      }

      // 3. If found, the user provided the correct 100k-bit key. Sign the ID.
      const signature = await signUser(masterKey, userId);

      return json({ ok: true, authorized: true, signature }, 200, corsHeaders);

    } catch (err) {
      return json({ authorized: false, error: err.message }, 400, corsHeaders);
    }
  }
};

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
 * Signs the userId with the 100k-bit master key 
 */
async function signUser(key, data) {
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
