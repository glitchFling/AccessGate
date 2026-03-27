export default {
  async fetch(request, env, ctx) {
    // 1. Only allow POST requests for the secure gate
    if (request.method !== "POST") {
      return new Response("AccessGate Online - System Ready", {
        headers: { "content-type": "text/plain" }
      });
    }

    try {
      // 2. Parse the incoming JSON body
      const body = await request.json();
      const { userId, story } = body;

      if (!userId) {
        return json({ error: "Missing userId" }, 400);
      }

      // 3. Fetch the 100,000-bit Master Key (Server-Side only)
      // This key is stored in KV and never leaves the Cloudflare Edge
      const uniMasterKey = await env.GLITCHPROTECT_KV.get("uni-master-key");
      if (!uniMasterKey) {
        throw new Error("Master Key Configuration Missing");
      }

      // 4. Cryptographic Operations (Server-Side)
      // Derive a unique key for this user and sign the story
      const userKey = await deriveUserKey(uniMasterKey, userId);
      const signature = await signStory(uniMasterKey, { userId, story: story || "no story" });

      // 5. Return the result (Keep the Master Key secret!)
      return json({
        ok: true,
        userId,
        signature,
        verified: true
      });

    } catch (err) {
      return json({ error: "Invalid Request", details: err.message }, 400);
    }
  }
};

/** 
 * Helper: Standard JSON Response 
 */
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
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
