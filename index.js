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
      const { userId, userKey } = body; // User must provide their 100k-bit key

      // 1. Get the real master key from KV
      const masterKey = await env.ACESSGATE_KV.get("uni-master-key");

      // 2. UNAUTHORIZED CHECK: Compare user input to the master key
      if (!userKey || userKey !== masterKey) {
        return new Response(JSON.stringify({ error: "Unauthorized: Key Mismatch" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // 3. If they match, proceed to sign
      const signature = await signUser(masterKey, userId);

      return new Response(JSON.stringify({ ok: true, signature }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: "Bad Request" }), { 
        status: 400, 
        headers: corsHeaders 
      });
    }
  }
};

// ... (Keep your signUser and bytesToHex functions below) ...

/**
 * Server-Side HMAC-SHA256 Signing
 */
async function signUser(masterKey, userId) {
  const enc = new TextEncoder();
  const keyData = enc.encode(masterKey);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(userId));
  return Array.from(new Uint8Array(sigBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
