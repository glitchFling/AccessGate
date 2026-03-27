export default {
  async fetch(request, env, ctx) {
    // 1. Define CORS headers to allow all domains (*)
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // 2. Handle the Browser's "Preflight" check (REQUIRED for CORS)
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return new Response("AccessGate Online", { headers: corsHeaders });
    }

    try {
      // 3. Get the userId from the user's request
      const body = await request.json();
      const { userId } = body;

      if (!userId) {
        return new Response(JSON.stringify({ error: "Missing userId" }), { 
          status: 400, 
          headers: corsHeaders 
        });
      }

      // 4. Access the 100,000-bit key from KV (using ACESSGATE_KV)
      // Ensure 'ACESSGATE_KV' is the exact name of your binding
      const uniMasterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      
      if (!uniMasterKey) {
        throw new Error("Master Key not found in KV");
      }

      // 5. Derive the unique signature (Server-Side)
      const signature = await signUser(uniMasterKey, userId);

      // 6. Return the success response
      return new Response(JSON.stringify({
        ok: true,
        userId,
        signature
      }), {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 400,
        headers: corsHeaders
      });
    }
  }
};

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
