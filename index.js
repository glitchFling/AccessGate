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

      // Debug: Check if KV is actually connected
      if (!env.ACESSGATE_KV) {
        throw new Error("KV Binding 'ACESSGATE_KV' is missing in Dashboard");
      }

      const masterKey = await env.ACESSGATE_KV.get("uni-master-key");
      
      if (!masterKey) {
        throw new Error("The key 'uni-master-key' does not exist in your KV namespace");
      }

      // 401 Check
      if (userKey !== masterKey) {
        return new Response(JSON.stringify({ error: "Unauthorized: Key Mismatch" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // If they match, generate the signature
      const signature = await signUser(masterKey, userId);

      return new Response(JSON.stringify({ ok: true, signature }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });

    } catch (err) {
      // THIS WILL TELL YOU THE REAL PROBLEM IN THE CONSOLE
      return new Response(JSON.stringify({ error: err.message }), { 
        status: 400, 
        headers: corsHeaders 
      });
    }
  }
};

async function signUser(key, data) {
  const enc = new TextEncoder();
  const cKey = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}
