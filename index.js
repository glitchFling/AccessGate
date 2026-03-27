export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    let isAuthorized;
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      const body = await request.json();
      const { userId, userKey } = body;

      // FIX: Added the missing "C" to ACCESSGATE_KV
      const masterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      
      if (!masterKey) {
        return new Response(JSON.stringify({ error: "KV Key 'uni-master-key' is missing" }), { 
          status: 400, headers: corsHeaders 
        });
      }

      // 401 Unauthorized check
      if (userKey !== masterKey) {
        isAuthorized = false;
        return new Response(JSON.stringify({ error: "Unauthorized: 100k-bit key mismatch" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const signature = await signUser(masterKey, userId);
      isAuthorized = true;
      return new Response(JSON.stringify({ ok: true, signature }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });

    } catch (err) {
      isAuthorized = false;
      return new Response(JSON.stringify({ error: err.message }), { 
        status: 400, headers: corsHeaders 
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
