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
      // ONE REQUEST PARAM: Read the body as a raw string (the userId)
      const userId = await request.text();

      if (!userId) {
        return json({ authorized: false, error: "Missing userId" }, 400, corsHeaders);
      }

      // 1. Fetch the 100k-bit Master Key
      const masterKey = await env.ACCESSGATE_KV.get("uni-master-key");
      if (!masterKey) {
        return json({ authorized: false, error: "KV key missing" }, 500, corsHeaders);
      }

      /** 
       * ONE PARAMETER FUNCTION: signUser(userId)
       * Uses 'masterKey' from the parent scope (closure)
       */
      const signUser = async (id) => {
        const enc = new TextEncoder();
        const input = enc.encode(masterKey + id);
        const digest = await crypto.subtle.digest("SHA-512", input);
        return [...new Uint8Array(digest)]
          .map(b => b.toString(16).padStart(2, "0"))
          .join("");
      };

      // 2. Generate the signature using the single parameter
      const signature = await signUser(userId);

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
 * Response helper 
 */
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });
}
