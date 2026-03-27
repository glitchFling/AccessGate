export default {
  async fetch(request, env, ctx) {
    // 1. Define CORS headers for reuse
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*", // Allows any domain to call this
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // 2. Handle the Browser's "Preflight" check
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return new Response("AccessGate Online", { headers: corsHeaders });
    }

    try {
      const body = await request.json();
      const { userId } = body;

      // ... (Your crypto logic with uniMasterKey here) ...
      
      const responseData = { 
        ok: true, 
        userId, 
        signature: "your_100k_bit_derived_sig" 
      };

      // 3. IMPORTANT: Add CORS headers to the actual data response
      return new Response(JSON.stringify(responseData), {
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
