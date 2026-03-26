export default {
  async fetch(request, env, ctx) {
    if (request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON" }, 400);
      }

      const userId = body.userId || "anonymous";
      const story = body.story || { msg: "no story" };

      const uni = await getUniMaster(env);
      const userKey = await deriveUserKey(uni, userId);
      const signature = await signStory(uni, { userId, story });

      return json({
        ok: true,
        userId,
        // you can remove this if you don't want to expose per-user keys
        userKey,
        signature
      });
    }

    return new Response("AccessGate Root – UniMaster online", {
      headers: { "content-type": "text/plain" }
    });
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" }
  });
}

async function getUniMaster(env) {
  const uni = await env.GLITCHPROTECT_KV.get("uni-master-key", "text");
  if (!uni) throw new Error("UniMaster key missing");
  return uni;
}

async function deriveUserKey(uniMasterKey, userId) {
  const data = new TextEncoder().encode(uniMasterKey + "::user::" + userId);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  return bytesToHex(bytes);
}

async function signStory(uniMasterKey, payload) {
  const enc = new TextEncoder();
  const keyData = enc.encode(uniMasterKey);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const data = enc.encode(JSON.stringify(payload));
  const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, data);
  const bytes = new Uint8Array(sigBuf);
  return bytesToHex(bytes);
}

function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
