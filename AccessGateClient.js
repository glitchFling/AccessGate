// AccessGate Browser Client
// Talks to your Cloudflare Worker endpoints

const AccessGateClient = {
  config: {
    base: "", // e.g. "https://your-worker.workers.dev"
    storageKey: "accessgate.identity.v1",
    deterministicSalt: "my-radio-io.v1"
  },

  // -------------------------
  // Storage
  // -------------------------
  _getStoredId() {
    try {
      return localStorage.getItem(this.config.storageKey);
    } catch {
      return null;
    }
  },

  _setStoredId(id) {
    try {
      localStorage.setItem(this.config.storageKey, id);
    } catch {}
  },

  _isValidId(id) {
    return typeof id === "string" && id.length >= 8 && id.length <= 128;
  },

  // -------------------------
  // Deterministic fallback
  // -------------------------
  async _hash(text) {
    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  },

  async _deterministicFallbackId() {
    const seed = [
      this.config.deterministicSalt,
      navigator.userAgent || "",
      navigator.language || "",
      navigator.platform || "",
      String(navigator.hardwareConcurrency || ""),
      String(navigator.maxTouchPoints || 0),
      String(new Date().getTimezoneOffset())
    ].join("|");

    const digest = await this._hash(seed);
    return "det_" + digest.slice(0, 48);
  },

  // -------------------------
  // Worker API calls
  // -------------------------
  async _post(path, body = {}) {
    const res = await fetch(this.config.base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    if (!res.ok) throw new Error(`Request failed: ${res.status}`);
    return res.json();
  },

  async requestSessionId() {
    const result = await this._post("/access/session");
    return result.id;
  },

  async requestIssuedId(existingId = null) {
    const result = await this._post("/access/issue", existingId ? { existingId } : {});
    return result.id;
  },

  async isBlocked(id) {
    const result = await this._post("/access/check", { id });
    return !!result.blocked;
  },

  async blockUser(id, reason = "manual", adminToken = "") {
    return this._post("/access/block", { id, reason, adminToken });
  },

  async unblockUser(id, adminToken = "") {
    return this._post("/access/unblock", { id, adminToken });
  },

  async isAdmin(adminToken) {
    const res = await fetch(this.config.base + "/access/is-admin", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-access-gate-token": adminToken
      },
      body: "{}"
    });

    if (!res.ok) return false;
    const result = await res.json();
    return !!result.isAdmin;
  },

  // -------------------------
  // Identity flow
  // -------------------------
  async getOrCreateIdentity() {
    // 1) Stored ID
    const stored = this._getStoredId();
    if (this._isValidId(stored)) return stored;

    // 2) Server session ID
    try {
      const sessionId = await this.requestSessionId();
      if (this._isValidId(sessionId)) {
        this._setStoredId(sessionId);
        return sessionId;
      }
    } catch {}

    // 3) Deterministic fallback
    try {
      const det = await this._deterministicFallbackId();
      if (this._isValidId(det)) {
        this._setStoredId(det);
        return det;
      }
    } catch {}

    // 4) Server-issued ID
    const issued = await this.requestIssuedId();
    this._setStoredId(issued);
    return issued;
  }
};

export default AccessGateClient;
