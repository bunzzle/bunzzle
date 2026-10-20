export const VERSION = "0.1.0";

export class BunzzleError extends Error {
  constructor(statusCode, name, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = name;
  }
}

const segment = (v) => encodeURIComponent(String(v)).replace(/%3A/gi, ":").replace(/%40/g, "@");

export class Bunzzle {
  #key;
  #base;
  #fetch;

  constructor(options = {}) {
    const key = options.apiKey ?? globalThis.process?.env?.BUNZZLE_API_KEY;
    if (!key) throw new Error("Bunzzle needs an API key: pass apiKey or set BUNZZLE_API_KEY");
    this.#key = key;
    this.#base = (
      options.baseUrl ??
      globalThis.process?.env?.BUNZZLE_URL ??
      "http://127.0.0.1:3000"
    ).replace(/\/+$/, "");
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async #request(method, path, { query, body, headers, text } = {}) {
    const url = new URL(this.#base + path);
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
    const res = await this.#fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${this.#key}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...Object.fromEntries(Object.entries(headers ?? {}).filter(([, v]) => v !== undefined)),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new BunzzleError(res.status, e.name ?? "http_error", e.message ?? res.statusText);
    }
    return text ? res.text() : res.json();
  }

  sendEmail(body, options = {}) {
    return this.#request("POST", `/emails`, {
      body,
      headers: { "idempotency-key": options.idempotencyKey },
    });
  }

  listEmails(options = {}) {
    return this.#request("GET", `/emails`, {
      query: {
        to: options.to,
        status: options.status,
        tag: options.tag,
        domain: options.domain,
        since: options.since,
        until: options.until,
        limit: options.limit,
        cursor: options.cursor,
      },
    });
  }

  sendBatch(body, options = {}) {
    return this.#request("POST", `/emails/batch`, {
      body,
      headers: { "idempotency-key": options.idempotencyKey },
    });
  }

  getEmail(id) {
    return this.#request("GET", `/emails/${segment(id)}`);
  }

  rescheduleEmail(id, body) {
    return this.#request("PATCH", `/emails/${segment(id)}`, { body });
  }

  cancelEmail(id) {
    return this.#request("POST", `/emails/${segment(id)}/cancel`);
  }

  getStats(options = {}) {
    return this.#request("GET", `/stats`, {
      query: {
        since: options.since,
        until: options.until,
        domain: options.domain,
        tag: options.tag,
      },
    });
  }

  listDomains() {
    return this.#request("GET", `/domains`);
  }

  createDomain(body) {
    return this.#request("POST", `/domains`, { body });
  }

  getDomain(name) {
    return this.#request("GET", `/domains/${segment(name)}`);
  }

  updateDomain(name, body) {
    return this.#request("PATCH", `/domains/${segment(name)}`, { body });
  }

  verifyDomain(name) {
    return this.#request("POST", `/domains/${segment(name)}/verify`);
  }

  getDmarcReports(name, options = {}) {
    return this.#request("GET", `/domains/${segment(name)}/dmarc`, {
      query: { days: options.days },
    });
  }

  rotateDomainKeys(name) {
    return this.#request("POST", `/domains/${segment(name)}/rotate`);
  }

  listWebhooks() {
    return this.#request("GET", `/webhooks`);
  }

  createWebhook(body) {
    return this.#request("POST", `/webhooks`, { body });
  }

  deleteWebhook(id) {
    return this.#request("DELETE", `/webhooks/${segment(id)}`);
  }

  listRoutes() {
    return this.#request("GET", `/routes`);
  }

  createRoute(body) {
    return this.#request("POST", `/routes`, { body });
  }

  deleteRoute(id) {
    return this.#request("DELETE", `/routes/${segment(id)}`);
  }

  retryRoute(id) {
    return this.#request("POST", `/routes/${segment(id)}/retry`);
  }

  listTemplates() {
    return this.#request("GET", `/templates`);
  }

  createTemplate(body) {
    return this.#request("POST", `/templates`, { body });
  }

  getTemplate(id, options = {}) {
    return this.#request("GET", `/templates/${segment(id)}`, {
      query: { version: options.version },
    });
  }

  updateTemplate(id, body) {
    return this.#request("PATCH", `/templates/${segment(id)}`, { body });
  }

  deleteTemplate(id) {
    return this.#request("DELETE", `/templates/${segment(id)}`);
  }

  previewTemplate(id, body) {
    return this.#request("POST", `/templates/${segment(id)}/preview`, { body });
  }

  listSuppressions() {
    return this.#request("GET", `/suppressions`);
  }

  createSuppression(body) {
    return this.#request("POST", `/suppressions`, { body });
  }

  deleteSuppression(email, options = {}) {
    return this.#request("DELETE", `/suppressions/${segment(email)}`, {
      query: { scope: options.scope },
    });
  }

  runDoctor() {
    return this.#request("GET", `/doctor`);
  }

  listIps() {
    return this.#request("GET", `/ips`);
  }

  listHolds(options = {}) {
    return this.#request("GET", `/holds`, { query: { all: options.all } });
  }

  releaseHold(id) {
    return this.#request("DELETE", `/holds/${segment(id)}`);
  }

  getQueue() {
    return this.#request("GET", `/queue`);
  }

  suspendDelivery(body) {
    return this.#request("POST", `/queue/suspensions`, { body });
  }

  resumeDelivery(target) {
    return this.#request("DELETE", `/queue/suspensions/${segment(target)}`);
  }

  failQueued(body) {
    return this.#request("POST", `/queue/fail`, { body });
  }

  cancelQueued(body) {
    return this.#request("POST", `/queue/cancel`, { body });
  }

  listPaths() {
    return this.#request("GET", `/paths`);
  }

  getMetrics() {
    return this.#request("GET", `/metrics`, { text: true });
  }

  getHealth() {
    return this.#request("GET", `/health`);
  }
}
