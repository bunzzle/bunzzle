export type Error = {
  statusCode: number;
  name: string;
  message: string;
};

export type SendEmail = {
  from: string;
  to: string | string[];
  subject?: string;
  template?: {
    id: string;
    version?: number;
    variables?: Record<string, unknown>;
  };
  cc?: string | string[];
  bcc?: string | string[];
  reply_to?: string | string[];
  html?: string;
  text?: string;
  headers?: Record<string, string>;
  attachments?: {
    filename: string;
    content?: string | number[];
    path?: string;
    content_type?: string;
    content_id?: string;
  }[];
  tags?: {
    name: string;
    value: string;
  }[];
  scheduled_at?: string;
  expires_at?: string;
  require_tls?: boolean;
  lane?: "transactional" | "bulk";
  tracking?: {
    opens?: boolean;
    clicks?: boolean;
  };
};

export type SentEmail = {
  id: string;
};

export type EmailList = {
  object: "list";
  data: {
    object: "email";
    id: string;
    from: string | null;
    to: string[];
    tags: {
      name: string;
      value: string;
    }[];
    lane: "transactional" | "bulk";
    created_at: string;
    last_event:
      | "scheduled"
      | "queued"
      | "sending"
      | "delivery_delayed"
      | "delivered"
      | "bounced"
      | "failed"
      | "expired"
      | "suppressed"
      | "canceled";
    recipients: {
      email: string;
      status:
        | "scheduled"
        | "queued"
        | "sending"
        | "delivery_delayed"
        | "delivered"
        | "bounced"
        | "failed"
        | "expired"
        | "suppressed"
        | "canceled";
    }[];
  }[];
  next_cursor: string | null;
};

export type SendBatch = {
  from: string;
  to: string | string[];
  subject?: string;
  template?: {
    id: string;
    version?: number;
    variables?: Record<string, unknown>;
  };
  cc?: string | string[];
  bcc?: string | string[];
  reply_to?: string | string[];
  html?: string;
  text?: string;
  headers?: Record<string, string>;
  attachments?: {
    filename: string;
    content?: string | number[];
    path?: string;
    content_type?: string;
    content_id?: string;
  }[];
  tags?: {
    name: string;
    value: string;
  }[];
  scheduled_at?: string;
  expires_at?: string;
  require_tls?: boolean;
  lane?: "transactional" | "bulk";
  tracking?: {
    opens?: boolean;
    clicks?: boolean;
  };
}[];

export type SentBatch = {
  data: {
    id: string;
  }[];
};

export type Email = {
  object: "email";
  id: string;
  from: string | null;
  to: string[];
  cc: string[];
  bcc: string[];
  reply_to: string[];
  subject: null;
  html: null;
  text: null;
  tags: {
    name: string;
    value: string;
  }[];
  lane: "transactional" | "bulk";
  created_at: string;
  scheduled_at: string | null;
  last_event:
    | "scheduled"
    | "queued"
    | "sending"
    | "delivery_delayed"
    | "delivered"
    | "bounced"
    | "failed"
    | "expired"
    | "suppressed"
    | "canceled";
  recipients: {
    email: string;
    status:
      | "scheduled"
      | "queued"
      | "sending"
      | "delivery_delayed"
      | "delivered"
      | "bounced"
      | "failed"
      | "expired"
      | "suppressed"
      | "canceled";
    attempts: number;
    last_reply: string | null;
    class: string | null;
    about: string | null;
    suppression_candidate: boolean;
    updated_at: string;
  }[];
  attempts: {
    at: string;
    domain: string;
    mx: string[];
    provider: string | null;
    via: "direct" | "relay";
    tls_policy: string | null;
    reconciled: boolean;
    sessions: {
      host: string;
      ip: string | null;
      reused_connection: boolean;
      tls: {
        status: string;
        version: string | null;
        cipher: string | null;
        rule: string | null;
        error: string | null;
      };
      stopped_at: string | null;
      error: string | null;
      conversation: {
        at_ms: number;
        from: "client" | "server" | "note";
        text: string;
      }[];
    }[];
    results: {
      email: string;
      status: string;
      reply?: string | null;
      class?: string | null;
      action?: string | null;
    }[];
  }[];
  events: Record<string, unknown>[];
};

export type RescheduleEmail = {
  scheduled_at: string;
};

export type EmailRef = {
  object: "email";
  id: string;
};

export type Stats = {
  object: "stats";
  since: string;
  until: string;
  totals: Record<string, number>;
  data: Record<string, string | number>[];
};

export type DomainList = {
  object: "list";
  data: {
    object: "domain";
    name: string;
    mode: "records" | "delegated";
    status: "pending" | "verified";
    created_at: string;
    checked_at: string | null;
    records: {
      record: string;
      name: string;
      type: "TXT" | "MX" | "CNAME";
      value: string;
      required: boolean;
      status: "not_started" | "verified" | "missing" | "mismatch";
      found: string | null;
    }[];
  }[];
};

export type CreateDomain = {
  name: string;
  mode?: "records" | "delegated";
};

export type Domain = {
  object: "domain";
  name: string;
  mode: "records" | "delegated";
  status: "pending" | "verified";
  created_at: string;
  checked_at: string | null;
  records: {
    record: string;
    name: string;
    type: "TXT" | "MX" | "CNAME";
    value: string;
    required: boolean;
    status: "not_started" | "verified" | "missing" | "mismatch";
    found: string | null;
  }[];
};

export type DomainDetail = {
  object: "domain";
  name: string;
  mode: "records" | "delegated";
  status: "pending" | "verified";
  created_at: string;
  checked_at: string | null;
  records: {
    record: string;
    name: string;
    type: "TXT" | "MX" | "CNAME";
    value: string;
    required: boolean;
    status: "not_started" | "verified" | "missing" | "mismatch";
    found: string | null;
  }[];
  ip_pool: string | null;
  tracking: {
    host: string;
    opens: boolean;
    clicks: boolean;
    record: {
      name: string;
      type: "CNAME";
      value: string | null;
      status: "pending" | "verified" | "missing" | "mismatch";
      found: string | null;
    };
    checked_at: string | null;
  } | null;
  gmail: {
    day: string;
    spam_rate: number | null;
    reputation: string | null;
    spf_pass_rate: number | null;
    dkim_pass_rate: number | null;
    dmarc_pass_rate: number | null;
    tls_rate: number | null;
  } | null;
};

export type UpdateDomain = {
  mode?: "records" | "delegated";
  ip_pool?: string | null;
  tracking?: {
    host: string;
    opens?: boolean;
    clicks?: boolean;
  } | null;
};

export type DomainUpdate = {
  name: string;
  ip_pool?: string | null;
  tracking?: {
    host: string;
    opens: boolean;
    clicks: boolean;
    record: {
      name: string;
      type: "CNAME";
      value: string | null;
      status: "pending" | "verified" | "missing" | "mismatch";
      found: string | null;
    };
    checked_at: string | null;
  } | null;
};

export type DmarcReports = {
  object: "list";
  domain: string;
  data: {
    day: string;
    messages: number;
    dmarc_pass: number;
    reporters: string[];
    sources: {
      source_ip: string;
      messages: number;
      dmarc_pass: number;
      dkim_pass: number;
      spf_pass: number;
    }[];
  }[];
};

export type Rotation = {
  result: string;
};

export type ProjectList = {
  object: "list";
  data: {
    object: "project";
    id: string;
    name: string;
    per_hour: number | null;
    per_day: number | null;
    ip_pool: string | null;
    suspended: boolean;
    created_at: string;
    suspended_at: string | null;
  }[];
};

export type CreateProject = {
  name: string;
};

export type Project = {
  object: "project";
  id: string;
  name: string;
  per_hour: number | null;
  per_day: number | null;
  ip_pool: string | null;
  suspended: boolean;
  created_at: string;
  suspended_at: string | null;
};

export type UpdateProject = {
  name?: string;
  per_hour?: number | null;
  per_day?: number | null;
  ip_pool?: string | null;
  suspended?: boolean;
};

export type ProjectDeleted = {
  object: "project";
  id: string;
  deleted: boolean;
};

export type CreateProjectKey = {
  name: string;
  scope?: "send" | "read" | "full";
  domains?: string[];
  rate_limit?: number;
  test?: boolean;
  ip_pool?: string;
};

export type ProjectKey = {
  object: "api_key";
  id: string;
  name: string;
  scope: "send" | "read" | "full";
  domains: string[] | null;
  rate_limit: number;
  test: boolean;
  ip_pool: string | null;
  created_at: string;
  token: string;
};

export type WebhookList = {
  object: "list";
  data: {
    object: "webhook";
    id: string;
    endpoint: string;
    events: (
      | "email.delivered"
      | "email.delivery_delayed"
      | "email.bounced"
      | "email.complained"
      | "email.unsubscribed"
      | "email.suppressed"
      | "email.failed"
      | "email.canceled"
      | "email.opened"
      | "email.clicked"
      | "project.limit_approaching"
    )[];
    created_at: string;
    signing_secret?: string;
  }[];
};

export type CreateWebhook = {
  endpoint: string;
  events?: (
    | "email.delivered"
    | "email.delivery_delayed"
    | "email.bounced"
    | "email.complained"
    | "email.unsubscribed"
    | "email.suppressed"
    | "email.failed"
    | "email.canceled"
    | "email.opened"
    | "email.clicked"
    | "project.limit_approaching"
  )[];
};

export type Webhook = {
  object: "webhook";
  id: string;
  endpoint: string;
  events: (
    | "email.delivered"
    | "email.delivery_delayed"
    | "email.bounced"
    | "email.complained"
    | "email.unsubscribed"
    | "email.suppressed"
    | "email.failed"
    | "email.canceled"
    | "email.opened"
    | "email.clicked"
    | "project.limit_approaching"
  )[];
  created_at: string;
  signing_secret?: string;
};

export type WebhookDeliveryList = {
  object: "list";
  data: {
    object: "webhook_delivery";
    id: string;
    type:
      | "email.delivered"
      | "email.delivery_delayed"
      | "email.bounced"
      | "email.complained"
      | "email.unsubscribed"
      | "email.suppressed"
      | "email.failed"
      | "email.canceled"
      | "email.opened"
      | "email.clicked"
      | "project.limit_approaching";
    state: "pending" | "sending" | "done" | "failed";
    created_at: string;
    next_attempt_at: string | null;
    attempts: {
      at: string;
      status: number | null;
      error: string | null;
      duration_ms: number;
    }[];
  }[];
};

export type Resent = {
  resent: number;
};

export type ResendWebhook = {
  from: string;
  to: string;
  failed?: boolean;
};

export type WebhookResend = {
  object: "webhook_resend";
  id: string;
  webhook_id: string;
  from: string;
  to: string;
  failed: boolean;
  state: "queued" | "done";
  resent: number;
  created_at: string;
  updated_at: string;
};

export type Deleted = {
  id: string;
  deleted: boolean;
};

export type RouteList = {
  object: "list";
  data: {
    object: "route";
    id: string;
    address: string;
    endpoint: string;
    format: "parsed" | "raw";
    created_at: string;
    signing_secret?: string;
  }[];
};

export type CreateRoute = {
  address: string;
  endpoint: string;
  format?: "parsed" | "raw";
};

export type Route = {
  object: "route";
  id: string;
  address: string;
  endpoint: string;
  format: "parsed" | "raw";
  created_at: string;
  signing_secret?: string;
};

export type RouteRetry = {
  id: string;
  requeued: number;
};

export type TemplateList = {
  object: "list";
  data: {
    object: "template";
    id: string;
    name: string;
    version: number;
    created_at: string;
    updated_at: string;
  }[];
};

export type CreateTemplate = {
  name: string;
  subject: string;
  html?: string | null;
  text?: string | null;
};

export type Template = {
  object: "template";
  id: string;
  name: string;
  version: number;
  created_at: string;
  updated_at: string;
  subject: string;
  html: string | null;
  text: string | null;
  versions: number[];
};

export type UpdateTemplate = {
  subject?: string;
  html?: string | null;
  text?: string | null;
};

export type PreviewTemplate = {
  version?: number;
  variables?: Record<string, unknown>;
};

export type Preview = {
  object: "preview";
  id: string;
  name: string;
  version: number;
  subject: string;
  html: string | null;
  text: string | null;
};

export type SuppressionList = {
  object: "list";
  data: {
    object: "suppression";
    email: string;
    scope: "all" | "bulk";
    reason: string;
    detail: string | null;
    email_id: string | null;
    created_at: string;
    expires_at: string | null;
  }[];
};

export type CreateSuppression = {
  email: string;
  scope?: "all" | "bulk";
};

export type SuppressionAdded = {
  email: string;
  scope: "all" | "bulk";
  reason: string;
};

export type SuppressionRemoved = {
  email: string;
  removed: number;
};

export type Doctor = {
  checks: {
    area: string;
    item: string;
    status: "ok" | "warn" | "fail";
    detail: string;
  }[];
  summary: {
    ok: number;
    warn: number;
    fail: number;
  };
};

export type OperatorList = {
  object: "list";
  data: Record<string, unknown>[];
};

export type OperatorView = Record<string, unknown>;

export type Suspend = {
  target: string;
  reason: string;
  until?: string;
};

export type RemoveQueued = {
  reason: string;
  domain?: string;
  sender_domain?: string;
  older_than_seconds?: number;
  dry_run?: boolean;
};

export type Health = {
  ok: boolean;
  version: string;
  uptime_s: number;
  core: "ok" | "unavailable";
};

export interface BunzzleOptions {
  apiKey?: string;
  baseUrl?: string;
  fetch?: typeof fetch;
}

export declare class BunzzleError extends Error {
  readonly statusCode: number;
  readonly name: string;
  constructor(statusCode: number, name: string, message: string);
}

export declare const VERSION: string;

export declare class Bunzzle {
  constructor(options?: BunzzleOptions);
  sendEmail(
    body: SendEmail,
    options?: {
      idempotencyKey?: string;
    },
  ): Promise<SentEmail>;
  listEmails(options?: {
    to?: string;
    status?: "queued" | "delivery_delayed" | "sending" | "delivered" | "bounced" | "failed";
    tag?: string;
    domain?: string;
    since?: string;
    until?: string;
    limit?: number;
    cursor?: string;
  }): Promise<EmailList>;
  sendBatch(
    body: SendBatch,
    options?: {
      idempotencyKey?: string;
    },
  ): Promise<SentBatch>;
  getEmail(id: string): Promise<Email>;
  rescheduleEmail(id: string, body: RescheduleEmail): Promise<EmailRef>;
  cancelEmail(id: string): Promise<EmailRef>;
  getStats(options?: {
    since?: string;
    until?: string;
    domain?: string;
    tag?: string;
  }): Promise<Stats>;
  listDomains(): Promise<DomainList>;
  createDomain(body: CreateDomain): Promise<Domain>;
  getDomain(name: string): Promise<DomainDetail>;
  updateDomain(name: string, body: UpdateDomain): Promise<DomainUpdate>;
  verifyDomain(name: string): Promise<Domain>;
  getDmarcReports(
    name: string,
    options?: {
      days?: number;
    },
  ): Promise<DmarcReports>;
  rotateDomainKeys(name: string): Promise<Rotation>;
  listProjects(): Promise<ProjectList>;
  createProject(body: CreateProject): Promise<Project>;
  getProject(id: string): Promise<Project>;
  updateProject(id: string, body: UpdateProject): Promise<Project>;
  deleteProject(id: string): Promise<ProjectDeleted>;
  createProjectKey(id: string, body: CreateProjectKey): Promise<ProjectKey>;
  listWebhooks(): Promise<WebhookList>;
  createWebhook(body: CreateWebhook): Promise<Webhook>;
  listWebhookDeliveries(
    id: string,
    options?: {
      from?: string;
      to?: string;
      failed?: boolean;
      before?: string;
      limit?: number;
    },
  ): Promise<WebhookDeliveryList>;
  resendWebhookDelivery(id: string, delivery: string): Promise<Resent>;
  resendWebhookRange(id: string, body: ResendWebhook): Promise<WebhookResend>;
  getWebhookResend(id: string, resend: string): Promise<WebhookResend>;
  deleteWebhook(id: string): Promise<Deleted>;
  listRoutes(): Promise<RouteList>;
  createRoute(body: CreateRoute): Promise<Route>;
  deleteRoute(id: string): Promise<Deleted>;
  retryRoute(id: string): Promise<RouteRetry>;
  listTemplates(): Promise<TemplateList>;
  createTemplate(body: CreateTemplate): Promise<Template>;
  getTemplate(
    id: string,
    options?: {
      version?: number;
    },
  ): Promise<Template>;
  updateTemplate(id: string, body: UpdateTemplate): Promise<Template>;
  deleteTemplate(id: string): Promise<Deleted>;
  previewTemplate(id: string, body: PreviewTemplate): Promise<Preview>;
  listSuppressions(): Promise<SuppressionList>;
  createSuppression(body: CreateSuppression): Promise<SuppressionAdded>;
  deleteSuppression(
    email: string,
    options?: {
      scope?: "all" | "bulk";
    },
  ): Promise<SuppressionRemoved>;
  runDoctor(): Promise<Doctor>;
  listIps(): Promise<OperatorList>;
  listHolds(options?: { all?: boolean }): Promise<OperatorView>;
  releaseHold(id: string): Promise<OperatorView>;
  getQueue(): Promise<OperatorView>;
  suspendDelivery(body: Suspend): Promise<OperatorView>;
  resumeDelivery(target: string): Promise<OperatorView>;
  failQueued(body: RemoveQueued): Promise<OperatorView>;
  cancelQueued(body: RemoveQueued): Promise<OperatorView>;
  listPaths(): Promise<OperatorList>;
  getMetrics(): Promise<string>;
  getHealth(): Promise<Health>;
}
