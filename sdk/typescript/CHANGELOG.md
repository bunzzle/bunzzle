# Changelog

## Unreleased

- Projects: `new_recipients_per_day` in `getProject`, `listProjects` and `updateProject`.
- Operations: `listNodes`.

## 0.2.0

First release on npm. Needs Bunzzle 0.2.0 or later.

- A method for every API operation, generated from `openapi.json`, with types for every request and response.
- Emails: `sendEmail`, `sendBatch`, `listEmails`, `getEmail`, `rescheduleEmail`, `cancelEmail`, `getStats`.
- Domains: `listDomains`, `createDomain`, `getDomain`, `updateDomain`, `verifyDomain`, `getDmarcReports`, `rotateDomainKeys`.
- Projects, with an admin key: `listProjects`, `createProject`, `getProject`, `updateProject`, `deleteProject`, `createProjectKey`.
- Webhooks with `listWebhookDeliveries`, `resendWebhookDelivery`, `resendWebhookRange` and `getWebhookResend`; inbound routes, templates with `previewTemplate`, suppressions.
- IP pool rules: `listPoolRules`, `createPoolRule`, `deletePoolRule`.
- Operations: `runDoctor`, `listIps`, `listHolds`, `releaseHold`, `getQueue`, `suspendDelivery`, `resumeDelivery`, `failQueued`, `cancelQueued`, `listPaths`, `getMetrics`, `getHealth`.
- `BunzzleError` with the status code, error name and message.
- No dependencies. Written for Bun, for use on servers.
