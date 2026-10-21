# Bunzzle SDK for TypeScript and JavaScript

A client for the Bunzzle API, written for Bun. It uses `fetch` and has no dependencies. It is for code that runs on a server: an API key in a web page can be read by anyone who opens it, and the API does not accept calls from web pages. It needs Bunzzle 0.2.0 or later. The code and types are generated from [openapi.json](../../openapi.json), so every API operation is here.

## Install

```sh
bun add @bunzzle/sdk
```

## Use

```ts
import { Bunzzle, BunzzleError } from "@bunzzle/sdk";

const bunzzle = new Bunzzle({ apiKey: "bz_…", baseUrl: "https://mail.example.com" });

const { id } = await bunzzle.sendEmail({
  from: "Acme <hello@acme.com>",
  to: "someone@example.com",
  subject: "Welcome",
  html: "<p>Hi</p>",
});

const email = await bunzzle.getEmail(id);
console.log(email.last_event, email.recipients);
```

Without options, the API key comes from `BUNZZLE_API_KEY` and the address from `BUNZZLE_URL` (`http://127.0.0.1:3000` if neither is set).

Each method is named after an operation of the API: `sendEmail`, `sendBatch`, `listEmails`, `getEmail`, `rescheduleEmail`, `cancelEmail`, `getStats`, `createDomain`, `getDomain`, `updateDomain`, `verifyDomain`, `createWebhook`, `createRoute`, `createTemplate`, `previewTemplate`, `createSuppression` and the rest in [index.d.ts](index.d.ts). Path values come first, then the body, then an options object for query values and headers:

```ts
await bunzzle.sendEmail(email, { idempotencyKey: "order-42" });
await bunzzle.listEmails({ to: "someone@example.com", status: "bounced", limit: 50 });
await bunzzle.updateDomain("acme.com", { tracking: { host: "links.acme.com", clicks: true } });
await bunzzle.deleteSuppression("someone@example.com", { scope: "bulk" });
```

A request the API refuses throws a `BunzzleError` with the status code, the error name and the message:

```ts
try {
  await bunzzle.sendEmail(email);
} catch (err) {
  if (err instanceof BunzzleError && err.statusCode === 422) console.log(err.message);
  else throw err;
}
```

Pass `fetch` in the options to use your own (for retries, proxies or tests).

## License

[MIT](LICENSE).
