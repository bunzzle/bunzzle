# Projects

One Bunzzle server can hold several projects. Each project has its own API keys, domains, email, webhooks, inbound routes, templates, suppressions and stats. A project key sees and changes only its own project; an id from another project answers 404.

A new server has one project, `default`. Every existing key and domain belongs to it, so a server with one project works the same as before.

## Admin keys

An admin key manages projects. It cannot send email or read a project's data.

```sh
sudo bunzzle keys create --name ops --admin
```

With an admin key:

```sh
curl -X POST http://127.0.0.1:3000/projects \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "shop"}'

curl -X POST http://127.0.0.1:3000/projects/shop/keys \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name": "shop-app", "scope": "full"}'
```

`GET /projects`, `GET /projects/:id`, `PATCH /projects/:id` and `DELETE /projects/:id` list, show, change and remove projects. `:id` is the project's id or name. Every change is written to the event log as a `project.*` event with the project and the key that made it.

## From the command line

```sh
sudo bunzzle projects add shop
sudo bunzzle projects list
sudo bunzzle projects show shop
sudo bunzzle keys create --project shop --name shop-app --scope full
sudo bunzzle domains add shop.example --project shop
```

`--project NAME` works with `domains`, `keys`, `webhooks`, `routes`, `suppressions`, `emails` and `stats`. Without it they work on `default`.

## Domains

A domain belongs to one project. Adding a domain that another project already has answers 409 `domain_taken`. The operator moves a domain, with its inbound routes, to another project:

```sh
sudo bunzzle domains move shop.example shop
```

Email already queued for the old project is still sent. Its stats and suppressions stay with the old project.

## Reputation

Each sending domain's bulk email is checked on its own. When the server has two or more projects (removed ones do not count), the bulk email of a project that sends it from two or more domains is also checked over all those domains together: a hard bounce rate of 5 % or a complaint rate of 0.3 % over the last two days holds the whole project's bulk lane. The total must reach `BUNZZLE_GUARD_MIN_VOLUME` emails, which each domain alone may not, so spreading email over many domains does not avoid the check. A project with one domain, or a server with one project, is checked per domain only. Transactional email keeps going. `bunzzle holds` shows the hold, and only the operator releases it with `bunzzle holds release ID`.

## Suppressions

Complaints, unsubscribes and addresses added by hand belong to one project. An address that bounced because it does not exist, or whose domain takes no email, is suppressed for every project: other projects see it as reason `invalid`, without the bounce text or which project sent to it. A project cannot remove such an address. `BUNZZLE_SHARED_BOUNCES=false` keeps these bounces per project too.

## IP pools

The operator can give a pool from `BUNZZLE_SOURCE_IPS` to one project:

```sh
sudo bunzzle pools list
sudo bunzzle pools own acme shop
sudo bunzzle pools share acme
```

An owned pool is used only by its project: its domains, keys and the project itself (`PATCH /projects/shop` with `{"ip_pool": "acme"}`) can choose it, other projects cannot. `main` and `bulk` are always shared. When a pool gets an owner, other projects' domains and keys that chose it go back to the shared IPs; email they already queued keeps its pool.

A key's pool comes first, then the domain's, then the project's.

## Send limits

```sh
sudo bunzzle projects limits shop --per-hour 1000 --per-day 10000
sudo bunzzle projects limits shop --per-day none
```

Or `PATCH /projects/shop` with `{"per_hour": 1000, "per_day": 10000}`; `null` removes a limit.

Limits count recipients that will be sent to: suppressed addresses and email sent with a test key do not count. The hour is the last 60 minutes, counted per minute; the day is the current hour and the 23 before it. Counting starts when a project gets its first limit.

Email over a limit is refused when it is sent, never held later: the API answers 429 `project_limit` with a `Retry-After` header in seconds, and SMTP submission answers `451 4.7.1`. A batch is accepted whole or not at all. Refused email does not count. An email with more recipients than the limit itself answers 422.

When a project reaches 90 % of a limit, its webhooks get one `project.limit_approaching` event per hour or day, with `window`, `limit` and `used`.

## Suspending a project

```sh
sudo bunzzle projects suspend shop
sudo bunzzle projects resume shop
```

Or `PATCH /projects/shop` with `{"suspended": true}` or `{"suspended": false}`.

While a project is suspended:

- sending answers 403 `project_suspended`; a batch is refused whole
- its queued email waits and is sent after the project is resumed
- queued email whose `expires_at` passes fails as expired at that time, with the usual `email.failed` webhook; it is not sent after resume
- inbound routes keep delivering, and webhooks keep receiving bounces and complaints

Email the server sends itself, such as TLS reports, is never held or refused, even when it comes from a suspended project's domain.

Suspending or resuming twice changes nothing the second time.

## Removing a project

```sh
sudo bunzzle projects remove shop
```

Or `DELETE /projects/shop`. At once:

- the project's API keys stop working
- its queued email is canceled; email that is being sent at that moment finishes
- its domains are released, so another project can add them
- its webhooks and inbound routes stop

The rest of its data is deleted in the background, in small batches. Email that was being sent is deleted once its outcome is known. The project's name can be used again after that. Removing a project twice answers the same as once. The `default` project cannot be removed.
