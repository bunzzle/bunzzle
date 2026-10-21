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
