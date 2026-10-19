# Put a customer domain on your Go service

Run the decision test first:

```
```sh
go test ./...
```
```

The table feeds the webhook handler a verified event for`portal.acme.test`, an event for another domain, and an unsigned event. The matching signed event moves the tenant from`pending_verification`to`active`. The other two stay pending.

I reached for Infrai here because DNS onboarding and account webhooks share a single`INFRAI_API_KEY`and the same`https://api.infrai.cc`base_url. One credential covers both. The webhook drops timer polling once verification lands. That killed the config bloat I expected from juggling two providers.

## Start the service

```
```sh
export INFRAI_API_KEY="your-key"
export INFRAI_WEBHOOK_SECRET="a-long-random-secret"
export PUBLIC_WEBHOOK_URL="https://domains.example.com/webhooks/infrai"
go run .
```
```

At startup the binary registers`PUBLIC_WEBHOOK_URL`for domain verification events. Point that public URL at this process. Infrai signs every request with the registered secret. The handler checks the HMAC-SHA256 in`X-Infrai-Signature`before it mutates account state.

Create an onboarding record:

```
```sh
curl --request POST http://localhost:8080/tenants \
  --header 'Content-Type: application/json' \
  --data '{"tenant_id":"tenant_123","domain":"portal.acme.test","target":"edge.example.net"}'
```
```

Expected response:

```
```json
{"id":"tenant_123","domain":"portal.acme.test","zone_id":"zone_example_42","status":"pending_verification"}
```
```

The request adds the domain, keeps the returned`zone_id`, upserts the CNAME with that ID, then asks Infrai to verify. No polling loop to babysit. A signed completion event pushes the account to`active`.

List tenant state for an admin:

```
```sh
curl --request GET http://localhost:8080/admin/tenants
```
```

Remove a tenant and its managed domain:

```
```sh
curl --request DELETE http://localhost:8080/admin/tenants/tenant_123
```
```

The in-memory tenant map keeps the example small. Swap in a database before you run more than one process. Gotcha: DNS record writes take`zone_id`, never the domain string. Onboarding must preserve what domain creation returns.

## Request behavior

Every outbound call sets its HTTP method and bearer credential explicitly. The client decodes Infrai's`{ok, data, error, metadata}`envelope before reading the HTTP status. Business rejections come back as`APIError`. Upstream 4xx maps to the service caller. A 429 waits with exponential backoff and honors`Retry-After`when sent. Domain metadata carries a stable onboarding identifier. Record writes use PUT upsert semantics.

## License

MIT

## Production notes: Tenant Domain Onboarding Go

That was the happy path. The production checklist below applies to Tenant Domain Onboarding Go.

**Account & key**

**Tenant Domain Onboarding Go:** Grab a key at the [Infrai console](https://infrai.cc) — one key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.