# OFAuth C# SDK

Install `OnlyFans.SDK` for .NET 8 or later. The package provides typed resource clients, asynchronous pagination, errors, uploads, webhook verification, server Realtime, and standard OAuth helpers.

```csharp
var client = new OFAuthClient(new OFAuthClientOptions
{
    AccessToken = currentAccessToken,
    LinkedAccountId = selectedAccountId,
});
var profile = await client.Access.Profile.GetAsync();

var link = new OFAuthLink(new OFAuthLinkOptions
{
    ClientId = clientId, ClientSecret = clientSecret, RedirectUri = redirectUri,
});
var pending = link.CreateAuthorizationUrl(new CreateAuthorizationUrlOptions { Scopes = ["profile:read"] });
// Save pending under your trusted user and session before redirecting to pending.Url.
var callback = link.ParseCallback(callbackUrl, pending.State);
var tokens = await link.ExchangeCodeAsync(callback.Code, pending.CodeVerifier);
var renewed = await link.RefreshAsync(tokens.RefreshToken);
await link.RevokeAsync(tokens.RefreshToken, "refresh_token");
```

Set `OFAuthClientOptions.AccessTokenProvider` to your auth system's `IAccessTokenProvider` to obtain the current token for each request. Set `OFAuthLinkOptions.ClientAuthentication` to `client_secret_post` for form credentials.

## OAuth contract

Register a confidential backend client and an exact callback URL. Sandbox, Test, and Live use the same authorization code flow with S256 PKCE.

- Browser authorization: `https://link.ofauth.com/v3/authorize`.
- Token exchange and refresh: `POST https://api.ofauth.com/v3/link/token` with a form body.
- Revocation: `POST https://api.ofauth.com/v3/link/revoke` with form `token` and optional `token_type_hint`.
- Metadata: `https://api.ofauth.com/.well-known/oauth-authorization-server/v3/link`.
- Profile: `GET https://api.ofauth.com/v3/link/userinfo` with `identity:read`.

Code exchange always returns a refresh token. Access tokens are opaque Bearer secrets with a 900-second lifetime. Use the returned `expires_in`. Refresh echoes the same client-bound refresh token and extends its 90-day inactivity window. Independent processes can refresh concurrently and retry after a lost response.

The helper uses `client_secret_basic` by default and also supports `client_secret_post`. Each request uses one method. Keep client secrets and refresh tokens on your backend and send them only to OAuth endpoints.

Bind fresh state and the PKCE verifier to the initiating application user and session. Persist pending state in your application, expire it, and consume it once after validating the session. Callback helpers validate the expected state and issuer and reject duplicate parameters. A lost initial code response requires a new authorization attempt.

Your auth framework owns token persistence and renewal. Supply its current access token or token getter to the resource client. The SDK does not provide a second credential manager or database schema. Without a framework, store the standard token response in your database and call the small OAuth helper near expiry. Condition writes on a registration revision so an in-flight refresh cannot overwrite a replacement or recreate a deleted registration. Refresh concurrency does not require a distributed lock.

Discover accounts through `GET /v3/linked-accounts`, then select one explicitly. Token responses do not contain account lists. Client construction sends no requests. An account ID selects a resource; it does not grant authority.

Refresh-token revocation ends that credential and its access tokens. Access-token revocation ends only that bearer. `DELETE /v3/authorization` disconnects the entire authorization. Provider reconnect repairs one selected provider session through `POST /v3/linked-accounts/{id}/reconnect`; it does not renew OAuth or replay writes.

Resource errors distinguish invalid bearer, insufficient permission, account selection, provider reconnect, quota, and transient failure. Follow the error's recovery action. Authenticated requests reject redirects. When injecting a custom transport, preserve this redirect policy; in C#, configure `HttpClientHandler.AllowAutoRedirect = false`.

Developer calls use the application's Developer entitlement. Owners grant account access and do not need an Operator subscription. Operator uses its holder's allowance and cannot access Realtime or Vault+.

See [the public documentation](https://docs.ofauth.com) for consent, grants, guest connection, account linking, and release availability. This branch is coordinated with [OAuth foundation #1274](https://github.com/seb-lewis/ofauth-mono/issues/1274) and requires the matching issuer release.

## Client usage

```csharp
var client = new OFAuthClient(new OFAuthClientOptions
{
    AccessToken = accessToken,           // or AccessTokenProvider = tokenManager
    LinkedAccountId = "conn_...",        // default account for Access and Vault+ calls
    // BaseUrl = "https://api.staging.ofauth.com",
    // HttpClient = httpClientFactory.CreateClient("ofauth"),
});

var profile = await client.Access.Profile.GetAsync();
Console.WriteLine(profile.Username);

var chats = await client.Access.Chats.ListAsync(new AccessChatsListParams { Limit = 10 });

await client.Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
{
    UserId = "123",
    Body = new MessageContent { Text = "Thanks for subscribing!" },
}, cancellationToken);
```

Operations are grouped like the API: `client.Access.{Area}...{Method}Async(params, cancellationToken)`,
`client.VaultPlus...`, and `client.LinkedAccounts...`. Each operation has a `{Name}Params` record (path and query
parameters, `Body`, and an optional `LinkedAccountId`) and a typed response. Doc comments show the scope each
operation needs.

Shorthand constructors: `new OFAuthClient("access-token", "conn_...")` and
`new OFAuthClient(tokenManager, "conn_...", httpClient)`. You can also implement `IAccessTokenProvider`
(`GetAccessTokenAsync(bool forceRefresh, CancellationToken)`) or use `DelegateAccessTokenProvider`.

### Linked accounts

An authorization can cover several linked accounts. Access and Vault+ operations send `x-linked-account-id`:

```csharp
// Per call
await client.Access.Profile.GetAsync(new AccessProfileGetParams { LinkedAccountId = "conn_2" });

// A client bound to another account (shares the token source and HttpClient)
var other = client.WithLinkedAccount("conn_2");

// The authorization's accounts (no linked account header needed)
await foreach (var account in client.LinkedAccounts.IterateAsync())
    Console.WriteLine($"{account.Id} {account.DisplayName}");
```

If an operation needs a linked account and neither the call nor the client sets one, the SDK throws
`OFAuthException` before sending anything.

### Pagination

Paginated operations have an `Iterate...Async` method that returns `IAsyncEnumerable<T>` and fetches pages as needed:

```csharp
await foreach (var chat in client.Access.Chats.IterateAsync(new AccessChatsListParams { Limit = 50 }, maxItems: 500))
{
    Console.WriteLine(chat.User.Id);
}
```

Iteration stops when the API reports no more pages, the next cursor is empty, a page is empty, or `maxItems` is
reached. To page manually, pass `Cursor` from the previous response (`page.Page.NextCursor`, or `NextCursor` for
linked accounts).

### Retries and timeouts

Calls are retried automatically (`MaxRetries`, default 2; `0` disables):

- 429: any method. 503 `authorization_temporarily_unavailable`: any method (rejected before execution).
- Network errors, timeouts, and other 502/503/504: GET, HEAD, and OPTIONS only.
- Never other 4xx, never after your `CancellationToken` fires, never the OAuth token / revoke endpoints.

Only genuine network failures (`HttpRequestException`, `IOException`, `SocketException`) and the SDK's own
per-attempt timeout count as network errors and become `OFAuthConnectionException`. Any other exception thrown by your
`HttpClient` or `HttpMessageHandler` (for example a policy refusal) propagates unchanged on the first attempt and is
never retried.

The wait is `Retry-After` (seconds or HTTP date), else `RateLimit-Reset`, else exponential backoff (0.5s * 2^n with
full jitter, capped at 8s). If the server asks to wait longer than `MaxRetryDelay` (default 60s), for example a
`quota_exhausted` 429, the error is thrown instead. `Timeout` (default 60s) applies per attempt; upload part PUTs use
at least 300s. Errors expose `Attempts`; requests that never got a response throw `OFAuthConnectionException`
(`IsTimeout`, `Attempts`). The `invalid_token` refresh-and-retry does not count against `MaxRetries`.

```csharp
var client = new OFAuthClient(new OFAuthClientOptions
{
    AccessTokenProvider = tokenManager,
    MaxRetries = 3,
    Timeout = TimeSpan.FromSeconds(30),
    MaxRetryDelay = TimeSpan.FromSeconds(10),
});
```

When you pass your own `HttpClient`, its `HttpClient.Timeout` still applies (set it to `Timeout.InfiniteTimeSpan`
to rely on the SDK's per-attempt timeout).

### Hooks and debug logging

```csharp
var client = new OFAuthClient(new OFAuthClientOptions
{
    AccessToken = token,
    OnRequest = info => metrics.Count(info.Operation, info.Attempt),        // Method, Url, Headers (credentials redacted), Attempt
    OnResponse = info => metrics.Time(info.StatusCode, info.Duration),      // Method, Url, StatusCode, RequestId, Duration, Attempt
    DebugLogger = line => logger.LogDebug("{Line}", line),                  // or Debug = true for standard error
});
```

Hooks never see credentials, so they are safe to log. `Headers` redacts `Authorization`, `Cookie`, `X-Api-Key`,
`Cf-Access-Client-Secret`, and any header whose name contains `token`, `secret`, or `password`, whatever the casing.
`Url` has the values of credential-like query parameters (`X-Amz-Signature` and other `X-Amz-*`, `token`, `sig`,
`key`, ...) replaced by `REDACTED`; the request itself is sent unchanged. `DefaultHeaders` cannot set `Authorization`
(the constructor throws): the SDK sends the bearer token itself.

Debug logging (also on with the environment variable `OFAUTH_DEBUG=1`) writes one line per attempt, plus retry
notices, and never tokens, secrets, or bodies:

```
[ofauth] GET /v3/access/profile -> 503 (120ms, req_abc)
[ofauth] retrying GET /v3/access/profile in 0.31s (retry 1 of 2, 503 transient_provider_failure)
[ofauth] GET /v3/access/profile -> 200 (95ms, req_abd)
```

Exceptions thrown by hooks are caught and ignored.

### Errors and recovery actions

Non-2xx responses throw `OFAuthApiException`:

| Property | Meaning |
| --- | --- |
| `StatusCode` | HTTP status |
| `Code` | Stable error code (`error`), e.g. `linked_account_reconnect_required` |
| `RecoveryAction` | What to do next (`recovery.action`), e.g. `reconnect_linked_account` |
| `RequestId` | From the body or `x-request-id`; quote it in support requests |
| `RetryAfter` | From `Retry-After` |
| `ResponseBody` | Raw body |
| `RecoveryActionKind` | `RecoveryAction` as an enum (`Unknown` for values this SDK version does not know) |
| `Operation` / `RequiredScope` | Canonical name of the failed call and the scope it needs |
| `Attempts` | HTTP attempts made, retries included |
| `Issues` | `IReadOnlyList<ValidationIssue>` (`Code`, `Path`, `Message`) for validation errors, else null |
| `ErrorType` | Raw `type` of handler errors, e.g. `RESOURCE_NOT_FOUND`, else null |
| `ErrorMessage` | Human-readable detail (`message`, the summarized issues, or the handler error text) |

Error bodies come in three documented shapes, all normalized onto `Code`:

- `RuntimeError` (`{ "error", "recovery", "requestId" }`): `Code` is `error`, `RecoveryAction` is `recovery.action`.
- `RequestValidationError` (a query, path, or body parameter failed validation): `Code` is `invalid_request`, `RecoveryAction` is `check_request`, `Issues` lists each failure, and `ErrorMessage` reads like `limit: Number must be less than or equal to 100`.
- `AccessHandlerError` (`{ "error": "<message>", "type": "RESOURCE_NOT_FOUND" }`, from some Access handlers such as uploads): `Code` is the lower-cased `type` (`resource_not_found`), `ErrorType` keeps the raw class, `ErrorMessage` is the `error` text, and `RecoveryAction` is null (the helpers fall back to the status).

Branch on `RecoveryAction`, not on the status code alone:

```csharp
try
{
    await client.Access.Profile.GetAsync();
}
catch (OFAuthApiException ex) when (ex.RecoveryAction == "reconnect_linked_account")
{
    // Ask the creator to reconnect through Link.
}
catch (OFAuthApiException ex) when (ex.RecoveryAction == "retry")
{
    await Task.Delay(ex.RetryAfter ?? TimeSpan.FromSeconds(1));
}
```

Or use the helpers:

| Helper | True when |
| --- | --- |
| `IsRetryable` | action `retry` / `retry_after_reset`, or status 429, 502, 503, 504 |
| `NeedsTokenRefresh` | action `obtain_external_oauth_token` |
| `NeedsReauthorization` | action `restart_authorization`, `request_additional_consent`, or `grant_linked_account` (on `OFAuthOAuthException`: `invalid_grant`; on `OFAuthNotAuthorizedException`: always) |
| `NeedsReconnect` | action `reconnect_linked_account` |
| `IsIntegrationProblem` | action `complete_integration_approval`, `update_developer_plan`, `contact_integration_owner`, or `enable_vault_plus` |

```csharp
catch (OFAuthException ex) when (ex.NeedsReauthorization)
{
    return Redirect("/ofauth/connect"); // also covers invalid_grant and users without stored tokens
}
```

All SDK errors derive from `OFAuthException`.
## Webhooks

Deliveries follow [Standard Webhooks](https://www.standardwebhooks.com) (`webhook-id`, `webhook-timestamp`,
`webhook-signature`; `svix-*` headers are accepted too). Verify the **raw** body:

```csharp
WebhookEvent evt = Webhooks.Verify(rawBody, name => request.Headers[name].ToString(), secret); // whsec_...
// evt.Type, evt.EventId, evt.LinkedAccountId, evt.Data (JsonElement)
var revoked = evt.Deserialize<LifecycleAuthorizationRevokedEnvelope>();
```

Failures throw `WebhookVerificationException` with `Code` = `MISSING_HEADERS`, `INVALID_TIMESTAMP`,
`TIMESTAMP_OUT_OF_TOLERANCE` (default tolerance 5 minutes), `NO_VALID_SIGNATURES`, `SIGNATURE_MISMATCH`, or
`INVALID_JSON`.

`WebhookRouter` verifies and dispatches by type, with a typed `On...` method per event:

```csharp
var router = new WebhookRouter(secret)
    .OnAuthorizationRevoked(async e => await DeleteTokensAsync(e.AuthorizationId))
    .OnLinkedAccountExpired(e => NotifyReconnect(e.LinkedAccountId))
    .OnRealtimeChatMessageReceived(e => Console.WriteLine(e.Data.Id))
    .OnDefault(e => Console.WriteLine($"unhandled {e.Type}"));

// ASP.NET Core minimal API (works with any framework: pass the raw body and a header lookup)
app.MapPost("/webhooks/ofauth", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();
    var result = await router.ProcessAsync(body, name => request.Headers[name].ToString());
    return Results.Content(result.ResponseBody ?? "", "application/json", statusCode: result.StatusCode);
});
```

`ProcessAsync` never throws: 200 on success, 401 when verification fails, 500 when a handler throws (OFAuth retries).
`HandleAsync` throws instead. Deduplicate on `EventId` and apply events per linked account in `Order`.

Event types: `authorization.granted|updated|revoked`, `linked_account.expired|reconnected|disconnected`, and the
`realtime.*` events (see `WebhookEventTypes`, with `EnvelopeTypes` and `DataTypes` maps).

### Testing webhooks

`OFAuth.Testing` builds and signs deliveries exactly as OFAuth sends them. Events come from the API spec's example
for each of the 17 types, with a fresh `eventId`; overrides are deep-merged.

```csharp
using OFAuth.Testing;

var secret = TestWebhooks.GenerateSecret();
var router = new WebhookRouter(secret).OnAuthorizationRevoked(e => revoked.Add(e.AuthorizationId));

// One call: build, sign with the router's secret, verify, dispatch.
await router.HandleTestEventAsync(WebhookEventTypes.AuthorizationRevoked, new { authorizationId = "authz_1" });

// Or step by step (e.g. to POST to your endpoint with WebApplicationFactory):
JsonObject evt = TestWebhooks.CreateTestEvent("realtime.chat_message.received", new { data = new { id = 5 } });
SignedWebhook signed = TestWebhooks.SignWebhook(evt, secret); // signed.Headers (webhook-id/-timestamp/-signature), signed.Body
await router.HandleAsync(signed);
```
## Realtime

Stream `realtime.*` events for one linked account over Server-Sent Events (`GET /v3/realtime/events`), through the
client's `HttpClient`:

```csharp
await using var realtime = client.Realtime(); // uses the client's token source and linked account
realtime.OnChatMessageReceived(e => Console.WriteLine($"message {e.Data.Id}"));
realtime.OnEvent(e => Console.WriteLine(e.Type));
realtime.OnResync(() => RefetchEverything()); // events were missed: refetch through the REST API
realtime.OnClose(info => Console.WriteLine($"{info.Reason} ({info.Status}), reconnecting: {info.WillReconnect}"));
realtime.OnError(error => logger.LogWarning(error, "realtime"));

await realtime.ConnectAsync(); // throws OFAuthApiException (401, 409, 503 with RetryAfter, ...) if the first connect fails
// ...
await realtime.CloseAsync();
```

The connection reconnects with jittered exponential backoff from the server's `retry:` (3 seconds), capped at
`MaxReconnectDelay` (30 seconds) and never shorter than `Retry-After`, and resumes with `Last-Event-ID`. Events are
delivered at least once; repeated `eventId`s are dropped. `LastEventId` is the last event's id (its `order`): store it
and pass it as `RealtimeOptions.LastEventId` to resume after a restart. Lifecycle events are delivered by webhook only.

`RealtimeCloseInfo.Reason` says why a stream ended:

| Reason | When | Then |
| --- | --- | --- |
| `Reauth` | `closed` with `reauth`, or 401 | Gets a fresh token (`forceRefresh`) and retries once, then stops. A fixed `AccessToken` stops at once on 401. |
| `Replaced` | `closed` with `replaced`, or 409 | Stops. Up to 10 streams per linked account can be open; a newer one replaces the oldest. |
| `Unavailable` | `closed` with `unavailable`, 503, 429 | Backs off and resumes. |
| `Dropped` | The stream ended without `closed`, or a network error | Resumes. |
| `HeartbeatTimeout` | Nothing, not even the 15 s heartbeat, for `HeartbeatTimeout` (45 s) | Resumes. |
| `Rejected` | 400, 403, 404, 406, a response that is not `text/event-stream`, or an exception from a custom handler | Stops. |
| `ClientClosed` | `CloseAsync()`, or cancelling `ConnectAsync` | Stops. |

`Status` carries the HTTP status of a refusal and `RetryIn` the delay before the next attempt. A first `ConnectAsync`
that never opens throws instead of retrying in the background (after the one token refresh); network errors and
timeouts throw `OFAuthConnectionException`. Calling `ConnectAsync` while connected does nothing.

`RealtimeOptions` sets `LinkedAccountId` (default: the client's), `LastEventId`, `Reconnect`, `MaxReconnectDelay`,
`HeartbeatTimeout` (`TimeSpan.Zero` disables it; it also bounds the wait for the response headers), `OnRequest`,
`OnResponse`, `Debug`, and `DebugLogger`. `client.Realtime()` is the only way to get a `RealtimeConnection` (its
constructor is internal). It always streams `/v3/realtime/events` on the client's `BaseUrl` origin with the client's
token source and `DefaultHeaders`. Realtime is served on the same origin as every other API route, so there is no
realtime URL option and a staging client never sends its token to production Realtime. A `BaseUrl` that is not
http(s) throws `OFAuthException`. The open stream is not subject to `OFAuthClientOptions.Timeout`, and
`HttpClient.Timeout` only applies until the response headers arrive.

Handlers run one at a time, in order, on the connection's read loop. Async handlers are awaited, so a slow handler
delays the next event (but does not count against the heartbeat).

Each connection attempt goes through the hooks and debug logging: `OnRequest` gets `GET`, the sanitized stream URL, and
the headers with `Authorization` redacted; `OnResponse` gets status 200 when the stream opens, or the refusal status
(401, 409, 503, ...), with the duration and the `x-realtime-session-id` (or `x-request-id`) header as `RequestId`.
`client.Realtime()` uses the client's hooks and debug setting unless the options set their own.

```
[ofauth] SSE /v3/realtime/events -> 200 (85ms, rts_abc)
```

### Realtime in the browser

Browsers never get an access token. Your server mints a stream URL and hands only the URL to the page, which opens it
with `EventSource` (or `connectRealtimeStream` from the TypeScript SDK's `@ofauth/onlyfans-sdk/realtime-browser`):

```csharp
RealtimeStreamUrl stream = await client.CreateStreamUrlAsync(); // POST /v3/realtime; or CreateStreamUrlAsync("conn_2")
return Results.Json(new { url = stream.Url, expiresAt = stream.ExpiresAt });
```

The URL carries a 10-minute stream credential that can only read this account's Realtime events (rate limited to 30 per
minute per authorization). When it expires the stream ends with `reauth`; mint a new one.
## Uploads

```csharp
var result = await client.UploadMediaAsync(File.ReadAllBytes("photo.jpg"), new UploadMediaOptions { Filename = "photo.jpg",
    ContentType = "image/jpeg",
    OnProgress = (done, total) => Console.WriteLine($"{done}/{total}"),
    // VaultUpload = new UploadVaultTarget { UserId = "123", ListId = 5 },
});

object mediaItem = result.AlreadyExists ? result.MediaId! : result.UploadId!;
await client.Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
{
    UserId = "123",
    Body = new MessageContent { Text = "New photo", MediaItems = new List<object?> { mediaItem } },
});
```

`UploadMediaAsync` starts the upload (with the MD5 of the file as `etag`, so media already in the vault is reused),
PUTs each part, and finalizes. The result is typed: for `already_exists`, `Media` is the vault `MediaAsset` and
`MediaId` its id; for `uploaded`, `UploadId` is the upload reference and `Finalize` the
`AccessUploadsFinalizeResponse`. With `VaultUpload`, `VaultMediaIds` lists the numeric vault media ids finalize created,
for example to hide them later:

```csharp
await client.Access.Vault.Media.HideAsync(new AccessVaultMediaHideParams
{
    Body = new AccessVaultMediaHideBody { MediaIds = result.VaultMediaIds.Select(id => (double?)id).ToList() },
});
```
## Configuration

| Option | Default |
| --- | --- |
| `OFAuthClientOptions.BaseUrl` | `https://api.ofauth.com` (staging: `https://api.staging.ofauth.com`). Realtime always streams `/v3/realtime/events` on this origin. |
| `OFAuthLinkOptions.AuthUrl` | `https://link.ofauth.com` (staging: `https://link.staging.ofauth.com`) |
| `OFAuthLinkOptions.ApiUrl` | `https://api.ofauth.com` |
| `HttpClient` | A shared `HttpClient`; pass your own (e.g. from `IHttpClientFactory`). The SDK never disposes it. |
| `DefaultHeaders` | Extra headers on every request (case-insensitive; `Authorization` is not allowed) |
| `MaxRetries` / `Timeout` / `MaxRetryDelay` | 2 / 60s per attempt / 60s (see Retries and timeouts) |
| `OnRequest` / `OnResponse` | Hooks, none by default |
| `Debug` / `DebugLogger` | Off (or `OFAUTH_DEBUG=1`); standard error when `Debug` is true |
| `TimeProvider` | `TimeProvider.System`; used for retry waits (replace it in tests) |

### Models

Models are generated from the OpenAPI spec with System.Text.Json. Enums are strings (allowed values are in the doc
comments), so new values never break parsing. Values whose schema is a union the SDK cannot model as one type (for
example `object | array` or `string | number`) are `JsonElement` in responses and `object` in request bodies. Object
variants of a union are merged into one class. Responses are parsed leniently (numbers into string properties,
`3.0` into long properties).
## Development

The SDK is generated: edit `scripts/generate-csharp.mjs` or `scripts/templates/csharp/*.cs`, then

```bash
node scripts/generate-types.mjs     # normalize schemas/openapi.json
node scripts/generate-csharp.mjs    # write packages/csharp/OFAuth
cd packages/csharp
dotnet build OFAuth.sln
dotnet test OFAuth.Test              # unit tests (fake HttpMessageHandler and event streams, fake clock)
dotnet test OFAuth.AspNetCore.Test   # MapOFAuth with TestServer
dotnet test contract                 # manifest mapping; live GET contract with E2E_ACCESS_BASE_URL,
                                     # E2E_ACCESS_TOKEN, E2E_LINKED_ACCOUNT_ID
dotnet run --project examples -- webhook
```

`OFAuth.AspNetCore` is hand-written (the generator only writes `OFAuth/`). Public APIs, generated code included,
have XML doc comments (CS1591 is not suppressed); each operation's comment has a usage example.

### API reference

`docfx.json` builds an HTML reference from the XML doc comments into `docs/` (gitignored), without a global tool
install (.NET 10 SDK):

```bash
cd packages/csharp
dotnet tool exec --yes docfx -- docfx.json   # or: dnx docfx --yes -- docfx.json
```
## License

Apache-2.0
