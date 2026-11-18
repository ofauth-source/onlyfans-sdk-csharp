// OFAuth webhook verification and routing (Standard Webhooks).
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OFAuth;

/// <summary>Why a webhook delivery failed verification.</summary>
public static class WebhookVerificationErrorCodes
{
    /// <summary>A <c>webhook-id</c>, <c>webhook-timestamp</c>, or <c>webhook-signature</c> header is missing.</summary>
    public const string MissingHeaders = "MISSING_HEADERS";

    /// <summary><c>webhook-timestamp</c> is not a Unix timestamp.</summary>
    public const string InvalidTimestamp = "INVALID_TIMESTAMP";

    /// <summary>The delivery is older or newer than the tolerance.</summary>
    public const string TimestampOutOfTolerance = "TIMESTAMP_OUT_OF_TOLERANCE";

    /// <summary><c>webhook-signature</c> has no <c>v1</c> entry.</summary>
    public const string NoValidSignatures = "NO_VALID_SIGNATURES";

    /// <summary>No signature matches the body and secret.</summary>
    public const string SignatureMismatch = "SIGNATURE_MISMATCH";

    /// <summary>The body is not a JSON object.</summary>
    public const string InvalidJson = "INVALID_JSON";
}

/// <summary>The delivery failed verification. Respond with 400 or 401 and do not process it.</summary>
public sealed class WebhookVerificationException : OFAuthException
{
    /// <summary>One of <see cref="WebhookVerificationErrorCodes"/>.</summary>
    public string Code { get; }

    /// <summary>Create a verification error.</summary>
    /// <param name="message">What failed.</param>
    /// <param name="code">One of <see cref="WebhookVerificationErrorCodes"/>.</param>
    /// <param name="innerException">The cause, if any.</param>
    public WebhookVerificationException(string message, string code, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }
}

/// <summary>The signature headers of one delivery.</summary>
/// <param name="Id"><c>webhook-id</c>.</param>
/// <param name="Timestamp"><c>webhook-timestamp</c> (Unix seconds).</param>
/// <param name="Signature"><c>webhook-signature</c> (space-separated <c>v1,&lt;base64&gt;</c> entries).</param>
public sealed record WebhookHeaders(string Id, string Timestamp, string Signature);

/// <summary>
/// A verified webhook event. Every event has the same envelope; <see cref="Data"/> depends on <see cref="Type"/>.
/// Use <see cref="Deserialize{T}"/> or <see cref="GetData{T}"/> for the typed classes listed in
/// <see cref="WebhookEventTypes"/>.
/// </summary>
public sealed class WebhookEvent
{
    /// <summary>Unique event id. Deduplicate on it: deliveries are retried.</summary>
    [JsonPropertyName("eventId")] public string EventId { get; set; } = "";

    /// <summary>Event type, e.g. <c>authorization.revoked</c>. See <see cref="WebhookEventTypes"/>.</summary>
    [JsonPropertyName("type")] public string Type { get; set; } = "";

    /// <summary>Envelope schema version (<c>1</c>).</summary>
    [JsonPropertyName("schemaVersion")] public string SchemaVersion { get; set; } = "";

    /// <summary>Per linked account ordering. Apply events in this order: retries can arrive out of order.</summary>
    [JsonPropertyName("order")] public long Order { get; set; }

    /// <summary>When the event happened (ISO 8601).</summary>
    [JsonPropertyName("occurredAt")] public string OccurredAt { get; set; } = "";

    /// <summary><c>sandbox</c>, <c>test</c>, or <c>live</c>.</summary>
    [JsonPropertyName("environment")] public string Environment { get; set; } = "";

    /// <summary>Your integration id.</summary>
    [JsonPropertyName("integrationId")] public string IntegrationId { get; set; } = "";

    /// <summary>The OAuth client the authorization belongs to.</summary>
    [JsonPropertyName("externalOauthClientId")] public string? ExternalOauthClientId { get; set; }

    /// <summary>The authorization identifier from the API.</summary>
    [JsonPropertyName("authorizationId")] public string? AuthorizationId { get; set; }

    /// <summary>Null for <c>authorization.*</c> events.</summary>
    [JsonPropertyName("linkedAccountId")] public string? LinkedAccountId { get; set; }

    /// <summary>True for test deliveries.</summary>
    [JsonPropertyName("test")] public bool Test { get; set; }

    /// <summary>Event payload. Its shape depends on <see cref="Type"/>.</summary>
    [JsonPropertyName("data")] public JsonElement Data { get; set; }

    /// <summary>The raw JSON body.</summary>
    [JsonIgnore] public string RawJson { get; internal set; } = "";

    /// <summary>True for <c>authorization.*</c> and <c>linked_account.*</c> events.</summary>
    [JsonIgnore]
    public bool IsLifecycle => Type.StartsWith("authorization.", StringComparison.Ordinal)
        || Type.StartsWith("linked_account.", StringComparison.Ordinal);

    /// <summary>The whole event as a typed envelope, e.g. <c>LifecycleAuthorizationRevokedEnvelope</c>.</summary>
    public T Deserialize<T>() => JsonSerializer.Deserialize<T>(RawJson, ApiTransport.JsonOptions)!;

    /// <summary><see cref="Data"/> as a typed class, e.g. <c>RealtimeChatMessageReceivedData</c>.</summary>
    public T GetData<T>() => Data.Deserialize<T>(ApiTransport.JsonOptions)!;

    internal static WebhookEvent Parse(string json)
    {
        WebhookEvent? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<WebhookEvent>(json, ApiTransport.JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new WebhookVerificationException("Webhook body is not valid JSON", WebhookVerificationErrorCodes.InvalidJson, ex);
        }
        if (parsed is null)
        {
            throw new WebhookVerificationException("Webhook body is not a JSON object", WebhookVerificationErrorCodes.InvalidJson);
        }
        parsed.Data = parsed.Data.ValueKind == JsonValueKind.Undefined ? default : parsed.Data.Clone();
        parsed.RawJson = json;
        return parsed;
    }
}

/// <summary>
/// Webhook verification. Deliveries follow Standard Webhooks: <c>webhook-id</c>, <c>webhook-timestamp</c>, and
/// <c>webhook-signature</c> headers (<c>svix-*</c> accepted too), signed with HMAC-SHA256 over
/// <c>{id}.{timestamp}.{body}</c> with the destination's <c>whsec_</c> secret.
/// </summary>
/// <example>
/// <code>
/// // ASP.NET Core minimal API
/// app.MapPost("/webhooks/ofauth", async (HttpRequest request) =>
/// {
///     using var reader = new StreamReader(request.Body);
///     var body = await reader.ReadToEndAsync();
///     var evt = Webhooks.Verify(body, name => request.Headers[name].ToString(), secret);
///     return Results.Ok();
/// });
/// </code>
/// </example>
public static class Webhooks
{
    /// <summary>Default maximum age of a delivery.</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromMinutes(5);

    /// <summary>Read the signature headers with a header lookup (case-insensitive names are the caller's job).</summary>
    public static WebhookHeaders ExtractHeaders(Func<string, string?> getHeader)
    {
        ArgumentNullException.ThrowIfNull(getHeader);
        string? Get(string name) => getHeader(name) is { Length: > 0 } value ? value : null;
        var id = Get("webhook-id") ?? Get("svix-id");
        var timestamp = Get("webhook-timestamp") ?? Get("svix-timestamp");
        var signature = Get("webhook-signature") ?? Get("svix-signature");
        if (id is null || timestamp is null || signature is null)
        {
            throw new WebhookVerificationException(
                "Missing webhook-id, webhook-timestamp, or webhook-signature header", WebhookVerificationErrorCodes.MissingHeaders);
        }
        return new WebhookHeaders(id, timestamp, signature);
    }

    /// <summary>Read the signature headers from name/value pairs (names are matched case-insensitively).</summary>
    public static WebhookHeaders ExtractHeaders(IEnumerable<KeyValuePair<string, string>> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers) map.TryAdd(header.Key, header.Value);
        return ExtractHeaders(name => map.TryGetValue(name, out var value) ? value : null);
    }

    /// <summary>Verify a delivery's signature against the raw body. Throws <see cref="WebhookVerificationException"/>.</summary>
    public static void VerifySignature(
        string payload,
        WebhookHeaders headers,
        string secret,
        TimeSpan? tolerance = null,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(secret);

        if (!long.TryParse(headers.Timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp))
        {
            throw new WebhookVerificationException("Invalid webhook-timestamp", WebhookVerificationErrorCodes.InvalidTimestamp);
        }
        var current = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        if (Math.Abs(current - timestamp) > (tolerance ?? DefaultTolerance).TotalSeconds)
        {
            throw new WebhookVerificationException(
                "Webhook timestamp is outside the tolerance", WebhookVerificationErrorCodes.TimestampOutOfTolerance);
        }

        var signatures = headers.Signature
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(entry => entry.Split(',', 2))
            .Where(parts => parts.Length == 2 && parts[0] == "v1" && parts[1].Length > 0)
            .Select(parts => parts[1])
            .ToList();
        if (signatures.Count == 0)
        {
            throw new WebhookVerificationException(
                "No v1 signature in webhook-signature", WebhookVerificationErrorCodes.NoValidSignatures);
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret[6..] : secret);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("The webhook secret is not valid base64 (expected whsec_...)", nameof(secret), ex);
        }
        var signed = Encoding.UTF8.GetBytes($"{headers.Id}.{headers.Timestamp}.{payload}");
        var expected = Encoding.ASCII.GetBytes(Convert.ToBase64String(HMACSHA256.HashData(key, signed)));

        var match = false;
        foreach (var signature in signatures)
        {
            // Check every entry so timing does not reveal which one matched.
            match |= CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(signature), expected);
        }
        if (!match)
        {
            throw new WebhookVerificationException("Webhook signature does not match", WebhookVerificationErrorCodes.SignatureMismatch);
        }
    }

    /// <summary>Verify a delivery and parse its event. Pass the raw body exactly as received.</summary>
    public static WebhookEvent Verify(string payload, Func<string, string?> getHeader, string secret, TimeSpan? tolerance = null)
    {
        VerifySignature(payload, ExtractHeaders(getHeader), secret, tolerance);
        return WebhookEvent.Parse(payload);
    }

    /// <summary>Verify a delivery and parse its event. Pass the raw body exactly as received.</summary>
    public static WebhookEvent Verify(
        string payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        string secret,
        TimeSpan? tolerance = null)
    {
        VerifySignature(payload, ExtractHeaders(headers), secret, tolerance);
        return WebhookEvent.Parse(payload);
    }

    /// <summary>Verify a UTF-8 body and parse its event.</summary>
    public static WebhookEvent Verify(byte[] payload, Func<string, string?> getHeader, string secret, TimeSpan? tolerance = null) =>
        Verify(Encoding.UTF8.GetString(payload), getHeader, secret, tolerance);

    /// <summary>Verify a UTF-8 body and parse its event.</summary>
    public static WebhookEvent Verify(
        byte[] payload,
        IEnumerable<KeyValuePair<string, string>> headers,
        string secret,
        TimeSpan? tolerance = null) =>
        Verify(Encoding.UTF8.GetString(payload), headers, secret, tolerance);
}

/// <summary>The outcome of <see cref="WebhookRouter.ProcessAsync"/>: what to send back to OFAuth.</summary>
public sealed record WebhookProcessResult(int StatusCode, string? ResponseBody, WebhookEvent? Event, Exception? Exception);

/// <summary>
/// Verifies deliveries and dispatches them by <c>type</c>. Typed <c>On...</c> methods are generated for every event.
/// </summary>
/// <remarks>Deduplicate on <c>eventId</c>, and apply events per <c>linkedAccountId</c> in <c>order</c>.</remarks>
/// <example>
/// <code>
/// var router = new WebhookRouter(secret)
///     .OnAuthorizationRevoked(async e => await DeleteTokens(e.AuthorizationId))
///     .OnRealtimeChatMessageReceived(e => Console.WriteLine(e.Data.Id))
///     .OnDefault(e => Console.WriteLine($"unhandled {e.Type}"));
/// var result = await router.ProcessAsync(body, name => request.Headers[name].ToString());
/// // respond with result.StatusCode
/// </code>
/// </example>
public sealed partial class WebhookRouter
{
    private readonly Dictionary<string, Func<WebhookEvent, Task>> _handlers = new(StringComparer.Ordinal);
    private Func<WebhookEvent, Task>? _defaultHandler;
    private string _secret;

    /// <summary>Create a router.</summary>
    /// <param name="secret">The destination's <c>whsec_</c> signing secret.</param>
    /// <param name="tolerance">Maximum delivery age. Defaults to 5 minutes.</param>
    public WebhookRouter(string secret, TimeSpan? tolerance = null)
    {
        _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        Tolerance = tolerance;
    }

    /// <summary>Maximum delivery age. Defaults to 5 minutes.</summary>
    public TimeSpan? Tolerance { get; set; }

    internal string Secret => _secret;

    /// <summary>Handle one event type with the untyped event.</summary>
    public WebhookRouter On(string type, Func<WebhookEvent, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handlers[type] = handler;
        return this;
    }

    /// <summary>Handle one event type with the untyped event.</summary>
    public WebhookRouter On(string type, Action<WebhookEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e =>
        {
            handler(e);
            return Task.CompletedTask;
        });
    }

    /// <summary>Handle one event type with a typed envelope (see <see cref="WebhookEventTypes.EnvelopeTypes"/>).</summary>
    public WebhookRouter On<TEnvelope>(string type, Func<TEnvelope, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e => handler(e.Deserialize<TEnvelope>()));
    }

    /// <summary>Handle one event type with a typed envelope.</summary>
    public WebhookRouter On<TEnvelope>(string type, Action<TEnvelope> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e => handler(e.Deserialize<TEnvelope>()));
    }

    /// <summary>Handle events without a specific handler.</summary>
    public WebhookRouter OnDefault(Func<WebhookEvent, Task> handler)
    {
        _defaultHandler = handler ?? throw new ArgumentNullException(nameof(handler));
        return this;
    }

    /// <summary>Handle events without a specific handler.</summary>
    public WebhookRouter OnDefault(Action<WebhookEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return OnDefault(e =>
        {
            handler(e);
            return Task.CompletedTask;
        });
    }

    /// <summary>Rotate the signing secret.</summary>
    public void SetSecret(string secret) => _secret = secret ?? throw new ArgumentNullException(nameof(secret));

    /// <summary>Verify and dispatch a raw delivery. Returns the event; throws on verification or handler errors.</summary>
    public async Task<WebhookEvent> HandleAsync(string payload, Func<string, string?> getHeader)
    {
        var evt = Webhooks.Verify(payload, getHeader, _secret, Tolerance);
        await DispatchAsync(evt).ConfigureAwait(false);
        return evt;
    }

    /// <summary>Verify and dispatch a raw delivery. Returns the event; throws on verification or handler errors.</summary>
    public async Task<WebhookEvent> HandleAsync(string payload, IEnumerable<KeyValuePair<string, string>> headers)
    {
        var evt = Webhooks.Verify(payload, headers, _secret, Tolerance);
        await DispatchAsync(evt).ConfigureAwait(false);
        return evt;
    }

    /// <summary>
    /// Framework-agnostic handler: verifies and dispatches, never throws. Respond with
    /// <see cref="WebhookProcessResult.StatusCode"/>: 200 on success, 401 when verification fails, 500 when a
    /// handler throws (OFAuth retries).
    /// </summary>
    public async Task<WebhookProcessResult> ProcessAsync(string payload, Func<string, string?> getHeader)
    {
        WebhookEvent evt;
        try
        {
            evt = Webhooks.Verify(payload, getHeader, _secret, Tolerance);
        }
        catch (WebhookVerificationException ex)
        {
            return new WebhookProcessResult(401, JsonSerializer.Serialize(new { error = ex.Code }), null, ex);
        }
        try
        {
            await DispatchAsync(evt).ConfigureAwait(false);
            return new WebhookProcessResult(200, null, evt, null);
        }
        catch (Exception ex)
        {
            return new WebhookProcessResult(500, "{\"error\":\"handler_failed\"}", evt, ex);
        }
    }

    /// <summary>Dispatch an already verified event.</summary>
    public Task DispatchAsync(WebhookEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        var handler = _handlers.TryGetValue(evt.Type, out var h) ? h : _defaultHandler;
        return handler is null ? Task.CompletedTask : handler(evt);
    }
}
