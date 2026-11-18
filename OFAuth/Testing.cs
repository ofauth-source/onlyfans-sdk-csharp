// Test helpers: sign webhook deliveries and build sample events (OFAuth.Testing).
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs. Fixtures are generated in Testing.g.cs.
#nullable enable

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OFAuth.Testing;

/// <summary>A signed webhook delivery: send <see cref="Body"/> with <see cref="Headers"/>.</summary>
/// <param name="Headers"><c>webhook-id</c>, <c>webhook-timestamp</c>, and <c>webhook-signature</c>.</param>
/// <param name="Body">The raw JSON body that was signed.</param>
public sealed record SignedWebhook(IReadOnlyDictionary<string, string> Headers, string Body);

/// <summary>
/// Build and sign webhook deliveries in tests, exactly as OFAuth sends them.
/// </summary>
/// <example>
/// <code>
/// var secret = TestWebhooks.GenerateSecret();
/// var router = new WebhookRouter(secret).OnAuthorizationRevoked(e => revoked.Add(e.AuthorizationId));
/// await router.HandleTestEventAsync(WebhookEventTypes.AuthorizationRevoked, new { authorizationId = "authz_1" });
/// </code>
/// </example>
public static class TestWebhooks
{
    /// <summary>Every event type with a fixture (all 17 webhook event types).</summary>
    public static IReadOnlyCollection<string> EventTypes { get; } = WebhookFixtures.Examples.Keys.ToList();

    /// <summary>A random signing secret (<c>whsec_</c> + base64 of 32 bytes).</summary>
    public static string GenerateSecret() => "whsec_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// A valid event envelope for <paramref name="type"/>, from the API spec's example, with a fresh <c>eventId</c>.
    /// <paramref name="overrides"/> (an anonymous object, dictionary, or <see cref="JsonNode"/>) is deep-merged in:
    /// objects merge, other values (arrays included) replace.
    /// </summary>
    /// <param name="type">Event type, e.g. <c>authorization.revoked</c> (see <see cref="WebhookEventTypes"/>).</param>
    /// <param name="overrides">Fields to change, e.g. <c>new { linkedAccountId = "conn_1", data = new { id = 5 } }</c>.</param>
    /// <exception cref="ArgumentException">Unknown event type.</exception>
    public static JsonObject CreateTestEvent(string type, object? overrides = null)
    {
        ArgumentNullException.ThrowIfNull(type);
        if (!WebhookFixtures.Examples.TryGetValue(type, out var example))
        {
            throw new ArgumentException(
                $"Unknown event type '{type}'. Known: {string.Join(", ", WebhookFixtures.Examples.Keys)}", nameof(type));
        }
        var evt = JsonNode.Parse(example)!.AsObject();
        evt["eventId"] = "evt_test_" + Guid.NewGuid().ToString("N");
        if (overrides is not null)
        {
            var patch = overrides as JsonNode ?? JsonSerializer.SerializeToNode(overrides, ApiTransport.JsonOptions);
            if (patch is not JsonObject patchObject) throw new ArgumentException("overrides must serialize to a JSON object", nameof(overrides));
            Merge(evt, patchObject);
        }
        return evt;
    }

    /// <summary>Sign a raw JSON body with Standard Webhooks headers.</summary>
    /// <param name="payload">The exact body to send.</param>
    /// <param name="secret">The <c>whsec_</c> signing secret.</param>
    /// <param name="id">The <c>webhook-id</c>. A random <c>msg_</c> id when omitted.</param>
    /// <param name="timestamp">The <c>webhook-timestamp</c>. Now when omitted.</param>
    public static SignedWebhook SignWebhook(string payload, string secret, string? id = null, DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(secret);
        id ??= "msg_" + Guid.NewGuid().ToString("N");
        var ts = (timestamp ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var key = Convert.FromBase64String(secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret[6..] : secret);
        var signature = Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{id}.{ts}.{payload}")));
        return new SignedWebhook(
            new Dictionary<string, string>
            {
                ["webhook-id"] = id,
                ["webhook-timestamp"] = ts,
                ["webhook-signature"] = $"v1,{signature}",
            },
            payload);
    }

    /// <summary>Serialize <paramref name="payload"/> (e.g. from <see cref="CreateTestEvent"/>) and sign it.</summary>
    /// <param name="payload">An object or <see cref="JsonNode"/> to send as JSON.</param>
    /// <param name="secret">The <c>whsec_</c> signing secret.</param>
    /// <param name="id">The <c>webhook-id</c>. Random when omitted.</param>
    /// <param name="timestamp">The <c>webhook-timestamp</c>. Now when omitted.</param>
    public static SignedWebhook SignWebhook(object payload, string secret, string? id = null, DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var body = payload is JsonNode node ? node.ToJsonString() : JsonSerializer.Serialize(payload, payload.GetType(), ApiTransport.JsonOptions);
        return SignWebhook(body, secret, id, timestamp);
    }

    /// <summary>Verify and dispatch a signed delivery through the router.</summary>
    /// <param name="router">The router under test.</param>
    /// <param name="signed">A delivery from <see cref="SignWebhook(string, string, string?, DateTimeOffset?)"/>.</param>
    public static Task<WebhookEvent> HandleAsync(this WebhookRouter router, SignedWebhook signed)
    {
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(signed);
        return router.HandleAsync(signed.Body, signed.Headers);
    }

    /// <summary>
    /// One call: build a test event (<see cref="CreateTestEvent"/>), sign it with the router's secret, then verify and
    /// dispatch it.
    /// </summary>
    /// <param name="router">The router under test.</param>
    /// <param name="type">Event type.</param>
    /// <param name="overrides">Fields to change.</param>
    public static Task<WebhookEvent> HandleTestEventAsync(this WebhookRouter router, string type, object? overrides = null)
    {
        ArgumentNullException.ThrowIfNull(router);
        return router.HandleAsync(SignWebhook(CreateTestEvent(type, overrides), router.Secret));
    }

    private static void Merge(JsonObject target, JsonObject patch)
    {
        foreach (var (key, value) in patch.ToList())
        {
            if (value is JsonObject patchChild && target[key] is JsonObject targetChild)
            {
                Merge(targetChild, patchChild);
            }
            else
            {
                target[key] = value?.DeepClone();
            }
        }
    }
}
