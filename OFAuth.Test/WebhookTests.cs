using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OFAuth.Test;

public class WebhookTests
{
    private static readonly byte[] SecretBytes = Encoding.UTF8.GetBytes("test-webhook-secret-bytes");
    private static readonly string Secret = "whsec_" + Convert.ToBase64String(SecretBytes);

    private static readonly string Body = JsonSerializer.Serialize(new
    {
        eventId = "evt_1",
        type = "authorization.revoked",
        schemaVersion = "1",
        order = 1,
        occurredAt = "2026-10-12T14:30:15.143Z",
        environment = "live",
        integrationId = "int_1",
        externalOauthClientId = "c_1",
        authorizationId = "external_live_1",
        linkedAccountId = (string?)null,
        test = false,
        data = new { authorization_id = "external_live_1", reason = "owner_revoked", linked_account_ids = new[] { "conn_1" } },
    });

    private static string Sign(string id, long timestamp, string payload) =>
        Convert.ToBase64String(HMACSHA256.HashData(SecretBytes, Encoding.UTF8.GetBytes($"{id}.{timestamp}.{payload}")));

    private static Dictionary<string, string> Headers(string prefix = "webhook", long? timestamp = null, string? payload = null)
    {
        var ts = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new Dictionary<string, string>
        {
            [$"{prefix}-id"] = "msg_1",
            [$"{prefix}-timestamp"] = ts.ToString(),
            [$"{prefix}-signature"] = $"v1,bogus v1,{Sign("msg_1", ts, payload ?? Body)}",
        };
    }

    [Fact]
    public void VerifiesAValidDelivery()
    {
        var evt = Webhooks.Verify(Body, Headers(), Secret);
        Assert.Equal("evt_1", evt.EventId);
        Assert.Equal(WebhookEventTypes.AuthorizationRevoked, evt.Type);
        Assert.True(evt.IsLifecycle);
        Assert.Null(evt.LinkedAccountId);

        var typed = evt.Deserialize<LifecycleAuthorizationRevokedEnvelope>();
        Assert.Equal("external_live_1", typed.AuthorizationId);
        Assert.Equal("owner_revoked", typed.Data.Reason);
        Assert.Equal(new[] { "conn_1" }, typed.Data.LinkedAccountIds);
    }

    [Fact]
    public void AcceptsSvixHeadersAndHeaderLookups()
    {
        var headers = Headers("svix");
        var evt = Webhooks.Verify(Encoding.UTF8.GetBytes(Body), name => headers.TryGetValue(name, out var v) ? v : null, Secret);
        Assert.Equal("evt_1", evt.EventId);
    }

    [Fact]
    public void MatchesHeaderNamesCaseInsensitively()
    {
        var headers = Headers().ToDictionary(h => h.Key.ToUpperInvariant(), h => h.Value);
        Assert.Equal("evt_1", Webhooks.Verify(Body, headers, Secret).EventId);
    }

    [Fact]
    public void RejectsABadSignature()
    {
        var headers = Headers();
        headers["webhook-signature"] = "v1," + Convert.ToBase64String(new byte[32]);
        var error = Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body, headers, Secret));
        Assert.Equal(WebhookVerificationErrorCodes.SignatureMismatch, error.Code);

        var tampered = Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body + " ", Headers(), Secret));
        Assert.Equal(WebhookVerificationErrorCodes.SignatureMismatch, tampered.Code);
    }

    [Fact]
    public void RejectsOldTimestamps()
    {
        var old = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3600;
        var error = Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body, Headers(timestamp: old), Secret));
        Assert.Equal(WebhookVerificationErrorCodes.TimestampOutOfTolerance, error.Code);
        // A wider tolerance accepts it.
        Assert.Equal("evt_1", Webhooks.Verify(Body, Headers(timestamp: old), Secret, TimeSpan.FromHours(2)).EventId);
    }

    [Fact]
    public void ReportsMissingHeadersInvalidTimestampsAndMissingSignatures()
    {
        Assert.Equal(
            WebhookVerificationErrorCodes.MissingHeaders,
            Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body, new Dictionary<string, string>(), Secret)).Code);

        var badTs = Headers();
        badTs["webhook-timestamp"] = "soon";
        Assert.Equal(
            WebhookVerificationErrorCodes.InvalidTimestamp,
            Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body, badTs, Secret)).Code);

        var noV1 = Headers();
        noV1["webhook-signature"] = "v2,abc";
        Assert.Equal(
            WebhookVerificationErrorCodes.NoValidSignatures,
            Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(Body, noV1, Secret)).Code);
    }

    [Fact]
    public void ReportsInvalidJson()
    {
        const string payload = "not json";
        var error = Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(payload, Headers(payload: payload), Secret));
        Assert.Equal(WebhookVerificationErrorCodes.InvalidJson, error.Code);
    }

    [Fact]
    public async Task RoutesByTypeWithTypedAndDefaultHandlers()
    {
        string? revoked = null;
        string? fallback = null;
        var router = new WebhookRouter(Secret)
            .OnAuthorizationRevoked(e => revoked = e.Data.Reason)
            .OnDefault(e => fallback = e.Type);

        var headers = Headers();
        var evt = await router.HandleAsync(Body, headers);
        Assert.Equal("evt_1", evt.EventId);
        Assert.Equal("owner_revoked", revoked);
        Assert.Null(fallback);

        var other = Body.Replace("authorization.revoked", "linked_account.expired");
        await router.HandleAsync(other, Headers(payload: other));
        Assert.Equal("linked_account.expired", fallback);
    }

    [Fact]
    public async Task ProcessReturnsStatusCodes()
    {
        var router = new WebhookRouter(Secret).On(WebhookEventTypes.AuthorizationRevoked, _ => throw new InvalidOperationException("boom"));
        var headers = Headers();
        string? Lookup(string name) => headers.TryGetValue(name, out var v) ? v : null;

        var failed = await router.ProcessAsync(Body, Lookup);
        Assert.Equal(500, failed.StatusCode);
        Assert.IsType<InvalidOperationException>(failed.Exception);

        var unverified = await router.ProcessAsync(Body + "x", Lookup);
        Assert.Equal(401, unverified.StatusCode);
        Assert.Equal("{\"error\":\"SIGNATURE_MISMATCH\"}", unverified.ResponseBody);

        var ok = await new WebhookRouter(Secret).ProcessAsync(Body, Lookup);
        Assert.Equal(200, ok.StatusCode);
        Assert.Equal("evt_1", ok.Event!.EventId);
    }

    [Fact]
    public void ListsEveryEventType()
    {
        Assert.Equal(17, WebhookEventTypes.EnvelopeTypes.Count);
        Assert.Equal(typeof(RealtimeChatMessageReceivedData), WebhookEventTypes.DataTypes[WebhookEventTypes.RealtimeChatMessageReceived]);
    }
}
