using System.Text.Json.Nodes;
using OFAuth.Testing;

namespace OFAuth.Test;

public class TestingHelperTests
{
    private static readonly string Secret = TestWebhooks.GenerateSecret();

    [Fact]
    public async Task BuildsAValidEventForEveryType()
    {
        Assert.Equal(17, TestWebhooks.EventTypes.Count);
        Assert.Equal(WebhookEventTypes.EnvelopeTypes.Keys.OrderBy(k => k, StringComparer.Ordinal), TestWebhooks.EventTypes);
        var router = new WebhookRouter(Secret);
        foreach (var type in TestWebhooks.EventTypes)
        {
            var evt = await router.HandleTestEventAsync(type);
            Assert.Equal(type, evt.Type);
            Assert.StartsWith("evt_test_", evt.EventId);
            // The typed envelope class parses the fixture.
            Assert.NotNull(System.Text.Json.JsonSerializer.Deserialize(evt.RawJson, WebhookEventTypes.EnvelopeTypes[type], ApiTransport.JsonOptions));
        }
    }

    [Fact]
    public void DeepMergesOverridesAndUsesFreshEventIds()
    {
        var a = TestWebhooks.CreateTestEvent(WebhookEventTypes.RealtimeChatMessageReceived);
        var b = TestWebhooks.CreateTestEvent(WebhookEventTypes.RealtimeChatMessageReceived, new
        {
            linkedAccountId = "conn_9",
            data = new { id = 555 },
        });
        Assert.NotEqual(a["eventId"]!.GetValue<string>(), b["eventId"]!.GetValue<string>());
        Assert.Equal("conn_9", b["linkedAccountId"]!.GetValue<string>());
        Assert.Equal(555, b["data"]!["id"]!.GetValue<int>());
        // Other data fields from the fixture are kept.
        var otherKeys = a["data"]!.AsObject().Select(p => p.Key).Where(k => k != "id").ToList();
        Assert.All(otherKeys, k => Assert.True(b["data"]!.AsObject().ContainsKey(k)));

        var fixed_ = TestWebhooks.CreateTestEvent(WebhookEventTypes.AuthorizationRevoked, new JsonObject { ["eventId"] = "evt_1" });
        Assert.Equal("evt_1", fixed_["eventId"]!.GetValue<string>());
        Assert.Throws<ArgumentException>(() => TestWebhooks.CreateTestEvent("nope.event"));
    }

    [Fact]
    public void SignsDeliveriesThatVerify()
    {
        var signed = TestWebhooks.SignWebhook("{\"type\":\"x\"}", Secret, id: "msg_1", timestamp: DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        Assert.Equal("msg_1", signed.Headers["webhook-id"]);
        Assert.Equal("1700000000", signed.Headers["webhook-timestamp"]);
        Assert.StartsWith("v1,", signed.Headers["webhook-signature"]);
        Webhooks.VerifySignature(
            signed.Body,
            Webhooks.ExtractHeaders(signed.Headers),
            Secret,
            now: DateTimeOffset.FromUnixTimeSeconds(1_700_000_010));
        Assert.Throws<WebhookVerificationException>(() => Webhooks.Verify(signed.Body, signed.Headers, TestWebhooks.GenerateSecret()));
    }

    [Fact]
    public async Task DispatchesThroughTheRouterInOneCall()
    {
        var revoked = new List<string?>();
        var router = new WebhookRouter(Secret).OnAuthorizationRevoked(e => revoked.Add(e.AuthorizationId));
        await router.HandleTestEventAsync(WebhookEventTypes.AuthorizationRevoked, new { authorizationId = "authz_42" });

        var signed = TestWebhooks.SignWebhook(TestWebhooks.CreateTestEvent(WebhookEventTypes.AuthorizationRevoked), Secret);
        await router.HandleAsync(signed);

        Assert.Equal("authz_42", revoked[0]);
        Assert.Equal(2, revoked.Count);
    }
}
