using OFAuth.Testing;

namespace OFAuth.Examples;

/// <summary>
/// Verify and route webhook deliveries. In ASP.NET Core:
/// <code>
/// app.MapPost("/webhooks/ofauth", async (HttpRequest request) =>
/// {
///     using var reader = new StreamReader(request.Body);
///     var body = await reader.ReadToEndAsync();   // the raw body, exactly as received
///     var result = await router.ProcessAsync(body, name => request.Headers[name].ToString());
///     return Results.Content(result.ResponseBody ?? "", "application/json", statusCode: result.StatusCode);
/// });
/// </code>
/// </summary>
internal static class WebhookExample
{
    public static async Task RunAsync()
    {
        var secret = Env.Optional("OFAUTH_WEBHOOK_SECRET") ?? TestWebhooks.GenerateSecret();

        var router = new WebhookRouter(secret)
            .OnAuthorizationRevoked(e => Console.WriteLine($"revoked {e.AuthorizationId}: delete its tokens"))
            .OnLinkedAccountExpired(e => Console.WriteLine($"{e.LinkedAccountId} needs reconnecting"))
            .OnRealtimeChatMessageReceived(e => Console.WriteLine($"message {e.Data.Id} for {e.LinkedAccountId}"))
            .OnDefault(e => Console.WriteLine($"unhandled {e.Type} ({e.EventId})"));

        // A sample delivery signed exactly as OFAuth signs it (OFAuth.Testing helpers).
        var evt = TestWebhooks.CreateTestEvent(WebhookEventTypes.AuthorizationRevoked, new { authorizationId = "external_live_1" });
        var signed = TestWebhooks.SignWebhook(evt, secret);

        var result = await router.ProcessAsync(signed.Body, name => signed.Headers.GetValueOrDefault(name));
        Console.WriteLine($"respond {result.StatusCode}");

        // Or verify without the router:
        var verified = Webhooks.Verify(signed.Body, signed.Headers, secret);
        Console.WriteLine($"{verified.Type} #{verified.Order}, lifecycle: {verified.IsLifecycle}");

        // In tests, one call builds, signs, verifies, and dispatches:
        await router.HandleTestEventAsync(WebhookEventTypes.RealtimeChatMessageReceived, new { linkedAccountId = "conn_1" });
    }
}
