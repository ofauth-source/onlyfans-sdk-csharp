using System.Net;
using static OFAuth.Test.FakeHandler;

namespace OFAuth.Test;

/// <summary>Caller headers cannot add a second credential; hooks never see credentials or signed query values.</summary>
public class TokenHygieneTests
{
    [Theory]
    [InlineData("Authorization")]
    [InlineData("authorization")]
    [InlineData("AUTHORIZATION")]
    public void RejectsACallerAuthorizationHeader(string name)
    {
        var error = Assert.Throws<ArgumentException>(() => new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok",
            DefaultHeaders = new Dictionary<string, string> { [name] = "Bearer caller-secret" },
        }));
        Assert.Contains("the SDK sends", error.Message);
        Assert.DoesNotContain("caller-secret", error.Message);
    }

    [Fact]
    public async Task SdkHeadersWinAndSensitiveHeadersAreRedactedWhateverTheirCasing()
    {
        var handler = new FakeHandler(Json(new { id = 1 }));
        var requests = new List<OFAuthRequestInfo>();
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "secret-token",
            LinkedAccountId = "conn_1",
            HttpClient = handler.Client(),
            DefaultHeaders = new Dictionary<string, string>
            {
                ["X-Linked-Account-Id"] = "conn_spoofed",
                ["accept"] = "text/plain",
                ["cookie"] = "session=c1",
                ["X-API-Key"] = "k1",
                ["cf-access-client-secret"] = "s1",
                ["X-Upstream-Token"] = "t1",
                ["X-Trace"] = "visible",
            },
            OnRequest = r => requests.Add(r),
        });
        await client.Access.Profile.GetAsync();

        var sent = Assert.Single(handler.Requests);
        Assert.Equal("conn_1", sent.Header("x-linked-account-id"));
        Assert.Equal("text/plain", sent.Header("accept"));
        Assert.Equal("Bearer secret-token", sent.Header("authorization"));

        var headers = Assert.Single(requests).Headers;
        Assert.Equal("Bearer [redacted]", headers["authorization"]);
        foreach (var name in new[] { "cookie", "x-api-key", "cf-access-client-secret", "x-upstream-token" })
        {
            Assert.Equal("[redacted]", headers[name]);
        }
        Assert.Equal("visible", headers["x-trace"]);
        foreach (var secret in new[] { "secret-token", "c1", "k1", "s1", "t1" })
        {
            Assert.DoesNotContain(headers.Values, v => v.Contains(secret));
        }
    }

    [Theory]
    [InlineData(null, "https://api.ofauth.com/v3/realtime/events")]
    [InlineData("https://api.staging.ofauth.com", "https://api.staging.ofauth.com/v3/realtime/events")]
    [InlineData("HTTPS://api.staging.ofauth.com/", "https://api.staging.ofauth.com/v3/realtime/events")]
    [InlineData("http://127.0.0.1:1", "http://127.0.0.1:1/v3/realtime/events")]
    public async Task ClientRealtimeAlwaysConnectsToTheBaseUrlOrigin(string? baseUrl, string expected)
    {
        var requests = new List<OFAuthRequestInfo>();
        // A fake handler that refuses: the stream URL is recorded, nothing goes over the network.
        var handler = new FakeSseHandler(FakeSseHandler.Refuse(403));
        var options = new OFAuthClientOptions
        {
            AccessToken = "tok",
            LinkedAccountId = "conn_1",
            HttpClient = new HttpClient(handler),
            OnRequest = r => { lock (requests) requests.Add(r); },
        };
        if (baseUrl is not null) options.BaseUrl = baseUrl;
        await using var realtime = new OFAuthClient(options).Realtime(new RealtimeOptions { Reconnect = false });
        await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());
        var url = Assert.Single(requests).Url;
        Assert.Equal(new Uri(expected + "?linkedAccountId=conn_1"), url);
        Assert.Equal(url, new Uri(Assert.Single(handler.Requests).Url));
        if (baseUrl is not null) Assert.NotEqual("api.ofauth.com", url.Host);
    }

    [Fact]
    public void ClientRealtimeRejectsANonHttpBaseUrl()
    {
        var client = new OFAuthClient(new OFAuthClientOptions { AccessToken = "tok", LinkedAccountId = "conn_1", BaseUrl = "ftp://api.test" });
        Assert.Throws<OFAuthException>(() => client.Realtime());
    }

    [Fact]
    public void RealtimeConnectionsComeOnlyFromAClientAndCannotPointElsewhere()
    {
        // No public constructor: `new RealtimeConnection(...)` does not compile outside the SDK.
        Assert.Empty(typeof(RealtimeConnection).GetConstructors());
        Assert.NotEmpty(typeof(RealtimeConnection).GetConstructors(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic));
        // No URL or token settings for Realtime: it always uses the client's token and BaseUrl origin.
        Assert.Null(typeof(RealtimeOptions).GetProperty("Url"));
        Assert.Null(typeof(RealtimeOptions).GetProperty("AccessToken"));
        Assert.Null(typeof(RealtimeOptions).GetProperty("AccessTokenProvider"));
        Assert.Null(typeof(OFAuthClientOptions).GetProperty("RealtimeUrl"));
        Assert.Null(typeof(ApiTransport).GetMethod("RealtimeUrlFor"));
        Assert.DoesNotContain(
            typeof(OFAuthDefaults).GetFields().Where(f => f.IsLiteral).Select(f => f.GetRawConstantValue()),
            value => value is string s && s.Contains("/v3/realtime", StringComparison.Ordinal));
    }

    [Fact]
    public async Task HooksGetSanitizedUrlsButTheRequestKeepsTheSignature()
    {
        var handler = new FakeHandler(Status(204));
        var requests = new List<OFAuthRequestInfo>();
        var responses = new List<OFAuthResponseInfo>();
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok",
            BaseUrl = "https://api.test",
            HttpClient = handler.Client(),
            OnRequest = r => requests.Add(r),
            OnResponse = r => responses.Add(r),
        });
        var signed = "https://api.test/v3/access/uploads/u/parts/1?X-Amz-Signature=deadbeef&partNumber=1";
        await client.Transport.SendAsync(
            new ApiRequest(HttpMethod.Put, "/v3/access/uploads/u/parts/1") { Url = new Uri(signed) },
            CancellationToken.None);

        Assert.Equal(signed, Assert.Single(handler.Requests).Url);
        var want = "https://api.test/v3/access/uploads/u/parts/1?X-Amz-Signature=REDACTED&partNumber=1";
        Assert.Equal(want, Assert.Single(requests).Url.AbsoluteUri);
        Assert.Equal(want, Assert.Single(responses).Url.AbsoluteUri);
    }

    [Fact]
    public async Task ConnectionErrorsDoNotIncludeSignedQueryValues()
    {
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok",
            BaseUrl = "http://127.0.0.1:1",
            MaxRetries = 0,
        });
        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() => client.Transport.SendAsync(
            new ApiRequest(HttpMethod.Get, "/v3/x") { Url = new Uri("http://127.0.0.1:1/v3/x?token=deadbeef") },
            CancellationToken.None));
        Assert.DoesNotContain("deadbeef", error.ToString());
    }
}
