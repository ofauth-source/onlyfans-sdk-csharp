using System.Net;
using static OFAuth.Test.FakeHandler;

namespace OFAuth.Test;

public class RetryTests
{
    private static OFAuthClient Client(HttpMessageHandler handler, TestTime time, Action<OFAuthClientOptions>? configure = null)
    {
        var options = new OFAuthClientOptions
        {
            AccessToken = "tok",
            LinkedAccountId = "conn_1",
            HttpClient = new HttpClient(handler),
            TimeProvider = time,
        };
        configure?.Invoke(options);
        return new OFAuthClient(options);
    }

    private static Func<RecordedRequest, HttpResponseMessage> Error(int status, string code, Dictionary<string, string>? headers = null) =>
        Json(new { error = code, recovery = new { action = "retry" }, requestId = "req_e" }, status, headers);

    private static Task SendMessage(OFAuthClient client) =>
        client.Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
        {
            UserId = "1",
            Body = new MessageContent { Text = "hi" },
        });

    [Fact]
    public async Task RetriesIdempotentRequestsOn503()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(503, "transient_provider_failure"), Json(new { id = 1 }));
        await Client(handler, time).Access.Profile.GetAsync();
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData(502)]
    [InlineData(503)]
    [InlineData(504)]
    public async Task DoesNotRetryPostOnGatewayErrors(int status)
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(status, "transient_provider_failure"), Json(new { id = 1 }));
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => SendMessage(Client(handler, time)));
        Assert.Single(handler.Requests);
        Assert.Equal(1, error.Attempts);
        Assert.True(error.IsRetryable);
    }

    [Fact]
    public async Task RetriesPostOn429UsingRetryAfter()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(429, "rate_limited", new() { ["Retry-After"] = "2" }), Json(new { id = 1 }));
        await SendMessage(Client(handler, time));
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains(TimeSpan.FromSeconds(2), time.Delays);
    }

    [Fact]
    public async Task RetriesPostWhenAuthorizationIsTemporarilyUnavailable()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(503, "authorization_temporarily_unavailable"), Json(new { id = 1 }));
        await SendMessage(Client(handler, time));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task UsesRateLimitResetWhenThereIsNoRetryAfter()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(429, "rate_limited", new() { ["RateLimit-Reset"] = "5" }), Json(new { id = 1 }));
        await Client(handler, time).Access.Profile.GetAsync();
        Assert.Equal(new[] { TimeSpan.FromSeconds(5) }, time.Delays);
    }

    [Fact]
    public async Task StopsAfterMaxRetriesAndReportsAttempts()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(502, "transient_provider_failure"));
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler, time).Access.Profile.GetAsync());
        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(3, error.Attempts);
        // Exponential backoff with full jitter: at most 0.5s, then 1s.
        Assert.All(time.Delays, d => Assert.InRange(d, TimeSpan.Zero, TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task DoesNotRetryWhenTheServerDelayExceedsMaxRetryDelay()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(429, "quota_exhausted", new() { ["Retry-After"] = "3600" }), Json(new { id = 1 }));
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler, time).Access.Profile.GetAsync());
        Assert.Single(handler.Requests);
        Assert.Equal("quota_exhausted", error.Code);
        Assert.Empty(time.Delays);
    }

    [Fact]
    public async Task MaxRetriesZeroDisablesRetries()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(503, "transient_provider_failure"), Json(new { id = 1 }));
        await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler, time, o => o.MaxRetries = 0).Access.Profile.GetAsync());
        Assert.Single(handler.Requests);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task NeverRetriesOtherErrors(int status)
    {
        var time = new TestTime();
        var handler = new FakeHandler(Error(status, "invalid_request"), Json(new { id = 1 }));
        await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler, time).Access.Profile.GetAsync());
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task RetriesNetworkErrorsForGetOnly()
    {
        var time = new TestTime();
        var get = new FakeHandler(_ => throw new HttpRequestException("connection reset"), Json(new { id = 1 }));
        await Client(get, time).Access.Profile.GetAsync();
        Assert.Equal(2, get.Requests.Count);

        var post = new FakeHandler(_ => throw new HttpRequestException("connection reset"), Json(new { id = 1 }));
        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() => SendMessage(Client(post, time)));
        Assert.Single(post.Requests);
        Assert.Equal(1, error.Attempts);
        Assert.False(error.IsTimeout);
        Assert.Equal("access.chats.messages.send", error.Operation);
        Assert.IsType<HttpRequestException>(error.InnerException);
    }

    [Fact]
    public async Task TimesOutEachAttempt()
    {
        var time = new TestTime();
        var handler = new HangingHandler();
        var client = Client(handler, time, o =>
        {
            o.Timeout = TimeSpan.FromMilliseconds(50);
            o.MaxRetries = 1;
        });
        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() => client.Access.Profile.GetAsync());
        Assert.True(error.IsTimeout);
        Assert.Equal(2, error.Attempts);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task DoesNotRetryWhenTheCallerCancels()
    {
        var time = new TestTime();
        var handler = new HangingHandler();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Client(handler, time).Access.Profile.GetAsync(cancellationToken: cts.Token));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task InvalidTokenRefreshDoesNotCountAgainstMaxRetries()
    {
        var time = new TestTime();
        var handler = new FakeHandler(Json(new { error = "invalid_token" }, 401), Json(new { id = 1 }));
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessTokenProvider = new DelegateAccessTokenProvider((force, _) => Task.FromResult(force ? "fresh" : "stale")),
            LinkedAccountId = "conn_1",
            HttpClient = handler.Client(),
            MaxRetries = 0,
            TimeProvider = time,
        });
        await client.Access.Profile.GetAsync();
        Assert.Equal("Bearer fresh", handler.Requests[1].Header("Authorization"));
    }

    [Fact]
    public async Task UploadPartsUseAtLeastFiveMinutes()
    {
        // The part PUT outlives a 50ms client timeout because uploads use max(timeout, 300s).
        var time = new TestTime();
        var slowPut = new DelayedHandler(TimeSpan.FromMilliseconds(200), request => request.Method == HttpMethod.Put);
        slowPut.Responses.Enqueue(JsonResponse(new
        {
            status = "needs_upload",
            uploadId = "up_1",
            parts = new[] { new { partNumber = 1, uploadUrl = "https://api.ofauth.com/v3/access/uploads/up_1/parts/1", byteRange = new { start = 0, end = 0 } } },
        }));
        slowPut.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.OK));
        slowPut.Responses.Enqueue(JsonResponse(new { uploads = Array.Empty<object>() }));
        var client = Client(slowPut, time, o => o.Timeout = TimeSpan.FromMilliseconds(100));
        var result = await client.UploadMediaAsync(new byte[] { 1 }, new UploadMediaOptions { Filename = "upload.png", ContentType = "image/png" });
        Assert.Equal("up_1", result.UploadId);
    }

    private sealed class HangingHandler : HttpMessageHandler
    {
        private int _calls;

        public int Calls => _calls;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            await Task.Delay(Timeout.Infinite, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class DelayedHandler(TimeSpan delay, Func<HttpRequestMessage, bool> slow) : HttpMessageHandler
    {
        public Queue<HttpResponseMessage> Responses { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (slow(request)) await Task.Delay(delay, cancellationToken);
            lock (Responses) return Responses.Dequeue();
        }
    }
}

public class HookTests
{
    [Fact]
    public async Task CallsHooksWithRedactedHeadersAndLogsOneLinePerAttempt()
    {
        var time = new TestTime();
        var handler = new FakeHandler(
            Json(new { error = "transient_provider_failure" }, 503, new() { ["x-request-id"] = "req_1" }),
            Json(new { id = 1 }, 200, new() { ["x-request-id"] = "req_2" }));
        var requests = new List<OFAuthRequestInfo>();
        var responses = new List<OFAuthResponseInfo>();
        var lines = new List<string>();
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "secret-token",
            LinkedAccountId = "conn_1",
            HttpClient = handler.Client(),
            TimeProvider = time,
            OnRequest = info =>
            {
                requests.Add(info);
                throw new InvalidOperationException("hooks must not break requests");
            },
            OnResponse = info =>
            {
                responses.Add(info);
                throw new InvalidOperationException("hooks must not break requests");
            },
            DebugLogger = lines.Add,
        });

        await client.Access.Profile.GetAsync();

        Assert.Equal(new[] { 1, 2 }, requests.Select(r => r.Attempt));
        Assert.All(requests, r => Assert.Equal("Bearer [redacted]", r.Headers["Authorization"]));
        Assert.Equal("GET", requests[0].Method);
        Assert.Equal("https://api.ofauth.com/v3/access/profile", requests[0].Url.ToString());
        Assert.Equal("conn_1", requests[0].Headers["x-linked-account-id"]);
        Assert.Equal("access.profile.get", requests[0].Operation);

        Assert.Equal(new[] { 503, 200 }, responses.Select(r => r.StatusCode));
        Assert.Equal(new[] { "req_1", "req_2" }, responses.Select(r => r.RequestId));
        Assert.Equal(new[] { 1, 2 }, responses.Select(r => r.Attempt));

        Assert.Equal(3, lines.Count);
        Assert.Matches(@"^\[ofauth\] GET /v3/access/profile -> 503 \(\d+ms, req_1\)$", lines[0]);
        Assert.StartsWith("[ofauth] retrying GET /v3/access/profile in ", lines[1]);
        Assert.Matches(@"^\[ofauth\] GET /v3/access/profile -> 200 \(\d+ms, req_2\)$", lines[2]);
        Assert.DoesNotContain(lines, l => l.Contains("secret-token"));
    }
}

public class ScopeTests
{
    [Fact]
    public void MapsOperationsToScopes()
    {
        Assert.Equal("messages:write", Scopes.ByOperation["access.chats.messages.send"]);
        Assert.Equal(OFAuthOperations.AccessChatsMessagesSend, "access.chats.messages.send");
        Assert.Null(Scopes.ForOperation(OFAuthOperations.LinkedAccountsList));
    }

    [Fact]
    public void ScopesForDeduplicatesAndSorts()
    {
        Assert.Equal(
            new[] { "messages:write", "profile:read" },
            Scopes.For(OFAuthOperations.AccessProfileGet, OFAuthOperations.AccessChatsMessagesSend, OFAuthOperations.AccessProfileGet));
        Assert.Equal(
            new[] { "messages:write" },
            Scopes.For(new[] { OFAuthOperations.AccessChatsMessagesSend, OFAuthOperations.LinkedAccountsList }));
        Assert.Throws<ArgumentException>(() => Scopes.For("access.nope"));
    }

    [Fact]
    public async Task ErrorsCarryTheOperationAndRequiredScope()
    {
        var handler = new FakeHandler(Json(new
        {
            error = "missing_scope",
            recovery = new { action = "request_additional_consent" },
        }, 403));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => client.Access.Chats.Messages.SendAsync(
            new AccessChatsMessagesSendParams { UserId = "1", Body = new MessageContent { Text = "x" } }));
        Assert.Equal("access.chats.messages.send", error.Operation);
        Assert.Equal("messages:write", error.RequiredScope);
        Assert.Equal(new[] { "messages:write" }, error.MissingScopes);
        Assert.Equal(new[] { "messages:write" }, Scopes.Missing(error));
        Assert.True(error.NeedsReauthorization);
        Assert.Empty(Scopes.Missing(new InvalidOperationException()));
    }

    [Fact]
    public void AuthorizationUrlMergesOperationScopes()
    {
        var link = new OFAuthLink(new OFAuthLinkOptions { ClientSecret = "fixture", ClientId = "ofext_test_a", RedirectUri = "https://app/cb" });
        var request = link.CreateAuthorizationUrl(new CreateAuthorizationUrlOptions
        {
            Scopes = new[] { Scopes.ProfileRead },
            Operations = new[] { OFAuthOperations.AccessChatsMessagesSend, OFAuthOperations.AccessProfileGet },
        });
        Assert.Contains("scope=profile%3Aread%20messages%3Awrite&", request.Url);
        Assert.Throws<ArgumentException>(() => link.CreateAuthorizationUrl(new CreateAuthorizationUrlOptions()));
    }
}

public class ErrorConvenienceTests
{
    private static OFAuthApiException Error(int status, string? action, string code = "some_error")
    {
        var body = action is null
            ? $"{{\"error\":\"{code}\"}}"
            : $"{{\"error\":\"{code}\",\"recovery\":{{\"action\":\"{action}\"}}}}";
        return new OFAuthApiException(status, body, null);
    }

    [Theory]
    [InlineData("retry", true, false, false, false, false)]
    [InlineData("retry_after_reset", true, false, false, false, false)]
    [InlineData("obtain_external_oauth_token", false, true, false, false, false)]
    [InlineData("restart_authorization", false, false, true, false, false)]
    [InlineData("request_additional_consent", false, false, true, false, false)]
    [InlineData("grant_linked_account", false, false, true, false, false)]
    [InlineData("reconnect_linked_account", false, false, false, true, false)]
    [InlineData("complete_integration_approval", false, false, false, false, true)]
    [InlineData("update_developer_plan", false, false, false, false, true)]
    [InlineData("contact_integration_owner", false, false, false, false, true)]
    [InlineData("enable_vault_plus", false, false, false, false, true)]
    [InlineData("check_request", false, false, false, false, false)]
    public void ClassifiesRecoveryActions(string action, bool retryable, bool refresh, bool reauth, bool reconnect, bool integration)
    {
        var error = Error(400, action);
        Assert.Equal(retryable, error.IsRetryable);
        Assert.Equal(refresh, error.NeedsTokenRefresh);
        Assert.Equal(reauth, error.NeedsReauthorization);
        Assert.Equal(reconnect, error.NeedsReconnect);
        Assert.Equal(integration, error.IsIntegrationProblem);
        Assert.NotEqual(RecoveryActionKind.Unknown, error.RecoveryActionKind);
    }

    [Fact]
    public void KeepsUnknownActionsAndUsesTheStatusForRetryable()
    {
        var unknown = Error(400, "brand_new_action");
        Assert.Equal(RecoveryActionKind.Unknown, unknown.RecoveryActionKind);
        Assert.Equal("brand_new_action", unknown.RecoveryAction);
        Assert.Null(Error(400, null).RecoveryActionKind);
        Assert.True(Error(429, null).IsRetryable);
        Assert.True(Error(504, null).IsRetryable);
        Assert.False(Error(500, null).IsRetryable);
        Assert.Equal(RecoveryActionKind.EnableLinkedAccountVaultPlus, RecoveryActions.Parse("enable_linked_account_vault_plus"));
    }

    [Fact]
    public void ParsesRuntimeErrors()
    {
        var error = new OFAuthApiException(
            403,
            "{\"error\":\"missing_scope\",\"message\":\"needs vault:read\",\"recovery\":{\"action\":\"request_additional_consent\"},\"requestId\":\"req_1\"}",
            null);
        Assert.Equal("missing_scope", error.Code);
        Assert.Equal("request_additional_consent", error.RecoveryAction);
        Assert.Equal("req_1", error.RequestId);
        Assert.Equal("missing_scope: needs vault:read", error.Message);
        Assert.Null(error.Issues);
        Assert.Null(error.ErrorType);
        Assert.True(error.NeedsReauthorization);
    }

    [Fact]
    public void ParsesRequestValidationErrors()
    {
        const string body = "{\"success\":false,\"error\":{\"name\":\"ZodError\",\"issues\":["
            + "{\"code\":\"too_big\",\"path\":[\"limit\"],\"message\":\"Number must be less than or equal to 100\"},"
            + "{\"code\":\"invalid_type\",\"path\":[\"body\",\"items\",0],\"message\":\"Required\"}]}}";
        var error = new OFAuthApiException(400, body, null);
        Assert.Equal("invalid_request", error.Code);
        Assert.Equal("check_request", error.RecoveryAction);
        Assert.Equal(RecoveryActionKind.CheckRequest, error.RecoveryActionKind);
        Assert.Equal("limit: Number must be less than or equal to 100; body.items.0: Required", error.ErrorMessage);
        Assert.Equal("invalid_request: " + error.ErrorMessage, error.Message);
        Assert.NotNull(error.Issues);
        Assert.Equal(2, error.Issues!.Count);
        Assert.Equal("too_big", error.Issues[0].Code);
        Assert.Equal(new object[] { "limit" }, error.Issues[0].Path);
        Assert.Equal(new object[] { "body", "items", 0 }, error.Issues[1].Path);
        Assert.Equal("Required", error.Issues[1].Message);
        Assert.Null(error.ErrorType);
        Assert.Equal(body, error.ResponseBody);
        Assert.False(error.IsRetryable);
    }

    [Fact]
    public void ParsesAccessHandlerErrors()
    {
        var error = new OFAuthApiException(
            404,
            "{\"error\":\"Upload not found\",\"type\":\"RESOURCE_NOT_FOUND\",\"requestId\":\"req_3\",\"success\":false}",
            null);
        Assert.Equal("resource_not_found", error.Code);
        Assert.Equal("RESOURCE_NOT_FOUND", error.ErrorType);
        Assert.Equal("Upload not found", error.ErrorMessage);
        Assert.Equal("resource_not_found: Upload not found", error.Message);
        Assert.Null(error.RecoveryAction);
        Assert.Null(error.RecoveryActionKind);
        Assert.Null(error.Issues);
        Assert.Equal("req_3", error.RequestId);
        Assert.True(new OFAuthApiException(502, "{\"error\":\"Upstream failed\",\"type\":\"PROXY_ERROR\"}", null).IsRetryable);
    }

    [Fact]
    public void OAuthInvalidGrantNeedsReauthorization()
    {
        Assert.True(new OFAuthOAuthException(400, "{\"error\":\"invalid_grant\"}", null).NeedsReauthorization);
        Assert.False(new OFAuthOAuthException(400, "{\"error\":\"invalid_client\"}", null).NeedsReauthorization);
    }
}
