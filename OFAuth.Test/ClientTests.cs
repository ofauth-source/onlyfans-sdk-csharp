using System.Text.Json;
using static OFAuth.Test.FakeHandler;

namespace OFAuth.Test;

public class ClientTests
{
    private static OFAuthClient Client(FakeHandler handler, string? linkedAccountId = "conn_1", string baseUrl = OFAuthDefaults.ApiUrl) =>
        new(new OFAuthClientOptions
        {
            AccessToken = "tok",
            LinkedAccountId = linkedAccountId,
            HttpClient = handler.Client(),
            BaseUrl = baseUrl,
        });

    [Fact]
    public async Task SendsBearerTokenAndLinkedAccountHeader()
    {
        var handler = new FakeHandler(Json(new { id = 1 }));
        await Client(handler, baseUrl: "https://api.test/").Access.Profile.GetAsync();

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://api.test/v3/access/profile", request.Url);
        Assert.Equal("Bearer tok", request.Header("Authorization"));
        Assert.Equal("conn_1", request.Header("x-linked-account-id"));
        Assert.Equal("application/json", request.Header("Accept"));
    }

    [Fact]
    public async Task OverridesLinkedAccountAndEncodesPathAndQuery()
    {
        var handler = new FakeHandler(Json(new { items = Array.Empty<object>(), page = new { nextCursor = (string?)null, hasMore = false } }));
        await Client(handler).Access.Chats.Messages.ListAsync(new AccessChatsMessagesListParams
        {
            UserId = "12/3",
            Limit = 5,
            LinkedAccountId = "conn_2",
        });

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://api.ofauth.com/v3/access/chats/12%2F3/messages?limit=5", request.Url);
        Assert.Equal("conn_2", request.Header("x-linked-account-id"));
    }

    [Fact]
    public async Task SendsJsonBodiesWithoutNulls()
    {
        var handler = new FakeHandler(Json(new { id = 9 }));
        await Client(handler).Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
        {
            UserId = "1",
            Body = new MessageContent { Text = "hi", MediaItems = new List<object?> { "upload_1", 42 } },
        });

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("{\"mediaItems\":[\"upload_1\",42],\"text\":\"hi\"}", request.Body);
        Assert.StartsWith("application/json", request.ContentType);
    }

    [Fact]
    public async Task WithLinkedAccountUsesTheOtherAccount()
    {
        var handler = new FakeHandler(Json(new { id = 1 }));
        await Client(handler).WithLinkedAccount("conn_9").Access.Profile.GetAsync();
        Assert.Equal("conn_9", handler.Requests[0].Header("x-linked-account-id"));
    }

    [Fact]
    public async Task RequiresALinkedAccountForAccessOperations()
    {
        var handler = new FakeHandler(Json(new { }));
        var error = await Assert.ThrowsAsync<OFAuthException>(() => Client(handler, linkedAccountId: null).Access.Profile.GetAsync());
        Assert.Contains("linked account", error.Message);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task DoesNotSendLinkedAccountHeaderToLinkedAccountsRoutes()
    {
        var handler = new FakeHandler(Json(new { data = Array.Empty<object>(), has_more = false, next_cursor = (string?)null }));
        await Client(handler).LinkedAccounts.ListAsync(new LinkedAccountsListParams { Limit = 10 });

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://api.ofauth.com/v3/linked-accounts?limit=10", request.Url);
        Assert.Null(request.Header("x-linked-account-id"));
    }

    [Fact]
    public async Task ParsesTheErrorEnvelope()
    {
        var handler = new FakeHandler(Json(new
        {
            error = "linked_account_reconnect_required",
            recovery = new { action = "reconnect_linked_account" },
            requestId = "req_1",
            message = "Reconnect the account",
        }, 401));
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler).Access.Profile.GetAsync());
        Assert.Equal(401, error.StatusCode);
        Assert.Equal("linked_account_reconnect_required", error.Code);
        Assert.Equal("reconnect_linked_account", error.RecoveryAction);
        Assert.Equal("req_1", error.RequestId);
        Assert.Equal("Reconnect the account", error.ErrorMessage);
        Assert.Contains("linked_account_reconnect_required", error.Message);
    }

    [Fact]
    public async Task ReadsRetryAfterAndRequestIdHeader()
    {
        var handler = new FakeHandler(Json(
            new { error = "rate_limited", recovery = new { action = "retry" } },
            429,
            new() { ["Retry-After"] = "7", ["x-request-id"] = "req_h" }));
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok",
            LinkedAccountId = "conn_1",
            HttpClient = handler.Client(),
            MaxRetries = 0,
        });
        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => client.Access.Profile.GetAsync());
        Assert.Equal(TimeSpan.FromSeconds(7), error.RetryAfter);
        Assert.Equal("req_h", error.RequestId);
        Assert.Equal("retry", error.RecoveryAction);
    }

    [Fact]
    public async Task RetriesOnceWithARefreshedTokenAfterInvalidToken()
    {
        var handler = new FakeHandler(
            Json(new { error = "invalid_token", recovery = new { action = "obtain_external_oauth_token" } }, 401),
            Json(new { id = 1 }));
        var forced = new List<bool>();
        var provider = new DelegateAccessTokenProvider((force, _) =>
        {
            forced.Add(force);
            return Task.FromResult(force ? "fresh" : "stale");
        });
        var client = new OFAuthClient(provider, "conn_1", handler.Client());

        await client.Access.Profile.GetAsync();

        Assert.Equal(new[] { "Bearer stale", "Bearer fresh" }, handler.Requests.Select(r => r.Header("Authorization")));
        Assert.Equal(new[] { false, true }, forced);
    }

    [Fact]
    public async Task DoesNotRetryOtherUnauthorizedErrors()
    {
        var handler = new FakeHandler(Json(new { error = "authentication_denied" }, 401));
        var client = new OFAuthClient(new DelegateAccessTokenProvider((_, _) => Task.FromResult("t")), "conn_1", handler.Client());
        await Assert.ThrowsAsync<OFAuthApiException>(() => client.Access.Profile.GetAsync());
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task DoesNotRetryWithAStaticToken()
    {
        var handler = new FakeHandler(Json(new { error = "invalid_token" }, 401));
        await Assert.ThrowsAsync<OFAuthApiException>(() => Client(handler).Access.Profile.GetAsync());
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task HandlesNoContent()
    {
        var handler = new FakeHandler(Status(204));
        await Client(handler).LinkedAccounts.RemoveAsync(new LinkedAccountsRemoveParams { Id = "conn_1" });
        Assert.Equal(HttpMethod.Delete, handler.Requests[0].Method);
        Assert.Equal("https://api.ofauth.com/v3/linked-accounts/conn_1", handler.Requests[0].Url);
    }

    [Fact]
    public async Task ParsesTypedResponsesLeniently()
    {
        // `id` arrives as a string and `expires_in` as 600.0: both still parse.
        var handler = new FakeHandler(Json(new { id = "conn_1", provider = "onlyfans" }));
        var account = await Client(handler).LinkedAccounts.GetAsync(new LinkedAccountsGetParams { Id = "conn_1" });
        Assert.Equal("conn_1", account.Id);
    }

    [Fact]
    public void ExposesScopes()
    {
        Assert.Equal("profile:read", Scopes.ProfileRead);
    }
}

public class PaginationTests
{
    [Fact]
    public async Task FollowsPageNextCursor()
    {
        var handler = new FakeHandler(
            Json(new { items = new[] { new { user = new { id = 1 } }, new { user = new { id = 2 } } }, page = new { nextCursor = "c2", hasMore = true } }),
            Json(new { items = new[] { new { user = new { id = 3 } } }, page = new { nextCursor = (string?)null, hasMore = false } }));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());

        var ids = new List<double>();
        await foreach (var chat in client.Access.Chats.IterateAsync(new AccessChatsListParams { Limit = 2 })) ids.Add(chat.User.Id);

        Assert.Equal(new double[] { 1, 2, 3 }, ids);
        Assert.Equal(2, handler.Requests.Count);
        Assert.DoesNotContain("cursor=", handler.Requests[0].Url);
        Assert.Contains("cursor=c2", handler.Requests[1].Url);
        Assert.Contains("limit=2", handler.Requests[1].Url);
    }

    [Fact]
    public async Task StopsWhenHasMoreIsFalseEvenWithACursor()
    {
        var handler = new FakeHandler(
            Json(new { items = new[] { new { user = new { id = 1 } } }, page = new { nextCursor = "c2", hasMore = false } }));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var count = 0;
        await foreach (var _ in client.Access.Chats.IterateAsync()) count++;
        Assert.Equal(1, count);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task FollowsNextCursorForLinkedAccountsAndHonorsMaxItems()
    {
        var handler = new FakeHandler(
            Json(new { data = new[] { new { id = "a" }, new { id = "b" } }, has_more = true, next_cursor = "n1" }),
            Json(new { data = new[] { new { id = "c" } }, has_more = false, next_cursor = (string?)null }));
        var client = new OFAuthClient("tok", httpClient: handler.Client());

        var all = new List<string>();
        await foreach (var account in client.LinkedAccounts.IterateAsync()) all.Add(account.Id);
        Assert.Equal(new[] { "a", "b", "c" }, all);
        Assert.Contains("cursor=n1", handler.Requests[1].Url);

        var limited = new List<string>();
        await foreach (var account in client.LinkedAccounts.IterateAsync(maxItems: 1)) limited.Add(account.Id);
        Assert.Equal(new[] { "c" }, limited);
        Assert.Equal(3, handler.Requests.Count);
    }
}

public class UploadTests
{
    [Fact]
    public void ComputesMd5Hex()
    {
        Assert.Equal("d41d8cd98f00b204e9800998ecf8427e", Uploads.Md5Hex(Array.Empty<byte>()));
        Assert.Equal("9e107d9d372bb6826bd81d3542a419d6", Uploads.Md5Hex("The quick brown fox jumps over the lazy dog"u8));
    }

    [Fact]
    public async Task UploadsPartsAndFinalizes()
    {
        var data = new byte[10];
        for (var i = 0; i < data.Length; i++) data[i] = (byte)i;
        var handler = new FakeHandler(
            Json(new
            {
                status = "needs_upload",
                uploadId = "up_1",
                uploadType = "multipart",
                totalParts = 2,
                partSize = 6,
                expiresAt = "2026-01-01T00:00:00Z",
                parts = new[]
                {
                    new { partNumber = 1, uploadUrl = "https://api.ofauth.com/v3/access/uploads/up_1/parts/1?sig=a", byteRange = new { start = 0, end = 5 } },
                    new { partNumber = 2, uploadUrl = "https://api.ofauth.com/v3/access/uploads/up_1/parts/2?sig=b", byteRange = new { start = 6, end = 9 } },
                },
            }),
            Status(200),
            Status(200),
            Json(new
            {
                uploadIds = new[] { "up_1" },
                listId = 5,
                uploads = new[] { new { uploadId = "up_1", mediaId = 901, media = new { id = 901, type = "photo", ready = true } } },
            }));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var progress = new List<(long, long)>();

        var result = await client.UploadMediaAsync(data, new UploadMediaOptions { Filename = "upload.png",
            ContentType = "image/png",
            VaultUpload = new UploadVaultTarget { UserId = "u1", ListId = 5 },
            OnProgress = (done, total) => progress.Add((done, total)),
        });

        Assert.Equal("uploaded", result.Status);
        Assert.Equal("up_1", result.UploadId);
        Assert.Equal(4, handler.Requests.Count);

        var start = JsonDocument.Parse(handler.Requests[0].Body!).RootElement;
        Assert.Equal("https://api.ofauth.com/v3/access/uploads/start", handler.Requests[0].Url);
        Assert.Equal(Uploads.Md5Hex(data), start.GetProperty("etag").GetString());
        Assert.Equal(10, start.GetProperty("size").GetInt32());
        Assert.Equal("image/png", start.GetProperty("contentType").GetString());

        var part1 = handler.Requests[1];
        Assert.Equal(HttpMethod.Put, part1.Method);
        Assert.Equal("https://api.ofauth.com/v3/access/uploads/up_1/parts/1?sig=a", part1.Url);
        Assert.Equal("image/png", part1.ContentType);
        Assert.Equal("Bearer tok", part1.Header("Authorization"));
        Assert.Equal("conn_1", part1.Header("x-linked-account-id"));
        Assert.Equal(6, part1.Body!.Length);
        Assert.Equal(4, handler.Requests[2].Body!.Length);

        Assert.Equal(new[] { (6L, 10L), (10L, 10L) }, progress);
        Assert.Equal("https://api.ofauth.com/v3/access/uploads/finalize", handler.Requests[3].Url);
        Assert.Equal("{\"uploadIds\":[\"up_1\"],\"vaultUpload\":{\"userId\":\"u1\",\"listId\":5}}", handler.Requests[3].Body);

        // Typed finalize response and the vault media ids.
        Assert.NotNull(result.Finalize);
        Assert.Equal(new[] { "up_1" }, result.Finalize.UploadIds);
        Assert.Equal(5, result.Finalize.ListId);
        var finalized = Assert.Single(result.Finalize.Uploads!);
        Assert.Equal(901, finalized.MediaId);
        Assert.Equal("photo", finalized.Media.Type);
        Assert.Equal(new[] { 901L }, result.VaultMediaIds);
        Assert.Null(result.Media);
    }

    [Fact]
    public async Task UploadsWithoutVaultUploadHaveNoVaultMediaIds()
    {
        var handler = new FakeHandler(
            Json(new { status = "needs_upload", uploadId = "up_2", parts = Array.Empty<object>() }),
            Json(new { uploadIds = new[] { "up_2" } }));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var result = await client.UploadMediaAsync(new byte[] { 1 }, new UploadMediaOptions { Filename = "upload.png", ContentType = "image/png" });
        Assert.Equal("up_2", result.UploadId);
        Assert.Equal(new[] { "up_2" }, result.Finalize!.UploadIds);
        Assert.Empty(result.VaultMediaIds);
    }

    [Theory]
    [InlineData("""{"uploads":[{"uploadId":"a","mediaId":1},{"uploadId":"b","media":{"id":2}},{"uploadId":"c","mediaId":1}]}""", new long[] { 1, 2 })]
    [InlineData("""{"mediaIds":[3,"4",5.0]}""", new long[] { 3, 4, 5 })]
    [InlineData("""{"media":[{"id":6},{"id":7}]}""", new long[] { 6, 7 })]
    [InlineData("""{"uploadIds":["a"]}""", new long[0])]
    [InlineData("""[]""", new long[0])]
    public async Task VaultMediaIdsReadEveryKnownShape(string finalizeJson, long[] expected)
    {
        var handler = new FakeHandler(
            Json(new { status = "needs_upload", uploadId = "up_3", parts = Array.Empty<object>() }),
            _ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(finalizeJson, System.Text.Encoding.UTF8, "application/json"),
            });
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var result = await client.UploadMediaAsync(new byte[] { 1 }, new UploadMediaOptions { Filename = "upload.png",
            ContentType = "image/png",
            VaultUpload = new UploadVaultTarget { UserId = "u1" },
        });
        Assert.Equal(expected, result.VaultMediaIds);
    }

    [Fact]
    public async Task ReturnsExistingMedia()
    {
        var handler = new FakeHandler(Json(new { status = "already_exists", media = new { id = 77, type = "photo", ready = true } }));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());
        var result = await client.UploadMediaAsync(new byte[] { 1 }, new UploadMediaOptions { Filename = "upload.png", ContentType = "image/jpeg", Etag = "abc" });
        Assert.True(result.AlreadyExists);
        Assert.Equal(77, result.MediaId);
        Assert.NotNull(result.Media);
        Assert.Equal(77, result.Media.Id);
        Assert.Equal("photo", result.Media.Type);
        Assert.True(result.Media.Ready);
        Assert.Null(result.Finalize);
        Assert.Empty(result.VaultMediaIds);
        Assert.Single(handler.Requests);
        Assert.Contains("\"etag\":\"abc\"", handler.Requests[0].Body);
    }
}

public class RequestOriginTests
{
    private static object StartWithPart(string uploadUrl) => new
    {
        status = "needs_upload",
        uploadId = "up_1",
        parts = new[] { new { partNumber = 1, uploadUrl, byteRange = new { start = 0, end = 1 } } },
    };

    [Fact]
    public async Task UploadsPartsOnTheBaseUrlOrigin()
    {
        var handler = new FakeHandler(
            Json(StartWithPart("https://API.test:443/v3/access/uploads/up_1/parts/1")),
            Status(200),
            Json(new { uploadIds = new[] { "up_1" } }));
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok", LinkedAccountId = "conn_1", HttpClient = handler.Client(), BaseUrl = "https://api.test/",
        });

        await client.UploadMediaAsync(new byte[] { 1, 2 }, new UploadMediaOptions { Filename = "a.png", ContentType = "image/png" });

        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal("https://api.test/v3/access/uploads/up_1/parts/1", handler.Requests[1].Url);
        Assert.Equal("Bearer tok", handler.Requests[1].Header("Authorization"));
    }

    [Theory]
    [InlineData("https://evil.example/v3/access/uploads/up_1/parts/1")]
    [InlineData("https://uploads.api.ofauth.com/v3/access/uploads/up_1/parts/1")]
    [InlineData("http://api.ofauth.com/v3/access/uploads/up_1/parts/1")]
    [InlineData("https://api.ofauth.com:8443/v3/access/uploads/up_1/parts/1")]
    [InlineData("https://api.ofauth.com@evil.example/v3/access/uploads/up_1/parts/1")]
    public async Task RefusesPartUrlsOffTheApiOriginWithoutSending(string uploadUrl)
    {
        var handler = new FakeHandler(Json(StartWithPart(uploadUrl)), Status(200));
        var client = new OFAuthClient("tok", "conn_1", handler.Client());

        var error = await Assert.ThrowsAsync<OFAuthException>(() =>
            client.UploadMediaAsync(new byte[] { 1, 2 }, new UploadMediaOptions { Filename = "a.png", ContentType = "image/png" }));

        Assert.Contains("not the API origin", error.Message);
        Assert.Single(handler.Requests); // only the start call
    }

    [Fact]
    public async Task ChecksAbsoluteUrlsButNotPaths()
    {
        var handler = new FakeHandler(Json(new { }));
        var client = new OFAuthClient(new OFAuthClientOptions { AccessToken = "tok", HttpClient = handler.Client(), BaseUrl = "https://api.test" });

        await client.Transport.SendRawAsync(new ApiRequest(HttpMethod.Get, "/v3/access/profile"), CancellationToken.None);
        await Assert.ThrowsAsync<OFAuthException>(() => client.Transport.SendRawAsync(
            new ApiRequest(HttpMethod.Get, "/x") { Url = new Uri("https://api.ofauth.com/v3/x") }, CancellationToken.None));
        await Assert.ThrowsAsync<OFAuthException>(() => client.Transport.SendRawAsync(
            new ApiRequest(HttpMethod.Get, "/x") { Url = new Uri("/v3/x", UriKind.Relative) }, CancellationToken.None));

        Assert.Equal("https://api.test/v3/access/profile", Assert.Single(handler.Requests).Url);
    }
}
