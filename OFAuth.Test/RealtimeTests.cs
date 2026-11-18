using System.Collections.Concurrent;
using System.Text;
using static OFAuth.Test.FakeSseHandler;

namespace OFAuth.Test;

/// <summary>Realtime over Server-Sent Events, against a fake streaming HttpMessageHandler.</summary>
public class RealtimeTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static string Event(string eventId, long order, long id = 123, string type = "realtime.chat_message.received") =>
        $$"""{"eventId":"{{eventId}}","type":"{{type}}","schemaVersion":"1","order":{{order}},"receivedAt":"2026-10-12T14:30:15.143Z","environment":"live","integrationId":"int_1","linkedAccountId":"conn_1","test":false,"data":{"id":{{id}} """ + "}}";

    private static string Frame(string eventId, long order, long id = 123) => $"id: {order}\nevent: realtime.chat_message.received\ndata: {Event(eventId, order, id)}\n\n";

    private static string Closed(string reason) => $"event: closed\ndata: {{\"reason\":\"{reason}\"}}\n\n";

    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + Wait;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("condition not met");
            await Task.Delay(10);
        }
    }

    private sealed class Recorder
    {
        public ConcurrentQueue<RealtimeCloseInfo> Closes { get; } = new();
        public ConcurrentQueue<Exception> Errors { get; } = new();
        public ConcurrentQueue<RealtimeEvent> Events { get; } = new();
        public int Opens;
        public int Resyncs;

        public Recorder(RealtimeConnection realtime)
        {
            realtime.OnClose(Closes.Enqueue);
            realtime.OnError(Errors.Enqueue);
            realtime.OnEvent(Events.Enqueue);
            realtime.OnOpen(() => Interlocked.Increment(ref Opens));
            realtime.OnResync(() => Interlocked.Increment(ref Resyncs));
        }

        public RealtimeCloseInfo[] CloseList => Closes.ToArray();
    }

    private sealed class CountingProvider : IAccessTokenProvider
    {
        public ConcurrentQueue<bool> Calls { get; } = new();

        public Task<string> GetAccessTokenAsync(bool forceRefresh, CancellationToken cancellationToken)
        {
            Calls.Enqueue(forceRefresh);
            return Task.FromResult(forceRefresh ? "fresh" : "stale");
        }
    }

    [Fact]
    public async Task ParsesChunkedStreamsWithMultiLineDataCommentsBomAndSplitUtf8()
    {
        var body = new SseBody();
        var handler = new FakeSseHandler(Open(body));
        await using var realtime = handler.Client().Realtime(new RealtimeOptions { Reconnect = false });
        var recorder = new Recorder(realtime);
        var typed = new ConcurrentQueue<long>();
        realtime.OnChatMessageReceived(e => typed.Enqueue(e.Data.Id));

        await realtime.ConnectAsync();
        Assert.True(realtime.IsConnected);

        // BOM, a comment, an invalid retry, and an event whose data spans two lines and whose lines are split
        // mid-field, between \r and \n, and inside a multi-byte UTF-8 character.
        var json = Event("evt_1", 1).Replace("\"live\"", "\"livé\"");
        var split = json.IndexOf(',');
        var bytes = Encoding.UTF8.GetBytes("﻿: heartbeat\r\nretry: soon\r\nid: 1\r\nevent: realtime.chat_message.re" +
            "ceived\r\ndata: " + json[..(split + 1)] + "\r\ndata: " + json[(split + 1)..] + "\r\n\r\n");
        var accent = Array.IndexOf(bytes, (byte)0xC3);
        var cuts = new[] { 1, 5, bytes.Length / 3, accent + 1, Array.LastIndexOf(bytes, (byte)'\r') + 1, bytes.Length };
        var start = 0;
        foreach (var cut in cuts.Distinct().Order())
        {
            body.WriteBytes(bytes[start..cut]);
            start = cut;
            await Task.Delay(5);
        }
        // A second event without an id keeps the stream's last id.
        body.Write("data: " + Event("evt_2", 2, 456) + "\n\n");
        await Until(() => recorder.Events.Count == 2);

        var first = recorder.Events.First();
        Assert.Equal("evt_1", first.EventId);
        Assert.Equal("livé", first.Environment);
        Assert.Equal(1, first.Order);
        Assert.Equal(new long[] { 123, 456 }, typed.ToArray());
        Assert.Equal("1", realtime.LastEventId);
        Assert.Empty(recorder.Errors);

        body.Write("id: 3\ndata: " + Event("evt_3", 3) + "\n\n");
        await Until(() => recorder.Events.Count == 3);
        Assert.Equal("3", realtime.LastEventId);
    }

    [Fact]
    public async Task SendsTheStreamRequestAndResumesWithLastEventId()
    {
        var time = new TestTime();
        var handler = new FakeSseHandler(
            Sends("retry: 1000\n\n" + Frame("evt_5", 5) + ": heartbeat\n\n"),
            Sends(Frame("evt_6", 6) + Closed("replaced")));
        await using var realtime = handler.Client(time: time, headers: new() { ["CF-Access-Client-Id"] = "cf", ["Accept"] = "application/json" })
            .Realtime(new RealtimeOptions { HeartbeatTimeout = TimeSpan.Zero, LastEventId = "4" });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 2);

        Assert.Equal(2, handler.Count);
        var first = handler.Requests[0];
        Assert.Equal(HttpMethod.Get, first.Method);
        Assert.Equal("https://api.test/v3/realtime/events?linkedAccountId=conn_1", first.Url);
        Assert.Equal("Bearer tok", first.Header("Authorization"));
        Assert.Equal("text/event-stream", first.Header("Accept"));
        Assert.Equal("no-cache", first.Header("Cache-Control"));
        Assert.Equal("cf", first.Header("CF-Access-Client-Id"));
        Assert.Equal("4", first.Header("Last-Event-ID"));
        Assert.Equal("5", handler.Requests[1].Header("Last-Event-ID"));

        var closes = recorder.CloseList;
        Assert.Equal(RealtimeCloseReason.Dropped, closes[0].Reason);
        Assert.True(closes[0].WillReconnect);
        // Backoff starts from the server's retry: time, with up to 50% jitter.
        Assert.InRange(closes[0].RetryIn!.Value.TotalMilliseconds, 1000, 1500);
        Assert.Equal(RealtimeCloseReason.Replaced, closes[1].Reason);
        Assert.False(closes[1].WillReconnect);
        Assert.Equal(2, recorder.Opens);
        Assert.Equal("6", realtime.LastEventId);
        Assert.False(realtime.IsConnected);
    }

    [Fact]
    public async Task DropsRepeatedEventIdsWithoutMovingTheResumePoint()
    {
        var handler = new FakeSseHandler(Sends(Frame("evt_1", 1) + Frame("evt_1", 2) + Frame("evt_2", 3) + Closed("replaced")));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);
        var lastIds = new ConcurrentQueue<string?>();
        realtime.OnEvent(_ => lastIds.Enqueue(realtime.LastEventId));

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 1);

        Assert.Equal(new[] { "evt_1", "evt_2" }, recorder.Events.Select(e => e.EventId));
        Assert.Equal(new[] { "1", "3" }, lastIds);

        // Replayed events are deduped too.
        await realtime.DispatchAsync(Event("evt_2", 3));
        await realtime.DispatchAsync(Event("evt_9", 9));
        Assert.Equal(new[] { "evt_1", "evt_2", "evt_9" }, recorder.Events.Select(e => e.EventId));
        Assert.Equal("3", realtime.LastEventId);
    }

    [Fact]
    public async Task ResyncAndInvalidEvents()
    {
        var handler = new FakeSseHandler(Sends("event: resync\ndata: {}\n\nid: 7\ndata: not json\n\nid: 8\ndata: {\"eventId\":\"x\"}\n\n" + Closed("replaced")));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 1);

        Assert.Equal(1, recorder.Resyncs);
        Assert.Empty(recorder.Events);
        Assert.Equal(2, recorder.Errors.Count);
        Assert.Contains(recorder.Errors, e => e.Message.Contains("without a type"));
        Assert.Equal("8", realtime.LastEventId);
    }

    [Fact]
    public async Task ReauthRefreshesTheTokenOnceThenStops()
    {
        var provider = new CountingProvider();
        var handler = new FakeSseHandler(Sends(Closed("reauth")), Sends(Closed("reauth")));
        await using var realtime = handler.Client(provider).Realtime(new RealtimeOptions { HeartbeatTimeout = TimeSpan.Zero });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 2);

        Assert.Equal(new[] { false, true }, provider.Calls);
        Assert.Equal("Bearer stale", handler.Requests[0].Header("Authorization"));
        Assert.Equal("Bearer fresh", handler.Requests[1].Header("Authorization"));
        var closes = recorder.CloseList;
        Assert.All(closes, c => Assert.Equal(RealtimeCloseReason.Reauth, c.Reason));
        Assert.True(closes[0].WillReconnect);
        Assert.Equal(TimeSpan.Zero, closes[0].RetryIn);
        Assert.False(closes[1].WillReconnect);
        await Task.Delay(50);
        Assert.Equal(2, handler.Count);
    }

    [Fact]
    public async Task A401WithAFixedTokenStopsAtOnce()
    {
        var handler = new FakeSseHandler(Refuse(401, "invalid_token"));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(401, error.StatusCode);
        Assert.Equal("invalid_token", error.Code);
        Assert.Equal("realtime", error.Operation);
        Assert.Equal(1, handler.Count);
        var close = Assert.Single(recorder.CloseList);
        Assert.Equal(RealtimeCloseReason.Reauth, close.Reason);
        Assert.Equal(401, close.Status);
        Assert.False(close.WillReconnect);
    }

    [Fact]
    public async Task A401WithAProviderRefreshesOnceThenThrows()
    {
        var provider = new CountingProvider();
        var handler = new FakeSseHandler(Refuse(401, "invalid_token"), Refuse(401, "invalid_token"));
        await using var realtime = handler.Client(provider).Realtime();

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(401, error.StatusCode);
        Assert.Equal(new[] { false, true }, provider.Calls);
        Assert.Equal(2, handler.Count);
    }

    [Fact]
    public async Task A401RefreshThatSucceedsOpensTheStream()
    {
        var provider = new CountingProvider();
        var handler = new FakeSseHandler(Refuse(401, "invalid_token"), Sends(Closed("replaced")));
        await using var realtime = handler.Client(provider).Realtime();

        await realtime.ConnectAsync();

        Assert.Equal("Bearer fresh", handler.Requests[1].Header("Authorization"));
    }

    [Fact]
    public async Task A409IsReplaced()
    {
        var handler = new FakeSseHandler(Refuse(409, "stream_replaced"));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(409, error.StatusCode);
        var close = Assert.Single(recorder.CloseList);
        Assert.Equal(RealtimeCloseReason.Replaced, close.Reason);
        Assert.Equal(409, close.Status);
    }

    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(400)]
    public async Task OtherRefusalsAreRejected(int status)
    {
        var handler = new FakeSseHandler(Refuse(status));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(status, error.StatusCode);
        var close = Assert.Single(recorder.CloseList);
        Assert.Equal(RealtimeCloseReason.Rejected, close.Reason);
    }

    [Fact]
    public async Task A200ThatIsNotAnEventStreamIsRejected()
    {
        var handler = new FakeSseHandler((_, _) => Task.FromResult(FakeHandler.JsonResponse(new { ok = true })));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(200, error.StatusCode);
        Assert.Equal(RealtimeCloseReason.Rejected, Assert.Single(recorder.CloseList).Reason);
        Assert.Equal(0, recorder.Opens);
    }

    [Fact]
    public async Task A503OnTheFirstConnectThrowsWithRetryAfter()
    {
        var handler = new FakeSseHandler(Refuse(503, "realtime_unavailable", retryAfterSeconds: 7));
        await using var realtime = handler.Client().Realtime();

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => realtime.ConnectAsync());

        Assert.Equal(503, error.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(7), error.RetryAfter);
        Assert.Equal(1, handler.Count);
    }

    [Fact]
    public async Task UnavailableBacksOffHonoursRetryAfterAndResumes()
    {
        var time = new TestTime();
        var handler = new FakeSseHandler(
            Sends(Frame("evt_1", 1) + Closed("unavailable")),
            Refuse(503, "realtime_unavailable", retryAfterSeconds: 7),
            Refuse(429, "rate_limited"),
            NetworkError(),
            Sends(Frame("evt_2", 2) + Closed("replaced")));
        await using var realtime = handler.Client(time: time).Realtime(new RealtimeOptions
        {
            HeartbeatTimeout = TimeSpan.Zero,
            MaxReconnectDelay = TimeSpan.FromSeconds(10),
        });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 5);

        var closes = recorder.CloseList;
        Assert.Equal(
            new[] { RealtimeCloseReason.Unavailable, RealtimeCloseReason.Unavailable, RealtimeCloseReason.Unavailable, RealtimeCloseReason.Dropped, RealtimeCloseReason.Replaced },
            closes.Select(c => c.Reason));
        Assert.Equal(new int?[] { null, 503, 429, null, null }, closes.Select(c => c.Status));
        Assert.All(closes[..4], c => Assert.True(c.WillReconnect));
        // 3 s, then 6 s (at least Retry-After 7 s), then capped at 10 s.
        Assert.InRange(closes[0].RetryIn!.Value.TotalSeconds, 3, 4.5);
        Assert.InRange(closes[1].RetryIn!.Value.TotalSeconds, 7, 9);
        Assert.Equal(10, closes[2].RetryIn!.Value.TotalSeconds);
        Assert.Equal(10, closes[3].RetryIn!.Value.TotalSeconds);
        Assert.Equal(new[] { "evt_1", "evt_2" }, recorder.Events.Select(e => e.EventId));
        Assert.All(handler.Requests.Skip(1), r => Assert.Equal("1", r.Header("Last-Event-ID")));
        Assert.Contains(recorder.Errors, e => e is OFAuthConnectionException);
    }

    [Fact]
    public async Task ReconnectFalseStopsAfterADrop()
    {
        var handler = new FakeSseHandler(Sends(Frame("evt_1", 1)));
        await using var realtime = handler.Client().Realtime(new RealtimeOptions { Reconnect = false });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 1);

        var close = recorder.CloseList[0];
        Assert.Equal(RealtimeCloseReason.Dropped, close.Reason);
        Assert.False(close.WillReconnect);
        Assert.Null(close.RetryIn);
    }

    [Fact]
    public async Task ABrokenConnectionIsDropped()
    {
        var body = new SseBody();
        var handler = new FakeSseHandler(Open(body), Sends(Closed("replaced")));
        await using var realtime = handler.Client(time: new TestTime()).Realtime(new RealtimeOptions { HeartbeatTimeout = TimeSpan.Zero });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        body.Write(Frame("evt_1", 1));
        body.Fail();
        await Until(() => recorder.Closes.Count == 2);

        Assert.Equal(RealtimeCloseReason.Dropped, recorder.CloseList[0].Reason);
        Assert.Contains(recorder.Errors, e => e is IOException);
        Assert.Equal("1", handler.Requests[1].Header("Last-Event-ID"));
    }

    [Fact]
    public async Task ASilentStreamTimesOutAndReconnects()
    {
        var silent = new SseBody().Write(": hi\n\n");
        var handler = new FakeSseHandler(Open(silent), Sends(Frame("evt_1", 1) + Closed("replaced")));
        await using var realtime = handler.Client().Realtime(new RealtimeOptions
        {
            HeartbeatTimeout = TimeSpan.FromMilliseconds(200),
            MaxReconnectDelay = TimeSpan.FromMilliseconds(50),
        });
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 2);

        var close = recorder.CloseList[0];
        Assert.Equal(RealtimeCloseReason.HeartbeatTimeout, close.Reason);
        Assert.True(close.WillReconnect);
        Assert.Contains(recorder.Errors, e => e is OFAuthConnectionException { IsTimeout: true });
        Assert.Single(recorder.Events);
    }

    [Fact]
    public async Task TheHeartbeatTimeoutBoundsTheWaitForHeaders()
    {
        var handler = new FakeSseHandler(Hang());
        await using var realtime = handler.Client().Realtime(new RealtimeOptions { HeartbeatTimeout = TimeSpan.FromMilliseconds(100) });
        var recorder = new Recorder(realtime);

        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() => realtime.ConnectAsync());

        Assert.True(error.IsTimeout);
        Assert.Equal(RealtimeCloseReason.HeartbeatTimeout, Assert.Single(recorder.CloseList).Reason);
    }

    [Fact]
    public async Task CloseAsyncStopsTheStream()
    {
        var body = new SseBody();
        var handler = new FakeSseHandler(Open(body));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);

        await realtime.ConnectAsync();
        await realtime.ConnectAsync(); // a no-op while connected
        await realtime.CloseAsync();

        Assert.Equal(1, handler.Count);
        var close = Assert.Single(recorder.CloseList);
        Assert.Equal(RealtimeCloseReason.ClientClosed, close.Reason);
        Assert.False(close.WillReconnect);
        Assert.False(realtime.IsConnected);
    }

    [Fact]
    public async Task CloseFromAHandlerDoesNotDeadlock()
    {
        var handler = new FakeSseHandler(Sends(Frame("evt_1", 1) + Frame("evt_2", 2)));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);
        realtime.OnEvent(async _ => await realtime.CloseAsync());

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 1);

        Assert.Single(recorder.Events);
        Assert.Equal(RealtimeCloseReason.ClientClosed, recorder.CloseList[0].Reason);
    }

    [Fact]
    public async Task CancellingConnectAsyncStops()
    {
        var handler = new FakeSseHandler(Hang());
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => realtime.ConnectAsync(cts.Token));

        Assert.Equal(RealtimeCloseReason.ClientClosed, Assert.Single(recorder.CloseList).Reason);
    }

    [Fact]
    public async Task HooksAndDebugLogging()
    {
        var body = new SseBody();
        var handler = new FakeSseHandler(Open(body, "rts_1"));
        var requests = new List<OFAuthRequestInfo>();
        var responses = new List<OFAuthResponseInfo>();
        var lines = new List<string>();
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "secret-token",
            LinkedAccountId = "conn_1",
            BaseUrl = "https://api.test",
            HttpClient = new HttpClient(handler),
            OnRequest = requests.Add,
            OnResponse = responses.Add,
            DebugLogger = lines.Add,
        });
        await using var realtime = client.Realtime();

        await realtime.ConnectAsync();

        var request = Assert.Single(requests);
        Assert.Equal("GET", request.Method);
        Assert.Equal("https://api.test/v3/realtime/events?linkedAccountId=conn_1", request.Url.AbsoluteUri);
        Assert.Equal("Bearer [redacted]", request.Headers["Authorization"]);
        Assert.DoesNotContain(request.Headers.Values, v => v.Contains("secret-token"));
        var response = Assert.Single(responses);
        Assert.Equal(200, response.StatusCode);
        Assert.Equal("rts_1", response.RequestId);
        Assert.Matches(@"^\[ofauth\] SSE /v3/realtime/events -> 200 \(\d+ms, rts_1\)$", Assert.Single(lines));
    }

    [Fact]
    public async Task HookExceptionsDoNotBreakTheConnection()
    {
        var handler = new FakeSseHandler(Open(new SseBody()));
        await using var realtime = handler.Client().Realtime(new RealtimeOptions
        {
            OnRequest = _ => throw new InvalidOperationException("hook"),
            OnResponse = _ => throw new InvalidOperationException("hook"),
        });
        var recorder = new Recorder(realtime);
        realtime.OnOpen(() => throw new InvalidOperationException("handler"));

        await realtime.ConnectAsync();

        Assert.Equal(1, recorder.Opens);
        Assert.Contains(recorder.Errors, e => e.Message == "handler");
    }

    [Fact]
    public async Task HandlerExceptionsAreReportedAndTheStreamContinues()
    {
        var handler = new FakeSseHandler(Sends(Frame("evt_1", 1) + Frame("evt_2", 2) + Closed("replaced")));
        await using var realtime = handler.Client().Realtime();
        var recorder = new Recorder(realtime);
        realtime.OnChatMessageReceived(e =>
        {
            if (e.EventId == "evt_1") throw new InvalidOperationException("boom");
        });

        await realtime.ConnectAsync();
        await Until(() => recorder.Closes.Count == 1);

        Assert.Equal(2, recorder.Events.Count);
        Assert.Contains(recorder.Errors, e => e.Message == "boom");
    }

    [Fact]
    public async Task CreateStreamUrlPostsTheLinkedAccount()
    {
        var handler = new FakeHandler(
            FakeHandler.Json(new { url = "https://api.test/v3/realtime/events?linkedAccountId=conn_1&streamToken=st_1", expiresAt = "2026-10-25T12:10:00.000Z" }),
            FakeHandler.Json(new { error = "rate_limited" }, 429, new() { ["Retry-After"] = "1" }),
            FakeHandler.Json(new { url = "https://api.test/v3/realtime/events?linkedAccountId=conn_2&streamToken=st_2", expiresAt = "2026-10-25T12:10:00Z" }),
            FakeHandler.Json(new { error = "forbidden" }, 403));
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessToken = "tok",
            LinkedAccountId = "conn_1",
            BaseUrl = "https://api.test",
            HttpClient = handler.Client(),
            TimeProvider = new TestTime(),
        });

        var stream = await client.CreateStreamUrlAsync();
        Assert.StartsWith("https://api.test/v3/realtime/events?", stream.Url);
        Assert.Equal(new DateTimeOffset(2026, 10, 25, 12, 10, 0, TimeSpan.Zero), stream.ExpiresAt);
        var sent = handler.Requests[0];
        Assert.Equal(HttpMethod.Post, sent.Method);
        Assert.Equal("https://api.test/v3/realtime", sent.Url);
        Assert.Equal("""{"linkedAccountId":"conn_1"}""", sent.Body);
        Assert.Equal("Bearer tok", sent.Header("Authorization"));

        // 429 is retried; the account can be overridden.
        var other = await client.CreateStreamUrlAsync("conn_2");
        Assert.Contains("st_2", other.Url);
        Assert.Equal("""{"linkedAccountId":"conn_2"}""", handler.Requests[2].Body);

        var error = await Assert.ThrowsAsync<OFAuthApiException>(() => client.CreateStreamUrlAsync());
        Assert.Equal(403, error.StatusCode);
        Assert.Equal("realtime.createStreamUrl", error.Operation);

        var noAccount = new OFAuthClient(new OFAuthClientOptions { AccessToken = "tok", HttpClient = handler.Client() });
        await Assert.ThrowsAsync<OFAuthException>(() => noAccount.CreateStreamUrlAsync());
    }

    [Fact]
    public async Task InitialCursorSurvivesDisconnectOverHttp()
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var cursors = new List<string?>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = Task.Run(async () =>
        {
            for (var n = 0; n < 3; n++)
            {
                using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
                using var stream = socket.GetStream();
                using var reader = new StreamReader(stream, leaveOpen: true);
                string? cursor = null;
                while (await reader.ReadLineAsync(deadline.Token) is { Length: > 0 } line)
                    if (line.StartsWith("Last-Event-ID:", StringComparison.OrdinalIgnoreCase)) cursor = line.Split(':', 2)[1].Trim();
                cursors.Add(cursor);
                var body = n == 0 ? "retry: 1\n\nid: 10\n\n" : n == 1 ? Frame("evt_11", 11) + Frame("evt_11", 9) + Closed("unavailable") : Closed("replaced");
                var bytes = Encoding.UTF8.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");
                await stream.WriteAsync(bytes, deadline.Token);
            }
        });
        var client = new OFAuthClient(new OFAuthClientOptions { AccessToken = "tok", LinkedAccountId = "conn_1", BaseUrl = $"http://127.0.0.1:{port}" });
        await using var realtime = client.Realtime(new RealtimeOptions { MaxReconnectDelay = TimeSpan.FromMilliseconds(5) });
        var recorder = new Recorder(realtime);
        try
        {
            await realtime.ConnectAsync(deadline.Token);
            await Until(() => recorder.CloseList.Any(info => !info.WillReconnect));
            await server;
            Assert.Equal(new string?[] { null, "10", "11" }, cursors);
            Assert.Equal("11", realtime.LastEventId);
            Assert.Single(recorder.Events);
        }
        finally { listener.Stop(); }
    }
}
