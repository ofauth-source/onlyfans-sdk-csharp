// Realtime over Server-Sent Events: Realtime events for one linked account.
// Lifecycle events (authorization.*, linked_account.*) are delivered by webhook only.
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OFAuth;

/// <summary>
/// Options for <see cref="OFAuthClient.Realtime"/>. The stream always goes to <c>/v3/realtime/events</c> on the client's
/// <c>BaseUrl</c> origin with the client's access token, <c>HttpClient</c>, and <c>DefaultHeaders</c>; there is no URL option.
/// </summary>
public sealed record RealtimeOptions
{
    /// <summary>The linked account to receive events for. Defaults to the client's.</summary>
    public string? LinkedAccountId { get; init; }

    /// <summary>Resume after this event id (an event's <c>order</c>), e.g. one you stored before a restart.</summary>
    public string? LastEventId { get; init; }

    /// <summary>Reconnect after the stream drops or Realtime is briefly unavailable. Defaults to true.</summary>
    public bool Reconnect { get; init; } = true;

    /// <summary>Upper bound for the reconnect backoff. Defaults to 30 seconds.</summary>
    public TimeSpan MaxReconnectDelay { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Treat the stream as dead when nothing (not even the 15 s heartbeat) arrives for this long, and reconnect. Also
    /// bounds the wait for the response headers. Defaults to 45 seconds; <see cref="TimeSpan.Zero"/> disables it.
    /// </summary>
    public TimeSpan HeartbeatTimeout { get; init; } = TimeSpan.FromSeconds(45);

    /// <summary>
    /// Called before every connection attempt (method <c>GET</c>, the sanitized stream URL, headers with
    /// <c>Authorization</c> redacted). <see cref="OFAuthClient.Realtime"/> passes the client's hook. Exceptions thrown by
    /// the hook are ignored.
    /// </summary>
    public Action<OFAuthRequestInfo>? OnRequest { get; init; }

    /// <summary>
    /// Called when a connection attempt gets response headers: status 200 when the stream opened, else the HTTP status
    /// (401, 409, 503, ...). <c>RequestId</c> is the <c>x-realtime-session-id</c> (or <c>x-request-id</c>) header. Not
    /// called when no response arrived. <see cref="OFAuthClient.Realtime"/> passes the client's hook. Exceptions thrown
    /// by the hook are ignored.
    /// </summary>
    public Action<OFAuthResponseInfo>? OnResponse { get; init; }

    /// <summary>
    /// Log one line per connection attempt, e.g. <c>[ofauth] SSE /v3/realtime/events -&gt; 200 (85ms, rts_abc)</c>, to
    /// standard error. Also enabled by <c>OFAUTH_DEBUG=1</c>. <see cref="OFAuthClient.Realtime"/> passes the client's setting.
    /// </summary>
    public bool Debug { get; init; }

    /// <summary>Where debug lines go. Setting it enables debug logging.</summary>
    public Action<string>? DebugLogger { get; init; }
}

/// <summary>Fields shared by every Realtime event.</summary>
public abstract class RealtimeEventBase
{
    /// <summary>Unique event id. Delivery is at least once; the connection drops repeated ids.</summary>
    [JsonPropertyName("eventId")] public string EventId { get; set; } = "";

    /// <summary>Event type, e.g. <c>realtime.chat_message.received</c>. See <see cref="WebhookEventTypes"/>.</summary>
    [JsonPropertyName("type")] public string Type { get; set; } = "";

    /// <summary>Envelope schema version (<c>1</c>).</summary>
    [JsonPropertyName("schemaVersion")] public string SchemaVersion { get; set; } = "";

    /// <summary>Per linked account ordering. Also the stream's event id (<see cref="RealtimeConnection.LastEventId"/>).</summary>
    [JsonPropertyName("order")] public long Order { get; set; }

    /// <summary>When OFAuth received the event.</summary>
    [JsonPropertyName("receivedAt")] public string ReceivedAt { get; set; } = "";

    /// <summary><c>sandbox</c>, <c>test</c>, or <c>live</c>.</summary>
    [JsonPropertyName("environment")] public string Environment { get; set; } = "";

    /// <summary>Your integration id.</summary>
    [JsonPropertyName("integrationId")] public string IntegrationId { get; set; } = "";

    /// <summary>The linked account the event belongs to.</summary>
    [JsonPropertyName("linkedAccountId")] public string LinkedAccountId { get; set; } = "";

    /// <summary>True for test events.</summary>
    [JsonPropertyName("test")] public bool Test { get; set; }
}

/// <summary>A Realtime event from the event stream, with untyped <see cref="Data"/>.</summary>
public sealed class RealtimeEvent : RealtimeEventBase
{
    /// <summary>Event payload. Its shape depends on <see cref="RealtimeEventBase.Type"/>.</summary>
    [JsonPropertyName("data")] public JsonElement Data { get; set; }

    /// <summary>The raw JSON of the event.</summary>
    [JsonIgnore] public string RawJson { get; internal set; } = "";

    /// <summary><see cref="Data"/> as a typed class (see <see cref="WebhookEventTypes.DataTypes"/>).</summary>
    public T GetData<T>() => Data.Deserialize<T>(ApiTransport.JsonOptions)!;
}

/// <summary>A Realtime event with typed <see cref="Data"/>.</summary>
public sealed class RealtimeEvent<TData> : RealtimeEventBase
{
    /// <summary>Typed event payload.</summary>
    [JsonPropertyName("data")] public TData Data { get; set; } = default!;
}

/// <summary>Why a Realtime stream ended.</summary>
public enum RealtimeCloseReason
{
    /// <summary>
    /// The credential or authorization no longer holds (the server sent <c>closed</c> with <c>reauth</c>, or answered 401).
    /// The connection gets a fresh token (<c>forceRefresh</c>) and retries once, then stops.
    /// </summary>
    Reauth,

    /// <summary>
    /// A newer stream for this linked account took the slot (more than 10 streams per account; the oldest is replaced),
    /// or 409 <c>stream_replaced</c>. The connection stops.
    /// </summary>
    Replaced,

    /// <summary>A transient outage (<c>closed</c> with <c>unavailable</c>, 503, 429). The connection backs off and resumes.</summary>
    Unavailable,

    /// <summary>The stream ended without a <c>closed</c> event, or the request failed (network error). The connection resumes.</summary>
    Dropped,

    /// <summary>No bytes, not even the 15 s heartbeat, for <see cref="RealtimeOptions.HeartbeatTimeout"/>. The connection resumes.</summary>
    HeartbeatTimeout,

    /// <summary>
    /// The request was refused for good (400, 403, 404, 406, a response that is not an event stream, or an exception
    /// from a custom <see cref="HttpMessageHandler"/>). The connection stops.
    /// </summary>
    Rejected,

    /// <summary>You called <see cref="RealtimeConnection.CloseAsync"/> (or cancelled <see cref="RealtimeConnection.ConnectAsync"/>).</summary>
    ClientClosed,
}

/// <summary>Why the stream closed.</summary>
/// <param name="Reason">Why the stream ended.</param>
/// <param name="Status">The HTTP status when the server refused the stream (401, 409, 503, ...).</param>
/// <param name="WillReconnect">True when the connection will reconnect.</param>
/// <param name="RetryIn">When <paramref name="WillReconnect"/>, the delay before the next attempt.</param>
public sealed record RealtimeCloseInfo(RealtimeCloseReason Reason, int? Status, bool WillReconnect, TimeSpan? RetryIn);

/// <summary>
/// A stream URL for a browser, from <see cref="OFAuthClient.CreateStreamUrlAsync"/> (<c>POST /v3/realtime</c>).
/// </summary>
public sealed class RealtimeStreamUrl
{
    /// <summary>
    /// The full <c>GET /v3/realtime/events</c> URL, carrying a stream credential (not an access token). Hand only this URL
    /// to the page, which opens it with <c>EventSource</c> (or <c>connectRealtimeStream</c> from the TypeScript SDK's
    /// <c>@ofauth/onlyfans-sdk/realtime-browser</c>).
    /// </summary>
    [JsonPropertyName("url")] public string Url { get; set; } = "";

    /// <summary>When the credential expires (10 minutes, never after the access token). The open stream then ends with <c>reauth</c>.</summary>
    [JsonPropertyName("expiresAt")] public DateTimeOffset ExpiresAt { get; set; }
}

/// <summary>
/// A Realtime event stream (Server-Sent Events) for one linked account, with automatic reconnects and resume. Typed
/// <c>On...</c> methods are generated for every <c>realtime.*</c> event.
/// </summary>
/// <remarks>
/// <para>
/// Get one from <see cref="OFAuthClient.Realtime"/>: the constructor is internal, so a connection cannot be created
/// without a configured client. It streams <c>GET /v3/realtime/events</c> through the client's <c>HttpClient</c>.
/// </para>
/// <para>
/// Reconnects use jittered exponential backoff from the server's <c>retry:</c> (3 s), capped at
/// <see cref="RealtimeOptions.MaxReconnectDelay"/> and never shorter than <c>Retry-After</c>, and resume with
/// <c>Last-Event-ID</c>. Events are deduped by <c>eventId</c>. <c>reauth</c> or 401 refreshes the token once, then
/// stops; <c>replaced</c> or 409 stops. Up to 10 streams per linked account can be open; a newer one replaces the oldest.
/// </para>
/// <para>
/// Handlers run one at a time, in order, on the connection's read loop; an async handler delays the next event.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// await using var realtime = client.Realtime();
/// realtime.OnChatMessageReceived(e => Console.WriteLine(e.Data));
/// realtime.OnResync(() => RefetchEverything());
/// realtime.OnClose(info => Console.WriteLine($"closed {info.Reason}, reconnecting: {info.WillReconnect}"));
/// await realtime.ConnectAsync();
/// </code>
/// </example>
public sealed partial class RealtimeConnection : IAsyncDisposable
{
    internal const string EventsPath = "/v3/realtime/events";
    private const int DefaultRetryMs = 3_000;
    private const int DedupeWindow = 1_000;

    private static readonly AsyncLocal<RealtimeConnection?> CurrentLoop = new();

    private readonly RealtimeOptions _options;
    private readonly IAccessTokenProvider _tokenProvider;
    private readonly HttpClient _http;
    private readonly IReadOnlyDictionary<string, string> _headers;
    private readonly TimeProvider _time;
    private readonly string _url;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly Dictionary<string, List<Func<RealtimeEvent, Task>>> _typed = new(StringComparer.Ordinal);
    private readonly List<Func<RealtimeEvent, Task>> _eventHandlers = new();
    private readonly List<Action> _resyncHandlers = new();
    private readonly List<Action> _openHandlers = new();
    private readonly List<Action<RealtimeCloseInfo>> _closeHandlers = new();
    private readonly List<Action<Exception>> _errorHandlers = new();
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly Queue<string> _seenOrder = new();

    // Guarded by _gate.
    private long _generation;
    private bool _active;
    private bool _hasConnected;
    private TaskCompletionSource? _pending;
    private CancellationTokenSource? _lifetime;
    private Task? _loop;

    // Used by the read loop only.
    private int _attempt;
    private int _failures;
    private int _retryMs = DefaultRetryMs;
    private volatile string? _lastId;
    private volatile bool _streaming;

    /// <summary>Created by <see cref="OFAuthClient.Realtime"/> with the client's transport and derived URL.</summary>
    internal RealtimeConnection(RealtimeOptions options, ApiTransport transport, string url)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.LinkedAccountId)) throw new ArgumentException("LinkedAccountId is required", nameof(options));
        if (options.HeartbeatTimeout < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options), "HeartbeatTimeout must be zero or more");
        _options = options;
        _tokenProvider = transport.TokenProvider;
        _http = transport.HttpClient;
        _headers = transport.DefaultHeaders;
        _time = transport.TimeProvider;
        _url = url;
        _lastId = string.IsNullOrEmpty(options.LastEventId) ? null : options.LastEventId;
        _log = options.DebugLogger
            ?? (options.Debug || System.Environment.GetEnvironmentVariable("OFAUTH_DEBUG") == "1"
                ? line => Console.Error.WriteLine(line)
                : null);
    }

    /// <summary>True while a stream is open.</summary>
    public bool IsConnected => _streaming;

    /// <summary>The id (<c>order</c>) of the last event received, sent as <c>Last-Event-ID</c> on reconnects. Store it to resume after a restart.</summary>
    public string? LastEventId => _lastId;

    // ------------------------------------------------------------------------
    // Handlers
    // ------------------------------------------------------------------------

    /// <summary>Handle one event type. Dispose the result to unsubscribe.</summary>
    public IDisposable On(string type, Func<RealtimeEvent, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_gate)
        {
            if (!_typed.TryGetValue(type, out var list)) _typed[type] = list = new();
            list.Add(handler);
        }
        return new Subscription(() =>
        {
            lock (_gate) _typed[type].Remove(handler);
        });
    }

    /// <summary>Handle one event type. Dispose the result to unsubscribe.</summary>
    public IDisposable On(string type, Action<RealtimeEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e =>
        {
            handler(e);
            return Task.CompletedTask;
        });
    }

    /// <summary>Handle one event type with typed data (see <see cref="WebhookEventTypes.DataTypes"/>).</summary>
    public IDisposable On<TData>(string type, Func<RealtimeEvent<TData>, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e => handler(JsonSerializer.Deserialize<RealtimeEvent<TData>>(e.RawJson, ApiTransport.JsonOptions)!));
    }

    /// <summary>Handle one event type with typed data.</summary>
    public IDisposable On<TData>(string type, Action<RealtimeEvent<TData>> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return On(type, e =>
        {
            handler(JsonSerializer.Deserialize<RealtimeEvent<TData>>(e.RawJson, ApiTransport.JsonOptions)!);
            return Task.CompletedTask;
        });
    }

    /// <summary>Handle every event.</summary>
    public IDisposable OnEvent(Func<RealtimeEvent, Task> handler) => Add(_eventHandlers, handler);

    /// <summary>Handle every event.</summary>
    public IDisposable OnEvent(Action<RealtimeEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        return OnEvent(e =>
        {
            handler(e);
            return Task.CompletedTask;
        });
    }

    /// <summary>
    /// The resume point was older than the server's replay buffer (1,000 events or 15 minutes), so events were missed:
    /// refetch the state you show through the REST API.
    /// </summary>
    public IDisposable OnResync(Action handler) => Add(_resyncHandlers, handler);

    /// <summary>Called every time a stream opens (the first one, and every reconnect).</summary>
    public IDisposable OnOpen(Action handler) => Add(_openHandlers, handler);

    /// <summary>Called every time a stream ends, with the reason and whether the connection will reconnect.</summary>
    public IDisposable OnClose(Action<RealtimeCloseInfo> handler) => Add(_closeHandlers, handler);

    /// <summary>Called for connection errors, refused requests, invalid events, and handler exceptions.</summary>
    public IDisposable OnError(Action<Exception> handler) => Add(_errorHandlers, handler);

    private IDisposable Add<T>(List<T> list, T handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_gate) list.Add(handler);
        return new Subscription(() =>
        {
            lock (_gate) list.Remove(handler);
        });
    }

    private List<T> Snapshot<T>(List<T> list)
    {
        lock (_gate) return list.ToList();
    }

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------

    /// <summary>
    /// Open the stream. Completes once it is open. When the first attempt fails it throws instead of retrying in the
    /// background (after the one token refresh for a 401): <see cref="OFAuthApiException"/> with the status (401, 409,
    /// 503 with <c>RetryAfter</c>, ...), or <see cref="OFAuthConnectionException"/> for network errors and timeouts.
    /// Calling it while connected (or connecting) does not open a second stream.
    /// </summary>
    /// <param name="cancellationToken">Cancels connecting: the connection stops, as with <see cref="CloseAsync"/>. Ignored once open.</param>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        Task pending;
        lock (_gate)
        {
            if (!_active)
            {
                var generation = ++_generation;
                _active = true;
                _hasConnected = false;
                _lifetime = new CancellationTokenSource();
                _pending = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var token = _lifetime.Token;
                _loop = Task.Run(() => RunAsync(generation, token));
            }
            pending = _pending?.Task ?? Task.CompletedTask;
        }
        if (!cancellationToken.CanBeCanceled || pending.IsCompleted)
        {
            await pending.ConfigureAwait(false);
            return;
        }
        using (cancellationToken.Register(() =>
        {
            if (!pending.IsCompleted) Stop(null, cancellationToken);
        }))
        {
            await pending.ConfigureAwait(false);
        }
    }

    /// <summary>Close the stream and stop reconnecting. Waits for the read loop to finish (unless called from a handler).</summary>
    public async Task CloseAsync(CancellationToken cancellationToken = default)
    {
        var loop = Stop(new OFAuthException("Realtime connection closed before it opened"), null);
        if (loop is null || CurrentLoop.Value == this) return;
        try
        {
            await loop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // The loop reports its own errors.
        }
    }

    /// <summary>Close the stream and release resources.</summary>
    public async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        lock (_gate) _lifetime?.Dispose();
    }

    /// <summary>Stop the current run. Returns its loop task, or null when nothing was running.</summary>
    private Task? Stop(Exception? pendingError, CancellationToken? cancelled)
    {
        TaskCompletionSource? pending;
        CancellationTokenSource? lifetime;
        Task? loop;
        lock (_gate)
        {
            if (!_active) return _loop;
            _active = false;
            _generation++;
            pending = _pending;
            _pending = null;
            lifetime = _lifetime;
            loop = _loop;
        }
        try
        {
            lifetime?.Cancel();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or AggregateException)
        {
        }
        if (pending is not null)
        {
            if (cancelled is { } token) pending.TrySetCanceled(token);
            else pending.TrySetException(pendingError ?? new OFAuthException("Realtime connection closed"));
        }
        EmitClose(new RealtimeCloseInfo(RealtimeCloseReason.ClientClosed, null, false, null));
        return loop;
    }

    private bool IsCurrent(long generation)
    {
        lock (_gate) return generation == _generation;
    }

    // ------------------------------------------------------------------------
    // Run loop
    // ------------------------------------------------------------------------

    private readonly record struct Outcome(
        RealtimeCloseReason Reason,
        int? Status = null,
        Exception? Error = null,
        TimeSpan? RetryAfter = null,
        bool Healthy = false);

    private async Task RunAsync(long generation, CancellationToken lifetime)
    {
        CurrentLoop.Value = this;
        _attempt = 0;
        _failures = 0;
        var refresh = false;
        // One token refresh (and retry) per reauth / 401, until a stream is healthy again.
        var refreshUsed = false;
        try
        {
            while (true)
            {
                var outcome = await StreamAsync(generation, refresh, lifetime).ConfigureAwait(false);
                refresh = false;
                if (!IsCurrent(generation)) return;
                if (outcome.Healthy)
                {
                    _failures = 0;
                    refreshUsed = false;
                }

                var willReconnect = false;
                var delay = TimeSpan.Zero;
                switch (outcome.Reason)
                {
                    case RealtimeCloseReason.Reauth:
                        // A fixed token cannot be refreshed, so a 401 for it is final.
                        var canRetry = !(outcome.Status == 401 && _tokenProvider is StaticAccessTokenProvider);
                        if (!refreshUsed && canRetry)
                        {
                            refreshUsed = true;
                            refresh = true;
                            willReconnect = true;
                            _failures++;
                        }
                        break;
                    case RealtimeCloseReason.Unavailable:
                    case RealtimeCloseReason.Dropped:
                    case RealtimeCloseReason.HeartbeatTimeout:
                        willReconnect = _options.Reconnect;
                        if (willReconnect) delay = Backoff(outcome.RetryAfter);
                        break;
                }

                TaskCompletionSource? failed = null;
                lock (_gate)
                {
                    if (generation != _generation) return;
                    // A first connect that never opened throws instead of retrying in the background,
                    // except for the one token refresh.
                    if (!_hasConnected && !refresh) willReconnect = false;
                    if (!willReconnect)
                    {
                        _active = false;
                        failed = _pending;
                        _pending = null;
                    }
                }
                failed?.TrySetException(outcome.Error ?? new OFAuthException($"Realtime stream closed ({outcome.Reason})"));
                EmitClose(new RealtimeCloseInfo(
                    outcome.Reason,
                    outcome.Status,
                    willReconnect,
                    willReconnect ? delay : null));
                if (!willReconnect) return;
                if (delay > TimeSpan.Zero)
                {
                    try
                    {
                        await Task.Delay(delay, _time, lifetime).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                }
                if (!IsCurrent(generation)) return;
            }
        }
        catch (Exception ex)
        {
            // Never leave the loop silently: report, and fail a pending ConnectAsync.
            RaiseError(ex);
            TaskCompletionSource? pending = null;
            lock (_gate)
            {
                if (generation == _generation)
                {
                    _active = false;
                    pending = _pending;
                    _pending = null;
                }
            }
            pending?.TrySetException(ex);
        }
    }

    /// <summary>Exponential backoff from the server's <c>retry:</c> time, with jitter, at least <c>Retry-After</c>.</summary>
    private TimeSpan Backoff(TimeSpan? retryAfter)
    {
        var max = _options.MaxReconnectDelay.TotalMilliseconds;
        var baseDelay = Math.Min(max, _retryMs * Math.Pow(2, Math.Min(_failures, 30)));
        _failures++;
        var delay = Math.Min(max, baseDelay * (1 + Random.Shared.NextDouble() / 2));
        return TimeSpan.FromMilliseconds(Math.Max(delay, retryAfter?.TotalMilliseconds ?? 0));
    }

    /// <summary>One attempt: request the stream, then read it until it ends.</summary>
    private async Task<Outcome> StreamAsync(long generation, bool refresh, CancellationToken lifetime)
    {
        var attempt = ++_attempt;
        string token;
        try
        {
            token = await _tokenProvider.GetAccessTokenAsync(refresh, lifetime).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            return new Outcome(RealtimeCloseReason.ClientClosed);
        }
        catch (Exception ex)
        {
            if (IsCurrent(generation)) RaiseError(ex);
            return new Outcome(RealtimeCloseReason.Dropped, Error: ex);
        }
        if (!IsCurrent(generation)) return new Outcome(RealtimeCloseReason.ClientClosed);

        var url = new Uri(_url + "?linkedAccountId=" + Uri.EscapeDataString(_options.LinkedAccountId!));
        var safeUrl = ApiTransport.SanitizeUrl(url);
        using var message = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (var header in _headers) message.Headers.TryAddWithoutValidation(header.Key, header.Value);
        foreach (var name in new[] { "Accept", "Cache-Control", "Last-Event-ID" }) message.Headers.Remove(name);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        message.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (_lastId is { } lastId) message.Headers.TryAddWithoutValidation("Last-Event-ID", lastId);
        if (_options.OnRequest is { } onRequest)
        {
            IgnoreErrors(() => onRequest(new OFAuthRequestInfo("GET", safeUrl, ApiTransport.RedactedHeaders(message), attempt, null)));
        }

        var heartbeat = _options.HeartbeatTimeout;
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        var timedOut = 0;
        using var timer = heartbeat > TimeSpan.Zero
            ? _time.CreateTimer(
                _ =>
                {
                    Volatile.Write(ref timedOut, 1);
                    try
                    {
                        attemptCts.Cancel();
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                },
                null,
                heartbeat,
                Timeout.InfiniteTimeSpan)
            : null;
        void Arm() => timer?.Change(heartbeat, Timeout.InfiniteTimeSpan);
        void Disarm() => timer?.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

        var started = Stopwatch.GetTimestamp();
        HttpResponseMessage response;
        try
        {
            // ResponseHeadersRead: HttpClient.Timeout only covers the wait for the headers, never the open stream.
            response = await _http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, attemptCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (!IsCurrent(generation) || lifetime.IsCancellationRequested) return new Outcome(RealtimeCloseReason.ClientClosed);
            var timed = Volatile.Read(ref timedOut) == 1;
            var network = timed
                || ApiTransport.IsTransportFailure(ex, lifetime, attemptCts.Token)
                || ex is TaskCanceledException { InnerException: TimeoutException };
            Exception error = timed
                ? new OFAuthConnectionException($"GET {EventsPath} got no response in {heartbeat.TotalMilliseconds:0}ms", true, attempt, "realtime", ex)
                : network
                    ? new OFAuthConnectionException($"GET {EventsPath} failed: {ex.Message}", ex is TaskCanceledException, attempt, "realtime", ex)
                    : ex;
            _log?.Invoke($"[ofauth] SSE {EventsPath} -> {(timed ? "timeout" : network ? "network error" : "failed")} ({elapsed.TotalMilliseconds:0}ms)");
            RaiseError(error);
            // An exception from a custom handler (not a network failure) is final.
            return new Outcome(
                timed ? RealtimeCloseReason.HeartbeatTimeout : network ? RealtimeCloseReason.Dropped : RealtimeCloseReason.Rejected,
                Error: error);
        }

        using (response)
        {
            var duration = Stopwatch.GetElapsedTime(started);
            var status = (int)response.StatusCode;
            var requestId = ApiTransport.HeaderValue(response.Headers, "x-realtime-session-id")
                ?? ApiTransport.HeaderValue(response.Headers, "x-request-id");
            if (_options.OnResponse is { } onResponse)
            {
                IgnoreErrors(() => onResponse(new OFAuthResponseInfo("GET", safeUrl, status, requestId, duration, attempt, null)));
            }
            _log?.Invoke($"[ofauth] SSE {EventsPath} -> {status} ({duration.TotalMilliseconds:0}ms{(requestId is null ? "" : ", " + requestId)})");

            var contentType = response.Content.Headers.ContentType?.MediaType;
            if (status != 200 || !string.Equals(contentType, "text/event-stream", StringComparison.OrdinalIgnoreCase))
            {
                string? body;
                try
                {
                    body = await response.Content.ReadAsStringAsync(attemptCts.Token).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    body = null;
                }
                if (!IsCurrent(generation) || lifetime.IsCancellationRequested) return new Outcome(RealtimeCloseReason.ClientClosed);
                var error = new OFAuthApiException(status, body, response.Headers) { Operation = "realtime" };
                RaiseError(error);
                var reason = status switch
                {
                    401 => RealtimeCloseReason.Reauth,
                    409 => RealtimeCloseReason.Replaced,
                    429 or >= 500 => RealtimeCloseReason.Unavailable,
                    _ => RealtimeCloseReason.Rejected,
                };
                return new Outcome(reason, status, error, error.RetryAfter);
            }

            // Open.
            TaskCompletionSource? pending;
            lock (_gate)
            {
                if (generation != _generation) return new Outcome(RealtimeCloseReason.ClientClosed);
                _hasConnected = true;
                pending = _pending;
                _pending = null;
            }
            _attempt = 0;
            _streaming = true;
            pending?.TrySetResult();
            foreach (var handler in Snapshot(_openHandlers)) Safe(handler);

            RealtimeCloseReason? closed = null;
            var healthy = false;
            Exception? failure = null;
            var parser = new SseParser(_lastId ?? "");
            try
            {
                var stream = await response.Content.ReadAsStreamAsync(attemptCts.Token).ConfigureAwait(false);
                var decoder = new UTF8Encoding(false).GetDecoder();
                var bytes = new byte[8192];
                var chars = new char[Encoding.UTF8.GetMaxCharCount(bytes.Length)];
                while (closed is null)
                {
                    var read = await stream.ReadAsync(bytes, attemptCts.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    // Handlers may take a while; only silence on the wire counts against the heartbeat.
                    Disarm();
                    var count = decoder.GetChars(bytes, 0, read, chars, 0, flush: false);
                    parser.Push(chars.AsSpan(0, count));
                    foreach (var item in parser.TakeItems())
                    {
                        // A handler may have closed the connection.
                        if (!IsCurrent(generation)) break;
                        switch (item.Kind)
                        {
                            case SseItemKind.Retry:
                                _retryMs = item.RetryMs;
                                break;
                            case SseItemKind.Comment:
                                healthy = true;
                                break;
                            case SseItemKind.Cursor when closed is null:
                                _lastId = string.IsNullOrEmpty(item.LastEventId) ? null : item.LastEventId;
                                break;
                            case SseItemKind.Message when closed is null:
                                if (item.Event == "closed")
                                {
                                    closed = ParseCloseReason(item.Data);
                                    break;
                                }
                                healthy = true;
                                if (item.Event == "resync")
                                {
                                    foreach (var handler in Snapshot(_resyncHandlers)) Safe(handler);
                                }
                                else
                                {
                                    await HandleEventAsync(item.Data, item.LastEventId, item.Event).ConfigureAwait(false);
                                }
                                break;
                        }
                    }
                    if (!IsCurrent(generation)) break;
                    Arm();
                }
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                _streaming = false;
                parser.End();
            }
            Disarm();
            if (!IsCurrent(generation) || lifetime.IsCancellationRequested) return new Outcome(RealtimeCloseReason.ClientClosed, Healthy: healthy);
            if (closed is { } closeReason) return new Outcome(closeReason, Healthy: healthy);
            if (Volatile.Read(ref timedOut) == 1)
            {
                var error = new OFAuthConnectionException(
                    $"Realtime stream silent for {heartbeat.TotalMilliseconds:0}ms", true, attempt, "realtime", failure);
                RaiseError(error);
                return new Outcome(RealtimeCloseReason.HeartbeatTimeout, Error: error, Healthy: healthy);
            }
            if (failure is not null) RaiseError(failure);
            return new Outcome(RealtimeCloseReason.Dropped, Error: failure, Healthy: healthy);
        }
    }

    /// <summary>The <c>reason</c> of an <c>event: closed</c> frame; anything unknown counts as <c>unavailable</c>.</summary>
    internal static RealtimeCloseReason ParseCloseReason(string data)
    {
        try
        {
            using var doc = JsonDocument.Parse(data);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("reason", out var reason)
                && reason.ValueKind == JsonValueKind.String)
            {
                switch (reason.GetString())
                {
                    case "reauth": return RealtimeCloseReason.Reauth;
                    case "replaced": return RealtimeCloseReason.Replaced;
                }
            }
        }
        catch (JsonException)
        {
        }
        return RealtimeCloseReason.Unavailable;
    }

    /// <summary>
    /// Dispatch one event's JSON to the handlers as if it came from the stream (repeated <c>eventId</c>s are dropped).
    /// For tests and for replaying stored events; does not move <see cref="LastEventId"/>.
    /// </summary>
    public Task DispatchAsync(string json) => HandleEventAsync(json, "", "message");

    private async Task HandleEventAsync(string json, string sseId, string sseEvent)
    {
        RealtimeEvent? evt;
        try
        {
            evt = JsonSerializer.Deserialize<RealtimeEvent>(json, ApiTransport.JsonOptions);
        }
        catch (JsonException ex)
        {
            if (sseId.Length > 0) _lastId = sseId;
            RaiseError(new OFAuthException("Invalid Realtime event", ex));
            return;
        }
        if (evt is null || string.IsNullOrEmpty(evt.Type))
        {
            if (sseId.Length > 0) _lastId = sseId;
            RaiseError(new OFAuthException($"Realtime event without a type (SSE event {sseEvent})"));
            return;
        }
        evt.Data = evt.Data.ValueKind == JsonValueKind.Undefined ? default : evt.Data.Clone();
        evt.RawJson = json;
        // A repeat (at-least-once delivery) does not move the resume point back.
        if (evt.EventId.Length > 0 && !Remember(evt.EventId)) return;
        if (sseId.Length > 0) _lastId = sseId;

        List<Func<RealtimeEvent, Task>> handlers;
        lock (_gate)
        {
            handlers = _eventHandlers.ToList();
            if (_typed.TryGetValue(evt.Type, out var typed)) handlers.AddRange(typed);
        }
        foreach (var handler in handlers)
        {
            try
            {
                await handler(evt).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                RaiseError(ex);
            }
        }
    }

    /// <summary>True the first time an id is seen (the last 1,000 ids are remembered; the server replays at most 1,000).</summary>
    private bool Remember(string eventId)
    {
        lock (_seen)
        {
            if (!_seen.Add(eventId)) return false;
            _seenOrder.Enqueue(eventId);
            if (_seenOrder.Count > DedupeWindow) _seen.Remove(_seenOrder.Dequeue());
            return true;
        }
    }

    private void EmitClose(RealtimeCloseInfo info)
    {
        foreach (var handler in Snapshot(_closeHandlers)) Safe(() => handler(info));
    }

    private void IgnoreErrors(Action hook)
    {
        try
        {
            hook();
        }
        catch (Exception ex)
        {
            // Hooks must not break the connection.
            _log?.Invoke($"[ofauth] Realtime hook threw {ex.GetType().Name}; ignored");
        }
    }

    private void RaiseError(Exception error)
    {
        foreach (var handler in Snapshot(_errorHandlers))
        {
            try
            {
                handler(error);
            }
            catch
            {
                // Error handlers must not break the read loop.
            }
        }
    }

    private void Safe(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            RaiseError(ex);
        }
    }

    private sealed class Subscription : IDisposable
    {
        private Action? _dispose;

        public Subscription(Action dispose) => _dispose = dispose;

        public void Dispose() => Interlocked.Exchange(ref _dispose, null)?.Invoke();
    }
}

internal enum SseItemKind
{
    Message,
    Retry,
    Comment,
    Cursor,
}

/// <summary>One parsed item: a dispatched event, a valid <c>retry</c> field, or a comment.</summary>
internal readonly record struct SseItem(SseItemKind Kind, string Event, string Data, string LastEventId, int RetryMs);

/// <summary>
/// An incremental Server-Sent Events parser, per the HTML "event stream" interpretation rules. Feed decoded text with
/// <see cref="Push"/> in chunks of any size: lines may be split anywhere, including between <c>\r</c> and <c>\n</c>.
/// Lines end with <c>\n</c>, <c>\r\n</c>, or <c>\r</c>; a leading BOM is dropped.
/// </summary>
internal sealed class SseParser
{
    private readonly StringBuilder _line = new();
    private readonly StringBuilder _data = new();
    private readonly List<SseItem> _items = new();
    private bool _started;
    private bool _skipLf;
    private bool _hasData;
    private bool _hasId;
    private string _eventType = "";
    private string _idBuffer;

    public SseParser(string lastEventId = "")
    {
        LastEventId = lastEventId;
        _idBuffer = lastEventId;
    }

    /// <summary>The last event id, sent back as <c>Last-Event-ID</c> on reconnects (the <c>id</c> field persists across events).</summary>
    public string LastEventId { get; private set; }

    public void Push(ReadOnlySpan<char> text)
    {
        foreach (var c in text)
        {
            if (_skipLf)
            {
                _skipLf = false;
                if (c == '\n') continue;
            }
            if (!_started)
            {
                _started = true;
                if (c == '﻿') continue;
            }
            if (c == '\n' || c == '\r')
            {
                Line(_line.ToString());
                _line.Clear();
                _skipLf = c == '\r';
                continue;
            }
            _line.Append(c);
        }
    }

    /// <summary>The items parsed since the last call.</summary>
    public List<SseItem> TakeItems()
    {
        var items = _items.ToList();
        _items.Clear();
        return items;
    }

    /// <summary>The stream ended: an event without its closing blank line is discarded, as the spec requires.</summary>
    public void End()
    {
        _line.Clear();
        _data.Clear();
        _hasData = false;
        _hasId = false;
        _idBuffer = LastEventId;
        _eventType = "";
        _skipLf = false;
    }

    private void Line(string line)
    {
        if (line.Length == 0)
        {
            Dispatch();
            return;
        }
        if (line[0] == ':')
        {
            var comment = line[1..];
            _items.Add(new SseItem(SseItemKind.Comment, "", comment.StartsWith(' ') ? comment[1..] : comment, LastEventId, 0));
            return;
        }
        var colon = line.IndexOf(':');
        var field = colon < 0 ? line : line[..colon];
        var value = colon < 0 ? "" : line[(colon + 1)..];
        if (value.StartsWith(' ')) value = value[1..];
        switch (field)
        {
            case "event":
                _eventType = value;
                break;
            case "data":
                if (_hasData) _data.Append('\n');
                _data.Append(value);
                _hasData = true;
                break;
            case "id":
                if (!value.Contains('\0')) { _idBuffer = value; _hasId = true; }
                break;
            case "retry":
                if (value.Length > 0 && value.All(char.IsAsciiDigit) && int.TryParse(value, out var ms))
                {
                    _items.Add(new SseItem(SseItemKind.Retry, "", "", LastEventId, ms));
                }
                break;
        }
    }

    private void Dispatch()
    {
        LastEventId = _idBuffer;
        var hasData = _hasData;
        var hasId = _hasId;
        _hasId = false;
        var item = new SseItem(SseItemKind.Message, _eventType.Length > 0 ? _eventType : "message", _data.ToString(), LastEventId, 0);
        _eventType = "";
        _data.Clear();
        _hasData = false;
        if (hasData) _items.Add(item);
        else if (hasId) _items.Add(new SseItem(SseItemKind.Cursor, "", "", LastEventId, 0));
    }
}
