using System.Net;
using System.Text;
using System.Threading.Channels;

namespace OFAuth.Test;

/// <summary>A response body the test writes to chunk by chunk, like an open event stream.</summary>
public sealed class SseBody : Stream
{
    private readonly Channel<byte[]> _chunks = Channel.CreateUnbounded<byte[]>();
    private byte[] _current = Array.Empty<byte>();
    private int _offset;

    public SseBody Write(string text) => WriteBytes(Encoding.UTF8.GetBytes(text));

    public SseBody WriteBytes(byte[] bytes)
    {
        _chunks.Writer.TryWrite(bytes);
        return this;
    }

    /// <summary>End the stream (the server closed it).</summary>
    public void End() => _chunks.Writer.TryComplete();

    /// <summary>Fail the next read (the connection broke).</summary>
    public void Fail() => _chunks.Writer.TryComplete(new IOException("connection reset"));

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (_offset >= _current.Length)
        {
            if (!await _chunks.Reader.WaitToReadAsync(cancellationToken)) return 0;
            if (_chunks.Reader.TryRead(out var next))
            {
                _current = next;
                _offset = 0;
            }
        }
        var count = Math.Min(buffer.Length, _current.Length - _offset);
        _current.AsMemory(_offset, count).CopyTo(buffer);
        _offset += count;
        return count;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>An HttpMessageHandler that answers each request with the next script; 503 once they run out.</summary>
public sealed class FakeSseHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>> _scripts = new();

    public FakeSseHandler(params Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>[] scripts)
    {
        foreach (var script in scripts) _scripts.Enqueue(script);
    }

    public List<RecordedRequest> Requests { get; } = new();

    public int Count
    {
        get
        {
            lock (Requests) return Requests.Count;
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers) headers[header.Key] = string.Join(",", header.Value);
        string? body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        lock (Requests) Requests.Add(new RecordedRequest(request.Method, request.RequestUri!.ToString(), headers, body, request.Content?.Headers.ContentType?.ToString()));
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? script;
        lock (_scripts) script = _scripts.Count > 0 ? _scripts.Dequeue() : null;
        if (script is null) return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        return await script(request, cancellationToken);
    }

    public OFAuthClient Client(IAccessTokenProvider? provider = null, TimeProvider? time = null, Dictionary<string, string>? headers = null) =>
        new(new OFAuthClientOptions
        {
            AccessToken = provider is null ? "tok" : null,
            AccessTokenProvider = provider,
            LinkedAccountId = "conn_1",
            BaseUrl = "https://api.test",
            HttpClient = new HttpClient(this),
            TimeProvider = time,
            DefaultHeaders = headers ?? new Dictionary<string, string>(),
        });

    /// <summary>Open an event stream the test keeps writing to.</summary>
    public static Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Open(SseBody body, string? sessionId = null) => (_, _) =>
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) };
        response.Content.Headers.ContentType = new("text/event-stream");
        if (sessionId is not null) response.Headers.TryAddWithoutValidation("x-realtime-session-id", sessionId);
        return Task.FromResult(response);
    };

    /// <summary>An event stream that sends <paramref name="text"/> and ends.</summary>
    public static Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Sends(string text)
    {
        var body = new SseBody().Write(text);
        body.End();
        return Open(body);
    }

    /// <summary>A refusal with a JSON error body.</summary>
    public static Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Refuse(int status, string? error = null, int? retryAfterSeconds = null) => (_, _) =>
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent($$"""{"error":"{{error ?? "refused"}}","message":"no"}""", Encoding.UTF8, "application/json"),
        };
        if (retryAfterSeconds is { } seconds) response.Headers.TryAddWithoutValidation("Retry-After", seconds.ToString());
        return Task.FromResult(response);
    };

    /// <summary>Never answers (until cancelled).</summary>
    public static Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Hang() => async (_, ct) =>
    {
        await Task.Delay(Timeout.Infinite, ct);
        throw new InvalidOperationException("unreachable");
    };

    /// <summary>A network failure.</summary>
    public static Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> NetworkError() =>
        (_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("connection refused"));
}
