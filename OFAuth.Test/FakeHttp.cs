using System.Net;
using System.Text;
using System.Text.Json;

namespace OFAuth.Test;

/// <summary>A recorded request.</summary>
public sealed record RecordedRequest(HttpMethod Method, string Url, Dictionary<string, string> Headers, string? Body, string? ContentType)
{
    public string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;
}

/// <summary>An HttpMessageHandler that answers from a queue of responders and records every request.</summary>
public sealed class FakeHandler : HttpMessageHandler
{
    private readonly Queue<Func<RecordedRequest, HttpResponseMessage>> _responders = new();
    private Func<RecordedRequest, HttpResponseMessage>? _last;

    public List<RecordedRequest> Requests { get; } = new();

    public FakeHandler(params Func<RecordedRequest, HttpResponseMessage>[] responders)
    {
        foreach (var responder in responders) _responders.Enqueue(responder);
    }

    public HttpClient Client() => new(this);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers) headers[header.Key] = string.Join(",", header.Value);
        string? body = null;
        string? contentType = null;
        if (request.Content is not null)
        {
            body = await request.Content.ReadAsStringAsync(cancellationToken);
            contentType = request.Content.Headers.ContentType?.ToString();
        }
        var recorded = new RecordedRequest(request.Method, request.RequestUri!.ToString(), headers, body, contentType);
        lock (Requests) Requests.Add(recorded);

        Func<RecordedRequest, HttpResponseMessage> responder;
        lock (_responders)
        {
            if (_responders.Count > 0) _last = _responders.Dequeue();
            responder = _last ?? throw new InvalidOperationException("No response configured");
        }
        return responder(recorded);
    }

    public static Func<RecordedRequest, HttpResponseMessage> Json(object body, int status = 200, Dictionary<string, string>? headers = null) =>
        _ => JsonResponse(body, status, headers);

    public static HttpResponseMessage JsonResponse(object body, int status = 200, Dictionary<string, string>? headers = null)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
        foreach (var header in headers ?? new()) response.Headers.TryAddWithoutValidation(header.Key, header.Value);
        return response;
    }

    public static Func<RecordedRequest, HttpResponseMessage> Status(int status) =>
        _ => new HttpResponseMessage((HttpStatusCode)status);
}
