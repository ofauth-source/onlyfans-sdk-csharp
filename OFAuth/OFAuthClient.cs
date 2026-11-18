// OFAuth V3 client root. The namespaces (Access, VaultPlus, LinkedAccounts) are generated in Client.g.cs.
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

namespace OFAuth;

/// <summary>
/// OFAuth V3 API client for one authorization.
/// </summary>
/// <example>
/// <code>
/// var client = new OFAuthClient(new OFAuthClientOptions { AccessToken = token, LinkedAccountId = "conn_123" });
/// var profile = await client.Access.Profile.GetAsync();
/// await foreach (var chat in client.Access.Chats.IterateAsync()) Console.WriteLine(chat.User?.Id);
/// </code>
/// </example>
public sealed partial class OFAuthClient
{
    private readonly ApiTransport _transport;

    /// <summary>Create a client from options.</summary>
    public OFAuthClient(OFAuthClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _transport = new ApiTransport(options, options.ResolveTokenProvider());
    }

    /// <summary>Create a client with a fixed access token.</summary>
    public OFAuthClient(string accessToken, string? linkedAccountId = null, HttpClient? httpClient = null)
        : this(new OFAuthClientOptions { AccessToken = accessToken, LinkedAccountId = linkedAccountId, HttpClient = httpClient })
    {
    }

    /// <summary>Create a client with an access token provider from the caller's auth system.</summary>
    public OFAuthClient(IAccessTokenProvider accessTokenProvider, string? linkedAccountId = null, HttpClient? httpClient = null)
        : this(new OFAuthClientOptions
        {
            AccessTokenProvider = accessTokenProvider,
            LinkedAccountId = linkedAccountId,
            HttpClient = httpClient,
        })
    {
    }

    private OFAuthClient(ApiTransport transport)
    {
        _transport = transport;
    }

    /// <summary>The default linked account for Access and Vault+ calls.</summary>
    public string? LinkedAccountId => _transport.LinkedAccountId;

    /// <summary>Low-level transport, for calling routes the generated client does not cover.</summary>
    public ApiTransport Transport => _transport;

    /// <summary>A client for another linked account of the same authorization. Shares the token source and HTTP client.</summary>
    public OFAuthClient WithLinkedAccount(string linkedAccountId)
    {
        if (string.IsNullOrEmpty(linkedAccountId)) throw new ArgumentException("linkedAccountId is empty", nameof(linkedAccountId));
        return new OFAuthClient(_transport.WithLinkedAccount(linkedAccountId));
    }

    /// <summary>
    /// Upload a file (start, PUT parts, finalize). Returns the upload id to use in <c>mediaItems</c>,
    /// or the existing media when the file is already in the vault. Scope: <c>vault:write</c>.
    /// </summary>
    public Task<UploadMediaResult> UploadMediaAsync(
        byte[] data,
        UploadMediaOptions options,
        CancellationToken cancellationToken = default) =>
        Uploads.UploadMediaAsync(_transport, data, options, cancellationToken);

    /// <summary>Upload a stream. The stream is read into memory first (needed for the MD5 etag and part ranges).</summary>
    public async Task<UploadMediaResult> UploadMediaAsync(
        Stream data,
        UploadMediaOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var buffer = new MemoryStream();
        await data.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        return await UploadMediaAsync(buffer.ToArray(), options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A Realtime event stream (Server-Sent Events) for one linked account, using this client's access token source,
    /// <c>HttpClient</c>, <c>DefaultHeaders</c>, clock, request/response hooks, and debug logging (unless
    /// <paramref name="options"/> sets its own hooks or logger). Call <see cref="RealtimeConnection.ConnectAsync"/> on the result.
    /// This is the only way to create a <see cref="RealtimeConnection"/>. It always streams <c>/v3/realtime/events</c> on
    /// the client's <c>BaseUrl</c> origin: Realtime is served on the same origin as every other API route, so the token
    /// only goes where API requests go.
    /// </summary>
    /// <exception cref="OFAuthException">No linked account, or <c>BaseUrl</c> is not an http(s) URL.</exception>
    public RealtimeConnection Realtime(RealtimeOptions? options = null)
    {
        options ??= new RealtimeOptions();
        var linkedAccountId = options.LinkedAccountId ?? _transport.LinkedAccountId;
        if (string.IsNullOrEmpty(linkedAccountId))
        {
            throw new OFAuthException("Realtime() needs a LinkedAccountId: pass one in the options or set it on the client.");
        }
        var url = ApiTransport.RealtimeUrlFor(_transport.BaseUrl);
        return new RealtimeConnection(
            options with
            {
                LinkedAccountId = linkedAccountId,
                OnRequest = options.OnRequest ?? _transport.OnRequest,
                OnResponse = options.OnResponse ?? _transport.OnResponse,
                DebugLogger = options.DebugLogger ?? _transport.Log,
            },
            _transport,
            url);
    }

    /// <summary>
    /// Mint a Realtime stream URL for a browser (<c>POST /v3/realtime</c>). Send only <see cref="RealtimeStreamUrl.Url"/>
    /// to the page, which opens it with <c>EventSource</c> (or <c>connectRealtimeStream</c> from the TypeScript SDK's
    /// <c>@ofauth/onlyfans-sdk/realtime-browser</c>). The URL carries a 10-minute stream credential that can only read
    /// this account's Realtime events; the access token never leaves your server. Rate limited to 30 per minute per
    /// authorization. Goes through the client's retries, hooks, and errors (<see cref="OFAuthApiException"/>).
    /// </summary>
    /// <param name="linkedAccountId">The linked account to stream. Defaults to the client's.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="OFAuthException">No linked account.</exception>
    public Task<RealtimeStreamUrl> CreateStreamUrlAsync(string? linkedAccountId = null, CancellationToken cancellationToken = default)
    {
        var account = linkedAccountId ?? _transport.LinkedAccountId;
        if (string.IsNullOrEmpty(account))
        {
            throw new OFAuthException("CreateStreamUrlAsync() needs a LinkedAccountId: pass one or set it on the client.");
        }
        return _transport.SendAsync<RealtimeStreamUrl>(
            new ApiRequest(HttpMethod.Post, "/v3/realtime")
            {
                Body = new Dictionary<string, string> { ["linkedAccountId"] = account },
                Operation = "realtime.createStreamUrl",
            },
            cancellationToken);
    }
}
