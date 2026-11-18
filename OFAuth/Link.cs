// OFAuth Link: the OAuth 2.0 Authorization Code flow with PKCE.
// Run this on your backend: it holds the client secret and PKCE verifier.
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OFAuth;

/// <summary><c>sandbox</c>, <c>test</c>, or <c>live</c>. Each environment has its own client.</summary>
public enum OFAuthEnvironment
{
    /// <summary>Sandbox: simulated accounts.</summary>
    Sandbox,

    /// <summary>Test: real accounts, limited to the integration's testers.</summary>
    Test,

    /// <summary>Live: production.</summary>
    Live,
}

/// <summary>Configuration for <see cref="OFAuthLink"/>.</summary>
public sealed class OFAuthLinkOptions
{
    /// <summary>Client ID for one environment, e.g. <c>ofext_live_...</c>.</summary>
    public required string ClientId { get; set; }

    /// <summary>Client secret. Required for token exchange, refresh, and revoke.</summary>
    public required string ClientSecret { get; set; }

    /// <summary>client_secret_basic (default) or client_secret_post.</summary>
    public string ClientAuthentication { get; set; } = "client_secret_basic";

    /// <summary>Default redirect URI. Must exactly match a URI registered for the client.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>Auth origin for the browser authorize route. Defaults to <c>https://link.ofauth.com</c>.</summary>
    public string AuthUrl { get; set; } = OFAuthDefaults.AuthUrl;

    /// <summary>API origin for token and revoke. Defaults to <c>https://api.ofauth.com</c>.</summary>
    public string ApiUrl { get; set; } = OFAuthDefaults.ApiUrl;

    /// <summary>HTTP client to use. A shared client is used when omitted.</summary>
    public HttpClient? HttpClient { get; set; }
}

/// <summary>Options for <see cref="OFAuthLink.CreateAuthorizationUrl"/>.</summary>
public sealed class CreateAuthorizationUrlOptions
{
    /// <summary>Scopes to request (see <see cref="OFAuth.Scopes"/>). Every code exchange returns a refresh token.</summary>
    public IEnumerable<string>? Scopes { get; init; }

    /// <summary>
    /// Canonical operation names (e.g. <c>access.chats.messages.send</c>, see <see cref="OFAuthOperations"/>) whose
    /// scopes are added to <see cref="Scopes"/>.
    /// </summary>
    public IEnumerable<string>? Operations { get; init; }

    /// <summary>Redirect URI. Defaults to the configured one.</summary>
    public string? RedirectUri { get; init; }

    /// <summary>One-use state value. Generated when omitted.</summary>
    public string? State { get; init; }

    /// <summary>PKCE verifier. Generated when omitted.</summary>
    public string? CodeVerifier { get; init; }


}

/// <summary>An authorization request: send the user to <see cref="Url"/>, store the rest on your backend.</summary>
public sealed record AuthorizationRequest(string Url, string State, string CodeVerifier, string CodeChallenge);

/// <summary>The code and state from a successful callback.</summary>
public sealed record AuthorizationCallback(string Code, string State);

/// <summary>A PKCE verifier and its S256 challenge.</summary>
public sealed record Pkce(string CodeVerifier, string CodeChallenge);

/// <summary>Thrown by <see cref="OFAuthLink.ParseCallback(string, string?)"/> when the user denied access or the request was invalid.</summary>
public sealed class OFAuthAuthorizationException : OFAuthException
{
    /// <summary><c>access_denied</c>, <c>invalid_request</c>, or <c>invalid_state</c>.</summary>
    public string Code { get; }

    /// <summary>The <c>state</c> from the callback, if any.</summary>
    public string? State { get; }

    /// <summary>The <c>error_description</c> from the callback, if any.</summary>
    public string? Description { get; }

    /// <summary>Create an authorization error.</summary>
    /// <param name="code">Error code.</param>
    /// <param name="state">State from the callback.</param>
    /// <param name="description">Human-readable description.</param>
    public OFAuthAuthorizationException(string code, string? state, string? description)
        : base(description is null ? code : $"{code}: {description}")
    {
        Code = code;
        State = state;
        Description = description;
    }
}

/// <summary>An RFC 6749 error from the token or revoke endpoint.</summary>
public sealed class OFAuthOAuthException : OFAuthException
{
    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>e.g. <c>invalid_grant</c>: the refresh token is revoked or expired; authorize again.</summary>
    public string Code { get; }

    /// <summary>The <c>error_description</c> field.</summary>
    public string? Description { get; }

    /// <summary><c>client_deleted</c>, <c>developer_plan_unavailable</c>, or <c>security_suspended</c>.</summary>
    public string? Reason { get; }

    /// <summary>What to do next (<c>recovery.action</c>), when the server sends one.</summary>
    public string? RecoveryAction { get; }

    /// <summary><see cref="RecoveryAction"/> as an enum: null when absent, <see cref="OFAuth.RecoveryActionKind.Unknown"/> when unrecognized.</summary>
    public RecoveryActionKind? RecoveryActionKind { get; }

    /// <summary>How long to wait before retrying, from <c>Retry-After</c>.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Raw response body.</summary>
    public string? ResponseBody { get; }

    /// <summary>
    /// True for <c>invalid_grant</c> (the refresh token is revoked or expired) and for re-authorization
    /// recovery actions: send the user through authorization again.
    /// </summary>
    public override bool NeedsReauthorization =>
        Code == "invalid_grant" || RecoveryActions.IsReauthorization(RecoveryActionKind);

    /// <summary>Parse an RFC 6749 error response.</summary>
    /// <param name="statusCode">HTTP status code.</param>
    /// <param name="responseBody">Raw response body.</param>
    /// <param name="headers">Response headers.</param>
    public OFAuthOAuthException(int statusCode, string? responseBody, HttpResponseHeaders? headers)
        : this(statusCode, responseBody, ApiTransport.TryParseObject(responseBody), headers)
    {
    }

    private OFAuthOAuthException(int statusCode, string? responseBody, JsonElement? body, HttpResponseHeaders? headers)
        : base(Describe(statusCode, body))
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
        Code = ApiTransport.GetString(body, "error") ?? $"http_{statusCode}";
        Description = ApiTransport.GetString(body, "error_description");
        Reason = ApiTransport.GetString(body, "reason");
        RecoveryAction = body is { } b && b.TryGetProperty("recovery", out var recovery)
            ? ApiTransport.GetString(recovery, "action")
            : null;
        RecoveryActionKind = RecoveryActions.Parse(RecoveryAction);
        RetryAfter = ApiTransport.ParseRetryAfter(headers);
    }

    private static string Describe(int statusCode, JsonElement? body)
    {
        var code = ApiTransport.GetString(body, "error") ?? $"http_{statusCode}";
        var description = ApiTransport.GetString(body, "error_description");
        return description is null ? code : $"{code}: {description}";
    }
}

/// <summary>
/// OAuth client for one environment.
/// </summary>
/// <example>
/// <code>
/// var link = new OFAuthLink(new OFAuthLinkOptions { ClientId = id, ClientSecret = secret, RedirectUri = redirect });
/// var request = link.CreateAuthorizationUrl(new CreateAuthorizationUrlOptions
/// {
///     Scopes = new[] { Scopes.ProfileRead, Scopes.OfflineAccess },
/// });
/// // store request.State + request.CodeVerifier, redirect to request.Url; on the callback:
/// var callback = link.ParseCallback(callbackUrl, request.State);
/// var tokens = await link.ExchangeCodeAsync(callback.Code, request.CodeVerifier);
/// </code>
/// </example>
public sealed class OFAuthLink
{
    private static readonly Lazy<HttpClient> SharedHttpClient = new(() => new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }));
    private static readonly Regex ClientIdPattern = new("^ofext_(sandbox|test|live)_", RegexOptions.Compiled);

    private readonly string _clientSecret;
    private readonly string _clientAuthentication;
    private readonly string? _redirectUri;
    private readonly string _authUrl;
    private readonly string _apiUrl;
    private readonly HttpClient _httpClient;

    /// <summary>Create an OAuth client.</summary>
    /// <param name="options">Client ID, secret, redirect URI, and hosts.</param>
    public OFAuthLink(OFAuthLinkOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.ClientId)) throw new ArgumentException("ClientId is required", nameof(options));
        ClientId = options.ClientId;
        _clientSecret = options.ClientSecret;
        _clientAuthentication = options.ClientAuthentication;
        if (_clientAuthentication is not ("client_secret_basic" or "client_secret_post")) throw new ArgumentException("Unsupported client authentication", nameof(options));
        _redirectUri = options.RedirectUri;
        _authUrl = options.AuthUrl.TrimEnd('/');
        _apiUrl = options.ApiUrl.TrimEnd('/');
        _httpClient = options.HttpClient ?? SharedHttpClient.Value;
        Environment = EnvironmentFromClientId(options.ClientId);
    }

    /// <summary>The OAuth client ID.</summary>
    public string ClientId { get; }

    /// <summary>The default redirect URI, if configured.</summary>
    public string? RedirectUri => _redirectUri;

    /// <summary>Derived from the client ID.</summary>
    public OFAuthEnvironment? Environment { get; }

    /// <summary>The environment a client ID belongs to (<c>ofext_live_...</c> is Live).</summary>
    /// <param name="clientId">A client ID.</param>
    public static OFAuthEnvironment? EnvironmentFromClientId(string clientId)
    {
        var match = ClientIdPattern.Match(clientId ?? "");
        if (!match.Success) return null;
        return match.Groups[1].Value switch
        {
            "sandbox" => OFAuthEnvironment.Sandbox,
            "test" => OFAuthEnvironment.Test,
            _ => OFAuthEnvironment.Live,
        };
    }

    /// <summary>The S256 code challenge for a PKCE verifier: base64url(SHA-256(verifier)), no padding.</summary>
    /// <param name="codeVerifier">The PKCE verifier.</param>
    public static string CreateCodeChallenge(string codeVerifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

    /// <summary>A new PKCE verifier (43 characters) and its S256 challenge.</summary>
    public static Pkce GeneratePkce()
    {
        var verifier = RandomToken();
        return new Pkce(verifier, CreateCodeChallenge(verifier));
    }

    /// <summary>
    /// Build the URL to send the user to, with a fresh state and PKCE pair unless provided. Requests
    /// <see cref="CreateAuthorizationUrlOptions.Scopes"/> plus the scopes of <see cref="CreateAuthorizationUrlOptions.Operations"/>.
    /// </summary>
    /// <param name="options">Scopes, redirect URI, and optional state / verifier.</param>
    public AuthorizationRequest CreateAuthorizationUrl(CreateAuthorizationUrlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var redirectUri = options.RedirectUri ?? _redirectUri
            ?? throw new OFAuthException("CreateAuthorizationUrl needs a RedirectUri");
        var state = options.State ?? RandomToken();
        var codeVerifier = options.CodeVerifier ?? RandomToken();
        var codeChallenge = CreateCodeChallenge(codeVerifier);
        var scopes = new List<string>();
        foreach (var scope in options.Scopes ?? Enumerable.Empty<string>())
        {
            foreach (var part in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!scopes.Contains(part)) scopes.Add(part);
            }
        }
        if (options.Operations is not null)
        {
            foreach (var scope in OFAuth.Scopes.For(options.Operations))
            {
                if (!scopes.Contains(scope)) scopes.Add(scope);
            }
        }
        if (scopes.Count == 0) throw new ArgumentException("CreateAuthorizationUrl needs Scopes or Operations", nameof(options));

        var query = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"),
            new("client_id", ClientId),
            new("redirect_uri", redirectUri),
            new("scope", string.Join(" ", scopes)),
            new("state", state),
            new("code_challenge", codeChallenge),
            new("code_challenge_method", "S256"),
        };

        var url = $"{_authUrl}/v3/authorize?" + string.Join("&",
            query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        return new AuthorizationRequest(url, state, codeVerifier, codeChallenge);
    }

    /// <summary>
    /// Read the callback URL or query string. Throws <see cref="OFAuthAuthorizationException"/> for <c>error=...</c>
    /// callbacks, a missing code, and (when <paramref name="expectedState"/> is given) a state mismatch.
    /// </summary>
    /// <param name="callback">The callback URL, or just its query string.</param>
    /// <param name="expectedState">The state you stored when creating the authorization URL.</param>
    public AuthorizationCallback ParseCallback(string callback, string expectedState)
    {
        ArgumentNullException.ThrowIfNull(callback);
        var values = CallbackValues(callback);

        values.TryGetValue("state", out var state);
        if (string.IsNullOrEmpty(expectedState) || !string.Equals(state, expectedState, StringComparison.Ordinal))
        {
            throw new OFAuthAuthorizationException("invalid_state", state, "state does not match the pending authorization");
        }
        if (!values.TryGetValue("iss", out var issuer) || issuer != _apiUrl + "/v3/link") throw new OFAuthAuthorizationException("invalid_issuer", state, "Unexpected authorization server");
        if (values.TryGetValue("error", out var error) && !string.IsNullOrEmpty(error))
        {
            values.TryGetValue("error_description", out var description);
            throw new OFAuthAuthorizationException(error, state, description);
        }
        if (!values.TryGetValue("code", out var code) || string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            throw new OFAuthAuthorizationException("invalid_request", state, "missing code or state");
        }
        return new AuthorizationCallback(code, state);
    }

    /// <summary>Read a callback <see cref="Uri"/>.</summary>
    /// <param name="callback">The callback URL.</param>
    /// <param name="expectedState">The state you stored when creating the authorization URL.</param>
    public AuthorizationCallback ParseCallback(Uri callback, string expectedState) =>
        ParseCallback(callback.IsAbsoluteUri ? callback.Query : callback.OriginalString, expectedState);

    /// <summary>The <c>state</c> parameter of a callback URL or query string, without validating anything.</summary>
    internal static string? ReadState(string callback) =>
        CallbackValues(callback).TryGetValue("state", out var state) && state.Length > 0 ? state : null;

    private static Dictionary<string, string> CallbackValues(string callback)
    {
        var queryStart = callback.IndexOf('?');
        var query = queryStart >= 0 ? callback[(queryStart + 1)..] : callback;
        var hash = query.IndexOf('#');
        if (hash >= 0) query = query[..hash];
        return ParseQuery(query);
    }

    /// <summary>Exchange an authorization code for tokens.</summary>
    /// <param name="code">The code from the callback.</param>
    /// <param name="codeVerifier">The PKCE verifier from <see cref="CreateAuthorizationUrl"/>.</param>
    /// <param name="redirectUri">The redirect URI used in the authorization request. Defaults to the configured one.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<LinkTokenResponse> ExchangeCodeAsync(
        string code,
        string codeVerifier,
        string? redirectUri = null,
        CancellationToken cancellationToken = default)
    {
        var uri = redirectUri ?? _redirectUri
            ?? throw new OFAuthException("ExchangeCodeAsync needs the redirectUri used in the authorization request");
        return TokenRequestAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = uri,
            ["code_verifier"] = codeVerifier,
        }, cancellationToken);
    }

    /// <summary>
    /// Refresh the access token, echoing the stable client-bound refresh token. <c>invalid_grant</c> means the user must authorize again.
    /// Never retried automatically.
    /// </summary>
    /// <param name="refreshToken">The current refresh token.</param>
    /// <param name="scope">Optional narrower scope.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public Task<LinkTokenResponse> RefreshAsync(
        string refreshToken,
        IEnumerable<string>? scope = null,
        CancellationToken cancellationToken = default)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken };
        var scopes = scope?.ToList();
        if (scopes is { Count: > 0 }) form["scope"] = string.Join(" ", scopes);
        return TokenRequestAsync(form, cancellationToken);
    }

    /// <summary>Revoke one access token, or a refresh credential and all its access tokens.</summary>
    /// <param name="token">The token to revoke.</param>
    /// <param name="tokenTypeHint"><c>refresh_token</c> or <c>access_token</c>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        if (!string.IsNullOrEmpty(tokenTypeHint)) form["token_type_hint"] = tokenTypeHint;
        await FormRequestAsync("/v3/link/revoke", form, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>RFC 8414 authorization server metadata.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task<LinkAuthorizationServerMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{_apiUrl}/.well-known/oauth-authorization-server/v3/link");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new OFAuthOAuthException((int)response.StatusCode, body, response.Headers);
        return JsonSerializer.Deserialize<LinkAuthorizationServerMetadata>(body, ApiTransport.JsonOptions)!;
    }

    private async Task<LinkTokenResponse> TokenRequestAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        var body = await FormRequestAsync("/v3/link/token", form, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<LinkTokenResponse>(body, ApiTransport.JsonOptions)
            ?? throw new OFAuthException("Empty token response");
    }

    private async Task<string> FormRequestAsync(string path, Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_clientSecret)) throw new OFAuthException($"{path} needs the client secret");
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(ClientId)}:{Uri.EscapeDataString(_clientSecret)}"));
        if (_clientAuthentication == "client_secret_post")
        {
            form["client_id"] = ClientId;
            form["client_secret"] = _clientSecret;
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, _apiUrl + path)
        {
            Content = new FormUrlEncodedContent(form),
        };
        if (_clientAuthentication == "client_secret_basic") request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = response.StatusCode == HttpStatusCode.NoContent
            ? ""
            : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new OFAuthOAuthException((int)response.StatusCode, body, response.Headers);
        return body;
    }

    private static string RandomToken() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var key = Decode(eq >= 0 ? pair[..eq] : pair);
            var value = eq >= 0 ? Decode(pair[(eq + 1)..]) : "";
            if (!result.TryAdd(key, value)) throw new OFAuthAuthorizationException("invalid_request", null, "Duplicate callback parameter");
        }
        return result;
    }

    private static string Decode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
}
