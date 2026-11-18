// OFAuth V3 runtime: configuration, authentication, requests, retries, hooks, errors, pagination.
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

using System.Buffers;
using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OFAuth;

/// <summary>Default hosts and header names.</summary>
public static class OFAuthDefaults
{
    /// <summary>API origin.</summary>
    public const string ApiUrl = "https://api.ofauth.com";

    /// <summary>Auth origin for the browser authorize route and OAuth metadata.</summary>
    public const string AuthUrl = "https://link.ofauth.com";

    /// <summary>Header that selects the linked account for Access and Vault+ operations.</summary>
    public const string LinkedAccountHeader = "x-linked-account-id";

    /// <summary>Default number of automatic retries per call.</summary>
    public const int MaxRetries = 2;

    /// <summary>Default timeout per attempt.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>Minimum timeout for each upload part PUT.</summary>
    public static readonly TimeSpan UploadPartTimeout = TimeSpan.FromSeconds(300);

    /// <summary>Longest server-requested delay (<c>Retry-After</c>, <c>RateLimit-Reset</c>) the SDK waits for before retrying.</summary>
    public static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(60);
}

// ============================================================================
// Access tokens
// ============================================================================

/// <summary>
/// Hands out bearer access tokens, from the caller's auth system.
/// </summary>
public interface IAccessTokenProvider
{
    /// <summary>
    /// Return an access token. <paramref name="forceRefresh"/> is true when the API rejected the previous
    /// token (<c>invalid_token</c>): refresh instead of returning a cached token.
    /// </summary>
    /// <param name="forceRefresh">Refresh instead of returning a cached token.</param>
    /// <param name="cancellationToken">Cancels waiting for the token.</param>
    Task<string> GetAccessTokenAsync(bool forceRefresh, CancellationToken cancellationToken);
}

/// <summary>A fixed access token. Requests rejected with <c>invalid_token</c> are not retried.</summary>
public sealed class StaticAccessTokenProvider : IAccessTokenProvider
{
    private readonly string _accessToken;

    /// <summary>Use <paramref name="accessToken"/> for every request.</summary>
    /// <param name="accessToken">A bearer access token.</param>
    public StaticAccessTokenProvider(string accessToken)
    {
        if (string.IsNullOrEmpty(accessToken)) throw new ArgumentException("Access token is empty", nameof(accessToken));
        _accessToken = accessToken;
    }

    /// <inheritdoc />
    public Task<string> GetAccessTokenAsync(bool forceRefresh, CancellationToken cancellationToken) =>
        Task.FromResult(_accessToken);
}

/// <summary>An access token from a callback, called before every request.</summary>
public sealed class DelegateAccessTokenProvider : IAccessTokenProvider
{
    private readonly Func<bool, CancellationToken, Task<string>> _getAccessToken;

    /// <summary>Get tokens from a callback.</summary>
    /// <param name="getAccessToken">Receives <c>forceRefresh</c> and a cancellation token.</param>
    public DelegateAccessTokenProvider(Func<bool, CancellationToken, Task<string>> getAccessToken)
    {
        _getAccessToken = getAccessToken ?? throw new ArgumentNullException(nameof(getAccessToken));
    }

    /// <inheritdoc />
    public Task<string> GetAccessTokenAsync(bool forceRefresh, CancellationToken cancellationToken) =>
        _getAccessToken(forceRefresh, cancellationToken);
}

// ============================================================================
// Options and hooks
// ============================================================================

/// <summary>Configuration for <see cref="OFAuthClient"/>.</summary>
public sealed class OFAuthClientOptions
{
    /// <summary>
    /// A bearer access token from <c>POST /v3/link/token</c>. You refresh it yourself.
    /// Set this or <see cref="AccessTokenProvider"/>.
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Where to get access tokens, from the caller's auth system. Requests rejected with
    /// <c>invalid_token</c> are retried once with <c>forceRefresh: true</c>.
    /// </summary>
    public IAccessTokenProvider? AccessTokenProvider { get; set; }

    /// <summary>
    /// Default linked account for Access and Vault+ operations, sent as <c>x-linked-account-id</c>.
    /// Each call can override it with its <c>LinkedAccountId</c> parameter.
    /// </summary>
    public string? LinkedAccountId { get; set; }

    /// <summary>API origin. Defaults to <c>https://api.ofauth.com</c>.</summary>
    public string BaseUrl { get; set; } = OFAuthDefaults.ApiUrl;

    /// <summary>
    /// HTTP client to send requests with (e.g. from <c>IHttpClientFactory</c>). A shared client is used when omitted.
    /// The SDK never disposes it. Its own <see cref="HttpClient.Timeout"/> still applies: set it to
    /// <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> to rely on <see cref="Timeout"/> alone.
    /// The shared client does not follow redirects; build yours on a handler with
    /// <c>AllowAutoRedirect = false</c> so authenticated requests are never re-sent to another host.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>
    /// Extra headers sent with every request. Names are case-insensitive; an <c>Accept</c> here replaces the default,
    /// and <c>x-linked-account-id</c> set by the SDK wins. <c>Authorization</c> is not allowed (the client constructor
    /// throws <see cref="ArgumentException"/>): the SDK sends the bearer token from <see cref="AccessToken"/> or
    /// <see cref="AccessTokenProvider"/>.
    /// </summary>
    public IDictionary<string, string> DefaultHeaders { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Automatic retries per call (default 2; 0 disables retries). Retried: 429; 503
    /// <c>authorization_temporarily_unavailable</c>; and, for GET, PUT, and DELETE only, network errors,
    /// timeouts, and other 502/503/504 responses.
    /// </summary>
    public int MaxRetries { get; set; } = OFAuthDefaults.MaxRetries;

    /// <summary>Timeout per attempt (default 60 seconds). Upload part PUTs use at least 300 seconds.</summary>
    public TimeSpan Timeout { get; set; } = OFAuthDefaults.Timeout;

    /// <summary>
    /// When the server asks to wait longer than this (<c>Retry-After</c> or <c>RateLimit-Reset</c>), the error is
    /// thrown instead of retried. Defaults to 60 seconds.
    /// </summary>
    public TimeSpan MaxRetryDelay { get; set; } = OFAuthDefaults.MaxRetryDelay;

    /// <summary>
    /// Called before every attempt, with a sanitized URL and redacted headers (see <see cref="OFAuthRequestInfo"/>).
    /// Exceptions thrown by the hook are ignored.
    /// </summary>
    public Action<OFAuthRequestInfo>? OnRequest { get; set; }

    /// <summary>Called after every attempt that received a response. Exceptions thrown by the hook are ignored.</summary>
    public Action<OFAuthResponseInfo>? OnResponse { get; set; }

    /// <summary>
    /// Log one line per attempt (and retry notices) to standard error. Also enabled by the environment variable
    /// <c>OFAUTH_DEBUG=1</c>. Tokens, secrets, and bodies are never logged.
    /// </summary>
    public bool Debug { get; set; }

    /// <summary>Where debug lines go. Setting it enables debug logging (e.g. <c>line =&gt; logger.LogDebug(line)</c>).</summary>
    public Action<string>? DebugLogger { get; set; }

    /// <summary>Clock used to wait between retries. Defaults to <see cref="TimeProvider.System"/>; replace it in tests.</summary>
    public TimeProvider? TimeProvider { get; set; }

    internal IAccessTokenProvider ResolveTokenProvider()
    {
        if (AccessTokenProvider is not null && AccessToken is not null)
        {
            throw new ArgumentException("Set AccessToken or AccessTokenProvider, not both.");
        }
        if (AccessTokenProvider is not null) return AccessTokenProvider;
        if (!string.IsNullOrEmpty(AccessToken)) return new StaticAccessTokenProvider(AccessToken);
        throw new ArgumentException("OFAuthClientOptions needs an AccessToken or an AccessTokenProvider.");
    }

    /// <summary>A shallow copy (headers are copied into a new dictionary).</summary>
    public OFAuthClientOptions Clone()
    {
        var copy = (OFAuthClientOptions)MemberwiseClone();
        copy.DefaultHeaders = new Dictionary<string, string>(DefaultHeaders);
        return copy;
    }
}

/// <summary>An attempt about to be sent, passed to <see cref="OFAuthClientOptions.OnRequest"/>.</summary>
/// <param name="Method">HTTP method.</param>
/// <param name="Url">
/// Request URL without credentials: the values of credential-like query parameters (signatures, tokens, keys,
/// <c>X-Amz-*</c>) read <c>REDACTED</c>.
/// </param>
/// <param name="Headers">
/// Request headers (case-insensitive) with credential values redacted: <c>Authorization</c>
/// (<c>Bearer [redacted]</c>), <c>Cookie</c>, <c>X-Api-Key</c>, <c>Cf-Access-Client-Secret</c>, and any name
/// containing <c>token</c>, <c>secret</c>, or <c>password</c> (<c>[redacted]</c>).
/// </param>
/// <param name="Attempt">1 for the first attempt, 2 for the first retry, and so on.</param>
/// <param name="Operation">Canonical operation name, e.g. <c>access.profile.get</c>, when known.</param>
public sealed record OFAuthRequestInfo(
    string Method,
    Uri Url,
    IReadOnlyDictionary<string, string> Headers,
    int Attempt,
    string? Operation);

/// <summary>A response, passed to <see cref="OFAuthClientOptions.OnResponse"/>.</summary>
/// <param name="Method">HTTP method.</param>
/// <param name="Url">Request URL, sanitized as in <see cref="OFAuthRequestInfo.Url"/>.</param>
/// <param name="StatusCode">HTTP status code.</param>
/// <param name="RequestId">The <c>x-request-id</c> header (or the error body's <c>requestId</c>).</param>
/// <param name="Duration">Time from sending to reading the whole body.</param>
/// <param name="Attempt">1 for the first attempt, 2 for the first retry, and so on.</param>
/// <param name="Operation">Canonical operation name, when known.</param>
public sealed record OFAuthResponseInfo(
    string Method,
    Uri Url,
    int StatusCode,
    string? RequestId,
    TimeSpan Duration,
    int Attempt,
    string? Operation);

// ============================================================================
// Errors
// ============================================================================

/// <summary>Base class for every error thrown by the SDK.</summary>
public class OFAuthException : Exception
{
    /// <summary>Create an error.</summary>
    /// <param name="message">What went wrong.</param>
    public OFAuthException(string message) : base(message) { }

    /// <summary>Create an error with a cause.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The cause.</param>
    public OFAuthException(string message, Exception? innerException) : base(message, innerException) { }

    /// <summary>True when the user has to go through authorization again (send them to the authorize URL).</summary>
    public virtual bool NeedsReauthorization => false;
}

/// <summary>What to do about an error (<c>recovery.action</c>). Unrecognized values are <see cref="Unknown"/>.</summary>
public enum RecoveryActionKind
{
    /// <summary>A value this SDK version does not know. Read <see cref="OFAuthApiException.RecoveryAction"/>.</summary>
    Unknown,

    /// <summary><c>obtain_external_oauth_token</c>: get a new access token (refresh).</summary>
    ObtainExternalOauthToken,

    /// <summary><c>restart_authorization</c>: send the user through authorization again.</summary>
    RestartAuthorization,

    /// <summary><c>reconnect_linked_account</c>: the creator has to reconnect the account in OFAuth.</summary>
    ReconnectLinkedAccount,

    /// <summary><c>select_linked_account</c>: pass a linked account id.</summary>
    SelectLinkedAccount,

    /// <summary><c>grant_linked_account</c>: the authorization does not cover this account; authorize it.</summary>
    GrantLinkedAccount,

    /// <summary><c>list_linked_accounts</c>: list the authorization's linked accounts and pick a valid one.</summary>
    ListLinkedAccounts,

    /// <summary><c>request_additional_consent</c>: authorize again with the missing scope.</summary>
    RequestAdditionalConsent,

    /// <summary><c>enable_linked_account_vault_plus</c>: Vault+ is off for this linked account.</summary>
    EnableLinkedAccountVaultPlus,

    /// <summary><c>enable_vault_plus</c>: Vault+ is off for the integration.</summary>
    EnableVaultPlus,

    /// <summary><c>retry_after_reset</c>: wait for the quota or rate limit to reset.</summary>
    RetryAfterReset,

    /// <summary><c>retry</c>: a transient failure; retry later.</summary>
    Retry,

    /// <summary><c>complete_integration_approval</c>: the integration is not approved for this use yet.</summary>
    CompleteIntegrationApproval,

    /// <summary><c>update_developer_plan</c>: the developer plan does not allow this.</summary>
    UpdateDeveloperPlan,

    /// <summary><c>contact_integration_owner</c>: the integration owner has to act.</summary>
    ContactIntegrationOwner,

    /// <summary><c>do_not_repeat</c>: the request will fail the same way again.</summary>
    DoNotRepeat,

    /// <summary><c>check_request</c>: fix the request parameters.</summary>
    CheckRequest,

    /// <summary><c>check_resource</c>: the resource does not exist or is not accessible.</summary>
    CheckResource,

    /// <summary><c>correct_request</c>: the request was rejected as invalid; correct it before retrying.</summary>
    CorrectRequest,

    /// <summary><c>restart_upload</c>: the upload session is unusable; start a new upload.</summary>
    RestartUpload,
}

/// <summary>Known <c>recovery.action</c> values.</summary>
public static class RecoveryActions
{
    /// <summary><c>obtain_external_oauth_token</c></summary>
    public const string ObtainExternalOauthToken = "obtain_external_oauth_token";

    /// <summary><c>restart_authorization</c></summary>
    public const string RestartAuthorization = "restart_authorization";

    /// <summary><c>reconnect_linked_account</c></summary>
    public const string ReconnectLinkedAccount = "reconnect_linked_account";

    /// <summary><c>select_linked_account</c></summary>
    public const string SelectLinkedAccount = "select_linked_account";

    /// <summary><c>grant_linked_account</c></summary>
    public const string GrantLinkedAccount = "grant_linked_account";

    /// <summary><c>list_linked_accounts</c></summary>
    public const string ListLinkedAccounts = "list_linked_accounts";

    /// <summary><c>request_additional_consent</c></summary>
    public const string RequestAdditionalConsent = "request_additional_consent";

    /// <summary><c>enable_linked_account_vault_plus</c></summary>
    public const string EnableLinkedAccountVaultPlus = "enable_linked_account_vault_plus";

    /// <summary><c>enable_vault_plus</c></summary>
    public const string EnableVaultPlus = "enable_vault_plus";

    /// <summary><c>retry_after_reset</c></summary>
    public const string RetryAfterReset = "retry_after_reset";

    /// <summary><c>retry</c></summary>
    public const string Retry = "retry";

    /// <summary><c>complete_integration_approval</c></summary>
    public const string CompleteIntegrationApproval = "complete_integration_approval";

    /// <summary><c>update_developer_plan</c></summary>
    public const string UpdateDeveloperPlan = "update_developer_plan";

    /// <summary><c>contact_integration_owner</c></summary>
    public const string ContactIntegrationOwner = "contact_integration_owner";

    /// <summary><c>do_not_repeat</c></summary>
    public const string DoNotRepeat = "do_not_repeat";

    /// <summary><c>check_request</c></summary>
    public const string CheckRequest = "check_request";

    /// <summary><c>check_resource</c></summary>
    public const string CheckResource = "check_resource";

    /// <summary><c>correct_request</c></summary>
    public const string CorrectRequest = "correct_request";

    /// <summary><c>restart_upload</c></summary>
    public const string RestartUpload = "restart_upload";

    /// <summary>The kind for a raw value: null when <paramref name="action"/> is null, <see cref="RecoveryActionKind.Unknown"/> when unrecognized.</summary>
    /// <param name="action">A <c>recovery.action</c> value.</param>
    public static RecoveryActionKind? Parse(string? action) => action switch
    {
        null => null,
        ObtainExternalOauthToken => RecoveryActionKind.ObtainExternalOauthToken,
        RestartAuthorization => RecoveryActionKind.RestartAuthorization,
        ReconnectLinkedAccount => RecoveryActionKind.ReconnectLinkedAccount,
        SelectLinkedAccount => RecoveryActionKind.SelectLinkedAccount,
        GrantLinkedAccount => RecoveryActionKind.GrantLinkedAccount,
        ListLinkedAccounts => RecoveryActionKind.ListLinkedAccounts,
        RequestAdditionalConsent => RecoveryActionKind.RequestAdditionalConsent,
        EnableLinkedAccountVaultPlus => RecoveryActionKind.EnableLinkedAccountVaultPlus,
        EnableVaultPlus => RecoveryActionKind.EnableVaultPlus,
        RetryAfterReset => RecoveryActionKind.RetryAfterReset,
        Retry => RecoveryActionKind.Retry,
        CompleteIntegrationApproval => RecoveryActionKind.CompleteIntegrationApproval,
        UpdateDeveloperPlan => RecoveryActionKind.UpdateDeveloperPlan,
        ContactIntegrationOwner => RecoveryActionKind.ContactIntegrationOwner,
        DoNotRepeat => RecoveryActionKind.DoNotRepeat,
        CheckRequest => RecoveryActionKind.CheckRequest,
        CheckResource => RecoveryActionKind.CheckResource,
        CorrectRequest => RecoveryActionKind.CorrectRequest,
        RestartUpload => RecoveryActionKind.RestartUpload,
        _ => RecoveryActionKind.Unknown,
    };

    internal static bool IsReauthorization(RecoveryActionKind? kind) =>
        kind is RecoveryActionKind.RestartAuthorization
            or RecoveryActionKind.RequestAdditionalConsent
            or RecoveryActionKind.GrantLinkedAccount;
}

/// <summary>One failed check from a request validation error (<c>RequestValidationError</c>).</summary>
/// <param name="Code">Validator code, e.g. <c>too_big</c>.</param>
/// <param name="Path">Location of the bad value: <see cref="string"/> keys and <see cref="int"/> indexes, e.g. <c>["body", "items", 0]</c>.</param>
/// <param name="Message">Human-readable message.</param>
public sealed record ValidationIssue(string Code, IReadOnlyList<object> Path, string Message);

/// <summary>
/// An error response from <c>/v3/access</c>, <c>/v3/vault-plus</c>, or <c>/v3/linked-accounts</c>.
/// Branch on <see cref="RecoveryAction"/> (or the <see cref="NeedsReconnect"/>-style helpers), not on the HTTP status alone.
/// Validation failures have code <c>invalid_request</c> and list <see cref="Issues"/>; handler errors
/// (<c>{ "error": "...", "type": "RESOURCE_NOT_FOUND" }</c> bodies) use the lower-cased type as <see cref="Code"/>
/// and keep it in <see cref="ErrorType"/>.
/// </summary>
public class OFAuthApiException : OFAuthException
{
    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>
    /// Stable machine-readable code, e.g. <c>linked_account_reconnect_required</c>, <c>invalid_request</c>
    /// (validation errors), or <c>resource_not_found</c> (handler errors).
    /// </summary>
    public string Code { get; }

    /// <summary>Validation issues when the request failed validation (code <c>invalid_request</c>); otherwise null.</summary>
    public IReadOnlyList<ValidationIssue>? Issues { get; }

    /// <summary>Raw error class of handler errors (<c>type</c>), e.g. <c>RESOURCE_NOT_FOUND</c>; otherwise null.</summary>
    public string? ErrorType { get; }

    /// <summary>What to do next (<c>recovery.action</c>), e.g. <c>reconnect_linked_account</c>.</summary>
    public string? RecoveryAction { get; }

    /// <summary><see cref="RecoveryAction"/> as an enum: null when absent, <see cref="OFAuth.RecoveryActionKind.Unknown"/> when unrecognized.</summary>
    public RecoveryActionKind? RecoveryActionKind { get; }

    /// <summary>Request id from the body or the <c>x-request-id</c> header. Quote it in support requests.</summary>
    public string? RequestId { get; }

    /// <summary>How long to wait before retrying, from <c>Retry-After</c>.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Human-readable detail: the <c>message</c> field, the summarized validation issues, or the handler error text.</summary>
    public string? ErrorMessage { get; }

    /// <summary>Raw response body.</summary>
    public string? ResponseBody { get; }

    /// <summary>How many HTTP attempts were made (retries included).</summary>
    public int Attempts { get; internal set; } = 1;

    /// <summary>Canonical name of the operation that failed, e.g. <c>access.chats.messages.send</c>.</summary>
    public string? Operation { get; internal set; }

    /// <summary>The OAuth scope the operation needs (see <see cref="Scopes.ByOperation"/>), if any.</summary>
    public string? RequiredScope { get; internal set; }

    /// <summary>Parse an error response.</summary>
    /// <param name="statusCode">HTTP status code.</param>
    /// <param name="responseBody">Raw response body.</param>
    /// <param name="headers">Response headers (for <c>Retry-After</c> and <c>x-request-id</c>).</param>
    public OFAuthApiException(int statusCode, string? responseBody, HttpResponseHeaders? headers)
        : this(statusCode, responseBody, ParsedError.From(statusCode, ApiTransport.TryParseObject(responseBody)), headers)
    {
    }

    private OFAuthApiException(int statusCode, string? responseBody, ParsedError parsed, HttpResponseHeaders? headers)
        : base(parsed.Message is not null && parsed.Message != parsed.Code ? $"{parsed.Code}: {parsed.Message}" : parsed.Code)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
        Code = parsed.Code;
        ErrorMessage = parsed.Message;
        Issues = parsed.Issues;
        ErrorType = parsed.ErrorType;
        RecoveryAction = parsed.RecoveryAction;
        RecoveryActionKind = RecoveryActions.Parse(RecoveryAction);
        RequestId = parsed.RequestId ?? ApiTransport.HeaderValue(headers, "x-request-id");
        RetryAfter = ApiTransport.ParseRetryAfter(headers);
    }

    /// <summary>A transient failure: recovery action <c>retry</c> / <c>retry_after_reset</c>, or status 429, 502, 503, 504.</summary>
    public bool IsRetryable =>
        RecoveryActionKind is OFAuth.RecoveryActionKind.Retry or OFAuth.RecoveryActionKind.RetryAfterReset
        || StatusCode is 429 or 502 or 503 or 504;

    /// <summary>Get a new access token (recovery action <c>obtain_external_oauth_token</c>).</summary>
    public bool NeedsTokenRefresh => RecoveryActionKind == OFAuth.RecoveryActionKind.ObtainExternalOauthToken;

    /// <summary>
    /// Send the user through authorization again: recovery action <c>restart_authorization</c>,
    /// <c>request_additional_consent</c>, or <c>grant_linked_account</c>.
    /// </summary>
    public override bool NeedsReauthorization => RecoveryActions.IsReauthorization(RecoveryActionKind);

    /// <summary>The creator has to reconnect the linked account (recovery action <c>reconnect_linked_account</c>).</summary>
    public bool NeedsReconnect => RecoveryActionKind == OFAuth.RecoveryActionKind.ReconnectLinkedAccount;

    /// <summary>
    /// A problem with the integration, not the user: <c>complete_integration_approval</c>, <c>update_developer_plan</c>,
    /// <c>contact_integration_owner</c>, or <c>enable_vault_plus</c>.
    /// </summary>
    public bool IsIntegrationProblem =>
        RecoveryActionKind is OFAuth.RecoveryActionKind.CompleteIntegrationApproval
            or OFAuth.RecoveryActionKind.UpdateDeveloperPlan
            or OFAuth.RecoveryActionKind.ContactIntegrationOwner
            or OFAuth.RecoveryActionKind.EnableVaultPlus;

    /// <summary>
    /// <c>[RequiredScope]</c> when the error is <c>missing_scope</c> or <c>additional_consent_required</c>, else empty.
    /// Pass it to <see cref="CreateAuthorizationUrlOptions.Scopes"/> to ask for the missing consent.
    /// </summary>
    public IReadOnlyList<string> MissingScopes =>
        RequiredScope is not null && Code is "missing_scope" or "additional_consent_required"
            ? new[] { RequiredScope }
            : Array.Empty<string>();

    /// <summary>
    /// The documented error shapes, normalized: <c>RuntimeError</c> (<c>error</c> code + <c>recovery</c>),
    /// <c>RequestValidationError</c> (<c>error: { name, issues }</c>), and <c>AccessHandlerError</c>
    /// (<c>error</c> message + <c>type</c> class).
    /// </summary>
    private sealed record ParsedError(
        string Code,
        string? Message,
        string? RecoveryAction,
        string? RequestId,
        IReadOnlyList<ValidationIssue>? Issues,
        string? ErrorType)
    {
        internal static ParsedError From(int statusCode, JsonElement? body)
        {
            var message = ApiTransport.GetString(body, "message");
            var requestId = ApiTransport.GetString(body, "requestId");
            JsonElement? recovery = body is { } b && b.TryGetProperty("recovery", out var r) && r.ValueKind == JsonValueKind.Object ? r : null;
            var action = ApiTransport.GetString(recovery, "action");
            JsonElement? error = body is { } e && e.TryGetProperty("error", out var err) ? err : null;

            if (error is { ValueKind: JsonValueKind.Object } errorObject
                && ApiTransport.GetString(errorObject, "name") is not null
                && errorObject.TryGetProperty("issues", out var rawIssues)
                && rawIssues.ValueKind == JsonValueKind.Array)
            {
                var issues = new List<ValidationIssue>();
                foreach (var item in rawIssues.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object) continue;
                    var path = new List<object>();
                    if (item.TryGetProperty("path", out var rawPath) && rawPath.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var segment in rawPath.EnumerateArray())
                        {
                            if (segment.ValueKind == JsonValueKind.String) path.Add(segment.GetString()!);
                            else if (segment.ValueKind == JsonValueKind.Number && segment.TryGetInt32(out var index)) path.Add(index);
                        }
                    }
                    issues.Add(new ValidationIssue(
                        ApiTransport.GetString(item, "code") ?? "",
                        path,
                        ApiTransport.GetString(item, "message") ?? ""));
                }
                var summary = string.Join("; ", issues.Select(issue =>
                    issue.Path.Count > 0 ? $"{string.Join(".", issue.Path)}: {issue.Message}" : issue.Message));
                return new ParsedError(
                    "invalid_request",
                    summary.Length > 0 ? summary : message,
                    action ?? "check_request",
                    requestId,
                    issues,
                    null);
            }

            var errorText = error is { ValueKind: JsonValueKind.String } text ? text.GetString() : null;
            var type = ApiTransport.GetString(body, "type");
            if (errorText is not null && type is not null && recovery is null)
                return new ParsedError(type.ToLowerInvariant(), errorText, null, requestId, null, type);
            return new ParsedError(errorText ?? $"http_{statusCode}", message, action, requestId, null, null);
        }
    }
}

/// <summary>The request never got a response: a network error or a timeout (after any retries).</summary>
public sealed class OFAuthConnectionException : OFAuthException
{
    /// <summary>Create a connection error.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="isTimeout">True when the attempt timed out.</param>
    /// <param name="attempts">How many attempts were made.</param>
    /// <param name="operation">Canonical operation name, when known.</param>
    /// <param name="innerException">The underlying error.</param>
    public OFAuthConnectionException(string message, bool isTimeout, int attempts, string? operation, Exception? innerException)
        : base(message, innerException)
    {
        IsTimeout = isTimeout;
        Attempts = attempts;
        Operation = operation;
    }

    /// <summary>True when the last attempt timed out (see <see cref="OFAuthClientOptions.Timeout"/>).</summary>
    public bool IsTimeout { get; }

    /// <summary>How many HTTP attempts were made.</summary>
    public int Attempts { get; }

    /// <summary>Canonical name of the operation, when known.</summary>
    public string? Operation { get; }
}

// ============================================================================
// Transport
// ============================================================================

/// <summary>One API request. Used by the generated client.</summary>
public sealed class ApiRequest
{
    private readonly List<KeyValuePair<string, string>> _query = new();

    /// <summary>An empty JSON object body (<c>{}</c>).</summary>
    public static object EmptyObject { get; } = new Dictionary<string, object>();

    /// <summary>A request for <paramref name="path"/>.</summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">Path below the API origin.</param>
    public ApiRequest(HttpMethod method, string path)
    {
        Method = method;
        Path = path;
    }

    /// <summary>HTTP method.</summary>
    public HttpMethod Method { get; }

    /// <summary>Path below the API origin, e.g. <c>/v3/access/profile</c>.</summary>
    public string Path { get; }

    /// <summary>
    /// Absolute URL to call instead of <c>BaseUrl + Path</c>. Must be on the <c>BaseUrl</c> origin
    /// (scheme, host, and port); any other origin throws <see cref="OFAuthException"/> before anything is sent.
    /// </summary>
    public Uri? Url { get; init; }

    /// <summary>JSON body.</summary>
    public object? Body { get; init; }

    /// <summary>Raw body sent as-is (uploads).</summary>
    public HttpContent? RawContent { get; init; }

    /// <summary>Whether the operation requires <c>x-linked-account-id</c>.</summary>
    public bool LinkedAccount { get; init; }

    /// <summary>Linked account for this call. Falls back to the client default.</summary>
    public string? LinkedAccountId { get; init; }

    /// <summary>Canonical operation name, e.g. <c>access.chats.messages.send</c>. Copied to errors.</summary>
    public string? Operation { get; init; }

    /// <summary>The OAuth scope the operation needs. Copied to errors.</summary>
    public string? RequiredScope { get; init; }

    /// <summary>Timeout per attempt for this request, instead of the client's.</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>Query parameters in order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Query => _query;

    /// <summary>Add a query parameter. Null values are skipped; lists repeat the key.</summary>
    /// <param name="name">Parameter name.</param>
    /// <param name="value">Value; lists add one entry per item.</param>
    public void AddQuery(string name, object? value)
    {
        if (value is null) return;
        if (value is not string && value is IEnumerable list)
        {
            foreach (var item in list)
            {
                if (item is not null) _query.Add(new(name, ApiTransport.FormatValue(item)));
            }
            return;
        }
        _query.Add(new(name, ApiTransport.FormatValue(value)));
    }

    internal string BuildQueryString()
    {
        if (_query.Count == 0) return "";
        var sb = new StringBuilder("?");
        for (var i = 0; i < _query.Count; i++)
        {
            if (i > 0) sb.Append('&');
            sb.Append(Uri.EscapeDataString(_query[i].Key)).Append('=').Append(Uri.EscapeDataString(_query[i].Value));
        }
        return sb.ToString();
    }
}

/// <summary>Sends requests for one client configuration, with retries and hooks. Used by the generated client.</summary>
public sealed class ApiTransport
{
    // Timeouts are applied per attempt by the transport, so the shared client has none of its own.
    private static readonly Lazy<HttpClient> SharedHttpClient =
        new(() => new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan });

    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(8);

    /// <summary>JSON settings used for request and response bodies.</summary>
    public static JsonSerializerOptions JsonOptions { get; } = CreateJsonOptions();

    internal ApiTransport(OFAuthClientOptions options, IAccessTokenProvider tokenProvider)
    {
        if (options.MaxRetries < 0) throw new ArgumentOutOfRangeException(nameof(options), "MaxRetries must be 0 or more");
        if (options.Timeout <= TimeSpan.Zero && options.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be positive (or Timeout.InfiniteTimeSpan)");
        }
        HttpClient = options.HttpClient ?? SharedHttpClient.Value;
        BaseUrl = options.BaseUrl.TrimEnd('/');
        TokenProvider = tokenProvider;
        LinkedAccountId = options.LinkedAccountId;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in options.DefaultHeaders)
        {
            if (string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"Do not set the {header.Key} header in DefaultHeaders: the SDK sends \"Bearer <access token>\" itself. " +
                    "Pass the token as AccessToken or AccessTokenProvider instead.",
                    nameof(options));
            }
            headers[header.Key] = header.Value;
        }
        DefaultHeaders = headers;
        MaxRetries = options.MaxRetries;
        Timeout = options.Timeout;
        MaxRetryDelay = options.MaxRetryDelay;
        OnRequest = options.OnRequest;
        OnResponse = options.OnResponse;
        TimeProvider = options.TimeProvider ?? TimeProvider.System;
        Log = options.DebugLogger
            ?? (options.Debug || System.Environment.GetEnvironmentVariable("OFAUTH_DEBUG") == "1"
                ? line => Console.Error.WriteLine(line)
                : null);
    }

    internal HttpClient HttpClient { get; }
    internal string BaseUrl { get; }
    internal IAccessTokenProvider TokenProvider { get; }
    internal string? LinkedAccountId { get; private set; }
    internal IReadOnlyDictionary<string, string> DefaultHeaders { get; }
    internal int MaxRetries { get; }
    internal TimeSpan Timeout { get; }
    internal TimeSpan MaxRetryDelay { get; }
    internal Action<OFAuthRequestInfo>? OnRequest { get; }
    internal Action<OFAuthResponseInfo>? OnResponse { get; }
    internal Action<string>? Log { get; }
    internal TimeProvider TimeProvider { get; }

    internal ApiTransport WithLinkedAccount(string linkedAccountId)
    {
        var copy = (ApiTransport)MemberwiseClone();
        copy.LinkedAccountId = linkedAccountId;
        return copy;
    }

    /// <summary>Send a request and parse the JSON response as <typeparamref name="T"/>.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancels the call, including retry waits.</param>
    public async Task<T> SendAsync<T>(ApiRequest request, CancellationToken cancellationToken)
    {
        var text = await SendRawAsync(request, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(text)) return default!;
        try
        {
            return JsonSerializer.Deserialize<T>(text, JsonOptions)!;
        }
        catch (JsonException ex)
        {
            throw new OFAuthException(
                $"Could not parse the {request.Method} {request.Path} response as {typeof(T).Name}: {ex.Message}", ex);
        }
    }

    /// <summary>Send a request and ignore the response body.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancels the call, including retry waits.</param>
    public async Task SendAsync(ApiRequest request, CancellationToken cancellationToken)
    {
        await SendRawAsync(request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Send a request and return the raw response body (empty for 204).</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancels the call, including retry waits.</param>
    /// <exception cref="OFAuthApiException">The API returned an error (after any retries).</exception>
    /// <exception cref="OFAuthConnectionException">No response: network error or timeout (after any retries).</exception>
    /// <exception cref="OFAuthException"><see cref="ApiRequest.Url"/> is not on the API origin; nothing was sent.</exception>
    public async Task<string> SendRawAsync(ApiRequest request, CancellationToken cancellationToken)
    {
        var linkedAccountId = request.LinkedAccountId ?? LinkedAccountId;
        if (request.LinkedAccount && string.IsNullOrEmpty(linkedAccountId))
        {
            throw new OFAuthException(
                $"{request.Method} {request.Path} needs a linked account: pass LinkedAccountId, or set it on the client.");
        }
        var url = request.Url is null
            ? new Uri(BaseUrl + request.Path + request.BuildQueryString())
            : SameOriginUrl(request.Url, BaseUrl);
        // Hooks only ever see this form of the URL.
        var safeUrl = SanitizeUrl(url);
        // Raw content is buffered so the request can be re-sent after a token refresh or a retry.
        byte[]? rawBytes = null;
        MediaTypeHeaderValue? rawContentType = null;
        if (request.RawContent is not null)
        {
            rawBytes = await request.RawContent.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            rawContentType = request.RawContent.Headers.ContentType;
        }
        var json = request.Body is null ? null : JsonSerializer.Serialize(request.Body, request.Body.GetType(), JsonOptions);
        var idempotent = IsIdempotent(request.Method);
        var timeout = request.Timeout ?? Timeout;
        var method = request.Method.Method;
        var label = $"{method} {url.AbsolutePath}";

        var attempt = 0;
        var retries = 0;
        var forceRefresh = false;
        var refreshed = false;
        while (true)
        {
            attempt++;
            var token = await TokenProvider.GetAccessTokenAsync(forceRefresh, cancellationToken).ConfigureAwait(false);
            forceRefresh = false;
            using var message = new HttpRequestMessage(request.Method, url);
            foreach (var header in DefaultHeaders) message.Headers.TryAddWithoutValidation(header.Key, header.Value);
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (request.LinkedAccount)
            {
                // Replace (not append to) a caller's x-linked-account-id.
                message.Headers.Remove(OFAuthDefaults.LinkedAccountHeader);
                message.Headers.TryAddWithoutValidation(OFAuthDefaults.LinkedAccountHeader, linkedAccountId);
            }
            if (rawBytes is not null)
            {
                message.Content = new ByteArrayContent(rawBytes);
                message.Content.Headers.ContentType = rawContentType ?? new MediaTypeHeaderValue("application/octet-stream");
            }
            else
            {
                // A default only: a caller's Accept in DefaultHeaders is kept instead of being sent next to it.
                if (message.Headers.Accept.Count == 0) message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                if (json is not null) message.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }
            if (OnRequest is { } onRequest)
            {
                Safe(() => onRequest(new OFAuthRequestInfo(method, safeUrl, RedactedHeaders(message), attempt, request.Operation)));
            }

            var started = Stopwatch.GetTimestamp();
            HttpResponseMessage response;
            string body;
            using (var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                if (timeout != System.Threading.Timeout.InfiniteTimeSpan) attemptCts.CancelAfter(timeout);
                try
                {
                    response = await HttpClient.SendAsync(message, HttpCompletionOption.ResponseContentRead, attemptCts.Token)
                        .ConfigureAwait(false);
                    try
                    {
                        body = await ReadBodyAsync(response, attemptCts.Token).ConfigureAwait(false);
                    }
                    catch
                    {
                        response.Dispose();
                        throw;
                    }
                }
                catch (Exception ex) when (IsTransportFailure(ex, cancellationToken, attemptCts.Token))
                {
                    // Only network failures and the SDK's own per-attempt timeout get here; anything else a
                    // handler throws (e.g. a policy refusal) propagates unchanged and is not retried.
                    var timedOut = ex is OperationCanceledException;
                    var elapsed = Stopwatch.GetElapsedTime(started);
                    Log?.Invoke($"[ofauth] {label} -> {(timedOut ? "timeout" : "network error")} ({elapsed.TotalMilliseconds:0}ms)");
                    if (idempotent && retries < MaxRetries)
                    {
                        var delay = Backoff(retries);
                        retries++;
                        Log?.Invoke($"[ofauth] retrying {label} in {delay.TotalSeconds:0.##}s (retry {retries} of {MaxRetries})");
                        await Task.Delay(delay, TimeProvider, cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                    throw new OFAuthConnectionException(
                        timedOut
                            ? $"{label} timed out after {timeout.TotalSeconds:0.##}s ({attempt} attempt{(attempt == 1 ? "" : "s")})"
                            : $"{label} failed: {ex.Message} ({attempt} attempt{(attempt == 1 ? "" : "s")})",
                        timedOut,
                        attempt,
                        request.Operation,
                        ex);
                }
            }

            using (response)
            {
                var duration = Stopwatch.GetElapsedTime(started);
                var status = (int)response.StatusCode;
                var errorBody = response.IsSuccessStatusCode ? null : TryParseObject(body);
                var requestId = GetString(errorBody, "requestId") ?? HeaderValue(response.Headers, "x-request-id");
                if (OnResponse is { } onResponse)
                {
                    Safe(() => onResponse(new OFAuthResponseInfo(method, safeUrl, status, requestId, duration, attempt, request.Operation)));
                }
                Log?.Invoke($"[ofauth] {label} -> {status} ({duration.TotalMilliseconds:0}ms{(requestId is null ? "" : ", " + requestId)})");

                if (response.IsSuccessStatusCode) return body;

                var code = GetString(errorBody, "error");
                // invalid_token: refresh once. Separate from MaxRetries.
                if (status == 401 && !refreshed && code == "invalid_token" && TokenProvider is not StaticAccessTokenProvider)
                {
                    refreshed = true;
                    forceRefresh = true;
                    Log?.Invoke($"[ofauth] retrying {label} with a refreshed access token");
                    continue;
                }

                var error = new OFAuthApiException(status, body, response.Headers)
                {
                    Attempts = attempt,
                    Operation = request.Operation,
                    RequiredScope = request.RequiredScope,
                };
                if (retries < MaxRetries && ShouldRetry(status, code, idempotent)
                    && RetryDelay(response.Headers, retries) is { } wait)
                {
                    retries++;
                    Log?.Invoke($"[ofauth] retrying {label} in {wait.TotalSeconds:0.##}s (retry {retries} of {MaxRetries}, {status}{(code is null ? "" : " " + code)})");
                    await Task.Delay(wait, TimeProvider, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                throw error;
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="ex"/> is a genuine network failure (<see cref="HttpRequestException"/>,
    /// <see cref="IOException"/>, <see cref="System.Net.Sockets.SocketException"/>) or the SDK's own per-attempt
    /// timeout. The caller's cancellation and any other exception are not.
    /// </summary>
    internal static bool IsTransportFailure(Exception ex, CancellationToken callerToken, CancellationToken attemptToken)
    {
        if (callerToken.IsCancellationRequested) return false;
        if (ex is OperationCanceledException) return attemptToken.IsCancellationRequested;
        return ex is HttpRequestException or IOException or System.Net.Sockets.SocketException;
    }

    internal static bool IsIdempotent(HttpMethod method) =>
        method == HttpMethod.Get || method == HttpMethod.Head || method == HttpMethod.Options;

    private const UriComponents OriginComponents = UriComponents.Scheme | UriComponents.Host | UriComponents.StrongPort;

    /// <summary>
    /// Returns <paramref name="url"/> when it is absolute and on the API origin (scheme, host, and port of
    /// <paramref name="baseUrl"/>). Requests carry the access token and the linked account header, so an
    /// absolute URL on any other origin (e.g. an upload part URL pointing elsewhere) is refused before anything is sent.
    /// </summary>
    internal static Uri SameOriginUrl(Uri url, string baseUrl)
    {
        if (!url.IsAbsoluteUri || (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp))
        {
            throw new OFAuthException("Refusing to send an authenticated request: the request URL is not an absolute http(s) URL.");
        }
        var origin = url.GetComponents(OriginComponents, UriFormat.UriEscaped);
        var apiOrigin = new Uri(baseUrl).GetComponents(OriginComponents, UriFormat.UriEscaped);
        if (!string.Equals(origin, apiOrigin, StringComparison.OrdinalIgnoreCase))
        {
            throw new OFAuthException(
                $"Refusing to send the access token to {origin}: it is not the API origin ({apiOrigin}). " +
                "Authenticated requests only go to the configured BaseUrl.");
        }
        return url;
    }

    /// <summary>Whether an error status is retried (before the attempt limit and delay checks).</summary>
    internal static bool ShouldRetry(int status, string? code, bool idempotent) => status switch
    {
        429 => true,
        503 when code == "authorization_temporarily_unavailable" => true,
        502 or 503 or 504 => idempotent,
        _ => false,
    };

    /// <summary>
    /// The wait before retry number <paramref name="retry"/> + 1: <c>Retry-After</c>, else <c>RateLimit-Reset</c>, else
    /// exponential backoff with full jitter. Null when the server asks for more than <see cref="MaxRetryDelay"/>.
    /// </summary>
    internal TimeSpan? RetryDelay(HttpResponseHeaders headers, int retry)
    {
        var server = ParseRetryAfter(headers);
        if (server is null
            && HeaderValue(headers, "ratelimit-reset") is { } reset
            && double.TryParse(reset, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
        {
            server = TimeSpan.FromSeconds(Math.Max(0, seconds));
        }
        if (server is { } delay) return delay > MaxRetryDelay ? null : delay;
        return Backoff(retry);
    }

    /// <summary>Full jitter: a random wait between 0 and min(8s, 0.5s * 2^retry).</summary>
    internal static TimeSpan Backoff(int retry)
    {
        var cap = Math.Min(MaxBackoff.TotalMilliseconds, 500 * Math.Pow(2, Math.Min(retry, 20)));
        return TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * cap);
    }

    internal static Dictionary<string, string> RedactedHeaders(HttpRequestMessage message)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in message.Headers) headers[header.Key] = RedactHeader(header.Key, string.Join(", ", header.Value));
        if (message.Content is not null)
        {
            foreach (var header in message.Content.Headers) headers[header.Key] = RedactHeader(header.Key, string.Join(", ", header.Value));
        }
        return headers;
    }

    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "cf-access-client-secret",
    };

    /// <summary>True for header names whose values are credentials, whatever their casing.</summary>
    internal static bool IsSensitiveHeader(string name) =>
        SensitiveHeaders.Contains(name)
        || name.Contains("token", StringComparison.OrdinalIgnoreCase)
        || name.Contains("secret", StringComparison.OrdinalIgnoreCase)
        || name.Contains("password", StringComparison.OrdinalIgnoreCase);

    /// <summary>The value a hook sees for header <paramref name="name"/>.</summary>
    internal static string RedactHeader(string name, string value) =>
        string.Equals(name, "Authorization", StringComparison.OrdinalIgnoreCase) ? "Bearer [redacted]"
        : IsSensitiveHeader(name) ? "[redacted]"
        : value;

    private static readonly string[] SensitiveQueryParts =
        { "token", "secret", "sig", "key", "password", "credential", "auth", "session" };

    /// <summary>True for query parameter names whose values may be credentials, e.g. <c>X-Amz-Signature</c> or <c>token</c>.</summary>
    internal static bool IsSensitiveQueryKey(string name) =>
        name.StartsWith("x-amz-", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("x-goog-", StringComparison.OrdinalIgnoreCase)
        || SensitiveQueryParts.Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// <paramref name="url"/> for hooks, logs, and errors: no user info or fragment, and the values of credential-like
    /// query parameters (signatures, tokens, keys, <c>X-Amz-*</c>) replaced by <c>REDACTED</c>. Other parameters
    /// (<c>limit</c>, <c>cursor</c>, <c>linkedAccountId</c>, ...) are kept so hooks stay useful for debugging.
    /// </summary>
    internal static Uri SanitizeUrl(Uri url)
    {
        if (!url.IsAbsoluteUri) return url;
        var query = url.GetComponents(UriComponents.Query, UriFormat.UriEscaped);
        var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(pair =>
        {
            var name = pair.Split('=', 2)[0];
            return IsSensitiveQueryKey(Uri.UnescapeDataString(name.Replace('+', ' '))) ? name + "=REDACTED" : pair;
        });
        var builder = new UriBuilder(url) { UserName = "", Password = "", Fragment = "", Query = string.Join("&", pairs) };
        return builder.Uri;
    }

    /// <summary>
    /// The Realtime event stream URL on the API origin: <c>https://host</c> becomes <c>https://host/v3/realtime/events</c>.
    /// Realtime is served on the same origin as every other API route, so <see cref="OFAuthClient.Realtime"/> always
    /// streams from here and the token only goes where API requests go.
    /// </summary>
    /// <param name="baseUrl">The API origin, e.g. <c>https://api.ofauth.com</c>.</param>
    internal static string RealtimeUrlFor(string baseUrl)
    {
        var trimmed = baseUrl.TrimEnd('/');
        if (!trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && !trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            throw new OFAuthException(
                $"Cannot derive the Realtime URL from BaseUrl {trimmed}: it is not an http(s) URL.");
        }
        return trimmed + RealtimeConnection.EventsPath;
    }

    private static void Safe(Action hook)
    {
        try
        {
            hook();
        }
        catch
        {
            // Hooks must not break requests.
        }
    }

    private static async Task<string> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.NoContent) return "";
        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    /// <summary>A URL-encoded path segment.</summary>
    /// <param name="value">A string or number.</param>
    public static string PathSegment(object value) => Uri.EscapeDataString(FormatValue(value));

    /// <summary>Format a query or path value with the invariant culture.</summary>
    /// <param name="value">The value.</param>
    public static string FormatValue(object value) => value switch
    {
        string s => s,
        bool b => b ? "true" : "false",
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        float f => f.ToString("R", CultureInfo.InvariantCulture),
        JsonElement e => e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : e.GetRawText(),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    internal static JsonElement? TryParseObject(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static string? GetString(JsonElement? element, string property)
    {
        if (element is not { ValueKind: JsonValueKind.Object } e) return null;
        return e.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    internal static string? HeaderValue(HttpHeaders? headers, string name) =>
        headers is not null && headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

    internal static TimeSpan? ParseRetryAfter(HttpResponseHeaders? headers)
    {
        var retryAfter = headers?.RetryAfter;
        if (retryAfter is null)
        {
            var raw = HeaderValue(headers, "retry-after");
            return raw is not null && double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var s)
                ? TimeSpan.FromSeconds(s)
                : null;
        }
        if (retryAfter.Delta is { } delta) return delta;
        if (retryAfter.Date is { } date)
        {
            var wait = date - DateTimeOffset.UtcNow;
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
        }
        return null;
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.General)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
        };
        options.Converters.Add(new LenientStringConverter());
        options.Converters.Add(new LenientInt64Converter());
        return options;
    }
}

/// <summary>Reads numbers and booleans into string properties instead of failing.</summary>
internal sealed class LenientStringConverter : JsonConverter<string>
{
    public override bool HandleNull => false;

    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString(),
            JsonTokenType.Number => Encoding.UTF8.GetString(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()),
            JsonTokenType.True => "true",
            JsonTokenType.False => "false",
            _ => JsonDocument.ParseValue(ref reader).RootElement.GetRawText(),
        };

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value);
}

/// <summary>Reads integral floating point numbers (e.g. <c>3.0</c>) and numeric strings into long properties.</summary>
internal sealed class LenientInt64Converter : JsonConverter<long>
{
    public override long Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number)
        {
            if (reader.TryGetInt64(out var value)) return value;
            return checked((long)reader.GetDouble());
        }
        if (reader.TokenType == JsonTokenType.String
            && double.TryParse(reader.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
        {
            return checked((long)parsed);
        }
        throw new JsonException($"Expected an integer, got {reader.TokenType}");
    }

    public override void Write(Utf8JsonWriter writer, long value, JsonSerializerOptions options) =>
        writer.WriteNumberValue(value);
}

// ============================================================================
// Pagination
// ============================================================================

/// <summary>Cursor pagination used by the generated <c>Iterate*Async</c> methods.</summary>
public static class Pagination
{
    /// <summary>
    /// Iterate every item of a cursor-paginated operation. Stops when <paramref name="hasMore"/> is false,
    /// the next cursor is empty, a page has no items, or <paramref name="maxItems"/> is reached.
    /// </summary>
    /// <param name="fetchPage">Fetches the page for a cursor (null for the first page).</param>
    /// <param name="items">The items of a page.</param>
    /// <param name="nextCursor">The cursor of the next page.</param>
    /// <param name="hasMore">Whether there is another page; null when the operation has no such flag.</param>
    /// <param name="maxItems">Stop after this many items.</param>
    /// <param name="cancellationToken">Cancels the iteration.</param>
    public static async IAsyncEnumerable<TItem> PaginateAsync<TPage, TItem>(
        Func<string?, CancellationToken, Task<TPage>> fetchPage,
        Func<TPage, IEnumerable<TItem>?> items,
        Func<TPage, string?> nextCursor,
        Func<TPage, bool>? hasMore,
        int? maxItems,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var max = maxItems ?? int.MaxValue;
        var yielded = 0;
        string? cursor = null;
        while (yielded < max)
        {
            var page = await fetchPage(cursor, cancellationToken).ConfigureAwait(false);
            if (page is null) yield break;
            var count = 0;
            foreach (var item in items(page) ?? Enumerable.Empty<TItem>())
            {
                if (yielded >= max) yield break;
                count++;
                yielded++;
                yield return item;
            }
            var next = nextCursor(page);
            if ((hasMore is not null && !hasMore(page)) || string.IsNullOrEmpty(next) || count == 0) yield break;
            cursor = next;
        }
    }

    /// <summary>A cursor value as a string (cursors may be numbers).</summary>
    /// <param name="value">A cursor from a response.</param>
    public static string? CursorString(object? value) => value switch
    {
        null => null,
        string s => s,
        JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,
        _ => ApiTransport.FormatValue(value),
    };
}

// ============================================================================
// Scope helpers (the constants and the operation map are generated in Models.g.cs)
// ============================================================================

public static partial class Scopes
{
    /// <summary>
    /// The scopes needed to call <paramref name="operations"/> (canonical names such as
    /// <c>access.chats.messages.send</c>, see <see cref="OFAuthOperations"/>): de-duplicated and sorted.
    /// </summary>
    /// <param name="operations">Canonical operation names.</param>
    /// <exception cref="ArgumentException">An operation name is unknown.</exception>
    public static IReadOnlyList<string> For(params string[] operations) => For((IEnumerable<string>)operations);

    /// <summary>The scopes needed to call <paramref name="operations"/>, de-duplicated and sorted.</summary>
    /// <param name="operations">Canonical operation names.</param>
    /// <exception cref="ArgumentException">An operation name is unknown.</exception>
    public static IReadOnlyList<string> For(IEnumerable<string> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        var scopes = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var operation in operations)
        {
            if (ForOperation(operation) is { } scope) scopes.Add(scope);
        }
        return scopes.ToList();
    }

    /// <summary>The scope one operation needs, or null when it needs none (linked accounts, Vault+).</summary>
    /// <param name="operation">A canonical operation name.</param>
    /// <exception cref="ArgumentException">The operation name is unknown.</exception>
    public static string? ForOperation(string operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return ByOperation.TryGetValue(operation, out var scope)
            ? scope
            : throw new ArgumentException($"Unknown OFAuth operation '{operation}' (expected e.g. access.chats.messages.send)", nameof(operation));
    }

    /// <summary>
    /// The scopes the user still has to grant for <paramref name="error"/>: <c>[RequiredScope]</c> for
    /// <c>missing_scope</c> and <c>additional_consent_required</c> API errors, else empty.
    /// </summary>
    /// <param name="error">Any exception from an SDK call.</param>
    public static IReadOnlyList<string> Missing(Exception error) =>
        error is OFAuthApiException api ? api.MissingScopes : Array.Empty<string>();
}
