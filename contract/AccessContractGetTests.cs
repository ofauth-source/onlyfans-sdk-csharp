// Contract tests for every GET Access operation in accessEndpoints.manifest.json.
//
// Each manifest entry names its SDK method (`sdk`, e.g. "access.chats.messages.list"); the tests resolve it to
// the generated C# method (client.Access.Chats.Messages.ListAsync) through reflection.
//
// - ManifestMapsToSdkMethods runs offline.
// - AccessGetContract calls every GET operation against a real authorization and checks the response parses into
//   the generated types. It does nothing unless credentials are set:
//     E2E_ACCESS_BASE_URL     API origin, e.g. https://api.staging.ofauth.com
//     E2E_ACCESS_TOKEN        bearer access token (from POST /v3/link/token)
//                             preferred in CI instead of E2E_ACCESS_TOKEN: mint fresh tokens with
//     E2E_LINKED_ACCOUNT_ID   linked account to act on
//     E2E_CONTRACT_REQUIRED=1 fail (instead of pass) when the above are missing
//     E2E_CONTRACT_STRICT=1   fail when an endpoint could not be exercised (no fixture)
//     E2E_MIN_DELAY_MS        minimum delay between requests (default 250)
//     E2E_FIXTURE_<PARAM>     path parameter values, e.g. E2E_FIXTURE_USER_ID

using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace OFAuth.ContractTests;

public sealed record EndpointSpec(string Method, string Route, string Tag, string Summary, string? Scope, string Sdk);

public class AccessContractGetTests
{
    private static readonly Regex RouteParam = new(@"\{([A-Za-z0-9_]+)\}");

    // Per route param, the list routes whose first item supplies it.
    private static readonly Dictionary<string, string[]> FixtureSources = new()
    {
        ["userId"] = new[] { "/chats", "/subscribers" },
        ["postId"] = new[] { "/posts" },
        ["listId"] = new[] { "/lists" },
        ["vaultListId"] = new[] { "/vault/lists" },
        ["massMessageId"] = new[] { "/analytics/mass-messages/sent" },
        ["promotionId"] = new[] { "/promotions" },
        ["bundleId"] = new[] { "/promotions/bundles" },
        ["trackingLinkId"] = new[] { "/promotions/tracking-links" },
        ["trialLinkId"] = new[] { "/promotions/trial-links" },
        ["storyId"] = new[] { "/stories" },
        ["highlightId"] = new[] { "/stories/highlights" },
        ["mediaId"] = new[] { "/vault/media" },
        ["subscriptionId"] = new[] { "/subscriptions" },
        ["subscriberId"] = new[] { "/subscribers" },
        ["releaseFormId"] = new[] { "/release-forms" },
        ["labelId"] = new[] { "/users/labels" },
        ["categoryId"] = new[] { "/posts/bookmarks/categories" },
        ["commentId"] = new[] { "/posts/{postId}/comments" },
        ["messageId"] = new[] { "/chats/{userId}/messages" },
        ["settingId"] = new[] { "/settings" },
        ["buttonId"] = new[] { "/profile/social-buttons" },
        ["linkId"] = new[] { "/profile/links" },
        ["scheduleId"] = new[] { "/queue/schedules" },
    };

    private readonly ITestOutputHelper _output;

    public AccessContractGetTests(ITestOutputHelper output) => _output = output;

    private static List<EndpointSpec> LoadManifest()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "accessEndpoints.manifest.json");
        return JsonSerializer.Deserialize<List<EndpointSpec>>(File.ReadAllText(path), new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }

    private static string Pascal(string camel) => char.ToUpperInvariant(camel[0]) + camel[1..];

    /// <summary>Resolve "access.chats.messages.list" to (namespace object, ListAsync).</summary>
    private static (object Target, MethodInfo Method) SdkMethod(OFAuthClient client, string sdk)
    {
        var segments = sdk.Split('.');
        object target = client;
        foreach (var segment in segments[..^1])
        {
            var property = target.GetType().GetProperty(Pascal(segment))
                ?? throw new InvalidOperationException($"namespace {segment} not found for {sdk}");
            target = property.GetValue(target)!;
        }
        var method = target.GetType().GetMethod(Pascal(segments[^1]) + "Async")
            ?? throw new InvalidOperationException($"method {sdk} not found");
        return (target, method);
    }

    [Fact]
    public void ManifestMapsToSdkMethods()
    {
        var manifest = LoadManifest();
        Assert.True(manifest.Count > 20, $"unexpected manifest size {manifest.Count}");
        var client = new OFAuthClient("unused", "conn_unused");
        var missing = new List<string>();
        foreach (var entry in manifest)
        {
            try
            {
                SdkMethod(client, entry.Sdk);
            }
            catch (InvalidOperationException ex)
            {
                missing.Add($"{entry.Method.ToUpperInvariant()} {entry.Route}: {ex.Message}");
            }
        }
        Assert.True(missing.Count == 0, "Manifest entries without SDK methods:\n" + string.Join("\n", missing));
    }

    private static bool EnvFlag(string name) =>
        Environment.GetEnvironmentVariable(name) is "1" or "true" or "TRUE" or "True";

    private static void SetParam(object parameters, string name, string value)
    {
        var property = parameters.GetType().GetProperty(Pascal(name))
            ?? throw new InvalidOperationException($"no parameter {name}");
        var type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
        object converted = type == typeof(string) ? value
            : type == typeof(long) ? long.Parse(value, CultureInfo.InvariantCulture)
            : type == typeof(double) ? double.Parse(value, CultureInfo.InvariantCulture)
            : type == typeof(bool) ? value == "true"
            : type == typeof(List<string>) ? new List<string> { value }
            : throw new InvalidOperationException($"cannot set {name} of type {type.Name}");
        property.SetValue(parameters, converted);
    }

    private static Dictionary<string, string> DefaultQuery(string route)
    {
        var query = new Dictionary<string, string> { ["limit"] = "1" };
        if (route.Contains("/analytics/") || route.Contains("timeseries") || route.EndsWith("/top", StringComparison.Ordinal))
        {
            var end = DateTime.UtcNow;
            query["startDate"] = end.AddDays(-30).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            query["endDate"] = end.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }
        if (route == "/users/search") query["query"] = "test";
        return query;
    }

    private static string? FirstItemValue(object? response, string param)
    {
        if (response is null) return null;
        var root = JsonSerializer.SerializeToElement(response, response.GetType(), ApiTransport.JsonOptions);
        if (root.ValueKind != JsonValueKind.Object) return null;
        JsonElement first = default;
        foreach (var key in new[] { "items", "list", "data" })
        {
            if (root.TryGetProperty(key, out var list) && list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0)
            {
                first = list[0];
                break;
            }
        }
        if (first.ValueKind != JsonValueKind.Object) return null;
        if (param == "userId")
        {
            foreach (var key in new[] { "withUser", "user" })
            {
                if (first.TryGetProperty(key, out var user) && user.ValueKind == JsonValueKind.Object && user.TryGetProperty("id", out var uid))
                {
                    return Scalar(uid);
                }
            }
        }
        foreach (var key in new[] { "id", param })
        {
            if (first.TryGetProperty(key, out var value) && value.ValueKind != JsonValueKind.Null) return Scalar(value);
        }
        return null;
    }

    private static string Scalar(JsonElement value) => value.ValueKind == JsonValueKind.Number
        ? value.GetDouble().ToString("R", CultureInfo.InvariantCulture)
        : value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();

    private static string Env(string name) => (Environment.GetEnvironmentVariable(name) ?? "").Trim();

    [Fact]
    public async Task AccessGetContract()
    {
        var baseUrl = (Environment.GetEnvironmentVariable("E2E_ACCESS_BASE_URL") ?? "").Trim().TrimEnd('/');
        if (baseUrl.EndsWith("/v3/access", StringComparison.Ordinal)) baseUrl = baseUrl[..^"/v3/access".Length];
        if (baseUrl.EndsWith("/v3", StringComparison.Ordinal)) baseUrl = baseUrl[..^"/v3".Length];
        var token = Env("E2E_ACCESS_TOKEN");
        var linkedAccountId = Env("E2E_LINKED_ACCOUNT_ID");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };
        IAccessTokenProvider? tokens = token.Length > 0 ? new StaticAccessTokenProvider(token) : null;
        if (baseUrl.Length == 0 || tokens is null || linkedAccountId.Length == 0)
        {
            const string want = "E2E_ACCESS_BASE_URL, E2E_LINKED_ACCOUNT_ID, and E2E_ACCESS_TOKEN";
            Assert.False(EnvFlag("E2E_CONTRACT_REQUIRED"), "set " + want);
            _output.WriteLine("skipped: no e2e credentials (set " + want + ")");
            return;
        }

        var gets = LoadManifest().Where(e => e.Method.Equals("get", StringComparison.OrdinalIgnoreCase)).ToList();
        var byRoute = gets.ToDictionary(e => e.Route);
        var minDelay = TimeSpan.FromMilliseconds(int.TryParse(Environment.GetEnvironmentVariable("E2E_MIN_DELAY_MS"), out var ms) ? ms : 250);
        var client = new OFAuthClient(new OFAuthClientOptions
        {
            AccessTokenProvider = tokens,
            LinkedAccountId = linkedAccountId,
            BaseUrl = baseUrl,
            HttpClient = http,
        });
        var lastCall = DateTime.MinValue;

        async Task<object?> Call(EndpointSpec entry, Dictionary<string, string> pathValues)
        {
            var wait = minDelay - (DateTime.UtcNow - lastCall);
            if (wait > TimeSpan.Zero) await Task.Delay(wait);
            lastCall = DateTime.UtcNow;
            var (target, method) = SdkMethod(client, entry.Sdk);
            var parameterType = method.GetParameters()[0].ParameterType;
            var parameters = Activator.CreateInstance(parameterType)!;
            foreach (var (name, value) in DefaultQuery(entry.Route))
            {
                if (parameterType.GetProperty(Pascal(name)) is not null) SetParam(parameters, name, value);
            }
            foreach (var (name, value) in pathValues) SetParam(parameters, name, value);
            var task = (Task)method.Invoke(target, new[] { parameters, CancellationToken.None })!;
            await task;
            return task.GetType().GetProperty("Result")?.GetValue(task);
        }

        var fixtures = new Dictionary<string, string?>();
        async Task<string?> Resolve(string route, string param, int depth)
        {
            var key = param == "listId" && route.StartsWith("/vault/", StringComparison.Ordinal) ? "vaultListId" : param;
            var fromEnv = Environment.GetEnvironmentVariable("E2E_FIXTURE_" + Regex.Replace(key, "([a-z])([A-Z])", "$1_$2").ToUpperInvariant());
            if (!string.IsNullOrEmpty(fromEnv)) return fromEnv;
            if (fixtures.TryGetValue(key, out var cached)) return cached;
            fixtures[key] = null;
            if (depth > 2 || !FixtureSources.TryGetValue(key, out var sources)) return null;
            foreach (var source in sources)
            {
                if (!byRoute.TryGetValue(source, out var entry)) continue;
                var values = await ResolveAll(source, depth + 1);
                if (values is null) continue;
                try
                {
                    var value = FirstItemValue(await Call(entry, values), param);
                    if (value is not null) return fixtures[key] = value;
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"fixture {key} from {source}: {ex.Message}");
                }
            }
            return null;
        }

        async Task<Dictionary<string, string>?> ResolveAll(string route, int depth)
        {
            var values = new Dictionary<string, string>();
            foreach (Match match in RouteParam.Matches(route))
            {
                var value = await Resolve(route, match.Groups[1].Value, depth);
                if (value is null) return null;
                values[match.Groups[1].Value] = value;
            }
            return values;
        }

        var failures = new List<string>();
        var skipped = new List<string>();
        foreach (var entry in gets)
        {
            var values = await ResolveAll(entry.Route, 0);
            if (values is null)
            {
                skipped.Add(entry.Sdk);
                _output.WriteLine($"skip {entry.Route} {entry.Sdk}: no fixture");
                continue;
            }
            try
            {
                await Call(entry, values);
            }
            catch (Exception ex)
            {
                var error = ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;
                failures.Add($"GET {entry.Route} ({entry.Sdk}): {error.Message}");
            }
        }

        Assert.True(failures.Count == 0, string.Join("\n", failures));
        Assert.False(EnvFlag("E2E_CONTRACT_STRICT") && skipped.Count > 0,
            $"{skipped.Count} GET Access endpoints not exercised:\n- {string.Join("\n- ", skipped)}");
    }
}
