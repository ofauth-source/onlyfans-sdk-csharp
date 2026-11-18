namespace OFAuth.Examples;

internal static class Env
{
    public static string Require(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"Set {name}");

    public static string? Optional(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : null;

    public static OFAuthLink Link() => new(new OFAuthLinkOptions
    {
        ClientId = Require("OFAUTH_CLIENT_ID"),
        ClientSecret = Require("OFAUTH_CLIENT_SECRET"),
        RedirectUri = Optional("OFAUTH_REDIRECT_URI"),
        ApiUrl = Optional("OFAUTH_API_URL") ?? OFAuthDefaults.ApiUrl,
        AuthUrl = Optional("OFAUTH_AUTH_URL") ?? OFAuthDefaults.AuthUrl,
    });

    public static OFAuthClient Client() => new(new OFAuthClientOptions
    {
        AccessToken = Require("OFAUTH_ACCESS_TOKEN"),
        LinkedAccountId = Require("OFAUTH_LINKED_ACCOUNT_ID"),
        BaseUrl = Optional("OFAUTH_API_URL") ?? OFAuthDefaults.ApiUrl,
    });
}
