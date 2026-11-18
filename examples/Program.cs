// OFAuth V3 C# SDK examples.
//
//   dotnet run --project examples -- access       Call Access operations
//   dotnet run --project examples -- pagination   Iterate paginated results
//   dotnet run --project examples -- errors       Handle errors by recovery action
//   dotnet run --project examples -- upload <file> <content-type>
//   dotnet run --project examples -- realtime     Listen to Realtime events
//   dotnet run --project examples -- webhook      Verify and route a webhook delivery (self-signed sample)
//
// Environment: OFAUTH_CLIENT_ID, OFAUTH_CLIENT_SECRET, OFAUTH_REDIRECT_URI (oauth), OFAUTH_ACCESS_TOKEN or
// OFAUTH_REFRESH_TOKEN, OFAUTH_LINKED_ACCOUNT_ID, OFAUTH_API_URL (e.g. https://api.staging.ofauth.com).

using OFAuth.Examples;

var example = args.FirstOrDefault() ?? "";
switch (example)
{
    case "access":
        await AccessExample.RunAsync(Env.Client());
        break;
    case "pagination":
        await PaginationExample.RunAsync(Env.Client());
        break;
    case "errors":
        await ErrorHandlingExample.RunAsync(Env.Client());
        break;
    case "upload":
        await UploadExample.RunAsync(Env.Client(), args.ElementAtOrDefault(1) ?? "photo.jpg", args.ElementAtOrDefault(2) ?? "image/jpeg");
        break;
    case "realtime":
        await RealtimeExample.RunAsync(Env.Client());
        break;
    case "webhook":
        await WebhookExample.RunAsync();
        break;
    default:
        Console.WriteLine("usage: dotnet run --project examples -- access|pagination|errors|upload|realtime|webhook");
        break;
}
