namespace OFAuth.Examples;

/// <summary>Listen to Realtime events for the client's linked account until Ctrl+C.</summary>
internal static class RealtimeExample
{
    public static async Task RunAsync(OFAuthClient client)
    {
        // Streams /v3/realtime/events (Server-Sent Events) on the client's BaseUrl origin.
        await using var realtime = client.Realtime();

        realtime.OnChatMessageReceived(e => Console.WriteLine($"message {e.Data.Id} (order {e.Order})"));
        realtime.OnChatTypingUpdated(e => Console.WriteLine("typing..."));
        realtime.OnEvent(e => Console.WriteLine($"event {e.Type}"));
        realtime.OnResync(() => Console.WriteLine("events were missed: refetch through the REST API"));
        realtime.OnClose(info => Console.WriteLine($"closed {info.Reason} ({info.Status}); reconnecting: {info.WillReconnect}"));
        realtime.OnError(error => Console.WriteLine($"error: {error.Message}"));

        try
        {
            await realtime.ConnectAsync();
        }
        catch (OFAuthApiException ex) when (ex.StatusCode == 503)
        {
            Console.WriteLine($"Realtime is unavailable; retry in {ex.RetryAfter?.TotalSeconds ?? 3}s.");
            return;
        }

        var stop = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stop.TrySetResult();
        };
        Console.WriteLine("Listening. Ctrl+C to stop.");
        await stop.Task;
        // Store realtime.LastEventId and pass it as RealtimeOptions.LastEventId to resume after a restart.
        Console.WriteLine($"Last event id: {realtime.LastEventId}");
    }
}
