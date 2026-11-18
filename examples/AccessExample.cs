namespace OFAuth.Examples;

/// <summary>Typed Access operations: client.Access.{Namespace}.{Method}Async.</summary>
internal static class AccessExample
{
    public static async Task RunAsync(OFAuthClient client)
    {
        var profile = await client.Access.Profile.GetAsync();
        Console.WriteLine($"@{profile.Username} ({profile.Name})");

        var chats = await client.Access.Chats.ListAsync(new AccessChatsListParams { Limit = 5 });
        foreach (var chat in chats.Items)
        {
            Console.WriteLine($"Chat with user {chat.User.Id}, unread: {chat.UnreadCount ?? 0}");
        }

        if (chats.Items.FirstOrDefault() is { } first)
        {
            var userId = first.User.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var messages = await client.Access.Chats.Messages.ListAsync(new AccessChatsMessagesListParams { UserId = userId, Limit = 3 });
            Console.WriteLine($"{messages.Items.Count} recent messages");

            // Sending needs the messages:write scope.
            // await client.Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
            // {
            //     UserId = userId,
            //     Body = new MessageContent { Text = "Thanks for subscribing!" },
            // });
        }

        // Linked accounts of the authorization (no x-linked-account-id needed).
        var accounts = await client.LinkedAccounts.ListAsync();
        foreach (var account in accounts.Data) Console.WriteLine($"{account.Id}: {account.DisplayName}");

        // Another linked account of the same authorization.
        if (accounts.Data.Count > 1)
        {
            var other = client.WithLinkedAccount(accounts.Data[1].Id);
            Console.WriteLine($"Second account: @{(await other.Access.Profile.GetAsync()).Username}");
        }
    }
}
