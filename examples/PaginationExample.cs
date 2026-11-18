namespace OFAuth.Examples;

/// <summary>Iterate cursor-paginated operations with await foreach.</summary>
internal static class PaginationExample
{
    public static async Task RunAsync(OFAuthClient client)
    {
        // Every chat, fetching pages of 20 as needed; stop after 100.
        var count = 0;
        await foreach (var chat in client.Access.Chats.IterateAsync(new AccessChatsListParams { Limit = 20 }, maxItems: 100))
        {
            count++;
            Console.WriteLine($"{count}. user {chat.User.Id}");
        }

        // Linked accounts use data / next_cursor / has_more; the iterator handles both shapes.
        await foreach (var account in client.LinkedAccounts.IterateAsync())
        {
            Console.WriteLine($"{account.Id} granted at {account.GrantedAt}");
        }

        // Or page manually with the cursor.
        string? cursor = null;
        do
        {
            var page = await client.Access.Chats.ListAsync(new AccessChatsListParams { Limit = 50, Cursor = cursor });
            Console.WriteLine($"page with {page.Items.Count} chats");
            cursor = page.Page.HasMore ? page.Page.NextCursor : null;
        } while (cursor is not null);
    }
}
