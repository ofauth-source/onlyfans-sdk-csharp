namespace OFAuth.Examples;

/// <summary>Upload a file and attach it to a message.</summary>
internal static class UploadExample
{
    public static async Task RunAsync(OFAuthClient client, string path, string contentType)
    {
        var bytes = await File.ReadAllBytesAsync(path);
        var result = await client.UploadMediaAsync(bytes, new UploadMediaOptions { Filename = Path.GetFileName(path),
            ContentType = contentType,
            OnProgress = (done, total) => Console.WriteLine($"uploaded {done}/{total} bytes"),
        });

        // Either an upload id (new file) or the vault media id (already in the vault).
        object mediaItem = result.AlreadyExists ? result.MediaId! : result.UploadId!;
        Console.WriteLine($"{result.Status}: {mediaItem}");

        // await client.Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
        // {
        //     UserId = "123",
        //     Body = new MessageContent { Text = "New photo", MediaItems = new List<object?> { mediaItem } },
        // });
    }
}
