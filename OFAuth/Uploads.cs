// Media uploads: start an upload, PUT each part, then finalize.
// Copied from scripts/templates/csharp by scripts/generate-csharp.mjs.
#nullable enable

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OFAuth;

/// <summary>Options for <see cref="OFAuthClient.UploadMediaAsync(byte[], UploadMediaOptions, CancellationToken)"/>.</summary>
public sealed class UploadMediaOptions
{
    /// <summary>Original file name, including its extension. Required.</summary>
    public required string Filename { get; init; }

    /// <summary>MIME type, e.g. <c>image/jpeg</c> or <c>video/mp4</c>. Required.</summary>
    public required string ContentType { get; init; }

    /// <summary>Linked account to upload to. Defaults to the client's.</summary>
    public string? LinkedAccountId { get; init; }

    /// <summary>File hash used to find media already in the vault. Defaults to the MD5 hex digest of the file.</summary>
    public string? Etag { get; init; }

    /// <summary>Also save the upload to the vault (and optionally a vault list).</summary>
    public UploadVaultTarget? VaultUpload { get; init; }

    /// <summary>Called after each part with (uploaded bytes, total bytes).</summary>
    public Action<long, long>? OnProgress { get; init; }
}

/// <summary>Where to save an upload in the vault.</summary>
public sealed class UploadVaultTarget
{
    /// <summary>Vault owner user id.</summary>
    [JsonPropertyName("userId")]
    public required string UserId { get; init; }

    /// <summary>Vault list to add the media to.</summary>
    [JsonPropertyName("listId")]
    public long? ListId { get; init; }
}

/// <summary>Result of an upload.</summary>
public sealed class UploadMediaResult
{
    /// <summary><c>already_exists</c> (nothing was uploaded) or <c>uploaded</c>.</summary>
    public required string Status { get; init; }

    /// <summary>True when the file was already in the vault.</summary>
    public bool AlreadyExists => Status == "already_exists";

    /// <summary>For <c>already_exists</c>: the vault media (the start response's <c>media</c>).</summary>
    public MediaAsset? Media { get; init; }

    /// <summary>For <c>already_exists</c>: the vault media id. Use it in <c>mediaItems</c>.</summary>
    public long? MediaId { get; init; }

    /// <summary>For <c>uploaded</c>: the upload id. Use it in <c>mediaItems</c> for posts, messages, and stories.</summary>
    public string? UploadId { get; init; }

    /// <summary>For <c>uploaded</c>: the finalize response, with vault media when VaultUpload was set.</summary>
    public AccessUploadsFinalizeResponse? Finalize { get; init; }

    /// <summary>
    /// For <c>uploaded</c> with <see cref="UploadMediaOptions.VaultUpload"/>: the numeric vault media ids created by
    /// finalize (e.g. to hide them later with <c>Access.Vault.Media.HideAsync</c>). Empty otherwise.
    /// </summary>
    public IReadOnlyList<long> VaultMediaIds { get; init; } = Array.Empty<long>();
}

/// <summary>Upload helpers.</summary>
public static class Uploads
{
    /// <summary>MD5 hex digest (lowercase), the default upload etag.</summary>
    public static string Md5Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();

    internal static async Task<UploadMediaResult> UploadMediaAsync(
        ApiTransport transport,
        byte[] data,
        UploadMediaOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Filename)) throw new OFAuthException("UploadMediaAsync needs a Filename");
        if (string.IsNullOrEmpty(options.ContentType)) throw new OFAuthException("UploadMediaAsync needs a ContentType");

        var startBody = new Dictionary<string, object>
        {
            ["filename"] = options.Filename,
            ["etag"] = options.Etag ?? Md5Hex(data),
            ["size"] = data.LongLength,
            ["contentType"] = options.ContentType,
        };
        var start = await transport.SendAsync<JsonElement>(
            new ApiRequest(HttpMethod.Post, "/v3/access/uploads/start")
            {
                Operation = "access.uploads.start",
                RequiredScope = Scopes.VaultWrite,
                LinkedAccount = true,
                LinkedAccountId = options.LinkedAccountId,
                Body = startBody,
            },
            cancellationToken).ConfigureAwait(false);

        var status = ApiTransport.GetString(start, "status");
        if (status == "already_exists")
        {
            var media = start.TryGetProperty("media", out var m) && m.ValueKind == JsonValueKind.Object ? m : (JsonElement?)null;
            return new UploadMediaResult
            {
                Status = "already_exists",
                Media = media is { } raw ? TryDeserialize<MediaAsset>(raw) : null,
                MediaId = media is { } mm && mm.TryGetProperty("id", out var id) ? AsInt64(id) : null,
            };
        }
        var uploadId = ApiTransport.GetString(start, "uploadId");
        if (status != "needs_upload" || uploadId is null)
        {
            throw new OFAuthException($"Unexpected upload start status: {status ?? "(none)"}");
        }

        // Part PUTs move the bytes: allow at least five minutes each.
        var partTimeout = transport.Timeout == Timeout.InfiniteTimeSpan || transport.Timeout > OFAuthDefaults.UploadPartTimeout
            ? transport.Timeout
            : OFAuthDefaults.UploadPartTimeout;
        long uploaded = 0;
        if (start.TryGetProperty("parts", out var parts) && parts.ValueKind == JsonValueKind.Array)
        {
            foreach (var part in parts.EnumerateArray())
            {
                var uploadUrl = new Uri(ApiTransport.GetString(part, "uploadUrl")
                    ?? throw new OFAuthException("Upload part has no uploadUrl"));
                var range = part.GetProperty("byteRange");
                var first = range.GetProperty("start").GetInt64();
                var last = range.GetProperty("end").GetInt64();
                if (first < 0 || last < first || last >= data.LongLength)
                {
                    throw new OFAuthException($"Upload part byte range {first}-{last} is outside the file");
                }
                var length = (int)(last - first + 1);
                using var content = new ByteArrayContent(data, (int)first, length);
                content.Headers.ContentType = MediaTypeHeaderValue.Parse(options.ContentType);
                await transport.SendRawAsync(
                    new ApiRequest(HttpMethod.Put, uploadUrl.AbsolutePath)
                    {
                        Url = uploadUrl,
                        RawContent = content,
                        Timeout = partTimeout,
                        RequiredScope = Scopes.VaultWrite,
                        LinkedAccount = true,
                        LinkedAccountId = options.LinkedAccountId,
                    },
                    cancellationToken).ConfigureAwait(false);
                uploaded += length;
                options.OnProgress?.Invoke(uploaded, data.LongLength);
            }
        }

        var finalizeBody = new Dictionary<string, object> { ["uploadIds"] = new[] { uploadId } };
        if (options.VaultUpload is not null) finalizeBody["vaultUpload"] = options.VaultUpload;
        var finalize = await transport.SendAsync<JsonElement>(
            new ApiRequest(HttpMethod.Post, "/v3/access/uploads/finalize")
            {
                Operation = "access.uploads.finalize",
                RequiredScope = Scopes.VaultWrite,
                LinkedAccount = true,
                LinkedAccountId = options.LinkedAccountId,
                Body = finalizeBody,
            },
            cancellationToken).ConfigureAwait(false);
        return new UploadMediaResult
        {
            Status = "uploaded",
            UploadId = uploadId,
            Finalize = finalize.ValueKind == JsonValueKind.Object ? TryDeserialize<AccessUploadsFinalizeResponse>(finalize) : null,
            VaultMediaIds = VaultMediaIds(finalize),
        };
    }

    /// <summary>
    /// The vault media ids in a finalize response: <c>uploads[].mediaId</c> (or <c>uploads[].media.id</c>), else
    /// <c>mediaIds[]</c>, else <c>media[].id</c>. Duplicates are dropped.
    /// </summary>
    internal static IReadOnlyList<long> VaultMediaIds(JsonElement finalize)
    {
        var ids = new List<long>();
        void Add(long? id)
        {
            if (id is { } value && !ids.Contains(value)) ids.Add(value);
        }
        if (finalize.ValueKind != JsonValueKind.Object) return ids;
        if (finalize.TryGetProperty("uploads", out var uploads) && uploads.ValueKind == JsonValueKind.Array)
        {
            foreach (var upload in uploads.EnumerateArray())
            {
                if (upload.ValueKind != JsonValueKind.Object) continue;
                if (upload.TryGetProperty("mediaId", out var mediaId) && AsInt64(mediaId) is { } direct) Add(direct);
                else if (upload.TryGetProperty("media", out var media) && media.ValueKind == JsonValueKind.Object
                    && media.TryGetProperty("id", out var nested)) Add(AsInt64(nested));
            }
        }
        if (ids.Count == 0 && finalize.TryGetProperty("mediaIds", out var mediaIds) && mediaIds.ValueKind == JsonValueKind.Array)
        {
            foreach (var id in mediaIds.EnumerateArray()) Add(AsInt64(id));
        }
        if (ids.Count == 0 && finalize.TryGetProperty("media", out var mediaList) && mediaList.ValueKind == JsonValueKind.Array)
        {
            foreach (var media in mediaList.EnumerateArray())
            {
                if (media.ValueKind == JsonValueKind.Object && media.TryGetProperty("id", out var id)) Add(AsInt64(id));
            }
        }
        return ids;
    }

    // Ids are numbers in the spec; accept integral doubles and numeric strings too.
    private static long? AsInt64(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Number)
        {
            if (value.TryGetInt64(out var integer)) return integer;
            var number = value.GetDouble();
            return number == Math.Floor(number) && Math.Abs(number) < 9e15 ? (long)number : null;
        }
        return value.ValueKind == JsonValueKind.String && long.TryParse(value.GetString(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    }

    // The typed view is best effort: an unexpected shape leaves it null instead of failing a finished upload.
    private static T? TryDeserialize<T>(JsonElement value) where T : class
    {
        try
        {
            return value.Deserialize<T>(ApiTransport.JsonOptions);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException or FormatException or OverflowException)
        {
            return null;
        }
    }
}
