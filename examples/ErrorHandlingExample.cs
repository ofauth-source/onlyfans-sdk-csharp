namespace OFAuth.Examples;

/// <summary>Branch on the recovery action of OFAuthApiException.</summary>
internal static class ErrorHandlingExample
{
    public static async Task RunAsync(OFAuthClient client)
    {
        try
        {
            await client.Access.Profile.GetAsync();
            Console.WriteLine("OK");
        }
        catch (OFAuthApiException ex)
        {
            // Retryable errors (429, 502-504) were already retried MaxRetries times; Attempts says how many.
            Console.WriteLine($"{ex.StatusCode} {ex.Code} in {ex.Operation} after {ex.Attempts} attempt(s) (request {ex.RequestId})");
            if (ex.NeedsReconnect)
            {
                Console.WriteLine("Ask the creator to reconnect this account in OFAuth.");
            }
            else if (ex.NeedsReauthorization)
            {
                // missing_scope / additional_consent_required: ask for exactly what is missing.
                Console.WriteLine($"Authorize again with: {string.Join(" ", Scopes.Missing(ex))}");
            }
            else if (ex.NeedsTokenRefresh)
            {
                Console.WriteLine("The access token expired: refresh it through your auth system.");
            }
            else if (ex.IsRetryable)
            {
                Console.WriteLine($"Retry after {ex.RetryAfter?.TotalSeconds ?? 1} seconds.");
            }
            else if (ex.IsIntegrationProblem)
            {
                Console.WriteLine($"Fix the integration in the OFAuth dashboard: {ex.RecoveryAction}");
            }
            else
            {
                Console.WriteLine($"Unhandled ({ex.RecoveryActionKind}): {ex.Message}");
            }
        }
        catch (OFAuthOAuthException ex) when (ex.NeedsReauthorization)
        {
            // invalid_grant from OFAuthLink.RefreshAsync: the refresh token is gone; authorize again.
            Console.WriteLine("Authorization expired or revoked; send the user through Link again.");
        }
        catch (OFAuthConnectionException ex)
        {
            Console.WriteLine($"No response after {ex.Attempts} attempt(s){(ex.IsTimeout ? " (timeout)" : "")}: {ex.Message}");
        }
        catch (OFAuthException ex)
        {
            // Local errors, e.g. no linked account configured.
            Console.WriteLine(ex.Message);
        }
    }
}
