using System.Net.Sockets;
using static OFAuth.Test.FakeHandler;

namespace OFAuth.Test;

/// <summary>Only genuine network failures and the SDK's own timeout are wrapped and retried.</summary>
public class TransportFailureTests
{
    private sealed class PolicyRefusedException(string message) : Exception(message);

    /// <summary>Throws the next exception from the queue, then answers 200 with an empty object.</summary>
    private sealed class ThrowingHandler(params Exception[] errors) : HttpMessageHandler
    {
        private readonly Queue<Exception> _errors = new(errors);
        private int _calls;

        public int Calls => _calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            lock (_errors)
            {
                if (_errors.Count > 0) throw _errors.Dequeue();
            }
            return Task.FromResult(JsonResponse(new { id = 1 }));
        }
    }

    private static OFAuthClient Client(HttpMessageHandler handler) => new(new OFAuthClientOptions
    {
        AccessToken = "tok",
        LinkedAccountId = "conn_1",
        HttpClient = new HttpClient(handler),
        TimeProvider = new TestTime(),
    });

    [Fact]
    public async Task ACustomHandlerExceptionPropagatesUnchangedAndIsNotRetried()
    {
        var refusal = new PolicyRefusedException("blocked by policy");
        var handler = new ThrowingHandler(refusal, refusal, refusal);

        var error = await Assert.ThrowsAsync<PolicyRefusedException>(() => Client(handler).Access.Profile.GetAsync());

        Assert.Same(refusal, error);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task AHandlerOperationCanceledExceptionIsNotTreatedAsATimeout()
    {
        var cancelled = new OperationCanceledException("handler gave up");
        var handler = new ThrowingHandler(cancelled, cancelled, cancelled);

        var error = await Assert.ThrowsAsync<OperationCanceledException>(() => Client(handler).Access.Profile.GetAsync());

        Assert.Same(cancelled, error);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("io")]
    [InlineData("socket")]
    public async Task NetworkFailuresAreRetried(string kind)
    {
        Exception Make() => kind switch
        {
            "http" => new HttpRequestException("connection reset"),
            "io" => new IOException("broken pipe"),
            _ => new SocketException((int)SocketError.ConnectionRefused),
        };
        var handler = new ThrowingHandler(Make(), Make());

        await Client(handler).Access.Profile.GetAsync();

        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task NetworkFailuresAreWrappedAfterTheLastRetry()
    {
        var failure = new HttpRequestException("connection refused");
        var handler = new ThrowingHandler(failure, failure, failure);

        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() => Client(handler).Access.Profile.GetAsync());

        Assert.Equal(3, handler.Calls);
        Assert.Equal(3, error.Attempts);
        Assert.False(error.IsTimeout);
        Assert.Same(failure, error.InnerException);
    }

    [Fact]
    public async Task NetworkFailuresOnPostAreWrappedButNotRetried()
    {
        var handler = new ThrowingHandler(new HttpRequestException("reset"));

        var error = await Assert.ThrowsAsync<OFAuthConnectionException>(() =>
            Client(handler).Access.Chats.Messages.SendAsync(new AccessChatsMessagesSendParams
            {
                UserId = "1",
                Body = new MessageContent { Text = "hi" },
            }));

        Assert.Equal(1, handler.Calls);
        Assert.Equal(1, error.Attempts);
    }
}
