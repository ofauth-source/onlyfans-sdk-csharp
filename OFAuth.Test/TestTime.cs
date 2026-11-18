namespace OFAuth.Test;

/// <summary>
/// A clock for tests: <see cref="GetUtcNow"/> is settable and every timer (Task.Delay) fires immediately, recording its
/// due time, so retry waits never actually sleep.
/// </summary>
public sealed class TestTime : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public List<TimeSpan> Delays { get; } = new();

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        lock (Delays) Delays.Add(dueTime);
        ThreadPool.QueueUserWorkItem(_ => callback(state));
        return new NoopTimer();
    }

    private sealed class NoopTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
