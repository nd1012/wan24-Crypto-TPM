using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM RNG
    /// </summary>
    public sealed class TpmRng : DisposableRngBase
    {
        /// <summary>
        /// TPM engine
        /// </summary>
        private readonly Tpm2 Engine;
        /// <summary>
        /// Thread synchronization
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// TPM RNG length restriction
        /// </summary>
        private readonly int LengthRestriction;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="engine">Engine (will be disposed!)</param>
        /// <param name="options">Options (for creating a new engine)</param>
        public TpmRng(in Tpm2? engine = null, in Tpm2Options? options = null) : base(asyncDisposing: false)
        {
            Engine = engine ?? Tpm2Helper.CreateEngine(options);
            LengthRestriction = Tpm2Helper.GetMaxDigestSize(Engine);
        }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            if (buffer.Length == 0) return buffer;
            using SemaphoreSyncContext ssc = Sync;
            Fill(buffer, default);
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (buffer.Length == 0) return buffer;
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            Fill(buffer.Span, cancellationToken);
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Sync.Dispose();
            Engine.Dispose();
        }

        /// <summary>
        /// Fill a buffer with random data
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private void Fill(in Span<byte> buffer, in CancellationToken cancellationToken)
        {
            byte[] rnd;
            Span<byte> rndSpan;
            for (int index = 0; index != buffer.Length; cancellationToken.ThrowIfCancellationRequested())
            {
                rnd = Tpm2Helper.CreateRandomData(Math.Min(LengthRestriction, buffer.Length - index), Engine);
                rndSpan = rnd.AsSpan();
                rndSpan.CopyTo(buffer[index..]);
                index += rnd.Length;
                rndSpan.Clear();
            }
        }
    }
}
