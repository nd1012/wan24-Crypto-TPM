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
        /// Dispose the TPM engine, when disposing?
        /// </summary>
        private readonly bool DisposeEngine = false;
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
        /// TPM engine
        /// </summary>
        private readonly Tpm2Engine? TpmEngine = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="engine">Engine (will be disposed per default!)</param>
        /// <param name="options">Options (for creating a new engine)</param>
        /// <param name="disposeEngine">Dispose the given TPM engine when disposing?</param>
        public TpmRng(in Tpm2? engine = null, in Tpm2Options? options = null, in bool disposeEngine = true) : base(asyncDisposing: false)
        {
            DisposeEngine = engine is null || disposeEngine;
            Engine = engine ?? Tpm2Helper.CreateEngine(options);
            LengthRestriction = Tpm2Helper.GetMaxDigestSize(Engine);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="engine">Engine (won't be disposed, but used for locking when generating random data)</param>
        public TpmRng(in Tpm2Engine engine) : base(asyncDisposing: false)
        {
            TpmEngine = engine;
            Engine = engine.TPM;
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
            await FillAsync(buffer, cancellationToken).DynamicContext();
            return buffer;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Sync.Dispose();
            if (DisposeEngine) Engine.Dispose();
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
            using SemaphoreSyncContext? ssc = TpmEngine?.Sync.SyncContext();
            for (int index = 0; index != buffer.Length; cancellationToken.ThrowIfCancellationRequested())
            {
                rnd = Tpm2Helper.CreateRandomData(Math.Min(LengthRestriction, buffer.Length - index), Engine);
                rndSpan = rnd.AsSpan();
                rndSpan.CopyTo(buffer[index..]);
                index += rnd.Length;
                rndSpan.Clear();
            }
        }

        /// <summary>
        /// Fill a buffer with random data
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private async Task FillAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            byte[] rnd;
            Memory<byte> rndMemory;
            using SemaphoreSyncContext? ssc = TpmEngine is null ? null : await TpmEngine.Sync.SyncContextAsync(cancellationToken).DynamicContext();
            for (int index = 0; index != buffer.Length; cancellationToken.ThrowIfCancellationRequested())
            {
                rnd = Tpm2Helper.CreateRandomData(Math.Min(LengthRestriction, buffer.Length - index), Engine);
                rndMemory = rnd.AsMemory();
                rndMemory.CopyTo(buffer[index..]);
                index += rnd.Length;
                rndMemory.Span.Clear();
            }
        }
    }
}
