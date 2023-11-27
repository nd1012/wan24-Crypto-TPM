using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// Synchronized TPM2 engine (needs to be disposed, first, before creating another instance)
    /// </summary>
    public sealed class Tpm2Engine : DisposableBase
    {
        /// <summary>
        /// Synchronization
        /// </summary>
        private static readonly SemaphoreSync GlobalSync = new();

        /// <summary>
        /// Synchronization context
        /// </summary>
        private readonly SemaphoreSyncContext SyncContext;
        /// <summary>
        /// Dispose the engine?
        /// </summary>
        private readonly bool DisposeEngine = true;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        public Tpm2Engine(in Tpm2Options? options = null):base(asyncDisposing: false)
        {
            if (Tpm2Helper.DefaultEngine is null) throw new InvalidOperationException("Tpm2Helper.DefaultEngine is NULL");
            Sync = Tpm2Helper.DefaultEngineSync;
            SyncContext = default;
            Options = Tpm2Helper.GetDefaultOptions(options);
            TPM = Tpm2Helper.DefaultEngine;
            DisposeEngine = false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="syncContext">Synchronization context</param>
        /// <param name="options">Options</param>
        private Tpm2Engine(in SemaphoreSyncContext syncContext, in Tpm2Options? options) : base(asyncDisposing: false)
        {
            Sync = new();
            SyncContext = syncContext;
            try
            {
                Options = Tpm2Helper.GetDefaultOptions(options);
                TPM = Tpm2Helper.CreateEngine(Options);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Options
        /// </summary>
        public Tpm2Options Options { get; }

        /// <summary>
        /// TPM
        /// </summary>
        public Tpm2 TPM { get; } = null!;

        /// <summary>
        /// Thread synchronization
        /// </summary>
        public SemaphoreSync Sync { get; } = new();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (!DisposeEngine) return;
            Sync.Dispose();
            TPM?.Dispose();
            SyncContext.Dispose();
        }

        /// <summary>
        /// Cast as TPM2 instance
        /// </summary>
        /// <param name="engine">Engine</param>
        public static implicit operator Tpm2(in Tpm2Engine engine) => engine.TPM;

        /// <summary>
        /// Cast as TPM2 options
        /// </summary>
        /// <param name="engine">Engine</param>
        public static implicit operator Tpm2Options(in Tpm2Engine engine) => engine.Options;

        /// <summary>
        /// Create an instance
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Instance (needs to be disposed, first, before creating another instance)</returns>
        public static Tpm2Engine Create(in Tpm2Options? options = null, in CancellationToken cancellationToken = default) => new(GlobalSync.SyncContext(cancellationToken), options);

        /// <summary>
        /// Create an instance
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Instance (needs to be disposed, first, before creating another instance)</returns>
        public static async Task<Tpm2Engine> CreateAsync(Tpm2Options? options = null, CancellationToken cancellationToken = default)
            => new(await GlobalSync.SyncContextAsync(cancellationToken).DynamicContext(), options);
    }
}
