using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// Process secret (requires a TPM)
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="engine">Engine (should be <see langword="null"/>, if <c>tpmOptions</c> are given)</param>
    /// <param name="value">Raw value (will be cleared!)</param>
    /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
    /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
    /// <param name="tpmOptions">TPM options</param>
    /// <param name="options">Options (will be cleared!)</param>
    public sealed class TpmProcessSecret(
        in Tpm2Engine? engine,
        in byte[] value,
        in TimeSpan? encryptTimeout = null,
        in TimeSpan? recryptTimeout = null,
        in Tpm2Options? tpmOptions = null,
        in CryptoOptions? options = null
        )
        : BasicAllDisposableBase()
    {
        /// <summary>
        /// Value
        /// </summary>
        private readonly TpmSecuredValue _Value = tpmOptions is null
            ? new(engine ?? throw new ArgumentNullException(nameof(engine)), value, encryptTimeout, recryptTimeout, options)
            : new(value, encryptTimeout, recryptTimeout, tpmOptions, options);

        /// <summary>
        /// Value (will/should be cleared!)
        /// </summary>
        public byte[] Value
        {
            get => IfUndisposed(() => _Value.Value);
            set => IfUndisposed(() => _Value.Value = value);
        }

        /// <summary>
        /// Get a storable value
        /// </summary>
        /// <returns>Storable value</returns>
        public byte[] GetStorableValue()
        {
            EnsureUndisposed();
            using SecureByteArray secureValue = new(Value);
            return TpmValueProtection.Protect(secureValue.Array, ValueProtection.Scope.Process);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => _Value.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await _Value.DisposeAsync().DynamicContext();

        /// <summary>
        /// Create from stored value
        /// </summary>
        /// <param name="engine">Engine (should be <see langword="null"/>, if <c>tpmOptions</c> are given)</param>
        /// <param name="value">Stored value</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <returns>Instance</returns>
        public static TpmProcessSecret FromStoredValue(
            in Tpm2Engine? engine,
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in Tpm2Options? tpmOptions = null,
            in CryptoOptions? options = null
            )
            => new(engine, TpmValueProtection.Unprotect(value, ValueProtection.Scope.Process), encryptTimeout, recryptTimeout, tpmOptions, options);
    }
}
