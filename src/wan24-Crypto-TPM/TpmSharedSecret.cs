using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM protected shared secret (should be used as an only short living helper)
    /// </summary>
    public class TpmSharedSecret : SharedSecret
    {
        /// <summary>
        /// TPM options
        /// </summary>
        private readonly Tpm2Options TpmOptions = null!;
        /// <summary>
        /// Dispose the engine?
        /// </summary>
        private readonly bool DisposeEngine;
        /// <summary>
        /// Engine
        /// </summary>
        protected readonly Tpm2 Engine = null!;
        /// <summary>
        /// Internal secret
        /// </summary>
        protected readonly SecureByteArray InternalSecret = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="token">Token (will be cleared)</param>
        /// <param name="key">Key (will be cleared)</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options with MAC algorithm (won't be cleared)</param>
        public TpmSharedSecret(
            in byte[] token,
            in byte[]? key = null,
            in Tpm2? engine = null,
            in Tpm2Options? tpmOptions = null,
            in CryptoOptions? options = null
            )
            : base(options)
        {
            DisposeEngine = engine is null;
            try
            {
                if (key is null) Token = new(token);
                TpmOptions = Tpm2Helper.GetDefaultOptions(tpmOptions);
                Engine = engine ?? Tpm2Helper.CreateEngine(TpmOptions);
                Algorithm = TpmOptions.Algorithm ?? Tpm2Helper.GetDigestAlgorithm(Tpm2Helper.GetMaxDigestSize(Engine, TpmOptions));
                InternalSecret = new(Tpm2Helper.Hmac(token, Algorithm, key, Engine, TpmOptions));
                Secret = new(InternalSecret.Array.Mac(token, options).Xor(InternalSecret.Array));
                if (key is not null) Token = new(token.Mac(key, options));
            }
            catch
            {
                if (key is not null) token.Clear();
                Dispose();
                throw;
            }
            finally
            {
                key?.Clear();
            }
        }

        /// <summary>
        /// Used TPM HMAC algorithm
        /// </summary>
        public TpmAlgId Algorithm { get; }

        /// <summary>
        /// Protect the remote secret using a secret
        /// </summary>
        /// <param name="remoteSecret">Remote secret (size in byte must be equal to the used TPM HMAC algorithm digest size; will be overwritten!)</param>
        /// <returns>Protected remote secret (should be stored at the remote key storage and later received by authenticating with the shared secret)</returns>
        public override byte[] ProtectRemoteSecret(in byte[] remoteSecret)
        {
            EnsureUndisposed();
            if (remoteSecret.Length != InternalSecret.Length) throw new ArgumentOutOfRangeException(nameof(remoteSecret));
            return remoteSecret.Xor(InternalSecret.Array);
        }

        /// <inheritdoc/>
        public override byte[] DeriveFinalSecretAndDispose(in byte[] remoteSecret)
        {
            try
            {
                EnsureUndisposed();
                return Tpm2Helper.Hmac(Token, Algorithm, ProtectRemoteSecret(remoteSecret), Engine, TpmOptions);
            }
            finally
            {
                remoteSecret.Clear();
                Dispose();
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            InternalSecret?.Dispose();
            if (DisposeEngine) Engine?.Dispose();
        }
    }
}
