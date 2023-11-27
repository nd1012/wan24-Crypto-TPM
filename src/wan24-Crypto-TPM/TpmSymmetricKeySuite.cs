using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM secured symmetric key suite
    /// </summary>
    public record class TpmSymmetricKeySuite : SymmetricKeySuite
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Symmetric key (private!; will be cleared!)</param>
        /// <param name="identifier">Identifier (private!; will be cleared!)</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options with KDF settings (MAC algorithm will be set automatic; will be cleared!)</param>
        public TpmSymmetricKeySuite(
            in byte[] key, 
            in byte[]? identifier = null, 
            in Tpm2? engine = null, 
            in Tpm2Options? tpmOptions = null, 
            in CryptoOptions? options = null
            )
            : base(options)
        {
            try
            {
                if (identifier is null)
                {
                    ExpandedKey = new(InitKeyOnly(key, engine, tpmOptions));
                }
                else
                {
                    (byte[] expandedKey, Identifier) = InitKeyAndIdentifier(key, identifier, engine, tpmOptions);
                    ExpandedKey = new(expandedKey);
                }
            }
            catch (Exception ex)
            {
                Dispose();
                key.Clear();
                identifier?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("TPM symmetric key suite initialization failed", ex);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="engine">TPM engine (won't be disposed, but used for synchronizing TPM access)</param>
        /// <param name="key">Symmetric key (private!; will be cleared!)</param>
        /// <param name="identifier">Identifier (private!; will be cleared!)</param>
        /// <param name="options">Options with KDF settings (MAC algorithm will be set automatic; will be cleared!)</param>
        public TpmSymmetricKeySuite(
            in Tpm2Engine engine,
            in byte[] key,
            in byte[]? identifier = null,
            in CryptoOptions? options = null
            )
            : base(options)
        {
            try
            {
                using SemaphoreSyncContext ssc = engine.Sync;
                if (identifier is null)
                {
                    ExpandedKey = new(InitKeyOnly(key, engine, options: null));
                }
                else
                {
                    (byte[] expandedKey, Identifier) = InitKeyAndIdentifier(key, identifier, engine, options: null);
                    ExpandedKey = new(expandedKey);
                }
            }
            catch (Exception ex)
            {
                Dispose();
                key.Clear();
                identifier?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("TPM symmetric key suite initialization failed", ex);
            }
        }

        /// <summary>
        /// Constructor (not supported!)
        /// </summary>
        /// <param name="options"></param>
        /// <param name="identifier"></param>
        /// <param name="expandedKey"></param>
        public TpmSymmetricKeySuite(in CryptoOptions? options, in byte[]? identifier, in byte[] expandedKey) => throw new NotSupportedException();

        /// <summary>
        /// Constructor (not supported!)
        /// </summary>
        /// <param name="existing"></param>
        /// <param name="options"></param>
        public TpmSymmetricKeySuite(in ISymmetricKeySuite existing, in CryptoOptions? options = null) => throw new NotSupportedException();

        /// <summary>
        /// Replace the expanded key
        /// </summary>
        /// <param name="newExpandedKey">New expanded key (needs to fit the length of the existing expanded key value; will be cleared!)</param>
        public void ReplaceExpandedKey(in byte[] newExpandedKey)
        {
            EnsureUndisposed();
            if (newExpandedKey.Length != ExpandedKey.Length) throw new ArgumentOutOfRangeException(nameof(newExpandedKey));
            ExpandedKey.Dispose();
            ExpandedKey = new(newExpandedKey);
        }

        /// <summary>
        /// Initialize with only having a key
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">TPM options</param>
        /// <returns>Expanded key</returns>
        private byte[] InitKeyOnly(in byte[] key, Tpm2? engine, in Tpm2Options? options)
        {
            bool disposeEngine = engine is null;
            engine ??= Tpm2Helper.CreateEngine(options);
            try
            {
                byte[] mac = Tpm2Helper.Hmac(key, options?.Algorithm, key, engine, options);
                try
                {
                    Options.MacAlgorithm = Tpm2Helper.GetDigestAlgorithm(mac.Length).GetMacAlgorithmName();
                    return key.Stretch(mac.Length, mac, Options).Stretched;
                }
                finally
                {
                    mac.Clear();
                }
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Initialize with having a key and an identifier
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="identifier">Identifier</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">TPM options</param>
        /// <returns>Expanded key and identifier</returns>
        private (byte[] ExpandedKey, byte[] Identifier) InitKeyAndIdentifier(in byte[] key, in byte[] identifier, Tpm2? engine, in Tpm2Options? options)
        {
            bool disposeEngine = engine is null;
            engine ??= Tpm2Helper.CreateEngine(options);
            try
            {
                byte[] keyMac = Tpm2Helper.Hmac(key, options?.Algorithm, key, engine, options),
                    mac = null!;
                try
                {
                    Options.MacAlgorithm = Tpm2Helper.GetDigestAlgorithm(keyMac.Length).GetMacAlgorithmName();
                    mac = identifier.Mac(keyMac, Options);
                    return (key.Stretch(mac.Length, mac, Options).Stretched, mac);
                }
                catch
                {
                    mac?.Clear();
                    throw;
                }
                finally
                {
                    keyMac.Clear();
                }
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }
    }
}
