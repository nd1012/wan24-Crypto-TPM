using System.Runtime;
using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM2 extension methods
    /// </summary>
    public static class TpmExtensions
    {
        /// <summary>
        /// Get the <c>wan24-Crypto</c> MAC algorithm (without TPM!) ID of the TPM HMAC algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Algorithm ID or <c>-1</c>, if not supported</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static int GetMacAlgorithmId(this TpmAlgId algo) => algo switch
        {
            TpmAlgId.Sha1 => MacHmacSha1Algorithm.ALGORITHM_VALUE,
            TpmAlgId.Sha256 => MacHmacSha256Algorithm.ALGORITHM_VALUE,
            TpmAlgId.Sha384 => MacHmacSha384Algorithm.ALGORITHM_VALUE,
            TpmAlgId.Sha512 => MacHmacSha512Algorithm.ALGORITHM_VALUE,
            _ => -1
        };

        /// <summary>
        /// Get the MAC length of the TPM HMAC algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>MAC length in byte</returns>
        /// <exception cref="ArgumentException">Invalid algorithm</exception>
        [TargetedPatchingOptOut("Tiny method")]
        public static int GetMacLength(this TpmAlgId algo) => algo switch
        {
            TpmAlgId.Sha1 => MacTpmHmacSha1Algorithm.MAC_LENGTH,
            TpmAlgId.Sha256 => MacTpmHmacSha256Algorithm.MAC_LENGTH,
            TpmAlgId.Sha384 => MacTpmHmacSha384Algorithm.MAC_LENGTH,
            TpmAlgId.Sha512 => MacTpmHmacSha512Algorithm.MAC_LENGTH,
            _ => throw new ArgumentException($"Invalid algorithm {algo}", nameof(algo))
        };

        /// <summary>
        /// Get the <c>wan24-Crypto</c> MAC algorithm (without TPM!) name of the TPM HMAC algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Name</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static string? GetMacAlgorithmName(this TpmAlgId algo) => GetMacAlgorithm(algo)?.Name;

        /// <summary>
        /// Get the <c>wan24-Crypto</c> MAC algorithm (without TPM!) of the TPM HMAC algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Algorithm</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static MacAlgorithmBase? GetMacAlgorithm(this TpmAlgId algo)
        {
            int value = GetMacAlgorithmId(algo);
            return value == -1 ? null : MacHelper.GetAlgorithm(value);
        }

        /// <summary>
        /// Encrypt a private key suite protected using TPM
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <param name="algo">TPM HMAC algorithm</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="tpmOptions">Options</param>
        /// <returns>Cipher data</returns>
        public static byte[] TpmEncrypt(
            this PrivateKeySuite suite,
            in byte[] key,
            in CryptoOptions? options = null,
            in TpmAlgId? algo = null,
            Tpm2? engine = null,
            in Tpm2Options? tpmOptions = null
            )
        {
            bool disposeEngine = engine is null;
            engine ??= Tpm2Helper.CreateEngine(tpmOptions);
            try
            {
                using SecureByteArrayRefStruct tpmKey = new(
                    Tpm2Helper.Hmac(key, algo ?? Tpm2Helper.GetDigestAlgorithm(Tpm2Helper.GetMaxDigestSize(engine, tpmOptions)), key: null, engine, tpmOptions)
                    );
                return suite.Encrypt(tpmKey, options);
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("Failed to encypt private key suite using TPM2", ex);
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Enable creating a MAC 8using the max. supported TPM HMAC algorithm, if no algorithm was given)
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">TPM HMAC algorithm</param>
        /// <param name="included">Included in the header?</param>
        /// <param name="forceCoverWhole">Force the MAC to cover the whole data?</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="tpmOptions">TPM options (for creating an engine only, if required)</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithTpmHmac(
            this CryptoOptions options, 
            in TpmAlgId? algo = null,
            in bool included = true, 
            in bool forceCoverWhole = false, 
            Tpm2? engine = null, 
            in Tpm2Options? tpmOptions = null
            )
        {
            bool disposeEngine = engine is null;
            string name;
            engine ??= Tpm2Helper.CreateEngine(tpmOptions);
            try
            {
                name = (algo ?? Tpm2Helper.GetDigestAlgorithm(Tpm2Helper.GetMaxDigestSize(engine, tpmOptions))).GetMacAlgorithmName()
                    ?? throw CryptographicException.From("No registered matching HMAC algorithm found", new NotSupportedException());
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
            return options.WithMac(name, included, forceCoverWhole);
        }

        /// <summary>
        /// Create a HMAC
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="algo">HMAC algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmac(this byte[] data, TpmAlgId? algo = null, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, algo, key, engine, options);

        /// <summary>
        /// Create a HMAC
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="algo">HMAC algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmac(this Span<byte> data, TpmAlgId? algo = null, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, algo, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-1
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-1</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha1(this byte[] data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha1, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-256
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-256</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha256(this byte[] data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha256, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-384
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-384</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha384(this byte[] data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha384, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-512
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-512</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha512(this byte[] data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha512, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-1
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-1</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha1(this Span<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha1, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-256
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-256</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha256(this Span<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha256, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-384
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-384</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha384(this Span<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha384, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-512
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-512</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha512(this Span<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha512, key, engine, options);

        /// <summary>
        /// Create a HMAC
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="algo">HMAC algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmac(this ReadOnlySpan<byte> data, TpmAlgId? algo = null, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, algo, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-1
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-1</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha1(this ReadOnlySpan<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha1, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-256
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-256</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha256(this ReadOnlySpan<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha256, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-384
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-384</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha384(this ReadOnlySpan<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha384, key, engine, options);

        /// <summary>
        /// Create a HMAC-SHA-512
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC-SHA-512</returns>
        [TargetedPatchingOptOut("Just a method adapter")]
        public static byte[] TpmHmacSha512(this ReadOnlySpan<byte> data, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
            => Tpm2Helper.Hmac(data, TpmAlgId.Sha512, key, engine, options);
    }
}
