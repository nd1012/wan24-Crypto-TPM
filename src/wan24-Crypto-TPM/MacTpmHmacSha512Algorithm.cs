using System.Security.Cryptography;
using Tpm2Lib;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// HMAC-SHA512 MAC algorithm
    /// </summary>
    public sealed record class MacTpmHmacSha512Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "TPMHMAC-SHA512";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 10;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 64;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "TPM HMAC SHA512";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacTpmHmacSha512Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public MacTpmHmacSha512Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacTpmHmacSha512Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new Tpm2HmacAlgorithm(TpmAlgId.Sha512, pwd);

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(MacTpmHmacSha512Algorithm), ALGORITHM_NAME);
    }
}
