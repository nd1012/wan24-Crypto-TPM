using System.Security.Cryptography;
using Tpm2Lib;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// HMAC-SHA256 MAC algorithm
    /// </summary>
    public sealed record class MacTpmHmacSha256Algorithm : MacAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "TPMHMAC-SHA256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 8;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "TPM HMAC SHA256";

        /// <summary>
        /// Static constructor
        /// </summary>
        static MacTpmHmacSha256Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private MacTpmHmacSha256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static MacTpmHmacSha256Algorithm Instance { get; }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override bool UsesTpm => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new Tpm2HmacAlgorithm(TpmAlgId.Sha256, pwd);

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(MacTpmHmacSha256Algorithm), ALGORITHM_NAME);
    }
}
