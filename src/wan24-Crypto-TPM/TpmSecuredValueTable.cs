using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM secured value table
    /// </summary>
    public static class TpmSecuredValueTable
    {
        /// <summary>
        /// Values (key is the GUID)
        /// </summary>
        public static readonly ConcurrentChangeTokenDictionary<string, TpmSecuredValue> Values = new();
    }
}
