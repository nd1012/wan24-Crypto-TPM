using System.Collections.Concurrent;

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
        public static readonly ConcurrentDictionary<string, TpmSecuredValue> Values = new();
    }
}
