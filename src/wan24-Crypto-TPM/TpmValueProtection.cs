using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM value protection
    /// </summary>
    public static class TpmValueProtection
    {
        /// <summary>
        /// Protect a value
        /// </summary>
        /// <param name="value">Value to protect</param>
        /// <param name="scope">Scope</param>
        /// <returns>Protected value</returns>
        public static byte[] Protect(byte[] value, ValueProtection.Scope scope = ValueProtection.Scope.Process)
        {
            using SecureByteArrayRefStruct key = new(ValueProtection.GetScopeKey(scope));
            using SemaphoreSyncContext? ssc = Tpm2Helper.DefaultEngine is null ? null : Tpm2Helper.DefaultEngineSync.SyncContext();
            using SecureByteArrayRefStruct tpmKey = new(Tpm2Helper.Hmac(key));
            ssc?.Dispose();
            return value.Encrypt(tpmKey);
        }

        /// <summary>
        /// Unprotect a value
        /// </summary>
        /// <param name="protectedValue">Protected value</param>
        /// <param name="scope">Scope</param>
        /// <returns>Unprotected value</returns>
        public static byte[] Unprotect(byte[] protectedValue, ValueProtection.Scope scope = ValueProtection.Scope.Process)
        {
            using SecureByteArrayRefStruct key = new(ValueProtection.GetScopeKey(scope));
            using SemaphoreSyncContext? ssc = Tpm2Helper.DefaultEngine is null ? null : Tpm2Helper.DefaultEngineSync.SyncContext();
            using SecureByteArrayRefStruct tpmKey = new(Tpm2Helper.Hmac(key));
            ssc?.Dispose();
            return protectedValue.Decrypt(tpmKey);
        }

        /// <summary>
        /// Enable the <see cref="TpmValueProtection"/> handlers as default protect/unprotect handlers for <see cref="ValueProtection"/>
        /// </summary>
        public static void Enable()
        {
            ValueProtection.Protect = Protect;
            ValueProtection.Unprotect = Unprotect;
        }
    }
}
