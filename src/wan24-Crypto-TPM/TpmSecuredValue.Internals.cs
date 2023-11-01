using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    // Internals
    public partial class TpmSecuredValue
    {
        /// <summary>
        /// Encrypt timer
        /// </summary>
        private readonly System.Timers.Timer EncryptTimer = null!;
        /// <summary>
        /// Recrypt timer
        /// </summary>
        private readonly System.Timers.Timer RecryptTimer = null!;
        /// <summary>
        /// Thread synchronization
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// Engine
        /// </summary>
        private readonly Tpm2? Engine = null;
        /// <summary>
        /// Raw value
        /// </summary>
        private SecureByteArray? RawValue;
        /// <summary>
        /// Encrypted value
        /// </summary>
        private SecureByteArray? EncryptedValue = null;
        /// <summary>
        /// Encryption key
        /// </summary>
        private SecureByteArray? EncryptionKey = null;

        /// <summary>
        /// Encrypt
        /// </summary>
        protected virtual void Encrypt()
        {
            using SemaphoreSyncContext ssc = Sync;
            if (RawValue is null) return;
            EncryptedSince = DateTime.Now;
            EncryptTimer.Stop();
            EncryptionKey = new(RND.GetBytes(MacHmacSha512Algorithm.MAC_LENGTH));
            if (Engine is null)
            {
                using SecureByteArray rawValue = RawValue;
                EncryptedValue = new(rawValue!.Array.Encrypt(EncryptionKey, Options));
            }
            else
            {
                using SecureByteArrayRefStruct key = new(Tpm2Helper.Hmac(EncryptionKey, engine: Engine));
                using SecureByteArray rawValue = RawValue;
                EncryptedValue = new(rawValue!.Array.Encrypt(key, Options));
            }
            RawValue = null;
            RecryptTimer.Start();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <returns>Value (should be cleared!)</returns>
        protected virtual byte[] Decrypt()
        {
            if (RawValue is not null) return RawValue.Array.CloneArray();
            if (EncryptTimeout == TimeSpan.Zero)
                return EncryptedValue!.Array.Decrypt(EncryptionKey!, Options);
            EncryptedSince = DateTime.MinValue;
            RecryptTimer.Stop();
            try
            {
                using SecureByteArray encryptedValue = EncryptedValue!;
                using SecureByteArray encryptionKey = EncryptionKey!;
                if (Engine is null)
                {
                    RawValue = new(EncryptedValue!.Array.Decrypt(encryptionKey, Options));
                }
                else
                {
                    using SecureByteArrayRefStruct key = new(Tpm2Helper.Hmac(encryptionKey, engine: Engine));
                    RawValue = new(EncryptedValue!.Array.Decrypt(key, Options));
                }
                EncryptedValue = null;
                EncryptionKey = null;
                return RawValue.Array.CloneArray();
            }
            finally
            {
                EncryptTimer.Start();
            }
        }

        /// <summary>
        /// Re-crypt
        /// </summary>
        protected virtual void Recrypt()
        {
            using SemaphoreSyncContext ssc = Sync;
            if (RawValue is not null) return;
            RecryptTimer.Stop();
            using SecureByteArrayRefStruct rawValue = new(EncryptedValue!.Array.Decrypt(EncryptionKey!, Options));
            {
                EncryptionKey!.Dispose();
                EncryptedValue.Dispose();
                EncryptionKey = new(RND.GetBytes(MacHmacSha512Algorithm.MAC_LENGTH));
                if (Engine is null)
                {
                    EncryptedValue = new(rawValue.Array.Encrypt(EncryptionKey, Options));
                }
                else
                {
                    using SecureByteArrayRefStruct key = new(Tpm2Helper.Hmac(EncryptionKey, engine: Engine));
                    EncryptedValue = new(rawValue.Array.Encrypt(key, Options));
                }
            }
            RecryptTimer.Start();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            TpmSecuredValueTable.Values.TryRemove(GUID, out _);
            using System.Timers.Timer? encryptTimer = EncryptTimer;
            using System.Timers.Timer? recryptTimer = RecryptTimer;
            using SemaphoreSync sync = Sync;
            using SemaphoreSyncContext ssc = sync;
            using SecureByteArray? encryptedValue = EncryptedValue;
            using SecureByteArray? encryptionKey = EncryptionKey;
            using SecureByteArray? rawValue = RawValue;
            using Tpm2? engine = Engine;
            RecryptTimer?.Stop();
            EncryptTimer?.Stop();
            Options?.Clear();
        }
    }
}
