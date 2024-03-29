﻿using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// Secure value (keeps a value encrypted using TPM after a timeout without any access, re-crypts from time to time; see 
    /// <see href="https://static.usenix.org/events/sec01/full_papers/gutmann/gutmann.pdf"/>)
    /// </summary>
    public class TpmSecuredValue<T> : TpmSecuredValue where T : class, IStreamSerializer, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <param name="requireTpm">Require a TPM?</param>
        public TpmSecuredValue(
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in Tpm2Options? tpmOptions = null,
            in CryptoOptions? options = null,
            in bool requireTpm = true
            )
            : base(value, encryptTimeout, recryptTimeout, tpmOptions, options, requireTpm)
        { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <param name="requireTpm">Require a TPM?</param>
        public TpmSecuredValue(
            in T value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in Tpm2Options? tpmOptions = null,
            in CryptoOptions? options = null,
            in bool requireTpm = true
            )
            : base(value.ToBytes(), encryptTimeout, recryptTimeout, tpmOptions, options, requireTpm)
        { }

        /// <summary>
        /// Get/set as object
        /// </summary>
        public virtual T Object
        {
            get
            {
                byte[] data = Value;
                try
                {
                    return data.ToObject<T>();
                }
                finally
                {
                    data.Clear();
                }
            }
            set => IfUndisposed(() => Value = value.ToBytes());
        }

        /// <summary>
        /// Get the object
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Object</returns>
        public async Task<T> GetObjectAsync(CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            byte[] data = await GetValueAsync(cancellationToken).DynamicContext();
            try
            {
                return data.ToObject<T>();
            }
            finally
            {
                data.Clear();
            }
        }

        /// <summary>
        /// Set the object
        /// </summary>
        /// <param name="obj">Object</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task SetObjectAsync(T obj, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            await SetValueAsync(obj.ToBytes(), cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Cast as object
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator T(TpmSecuredValue<T> value) => value.Object;
    }

    /// <summary>
    /// Secure value (keeps a value encrypted using TPM after a timeout without any access, re-crypts from time to time; see 
    /// <see href="https://static.usenix.org/events/sec01/full_papers/gutmann/gutmann.pdf"/>)
    /// </summary>
    public partial class TpmSecuredValue : DisposableBase, ISecureValue, IStatusProvider
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="tpmOptions">TPM options</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <param name="requireTpm">Require a TPM?</param>
        public TpmSecuredValue(
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in Tpm2Options? tpmOptions = null,
            in CryptoOptions? options = null,
            in bool requireTpm = true
            )
            : base(asyncDisposing: false)
        {
            RawValue = new(value);
            try
            {
                if (!Tpm2Helper.TryCreateEngine(tpmOptions, out Engine) && requireTpm)
                    throw new InvalidOperationException("TPM not available");
                EncryptTimeout = encryptTimeout ?? DefaultEncryptTimeout;
                RecryptTimeout = recryptTimeout ?? DefaultRecryptTimeout;
                Options = options ?? new();
                if (Options.Algorithm is null) Options.WithEncryptionAlgorithm();
                EncryptTimer = new()
                {
                    Interval = EncryptTimeout.TotalMilliseconds,
                    AutoReset = false
                };
                EncryptTimer.Elapsed += (s, e) => Encrypt();
                if (Engine is null)
                {
                    RecryptTimer = new()
                    {
                        Interval = RecryptTimeout.TotalMilliseconds,
                        AutoReset = false
                    };
                    RecryptTimer.Elapsed += (s, e) => Recrypt();
                }
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    Encrypt();
                }
                else
                {
                    EncryptTimer.Start();
                }
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            TpmSecuredValueTable.Values[GUID] = this;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="engine">TPM engine (won't be disposed, but used for synchronizing TPM access)</param>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="options">Options (will be cleared!)</param>
        public TpmSecuredValue(
            in Tpm2Engine engine,
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null
            )
            : base(asyncDisposing: false)
        {
            RawValue = new(value);
            try
            {
                Engine = engine.TPM;
                EncryptTimeout = encryptTimeout ?? DefaultEncryptTimeout;
                RecryptTimeout = recryptTimeout ?? DefaultRecryptTimeout;
                Options = options ?? new();
                if (Options.Algorithm is null) Options.WithEncryptionAlgorithm();
                EncryptTimer = new()
                {
                    Interval = EncryptTimeout.TotalMilliseconds,
                    AutoReset = false
                };
                EncryptTimer.Elapsed += (s, e) => Encrypt();
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    Encrypt();
                }
                else
                {
                    EncryptTimer.Start();
                }
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            TpmSecuredValueTable.Values[GUID] = this;
        }

        /// <summary>
        /// Default encrypt timeout
        /// </summary>
        public static TimeSpan DefaultEncryptTimeout { get; set; } = TimeSpan.FromMilliseconds(150);

        /// <summary>
        /// Default re-crypt timeout
        /// </summary>
        public static TimeSpan DefaultRecryptTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// GUID
        /// </summary>
        public string GUID { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <inheritdoc/>
        public virtual IEnumerable<Status> State
        {
            get
            {
                yield return new(__("GUID"), GUID, __("Unique ID of the TPM secures value"));
                yield return new(__("Name"), Name, __("Name of the TPM secures value"));
                yield return new(__("Encrypted"), IsEncrypted ? EncryptedSince : false, __("If the TPM secures value is encrypted at present (if encrypted, when it has been encrypted)"));
                yield return new(__("Encryption"), IsEncrypted ? TimeSpan.Zero : LastAccess + EncryptTimeout, __("When the raw value is going to be encrypted next time"));
                yield return new(__("Timeout"), EncryptTimeout, __("Value encryption timeout after the last access"));
                yield return new(__("Re-crypt"), RecryptTimeout, __("Encrypted value re-cryption interval"));
                yield return new(__("Access time"), LastAccess, __("Time of the last raw value access"));
                yield return new(__("Access count"), AccessCount, __("Number of value access since initialization"));
            }
        }

        /// <inheritdoc/>
        [NoValidation, SensitiveData]
        public byte[] Value
        {
            get
            {
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync;
                LastAccess = DateTime.Now;
                AccessCount++;
                if (RawValue is null) return Decrypt();
                EncryptTimer.Stop();
                try
                {
                    return RawValue.Array.CloneArray();
                }
                finally
                {
                    EncryptTimer.Start();
                    RaiseOnAccess();
                }
            }
            set
            {
                using SecureByteArrayRefStruct secureValue = new(value);
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync;
                RecryptTimer?.Stop();
                EncryptTimer.Stop();
                if (RawValue is null)
                {
                    EncryptionKey!.Dispose();
                    EncryptedValue!.Dispose();
                    if (EncryptTimeout == TimeSpan.Zero)
                    {
                        EncryptionKey = new(RND.GetBytes(MacHmacSha512Algorithm.MAC_LENGTH));
                        if (Engine is null)
                        {
                            EncryptedValue = new(secureValue.Array.Encrypt(EncryptionKey, Options));
                        }
                        else
                        {
                            using SemaphoreSyncContext? essc = TpmEngine?.Sync.SyncContext();
                            using SecureByteArrayRefStruct key = new(Tpm2Helper.Hmac(EncryptionKey, engine: Engine));
                            EncryptedValue = new(secureValue.Array.Encrypt(key, Options));
                        }
                        RecryptTimer?.Start();
                        return;
                    }
                    else
                    {
                        EncryptedValue = null;
                        EncryptionKey = null;
                    }
                }
                RawValue?.Dispose();
                RawValue = new(secureValue.Array.CloneArray());
                EncryptTimer.Start();
            }
        }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; } = null!;

        /// <summary>
        /// Encrypt timeout
        /// </summary>
        public TimeSpan EncryptTimeout { get; }

        /// <summary>
        /// Recrypt timeout
        /// </summary>
        public TimeSpan RecryptTimeout { get; }

        /// <summary>
        /// Is the value encrypted at present?
        /// </summary>
        public bool IsEncrypted => IfUndisposed(() => RawValue is null);

        /// <summary>
        /// Last access time
        /// </summary>
        public DateTime LastAccess { get; private set; } = DateTime.MinValue;

        /// <summary>
        /// Encryption time
        /// </summary>
        public DateTime EncryptedSince { get; private set; } = DateTime.MinValue;

        /// <summary>
        /// Access count
        /// </summary>
        public long AccessCount { get; private set; }

        /// <summary>
        /// Get the value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Value (should be cleared!)</returns>
        public async Task<byte[]> GetValueAsync(CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            LastAccess = DateTime.Now;
            AccessCount++;
            if (RawValue is null) return Decrypt();
            EncryptTimer.Stop();
            try
            {
                return RawValue.Array.CloneArray();
            }
            finally
            {
                EncryptTimer.Start();
                RaiseOnAccess();
            }
        }

        /// <summary>
        /// Set the value
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task SetValueAsync(byte[] value, CancellationToken cancellationToken = default)
        {
            using SecureByteArrayStructSimple secureValue = new(value);
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            RecryptTimer?.Stop();
            EncryptTimer.Stop();
            if (RawValue is null)
            {
                EncryptionKey!.Dispose();
                EncryptedValue!.Dispose();
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    EncryptionKey = new(await RND.GetBytesAsync(MacHmacSha512Algorithm.MAC_LENGTH).DynamicContext());
                    if (Engine is null)
                    {
                        EncryptedValue = new(secureValue.Array.Encrypt(EncryptionKey, Options));
                    }
                    else
                    {
                        using SemaphoreSyncContext? essc = TpmEngine?.Sync.SyncContext(CancellationToken.None);
                        using SecureByteArrayStructSimple key = new(Tpm2Helper.Hmac(EncryptionKey, engine: Engine));
                        EncryptedValue = new(secureValue.Array.Encrypt(key, Options));
                    }
                    RecryptTimer?.Start();
                    return;
                }
                else
                {
                    EncryptedValue = null;
                    EncryptionKey = null;
                }
            }
            RawValue?.Dispose();
            RawValue = new(secureValue.Array.CloneArray());
            EncryptTimer.Start();
        }

        /// <summary>
        /// Delegate for an <see cref="OnAccess"/> event handler
        /// </summary>
        /// <param name="value">Secure value</param>
        /// <param name="e">Arguments</param>
        public delegate void Access_Delegate(TpmSecuredValue value, EventArgs e);
        /// <summary>
        /// Raised on value access
        /// </summary>
        public event Access_Delegate? OnAccess;
        /// <summary>
        /// Raise the <see cref="OnAccess"/> event
        /// </summary>
        protected virtual void RaiseOnAccess()
        {
            if (OnAccess is not null) ((Func<Task>)(async () =>
            {
                await Task.Yield();
                OnAccess?.Invoke(this, new());
            })).StartFairTask();
        }
    }
}
