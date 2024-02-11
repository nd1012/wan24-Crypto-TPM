using System.Security.Cryptography;
using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM2 HMAC algorithm
    /// </summary>
    public sealed class Tpm2HmacAlgorithm : KeyedHashAlgorithm
    {
        /// <summary>
        /// Dispose the engine?
        /// </summary>
        private readonly bool DisposeEngine;
        /// <summary>
        /// Engine
        /// </summary>
        private readonly Tpm2 Engine;
        /// <summary>
        /// Options
        /// </summary>
        private readonly Tpm2Options Options;
        /// <summary>
        /// HMAC handle
        /// </summary>
        private readonly TpmHandle HmacHandle;
        /// <summary>
        /// TPM2 session
        /// </summary>
        private readonly AuthSession Session;
        /// <summary>
        /// Transformed the final block?
        /// </summary>
        private bool TransformedFinal = false;
        /// <summary>
        /// Is disposed?
        /// </summary>
        private bool IsDisposed = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        public Tpm2HmacAlgorithm(in TpmAlgId algo, in byte[]? key = null, in Tpm2? engine = null, in Tpm2Options? options = null) : base()
        {
            DisposeEngine = engine is null;
            Options = Tpm2Helper.GetDefaultOptions(options);
            Engine = engine ?? Tpm2Helper.CreateEngine(Options);
            HmacHandle = Engine.HashSequenceStart(key ?? [], algo);
            Session = Engine.StartAuthSessionEx(TpmSe.Hmac, algo);
        }

        /// <inheritdoc/>
        public override bool CanReuseTransform => false;

        /// <inheritdoc/>
        public override void Initialize() { }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ObjectDisposedException.ThrowIf(IsDisposed || TransformedFinal, this);
            int len = cbSize;
            Span<byte> dataSpan = array.AsSpan(ibStart, len);
            if (len <= Tpm2Helper.DIGEST_BUFFER_SIZE)
            {
                if (ibStart == 0 && cbSize == array.Length)
                {
                    Engine[Session].SequenceUpdate(HmacHandle, array);
                }
                else
                {
                    using SecureByteArrayRefStruct buffer = new(len);
                    dataSpan.CopyTo(buffer.Span);
                    Engine[Session].SequenceUpdate(HmacHandle, buffer.Array);
                }
            }
            else
            {
                int index = 0;
                {
                    using SecureByteArrayRefStruct buffer = new(Tpm2Helper.DIGEST_BUFFER_SIZE);
                    for (; index + Tpm2Helper.DIGEST_BUFFER_SIZE <= len; index += Tpm2Helper.DIGEST_BUFFER_SIZE)
                    {
                        dataSpan[index..].CopyTo(buffer.Span);
                        Engine[Session].SequenceUpdate(HmacHandle, buffer.Array);
                    }
                }
                if (index == len) return;
                {
                    using SecureByteArrayRefStruct buffer = new(len - index);
                    dataSpan[index..].CopyTo(buffer.Span);
                    Engine[Session].SequenceUpdate(HmacHandle, buffer.Array);
                }
            }
        }

        /// <inheritdoc/>
        protected override void HashCore(ReadOnlySpan<byte> source)
        {
            ObjectDisposedException.ThrowIf(IsDisposed || TransformedFinal, this);
            using SecureByteArrayRefStruct buffer = new(source.ToArray());
            HashCore(buffer.Array, 0, buffer.Length);
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            ObjectDisposedException.ThrowIf(IsDisposed || TransformedFinal, this);
            try
            {
                return Engine[Session].SequenceComplete(HmacHandle, [], Options.ResourceHandle ?? TpmRh.Owner, out _);
            }
            finally
            {
                TransformedFinal = true;
            }
        }

        /// <inheritdoc/>
        protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            if (IsDisposed || TransformedFinal)
            {
                bytesWritten = 0;
                return false;
            }
            try
            {
                using SecureByteArrayRefStruct mac = new(HashFinal());
                mac.Span.CopyTo(destination);
                bytesWritten = mac.Length;
                return true;
            }
            catch(Exception ex)
            {
                ErrorHandling.Handle(new(new CryptographicException($"Failed to create TPM HMAC", ex), Constants.CRYPTO_ERROR_SOURCE, this));
                bytesWritten = 0;
                return false;
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (IsDisposed) return;
            IsDisposed = true;
            Engine.FlushContext(Session);
            if (DisposeEngine) Engine.Dispose();
        }
    }
}
