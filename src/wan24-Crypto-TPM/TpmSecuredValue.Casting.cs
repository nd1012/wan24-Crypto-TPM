using wan24.Core;

namespace wan24.Crypto.TPM
{
    // Casting
    public partial class TpmSecuredValue
    {
        /// <summary>
        /// Cast as value (should be cleared!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator byte[](in TpmSecuredValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be cleaned!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator Span<byte>(in TpmSecuredValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be cleaned!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator Memory<byte>(in TpmSecuredValue value) => value.Value;

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArray(in TpmSecuredValue value) => new(value.Value);

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArrayStruct(in TpmSecuredValue value) => new(value.Value);

        /// <summary>
        /// Cast as value (should be disposed!)
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator SecureByteArrayRefStruct(in TpmSecuredValue value) => new(value.Value);

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        public static implicit operator TpmSecuredValue(in byte[] value) => new(value);

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator TpmSecuredValue(in SecureByteArray value) => new(value.Array.CloneArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator TpmSecuredValue(in SecureByteArrayStruct value) => new(value.Array.CloneArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator TpmSecuredValue(in ReadOnlySpan<byte> value) => new(value.ToArray());

        /// <summary>
        /// Cast as <see cref="SecureValue"/> (don't forget to dispose!)
        /// </summary>
        /// <param name="value">Value (will be copied)</param>
        public static implicit operator TpmSecuredValue(in ReadOnlyMemory<byte> value) => new(value.Span.ToArray());
    }
}
