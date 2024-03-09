using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM crypto app configuration (<see cref="AppConfig"/> ; should be applied AFTER bootstrapping (<see cref="AppConfigAttribute.AfterBootstrap"/>))
    /// </summary>
    public class TpmCryptoAppConfig : AppConfigBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public TpmCryptoAppConfig() : base() { }

        /// <summary>
        /// Applied TPM crypto app configuration
        /// </summary>
        public TpmCryptoAppConfig? AppliedTpmCryptoConfig { get; protected set; }

        /// <summary>
        /// Default Linux TPM device path
        /// </summary>
        public string? DefaultLinuxDevicePath { get; set; }

        /// <summary>
        /// Create a <see cref="Tpm2Helper.DefaultEngine"/>?
        /// </summary>
        public bool CreateDefaultEngine { get; set; }

        /// <inheritdoc/>
        public override void Apply()
        {
            if (SetApplied)
            {
                if (AppliedTpmCryptoConfig is not null) throw new InvalidOperationException();
                AppliedTpmCryptoConfig = this;
            }
            if (DefaultLinuxDevicePath is not null) Tpm2Options.DefaultLinuxDevicePath = DefaultLinuxDevicePath;
            if (CreateDefaultEngine && Tpm2Helper.TryCreateEngine(options: null, out Tpm2? engine)) Tpm2Helper.DefaultEngine = engine;
            ApplyProperties(afterBootstrap: false);
            ApplyProperties(afterBootstrap: true);
        }

        /// <inheritdoc/>
        public override async Task ApplyAsync(CancellationToken cancellationToken = default)
        {
            if (SetApplied)
            {
                if (AppliedTpmCryptoConfig is not null) throw new InvalidOperationException();
                AppliedTpmCryptoConfig = this;
            }
            if (DefaultLinuxDevicePath is not null) Tpm2Options.DefaultLinuxDevicePath = DefaultLinuxDevicePath;
            await ApplyPropertiesAsync(afterBootstrap: false, cancellationToken).DynamicContext();
            await ApplyPropertiesAsync(afterBootstrap: true, cancellationToken).DynamicContext();
        }
    }
}
