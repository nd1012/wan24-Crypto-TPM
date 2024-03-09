using wan24.Core;

[assembly: Bootstrapper(typeof(wan24.Crypto.TPM.Bootstrap), nameof(wan24.Crypto.TPM.Bootstrap.Boot))]

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// Bootstrapper
    /// </summary>
    public static class Bootstrap
    {
        /// <summary>
        /// Boot
        /// </summary>
        public static void Boot()
        {
            StatusProviderTable.Providers["TPM"] = Tpm2Helper.State;
            if (ENV.IsBrowserApp) return;
            MacHelper.Algorithms[MacTpmHmacSha1Algorithm.ALGORITHM_NAME] = MacTpmHmacSha1Algorithm.Instance;
            MacHelper.Algorithms[MacTpmHmacSha256Algorithm.ALGORITHM_NAME] = MacTpmHmacSha256Algorithm.Instance;
            MacHelper.Algorithms[MacTpmHmacSha384Algorithm.ALGORITHM_NAME] = MacTpmHmacSha384Algorithm.Instance;
            MacHelper.Algorithms[MacTpmHmacSha512Algorithm.ALGORITHM_NAME] = MacTpmHmacSha512Algorithm.Instance;
        }
    }
}
