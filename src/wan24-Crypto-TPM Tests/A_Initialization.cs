using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Crypto.TPM;

namespace wan24_Crypto_TPM_Tests
{
    [TestClass]
    public class A_Initialization
    {
        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            wan24.Tests.TestsInitialization.Init(tc);
            Tpm2Helper.DefaultOptions = new()
            {
                UseSimulator = !Tpm2Helper.IsAvailable() // https://www.microsoft.com/en-us/download/details.aspx?id=52507
            };
            int maxDigest = Tpm2Helper.GetMaxDigestSize();
            if (maxDigest < MacTpmHmacSha512Algorithm.MAC_LENGTH)
            {
                Logging.WriteWarning("TPM HMAC-SHA512 isn't supported");
                MacHelper.Algorithms.TryRemove(MacTpmHmacSha512Algorithm.ALGORITHM_NAME, out _);
            }
            if (maxDigest < MacTpmHmacSha384Algorithm.MAC_LENGTH)
            {
                Logging.WriteWarning("TPM HMAC-SHA384 isn't supported");
                MacHelper.Algorithms.TryRemove(MacTpmHmacSha384Algorithm.ALGORITHM_NAME, out _);
            }
            if (maxDigest < MacTpmHmacSha256Algorithm.MAC_LENGTH)
            {
                Logging.WriteWarning("TPM HMAC-SHA256 isn't supported");
                MacHelper.Algorithms.TryRemove(MacTpmHmacSha256Algorithm.ALGORITHM_NAME, out _);
            }
            SharedTests.Initialize();
            Logging.WriteInfo("wan24-Crypto-TPM Tests initialized");
        }
    }
}
