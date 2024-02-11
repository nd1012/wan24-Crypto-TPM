using Microsoft.Extensions.Logging;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Crypto.TPM;
using wan24.ObjectValidation;

namespace wan24_Crypto_TPM_Tests
{
    [TestClass]
    public class A_Initialization
    {
        public static ILoggerFactory LoggerFactory { get; private set; } = null!;

        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            Logging.Logger = new ConsoleLogger(LogLevel.Trace);
            ValidateObject.Logger = (message) => Logging.WriteDebug(message);
            TypeHelper.Instance.ScanAssemblies(typeof(A_Initialization).Assembly);
            wan24.Core.Bootstrap.Async(typeof(A_Initialization).Assembly).Wait();
            wan24.Crypto.Bootstrap.Boot();
            wan24.Crypto.TPM.Bootstrap.Boot();
            DisposableBase.CreateStackInfo = true;
            ErrorHandling.ErrorHandler = (info) =>
            {
                if (info.Exception is StackInfoException six) Logging.WriteError(six.StackInfo.Stack);
            };
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
            ValidateObject.Logger("wan24-Crypto-TPM Tests initialized");
        }
    }
}
