using Microsoft.Extensions.Logging;
using wan24.Core;
using wan24.Crypto;
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
            MacHelper.Algorithms.TryRemove(MacTpmHmacSha512Algorithm.ALGORITHM_NAME, out _);// Not supported by the simulator
            DisposableBase.CreateStackInfo = true;
            ErrorHandling.ErrorHandler = (info) =>
            {
                if (info.Exception is StackInfoException six) Logging.WriteError(six.StackInfo.Stack);
            };
            Tpm2Helper.DefaultOptions = new()
            {
                //UseSimulator = true // https://www.microsoft.com/en-us/download/details.aspx?id=52507
            };
            ValidateObject.Logger("wan24-Crypto-TPM Tests initialized");
        }
    }
}
