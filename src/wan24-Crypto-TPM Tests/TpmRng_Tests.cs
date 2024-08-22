using wan24.Crypto.TPM;
using wan24.Tests;

namespace wan24_Crypto_TPM_Tests
{
    [TestClass]
    public class TpmRng_Tests : TestBase
    {
        [TestMethod]
        public void General_Tests()
        {
            using TpmRng rng = new();
            byte[] rnd = rng.GetBytes(1234);
            Assert.AreEqual(1234, rnd.Length);
            Assert.IsTrue(!rnd.All(b => b == 0));
        }
    }
}
