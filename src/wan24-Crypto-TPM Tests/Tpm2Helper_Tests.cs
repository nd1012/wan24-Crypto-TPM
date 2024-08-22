using Tpm2Lib;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.TPM;
using wan24.Tests;

namespace wan24_Crypto_TPM_Tests
{
    // NOTE: These tests require a running TCP TPM simulator!
    [TestClass]
    public class Tpm2Helper_Tests : TestBase
    {
        [TestMethod]
        public void Avail_Test()
        {
            Assert.IsTrue(Tpm2Helper.IsAvailable());
        }

        [TestMethod]
        public void RNG_Test()
        {
            using Tpm2 engine = Tpm2Helper.CreateEngine();
            int len = Tpm2Helper.GetMaxDigestSize(engine);
            Logging.WriteInfo(len.ToString());
            byte[] rnd = Tpm2Helper.CreateRandomData(len, engine);
            Assert.AreEqual(len, rnd.Length);
            Assert.IsFalse(rnd.All(b => b == 0));
        }

        [TestMethod]
        public void Hmac_Test()
        {
            using Tpm2 engine = Tpm2Helper.CreateEngine();
            int len = Tpm2Helper.GetMaxDigestSize(engine);
            Logging.WriteInfo(len.ToString());
            byte[] data = new byte[] { 1, 2, 3 },
                mac,
                mac2,
                mac3;
            TpmAlgId maxAlgo = Tpm2Helper.GetDigestAlgorithm(len);
            Logging.WriteInfo(maxAlgo.ToString());
            foreach (TpmAlgId algo in new TpmAlgId[] { TpmAlgId.Sha1, TpmAlgId.Sha256, TpmAlgId.Sha384, TpmAlgId.Sha512 })
            {
                if (algo > maxAlgo) break;
                Logging.WriteInfo(algo.ToString());

                // MAC and length
                mac = Tpm2Helper.Hmac(data, algo, engine: engine);
                Logging.WriteInfo($"\t{Convert.ToHexString(mac)}");
                Assert.AreEqual(algo.GetMacLength(), mac.Length, algo.ToString());
                Assert.IsFalse(mac.All(b => b == 0), algo.ToString());

                // 2nd MAC should be equal
                mac2 = Tpm2Helper.Hmac(data, algo, engine: engine);
                Assert.IsTrue(mac.SequenceEqual(mac2), algo.ToString());

                // MAC should be different from a regular MAC using the same algorithm and key
                mac3 = MacHelper.GetAlgorithm(algo.GetMacAlgorithmName()!).Mac(data, Array.Empty<byte>());
                Assert.IsFalse(mac.SequenceEqual(mac3), algo.ToString());
            }
        }
    }
}
