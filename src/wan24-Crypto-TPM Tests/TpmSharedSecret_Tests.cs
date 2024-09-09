using Tpm2Lib;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.TPM;
using wan24.Tests;

namespace wan24_Crypto_TPM_Tests
{
    [TestClass]
    public class TpmSharedSecret_Tests : TestBase
    {
        [TestMethod]
        public void General_Tests()
        {
            using Tpm2 engine = Tpm2Helper.CreateEngine();
            byte[] token = RND.GetBytes(123),
                remoteSecret = RND.GetBytes(Tpm2Helper.GetMaxDigestSize(engine)),
                finalSecret,
                finalSecret2;
            using(TpmSharedSecret tss = new(token.CloneArray(), engine: engine))
            {
                tss.ProtectRemoteSecret(remoteSecret);
                // tss.Secret.Array and remoteSecret need to be sent to the remote key storage
                finalSecret = tss.DeriveFinalSecretAndDispose(remoteSecret.CloneArray());
            }
            using (TpmSharedSecret tss = new(token, engine: engine))
                // tss.Secret.Array must be sent to the remote key storage for receiving remoteSecret
                finalSecret2 = tss.DeriveFinalSecretAndDispose(remoteSecret);
            Assert.IsTrue(finalSecret.SequenceEqual(finalSecret2));
        }
    }
}
