using Tpm2Lib;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Crypto.TPM;

namespace wan24_Crypto_TPM_Tests
{
    [TestClass]
    public class Mac_Tests
    {
        [TestMethod, Timeout(3000)]
        public async Task All_Tests() => await MacTests.TestAllAlgorithms();

        [TestMethod]
        public void Stress_Test()
        {
            byte[] data = new byte[] { 1, 2, 3 };
            for(int i = 0; i < 100; i++)
            {
                Logging.WriteInfo($"Test run {i + 1}");
                Logging.WriteInfo("\tCreate engine");
                using Tpm2 engine = Tpm2Helper.CreateEngine();
                Logging.WriteInfo("\tCreate handle");
                TpmHandle hmacHandle = engine.HashSequenceStart(Array.Empty<byte>(), TpmAlgId.Sha384);
                Logging.WriteInfo("\tCreate session");
                AuthSession session = engine.StartAuthSessionEx(TpmSe.Hmac, TpmAlgId.Sha384);
                try
                {
                    Logging.WriteInfo("\tUpdate sequence");
                    engine[session].SequenceUpdate(hmacHandle, data);
                    Logging.WriteInfo("\tFinalize sequence");
                    engine[session].SequenceComplete(hmacHandle, Array.Empty<byte>(), TpmHandle.RhOwner, out _);
                }
                finally
                {
                    Logging.WriteInfo("\tFlush session");
                    engine.FlushContext(session);
                }
            }
        }

        [TestMethod]
        public async Task StressAsync_Test()
        {
            // Test singleton connection synchronized per thread access
            byte[] data = new byte[] { 1, 2, 3 };
            List<Task> tasks = new();
            using Tpm2Engine engine = Tpm2Engine.Create();
            for (int i = 0; i < 10; i++)
                tasks.Add(Task.Run(() =>
                {
                    using SemaphoreSyncContext ssc = engine.Sync;
                    TpmHandle hmacHandle = engine.TPM.HashSequenceStart(Array.Empty<byte>(), TpmAlgId.Sha384);
                    AuthSession session = engine.TPM.StartAuthSessionEx(TpmSe.Hmac, TpmAlgId.Sha384);
                    try
                    {
                        engine.TPM[session].SequenceUpdate(hmacHandle, data);
                        engine.TPM[session].SequenceComplete(hmacHandle, Array.Empty<byte>(), TpmHandle.RhOwner, out _);
                    }
                    catch(Exception ex)
                    {
                        Logging.WriteInfo($"Test exception: {ex.GetType()} {ex.Message}");
                        throw;
                    }
                    finally
                    {
                        engine.TPM.FlushContext(session);
                    }
                    Logging.WriteInfo("Test done");
                }));
            await tasks.WaitAll();
        }

        [TestMethod]
        public async Task StressAsync2_Test()
        {
            // Test one connection per thread
            byte[] data = new byte[] { 1, 2, 3 };
            List<Task> tasks = new();
            for (int i = 0; i < 10; i++)
                tasks.Add(Task.Run(() =>
                {
                    using Tpm2Engine engine = Tpm2Engine.Create();
                    TpmHandle hmacHandle = engine.TPM.HashSequenceStart(Array.Empty<byte>(), TpmAlgId.Sha384);
                    AuthSession session = engine.TPM.StartAuthSessionEx(TpmSe.Hmac, TpmAlgId.Sha384);
                    try
                    {
                        engine.TPM[session].SequenceUpdate(hmacHandle, data);
                        engine.TPM[session].SequenceComplete(hmacHandle, Array.Empty<byte>(), TpmHandle.RhOwner, out _);
                    }
                    catch (Exception ex)
                    {
                        Logging.WriteInfo($"Test exception: {ex.GetType()} {ex.Message}");
                        throw;
                    }
                    finally
                    {
                        engine.TPM.FlushContext(session);
                    }
                    Logging.WriteInfo("Test done");
                }));
            await tasks.WaitAll();
        }

        [TestMethod]
        public void Stress2_Test()
        {
            byte[] data = new byte[] { 1, 2, 3 };
            for (int i = 0; i < 100; i++)
            {
                Logging.WriteInfo($"Test run {i + 1}");
                using MacStreams macStreams = MacTpmHmacSha384Algorithm.Instance.GetMacStream(Array.Empty<byte>());
                macStreams.Stream.Write(data);
                macStreams.Stream.FlushFinalBlock();
                _ = macStreams.Transform.Hash;
            }
        }
    }
}
