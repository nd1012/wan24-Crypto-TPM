using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using Tpm2Lib;
using wan24.Core;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM2 helper
    /// </summary>
    public static partial class Tpm2Helper
    {
        /// <summary>
        /// Digest buffer size in byte
        /// </summary>
        public const int DIGEST_BUFFER_SIZE = 1024;
        /// <summary>
        /// Default Linux TPM device
        /// </summary>
        public const string DEFAULT_LINUX_DEVICE = "/dev/tpm0";

        /// <summary>
        /// Regular expression to match the TPM device name from a device path (<c>/dev/tpm0</c> f.e.; <c>$1</c> contains the device name)
        /// </summary>
        private static readonly Regex RxDevicePath = RxDevicePath_Generator();
        /// <summary>
        /// Default options
        /// </summary>
        private static Tpm2Options _DefaultOptions = new();

        /// <summary>
        /// Default options (get/set instance will be copied on every access)
        /// </summary>
        public static Tpm2Options DefaultOptions
        {
            get => _DefaultOptions.GetCopy();
            set => _DefaultOptions = value.GetCopy();
        }

        /// <summary>
        /// Default singleton engine to use (you should synchronize the access using <see cref="DefaultEngineSync"/>)
        /// </summary>
        public static Tpm2? DefaultEngine { get; set; }

        /// <summary>
        /// Thread synchronization (used for <see cref="DefaultEngine"/> access)
        /// </summary>
        public static SemaphoreSync DefaultEngineSync { get; } = new();

        /// <summary>
        /// TPM state
        /// </summary>
        public static IEnumerable<Status> State
        {
            get
            {
                // TPM environment
                if (DefaultEngine is not null)
                    yield return new("Max. digest", GetMaxDigestSize(DefaultEngine), "Maximum supported digest size in bytes");
                yield return new("Linux device", Tpm2Options.DefaultLinuxDevicePath, "Default Linux TPM device path");
                // TPM secured values
                yield return new("TPM secured values", TpmSecuredValueTable.Values.Count, "Number of TPM secured values", "TPM secured values");
                foreach (TpmSecuredValue value in TpmSecuredValueTable.Values.Values)
                    foreach (Status status in value.State)
                        yield return new(status.Name, status.State, status.Description, $"TPM secured values\\{value.Name ?? value.GUID}");
            }
        }

        /// <summary>
        /// Get default options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static Tpm2Options GetDefaultOptions(Tpm2Options? options = null)
        {
            options ??= DefaultOptions;
            return options;
        }

        /// <summary>
        /// Create a TPM2 engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Engine (don't forget to dispose!)</returns>
        public static Tpm2 CreateEngine(Tpm2Options? options = null)
        {
            options = GetDefaultOptions(options);
            Tpm2Device? device = null;
            Tpm2? res = null;
            try
            {
                // Connect to the TPM device
                device = options.UseSimulator
                    ? new TcpTpmDevice(options.SimulatorIp, options.SimulatorPort, options.StopSimulator, options.SimulatorHasReferenceModel)
                    : ENV.IsWindows
                        ? new TbsDevice(options.HasResourceManager)
                        : new LinuxTpmDevice(options.LinuxDevicePath);
                device.Connect();
                // Initialize the software stack
                res = new(device);
                if (device is TcpTpmDevice tcpDevice)
                {
                    tcpDevice.PowerCycle();
                    res.Startup(Su.Clear);
                }
                // Initialize the TPM state
                options.Initializer?.Invoke(res, options);
                return res;
            }
            catch (Exception ex)
            {
                if (res is null)
                {
                    device?.Dispose();
                }
                else
                {
                    res.Dispose();
                }
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("Failed to get a TPM2 instance", ex);
            }
        }

        /// <summary>
        /// Try creating an engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="engine">Engine</param>
        /// <returns>If succeed</returns>
        public static bool TryCreateEngine(in Tpm2Options? options, [NotNullWhen(returnValue: true)] out Tpm2? engine)
        {
            try
            {
                engine = CreateEngine(options);
                return true;
            }
            catch
            {
                engine = null;
                return false;
            }
        }

        /// <summary>
        /// Determine if TPM >=2.x access is available
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>If available</returns>
        public static bool IsAvailable(Tpm2Options? options = null)
        {
            options = GetDefaultOptions(options?.GetCopy());
            try
            {
                if (!options.UseSimulator && ENV.IsLinux)
                {
                    options.LinuxDevicePath ??= DEFAULT_LINUX_DEVICE;
                    if (!RxDevicePath.IsMatch(options.LinuxDevicePath) || !Path.IsPathRooted(options.LinuxDevicePath) || !File.Exists(options.LinuxDevicePath))
                        return false;
                    string device = RxDevicePath.Replace(options.LinuxDevicePath, "$1"),
                        description = $"/sys/class/tpm/{device}/description";
                    if (File.Exists(description) && !File.ReadAllText(description).Contains("2."))
                        return false;
                    string version = $"/sys/class/tpm/{device}/tpm_version_major";
                    if (File.Exists(version) && int.TryParse(File.ReadAllText(version), out int v) && v != 2)
                        return false;
                }
                using Tpm2 engine = CreateEngine(options);
                return true;
            }
            catch (Exception ex)
            {
                Logging.WriteDebug($"Exception when checking TPM2 availability: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Determine if TPM >=2.x access is available
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If available</returns>
        public static async Task<bool> IsAvailableAsync(Tpm2Options? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options?.GetCopy());
            try
            {
                if (!options.UseSimulator && ENV.IsLinux)
                {
                    options.LinuxDevicePath ??= DEFAULT_LINUX_DEVICE;
                    if (!RxDevicePath.IsMatch(options.LinuxDevicePath) || !Path.IsPathRooted(options.LinuxDevicePath) || !File.Exists(options.LinuxDevicePath))
                        return false;
                    string device = RxDevicePath.Replace(options.LinuxDevicePath, "$1"),
                        description = $"/sys/class/tpm/{device}/description";
                    if (File.Exists(description) && !(await File.ReadAllTextAsync(description, cancellationToken).DynamicContext()).Contains("2."))
                        return false;
                    string version = $"/sys/class/tpm/{device}/tpm_version_major";
                    if (File.Exists(version) && int.TryParse(await File.ReadAllTextAsync(version, cancellationToken).DynamicContext(), out int v) && v != 2)
                        return false;
                }
                using Tpm2 engine = CreateEngine(options);
                return true;
            }
            catch (Exception ex)
            {
                Logging.WriteDebug($"Exception when checking TPM2 availability: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Get the max. digest size in byte
        /// </summary>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>Max. digest size in byte</returns>
        public static int GetMaxDigestSize(Tpm2? engine = null, Tpm2Options? options = null)
        {
            engine ??= DefaultEngine;
            bool disposeEngine = engine is null;
            engine ??= CreateEngine(options);
            try
            {
                engine.GetCapability(Cap.TpmProperties, (uint)Pt.MaxDigest, propertyCount: 1, out ICapabilitiesUnion capability);
                return (int)((TaggedTpmPropertyArray)capability).tpmProperty[0].value;
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("Failed to get the max. TPM2 digest size", ex);
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Get the digest algorithm for a digest size
        /// </summary>
        /// <param name="digestSize">Digest size in byte</param>
        /// <returns>Digest algorithm which matches the size</returns>
        public static TpmAlgId GetDigestAlgorithm(in int digestSize)
            => digestSize switch
            {
                MacTpmHmacSha1Algorithm.MAC_LENGTH => TpmAlgId.Sha1,
                MacTpmHmacSha256Algorithm.MAC_LENGTH => TpmAlgId.Sha256,
                MacTpmHmacSha384Algorithm.MAC_LENGTH => TpmAlgId.Sha384,
                MacTpmHmacSha512Algorithm.MAC_LENGTH => TpmAlgId.Sha512,
                _ => throw CryptographicException.From($"Digest size {digestSize} not implemented", new InvalidDataException())
            };

        /// <summary>
        /// Create random data
        /// </summary>
        /// <param name="len">Length in byte (must not exceed <see cref="GetMaxDigestSize(Tpm2?, Tpm2Options?)"/>, which usually restricts the length to the max. digest size 
        /// in byte)</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>Random data</returns>
        public static byte[] CreateRandomData(in int len = 32, Tpm2? engine = null, Tpm2Options? options = null)
        {
            if (len == 0) return [];
            engine ??= DefaultEngine;
            bool disposeEngine = engine is null;
            engine ??= CreateEngine(options);
            try
            {
                byte[] res = engine.GetRandom((ushort)len);
                if (res.Length == len) return res;
                res.Clear();
                throw new IOException($"TPM2 failed to generate {len} byte random data (got only {res.Length} byte instead)");
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("Failed to get random data using TPM2", ex);
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Create a HMAC
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="algo">HMAC algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC</returns>
        public static byte[] Hmac(in byte[] data, TpmAlgId? algo = null, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
        {
            engine ??= DefaultEngine;
            bool disposeEngine = engine is null;
            options = GetDefaultOptions(options);
            engine ??= CreateEngine(options);
            TpmRh hierarchy = options.ResourceHandle ?? TpmRh.Owner;
            AuthSession? authSession = null;
            try
            {
                algo ??= GetDigestAlgorithm(GetMaxDigestSize(engine, options));
                TpmHandle hmacHandle = engine.HashSequenceStart(key ?? [], algo.Value);
                authSession = engine.StartAuthSessionEx(TpmSe.Hmac, algo.Value);
                int len = data.Length;
                if (data.Length <= DIGEST_BUFFER_SIZE) return engine[authSession].SequenceComplete(hmacHandle, data, hierarchy, out _);
                Span<byte> dataSpan = data;
                int index = 0;
                {
                    using SecureByteArrayRefStruct buffer = new(DIGEST_BUFFER_SIZE);
                    for (; index + DIGEST_BUFFER_SIZE <= len; index += DIGEST_BUFFER_SIZE)
                    {
                        dataSpan[index..].CopyTo(buffer.Span);
                        engine[authSession].SequenceUpdate(hmacHandle, buffer);
                    }
                }
                if (index == len) return engine[authSession].SequenceComplete(hmacHandle, [], hierarchy, out _);
                {
                    using SecureByteArrayRefStruct buffer = new(len - index);
                    dataSpan[index..].CopyTo(buffer.Span);
                    return engine[authSession].SequenceComplete(hmacHandle, buffer, hierarchy, out _);
                }
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From($"Failed to create a HMAC ({algo}) using TPM2 hierarchy {hierarchy}", ex);
            }
            finally
            {
                if (authSession is not null) engine.FlushContext(authSession);
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Create a HMAC
        /// </summary>
        /// <param name="data">Authenticated data</param>
        /// <param name="algo">HMAC algorithm</param>
        /// <param name="key">Key</param>
        /// <param name="engine">Engine (won't be disposed)</param>
        /// <param name="options">Options</param>
        /// <returns>HMAC</returns>
        public static byte[] Hmac(in ReadOnlySpan<byte> data, TpmAlgId? algo = null, in byte[]? key = null, Tpm2? engine = null, Tpm2Options? options = null)
        {
            engine ??= DefaultEngine;
            bool disposeEngine = engine is null;
            options = GetDefaultOptions(options);
            engine ??= CreateEngine(options);
            TpmRh hierarchy = options.ResourceHandle ?? TpmRh.Owner;
            AuthSession? authSession = null;
            try
            {
                algo ??= GetDigestAlgorithm(GetMaxDigestSize(engine, options));
                TpmHandle hmacHandle = engine.HashSequenceStart(key ?? [], algo.Value);
                authSession = engine.StartAuthSessionEx(TpmSe.Hmac, algo.Value);
                int len = data.Length;
                if (data.Length <= DIGEST_BUFFER_SIZE)
                {
                    using SecureByteArrayRefStruct buffer = new(data.Length);
                    data.CopyTo(buffer.Span);
                    return engine[authSession].SequenceComplete(hmacHandle, buffer, hierarchy, out _);
                }
                int index = 0;
                {
                    using SecureByteArrayRefStruct buffer = new(DIGEST_BUFFER_SIZE);
                    for (; index + DIGEST_BUFFER_SIZE <= len; index += DIGEST_BUFFER_SIZE)
                    {
                        data[index..].CopyTo(buffer.Span);
                        engine[authSession].SequenceUpdate(hmacHandle, buffer);
                    }
                }
                if (index == len) return engine[authSession].SequenceComplete(hmacHandle, [], hierarchy, out _);
                {
                    using SecureByteArrayRefStruct buffer = new(len - index);
                    data[index..].CopyTo(buffer.Span);
                    return engine[authSession].SequenceComplete(hmacHandle, buffer, hierarchy, out _);
                }
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From($"Failed to create a HMAC ({algo}) using TPM2 hierarchy {hierarchy}", ex);
            }
            finally
            {
                if (authSession is not null) engine.FlushContext(authSession);
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Decrypt a private key suite
        /// </summary>
        /// <param name="cipher">Private key suite cipher data</param>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <param name="algo">TPM HMAC algorithm</param>
        /// <param name="engine">Engine</param>
        /// <param name="tpmOptions">Options</param>
        /// <returns>Private key suite (don't forget to dispose!)</returns>
        public static PrivateKeySuite DecryptPrivateKeySuite(
            in byte[] cipher,
            in byte[] key,
            in CryptoOptions? options = null,
            in TpmAlgId? algo = null,
            Tpm2? engine = null,
            in Tpm2Options? tpmOptions = null
            )
        {
            engine ??= DefaultEngine;
            bool disposeEngine = engine is null;
            engine ??= CreateEngine(tpmOptions);
            try
            {
                using SecureByteArrayRefStruct tpmKey = new(Hmac(key, algo, engine: engine, options: tpmOptions));
                return PrivateKeySuite.Decrypt(cipher, tpmKey, options);
            }
            catch (Exception ex)
            {
                if (ex is CryptographicException) throw;
                throw CryptographicException.From("Failed to decrypt private key suite using TPM2", ex);
            }
            finally
            {
                if (disposeEngine) engine.Dispose();
            }
        }

        /// <summary>
        /// Regular expression to match the TPM device name from a device path (<c>/dev/tpm0</c> f.e.; <c>$1</c> contains the device name)
        /// </summary>
        /// <returns>Regular expression</returns>
        [GeneratedRegex(@"^\/(.*\/)?([^\/]+)$", RegexOptions.Compiled)]
        private static partial Regex RxDevicePath_Generator();
    }
}
