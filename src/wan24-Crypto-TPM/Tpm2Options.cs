using System.ComponentModel.DataAnnotations;
using System.Net.Sockets;
using Tpm2Lib;
using wan24.ObjectValidation;

namespace wan24.Crypto.TPM
{
    /// <summary>
    /// TPM2 options
    /// </summary>
    public sealed record class Tpm2Options : ValidatableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public Tpm2Options() : base() { }

        /// <summary>
        /// Any tagged object (will be cloned, if it implements <see cref="ICloneable"/>, and <see cref="GetCopy"/> has been called)
        /// </summary>
        public object? Tag { get; set; }

        /// <summary>
        /// Engine initializer
        /// </summary>
        public Initialization_Delegate? Initializer { get; set; }

        /// <summary>
        /// Use a TCP TPM simulator? (<see href="https://www.microsoft.com/en-us/download/details.aspx?id=52507"/>)
        /// </summary>
        public bool UseSimulator { get; set; }

        /// <summary>
        /// TPM simulator IP address
        /// </summary>
        [Ip(AddressFamily.InterNetwork)]
        public string SimulatorIp { get; set; } = "127.0.0.1";

        /// <summary>
        /// TPM simulator port number
        /// </summary>
        [System.ComponentModel.DataAnnotations.Range(1, ushort.MaxValue)]
        public int SimulatorPort { get; set; } = 2321;

        /// <summary>
        /// Stop the TPM simulator after use?
        /// </summary>
        public bool StopSimulator { get; set; } = false;

        /// <summary>
        /// Does the TPM simulator have a reference model?
        /// </summary>
        public bool SimulatorHasReferenceModel { get; set; }

        /// <summary>
        /// Does the TPM have a resource manager?
        /// </summary>
        public bool HasResourceManager { get; set; } = true;

        /// <summary>
        /// Linux TPM device path
        /// </summary>
        [MinLength(1), MaxLength(short.MaxValue)]
        public string? LinuxDevicePath { get; set; }

        /// <summary>
        /// Resource handle
        /// </summary>
        public TpmRh? ResourceHandle { get; set; }

        /// <summary>
        /// Algorithm
        /// </summary>
        public TpmAlgId? Algorithm { get; set; }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public Tpm2Options GetCopy() => new()
        {
            Tag = Tag is ICloneable cloneable ? cloneable.Clone() : Tag,
            Initializer = Initializer,
            UseSimulator = UseSimulator,
            SimulatorIp = SimulatorIp,
            SimulatorPort = SimulatorPort,
            SimulatorHasReferenceModel = SimulatorHasReferenceModel,
            StopSimulator = StopSimulator,
            HasResourceManager = HasResourceManager,
            LinuxDevicePath = LinuxDevicePath,
            ResourceHandle = ResourceHandle,
            Algorithm = Algorithm
        };

        /// <summary>
        /// Set the tagged object (will be cloned, if it implements <see cref="ICloneable"/>, and <see cref="GetCopy"/> has been called)
        /// </summary>
        /// <param name="tag">Tagged object</param>
        /// <returns>This</returns>
        public Tpm2Options WithTag(object tag)
        {
            Tag = tag;
            return this;
        }

        /// <summary>
        /// Set an initializer
        /// </summary>
        /// <param name="initializer">Initializer</param>
        /// <returns>This</returns>
        public Tpm2Options WithInitializer(Initialization_Delegate initializer)
        {
            Initializer = initializer;
            return this;
        }

        /// <summary>
        /// Set a resource handle
        /// </summary>
        /// <param name="handle">Resource handle</param>
        /// <returns>This</returns>
        public Tpm2Options WithResourceHandle(TpmRh handle)
        {
            ResourceHandle = handle;
            return this;
        }

        /// <summary>
        /// Set an algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>This</returns>
        public Tpm2Options WithAlgorithm(TpmAlgId algo)
        {
            Algorithm = algo;
            return this;
        }

        /// <summary>
        /// Delegate for an engine initializer
        /// </summary>
        /// <param name="engine">Engine (connected already)</param>
        /// <param name="options">Options</param>
        public delegate void Initialization_Delegate(Tpm2 engine, Tpm2Options options);
    }
}
