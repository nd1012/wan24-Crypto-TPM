# wan24-Crypto-TPM

**WARNING**: The code has not been tested with a real TPM running on Linux 
yet. I'd appreciate if someone would give me some feedback, if it worked for 
them. Anyway the tests use the Microsoft TPM simulator and did run 
successfully (and also with a real TPM device on Windows 11).

This library contains some helpers for easy TPM(2) usage. It does _way not_ 
implement everything that a TPM offers - these are the selected features, 
which include the TPM into your security model:

- Determine if TPM2 can be accessed
- Determine the max. supported digest (size)
- Random number generation (`TpmRng`)
- HMAC-SHA-1/256/384/512 (`Tpm2Helper` and `MacTpmHmacSha*Algorithm`)
- `TpmSymmetricKeySuite` which implements `ISymmetricKeySuite`
- `TpmSecuredValue` which works like `SecureValue`
- `TpmSharedSecret` for usage with a remote key storage
- `TpmValueProtection` to extend `ValueProtection`

As you can see, the number of features is quiet clear.

This library extends the `wan24-Crypto` library with these algorithms:

| Algorithm | ID | Name |
| --- | --- | --- |
| **MAC** |  |  |
| TPM HMAC-SHA-1 | 7 | TPMHMAC-SHA-1 |
| TPM HMAC-SHA-256 | 8 | TPMHMAC-SHA-256 |
| TPM HMAC-SHA-384 | 9 | TPMHMAC-SHA-384 |
| TPM HMAC-SHA-512 | 10 | TPMHMAC-SHA-512 |

**CAUTION**: TPM secured information won't be usable anymore, if the TPM (or 
even the TPM owner) changes!

The goal of this library is to make TPM usable for everyone in a simple way, 
without having to fight with a firmware and complex/missing documentation. 
It's an ideal extension to the existing `wan24-Crypto` infrastructure.

**NOTE**: There are no provisioning functionaliies implemented in this 
library. A TPM which is going to be used needs to be provisioned manually or 
from the host OS (Windows f.e. does provision a TPM automatically).

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto-TPM/).

## Usage

In case you don't use the `wan24-Core` bootstrapper logic, you need to 
initialize the TPM2 extension first, before you can use it:

```cs
wan24.Crypto.TPM.Bootstrap.Boot();
```

This will register the algorithms to the `wan24-Crypto` library.

**NOTE**: All algorithms will be registered, no matter if there's even a TPM 
available or not, or if the algorithm is supported by an available TPM. This 
is because the TPM options support configuring a simulator or to choose 
between multiple available TPMs. So the bootstrapper can't really know which 
algorithms are going to be available (or used).

In case you work with dependency injection (DI), you may want to add some 
services:

```cs
builder.Services.AddWan24CryptoTpm();
```

This will register transient `Tpm2Options` (using `Tpm2Helper.DefaultOptions`) 
and `Tpm2` (using `Tpm2Helper.CreateEngine`) service objects.

### `Tpm2Engine` fixes multithreading bugs

Using a `Tpm2` instance for each thread still has multithreading problems in 
the MS.TSS .NET library, that's why a `Tpm2Engine` should be used in 
multithreading environments. It ensures that

- only one `Tpm2` instance is being used at a time
- only one thread can use the `Tpm2` instance at a time

Example:

```cs
// Creating a Tpm2Engine uses static thread synchronization (a Tpm2Engine instance should be singleton)
using Tpm2Engine engine = Tmp2Engine.Create();

// Using per-engine thread synchronization (optional, to use one Tpm2Engine instance from multiple threads)
using SemaphoreSyncContext ssc = engine.Sync;

// Now you can perform a TPM operation using the engine.TPM property, which hosts the Tpm2 instance
```

**NOTE**: This is only required unless the multithreading bugs in the MS.TSS 
.NET library has been fixed by its vendor. In theory it should be possible to 
use a `Tpm2` instance per thread without static thread locking (while 
multithreaded access to a `Tpm2` instance still requires thread 
synchronization).

In case you're using `Tpm2Helper.DefaultEngine`, the `Tpm2Engine` usage is 
slightly different:

```cs
// Creating a Tpm2Engine uses static thread synchronization (a Tpm2Engine instance should be singleton)
using Tpm2Engine engine = new();// The empty constructor will use the Tpm2Helper.DefaultEngine and Tpm2Helper.DefaultEngineSync

// Using per-engine thread synchronization
using SemaphoreSyncContext ssc = engine.Sync;

// Now you can perform a TPM operation using the engine.TPM property, which hosts the Tpm2 instance
```

Implemented types support using a `Tpm2Engine` also, which will then not be 
disposed, but used for synchronizing the TPM access.

### TPM2 options

In the `Tpm2Options` you can define how to connect to the TPM. You may also 
specify

- a resource handle (currently used for finalizing a HMAC)
- an algorithm (currently used for creating a HMAC)
- a tagged object (which will be cloned, if it implements `ICloneable`, and 
the `GetCopy` method of the `Tpm2Options` instance has been called)

Using the `With*` methods you can configure options fluent.

### Determine if TPM2 can be accessed

```cs
bool canAccessTpm2 = Tpm2Helper.IsAvailable();
```

Because on a Linux system some file IO operations may run, there's an 
`IsAvailableAsync` method, too.

### `Tpm2` instance creation

```cs
using Tpm2 engine = Tpm2Helper.CreateEngine();
```

The `Tpm2` instance is a connected TPM2 TSS, which allows to do whatever the 
TSS offers. By giving `Tpm2Options` to the `CreateEngine` method, you can 
define which TPM to use, and optional set an `Initializer` delegate, which may 
bring the TPM into the desired state, before running any other operation.

The `CreateEngine` method is being called internal, whenever you use a TPM 
functionality without giving an existing `Tpm2` instance to the called method. 
And if you didn't specify the `Tpm2Options`, the `Tpm2Helper.DefaultOptions` 
will be used, which you may preset, if required.

The `TryCreateEngine` does the same as `CreateEngine`, but won't throw on 
error.

### Maximum supported digest (size)

```cs
int maxDigestSize = Tpm2Helper.GetMaxDigestSize();// Size in byte
TpmAlgId maxDigest = Tpm2Helper.GetDigestAlgorithm(maxDigestSize);
```

The max. supported digest size limits the output of the random number 
generator, and it also defines the possible digest algorithms.

**NOTE**: `TpmRng` doesn't limit the random number count being generated in 
any way.

### Random number generator

**CAUTION**: The example code is actually a negative example - see "Best 
practices" for a better solution suggestion!

```cs
RND.Generator = new TpmRng();// If not used as singleton, an instance should be disposed!
```

The `TpmRng` implements the `IRng` interface, which allows to use the TPM as 
RNG for `wan24-Crypto`. Internal it uses the `Tpm2Helper.CreateRandomData` 
helper method, which is restricted to the TPMs random number output length, 
while the RNG implementation doesn't restrict the length of the generated 
random data.

### HMAC-SHA-1/256/384/512

```cs
byte[] hmac = Tpm2Helper.Hmac(anyAuthMessage);
```

**NOTE**: The owner resource handle will be used per default.

Using the `Tpm2Helper.Hmac` method you can create a HMAC-SHA-1/256/384/512 
using the TPM. These HMACs can only be re-created using the same TPM. 
Specifying an additional MAC key is optional.

**NOTE**: Not every TPM implements all algorithms. HMAC-SHA-256 seems to be 
implemented by most TPMs. If you don't specify an algorithm to the `Hmac` 
method, it'll determine and use the maximum supported algorithm.

**CAUTION**: If you change your TPM hardware, you won't be able to re-create a 
HMAC! This also applies even only the TPM owner changes.

You can also use the `wan24-Crypto` registered HMAC algorithms during 
encryption, for example. Then cipher data couldn't be decrypted on any other 
computer than the one that encrypted it.

**TIP**: If you use a TPM HMAC of your encryption password, you can ensure 
that the cipher data can only be decrypted from the same computer that was 
used to encrypt it!

There are also `TpmHmac*` extension methods for a `byte[]` and 
`(ReadOnly)Span<byte>`.

### TPM symmetric key suite

```cs
using TpmSymmetricKeySuite tpmAuth = new(key);
```

The `TpmSymmetricKeySuite` works as the `SymmetricKeySuite`, but uses a TPM 
HMAC for calculating the final key (and identifier, if any).

### TPM secured value

The `TpmSecuredValue` works as `SecureValue` and protects a value using the 
TPM.

If you'd like TPM only if available, you can set the constructor parameter 
value of `requireTpm` to `false`. If TPM is not available, the constructor 
won't throw, and `TpmSecuredValue` will just work as `SecureValue` as a 
fallback solution.

### En-/decrypting a private key suite

Using the `TpmEncrypt` extension method you can encrypt a `PrivateKeySuite` 
using a TPM flavored key. With `Tpm2Helper.DecryptPrivateKeySuite` you can 
decrypt it.

**CAUTION**: If you change your TPM hardware, there's no way to decrypt the 
private key suite anymore! The cipher data can only be decrypted using the 
same TPM hardware that was used for encryption. This also applies even only 
the TPM owner changes.

### TPM shared secret

The `TpmSharedSecret` is a helper for deriving a TPM secured key from a remote 
key storage.

**NOTE**: The following examples assume that your remote key storage requires 
sending a secret for receiving a secret. This may be different per each remote 
key storage.

Example how to initialize a new secret:

```cs
using Tpm2 engine = Tpm2Helper.CreateEngine();
byte[] token = RND.GetBytes(Tpm2Helper.GetMaxDigestLength(engine)),
	remoteSecret = RND.GetBytes(token.Length);
// Store the token somewhere for restoring the secret later
using TpmSharedSecret tpmSecret = new(token, engine: engine);
tpmSecret.ProtectRemoteSecret(remoteSecret);
// Send tpmSecret.Secret.Array and remoteSecret to the remote key storage
byte[] secret = tpmSecret + remoteSecret;
```

**CAUTION**: **_NEVER_** store `remoteSecret` persistent outside of the remote 
key storage! **_NEVER_** store `tpmSecret.Secret.Array` anywhere!

`tpmSecret.Secret.Array` is used to authenticate for receiving the value of 
`remoteSecret` from the remote key storage later.

**NOTE**: `token` may be stored plain, maybe protected using the OS 
capabilities (like the file system ACL, f.e.).

Example how to restore a previously initialized secret:

```cs
// Load the token from where it was saved during secret initialization
using TpmSharedSecret tpmSecret = new(token);
// Send tpmSecret.Secret.Array to the remote key storage and receive remoteSecret
byte[] secret = tpmSecret + remoteSecret;
```

The `TpmSharedSecret` also supports including an additional secret (for user 
authentication f.e.).

### TPM value protection

The `TpmValueProtection` uses the TPM for protecting a value as 
`ValueProtection` does without the TPM. For this the scope keys will be used 
as value for a TPM HMAC, which will then be the final key being used for the 
value encryption (the max. TPM supported HMAC algorithm will be used).

**NOTE**: The `TpmValueProtection` uses the scope keys from `ValueProtection` 
and uses the default TPM state for creating the HMAC. That means in particular 
you'll still have to ensure a restorable user scope key, while you don't have 
to take care the system scope key anymore.

You may replace the `ValueProtection` protect/unprotect handlers:

```cs
TpmValueProtection.Enable();
```

**NOTE**: The `TpmValueProtection` protect/unprotect handlers will connect to 
the TPM for every call, which is an overhead and may impact the performance of 
your application. If you don't want that, you may simply replace the 
`ValueProtection` user/system scope keys with TPM HMACs, probably including an 
user secret for the user scope key.

Or you can use both, the `ValueProtection` and the `TpmValueProtection`, as it 
is suitable for your application, separately.

### Extension methods

The `TpmExtensions` class exports some extension methods to make life more 
easy, when working with TPM types and `wan24-Crypto`. There are also 
extensions for the `PrivateKeySuite`, `byte[]` and `(ReadOnly)Span<byte>` 
(TPM HMAC creation). Using the `CryptoOptions.WithTpmHmac` extension method, 
you can set the max. supported TPM HMAC algorithm for any crypto application 
which requires to compute a MAC.

### Using a singleton TPM2 connection

By setting a `Tpm2`  instance to the `Tpm2Helper.DefaultEngine` property, you 
can specify a singleton connection to use from `Tpm2Helper` methods. Use the 
`Tmp2Helper.DefaultEngineSync` to synchronize multithreaded connection usage:

```cs
// Set a singleton default TPM engine
Tpm2Helper.DefaultEngine = Tpm2Helper.CreateEngine();

// Synchronize the default TPM engine access before performing any Tpm2Helper operation
using SemaphoreSyncContext ssc = Tpm2Helper.DefaultEngineSync;
// Now you can perform any Tpm2Helper operation in a multithreaded environment using the singleton Tpm2Helper.DefaultEngine
```

The `Tpm2Helper.DefaultEngine` value will be set to the `engine` parameter of 
`Tpm2Helper` methods, if no value was given.

## Why not support TPM PKI/signing/sealing/etc.?

If you followed the TPM development process until today you know that TPM2 is 
fully incompatible with TPM1. I try to concentrate on the absolute minimum 
that TPM offers, to stay (hopefully) compatible with TPM3 (or any future TPM 
version). With the HMAC function you should have everything that is required 
at minimum, for implementing everything else using `wan24-Crypto` (which 
offers way more functionality than TPM does). The `ExpandedKey` of a 
`TpmSymmetricKeySuite` can be used for any encryption, and it's bound to the 
available TPM, so you could encrypt a `PrivateKeySuite`, for example, which 
can then only be decrypted using the same TPM. And you're not bound to the TPM 
implemented algorithms, as you have the free choice to use any `wan24-Crypto` 
implemented cryptographic algorithm, and optional combine them with the 
provided TPM functionality.

To sum it up - the reasons for _not_ using all of the TPM capabilities:

- TPM doesn't implement the cryptographic algorithms that you need to use
- The TPM processing speed is decreased because of KDF usage in places where 
you don't want (need) to use KDF (at all)
- Future security developments require new TPM hardware, which will mess up 
your PKI
- _TPM is way not the answer_ to all crypto related questions
- TPMx may fully break TPM2 key capabilities (again), while the implemented 
features of `wan24-Crypto-TPM` _may_ still be supported ('cause they're the 
absolute basics, which should be valid for at last the next decade from now)

There are many good reasons to use only the absolute basics of the offered TPM 
features, and only a few applications which are really enriched by the TPM, 
which is usually being used in normal devices.

Someone might argue that TPM can encrypt/decrypt (seal/unseal) data 
independent from the OS and other hardware - yes, that's true. If AES-128 does 
still fit your security policy in 2023+, you'd be fine with it (use `Tpm2`). 
But remember that the in-TPM en-/decryption is only suitable for small blobs! 
This in combination limits the application in a way which is not acceptable 
for the most use cases for cryptography: If you want to process larger blobs, 
you have to DIY. If you need AES-256 (or any other algorithm than the TPM 
implemented ones), you have to DIY. Instead of using the TPM lockout, DIY and 
use KDF in addition. That's enough DIY to skip implementing support for the 
TPM offered functionality into `wan24-Crypto-TPM` and sticking to the TPMs 
HMAC only, which is enough already (and not to forget the RNG also). Brute 
Force will always stay possible, no matter if you use TPM or not - remember 
that.

However, if you need all the TPM functionality (if your boss or a customer is 
obsessed with TPM and no technical argument seems to count anymore - I know 
something like that...), you're free to use `Tpm2Helper.CreateEngine` and work 
with the `Tpm2` object directly and without any limit.

From my sight there's only one reason for sticking to the TPM implemented 
functionality: Private keys will be used for crypto/signature witin the TPM 
only, which allows protecting/authenticating sensitive information within an 
isolated processor, which runs independent from the rest of the system. But 
since the rest of the system controls the TPM, it's nothing more than a piece 
of hardware which can be used to identify a device. Remember that there's 
still software (the TSS and the firmware), which is required to be 
implemented, and is a point of failure for the TPM offered security stack. 
Once that software was attacked with success, your software has been broken, 
too. So even the identification of a device using TPM isn't 100% trustable.

## Supported platforms

All platforms which support TPM should be supported by this library. Anyway, 
Apple devices often don't contain a TPM, but a T2 (which is similar to TPM) 
instead (which may be called T8012, too).

I've successfully run the tests on a Windows 11 computer only so far, since at 
the moment I don't own a Linux device with a TPM. But Linux supports TPM, and 
the underlaying TSS.MSR .NET library supports Linux, finally.

So the supported platform list may be:

- Windows (10+)
- Linux
- (MAC OSX)

There seems to be no .NET library for Apples T2 chip, and I'm not going to 
implement one. You could use the MAC OSX API for the T2 chip directly by using 
interop, but however, since HMAC seems not to be supported, I'd use a T2 as a 
better HWRNG only.

For Apple iOS (and others != OSX) there is a "Security Enclave", which is a 
SoC like TPM - but also without HMAC support, so it can be seen as a better 
HWRNG, too.

On an Android device you'd use the KeyChain or TEE API usually, but there 
could also be a TPM being supported. However, it's not supported by the 
TSS.MSR, so this library can't offer support, too.

To sum it up: Forget about Apple and Android, and concentrate on Windows and 
Linux, if you'd like to use this TPM library.

## Best practice

### `TpmRng` usage

Random numbers are security critical, and it may be a bad idea to rely on one 
entropy source or RNG only. For this I suggest to use the `TpmRng` together 
with other RNGs, and combine their generated random numbers using a `XorRng`.

### TPM encrypted `PrivateKeySuite`

When your app requires a TPM protected private key suite, you can create one 
with these steps:

1. Create a `PrivateKeySuite`
2. Encrypt the `PrivateKeySuite` using the `TpmEncrypt` extension method
3. Store the cipher data in a file
4. Dispose the `PrivateKeySuite` when not in use anymore!

To load it when your app starts again:

1. Decrypt the `PrivateKeySuite` cipher data from the file using 
`Tpm2Helper.DecryptPrivateKeySuite`
2. Dispose the `PrivateKeySuite` when not in use anymore!

### Persistent secret storage

Different OS offer different secret storage solutions - but none of them seem 
to offer a real security benefit. There's only one thing, which could enhance 
security (really): Storing a part of a secret at another system.

To make this process combinable with TPM, there's the `TpmSharedSecret` 
helper class, which makes it possible to restore an (user) secret using a TPM 
bound token, which may be stored in plain on the processing system, but 
requires using a remote key storage to provide a partial key for a TPM 
processed token value, which acts as a shared secret.

When storing a mashine scope secret, it ensures that

- the ciphered data on that mashine can be remote-deleted by simply deleting 
the remote stored secret
- someone which could access any key part (or both), but isn't able to access 
the TPM, can't get to the final key

When storing an user scope secret, it ensures in addition that

- even when having both key parts and access to the TPM, a dictionary or Brute 
Force attack on the user password isn't practicable, when the user password is 
secure (has been KDF processed)

These benefits apply to both sides: The local system, and the remote key 
storage. By the way the remote key storage should store the provided secret 
encrypted using the shared secret, and never store the shared secret anywhere.

To get a final key

- the plain stored token must be available (1st part of the key)
- access to the TPM must be available (for computing the shared secret)
- the remote storage must reply the 2nd part of the key for the provided 
shared secret
- another TPM access must be possible to combine both key parts

An attacker can't use the plain stored token (1st key part) alone. He even 
can't request the 2nd key part from the remote key storage, if the TPM can't 
be accessed. Also the 2nd key part alone doesn't offer any success for an 
attacker, if the TPM can't be accessed, too - and even when having both key 
parts, the TPM access is a required component to get to the final key. To 
break the security, an attacker requires both key parts and having access to 
the TPM. This applies to a mashine scope secret.

For an user scope secret, an attacker would then still need the user password. 
To secure the user password, you should pre-process it using KDF before you 
use it as the `key` parameter in the `TpmSharedSecret` constructor. This I'd 
call an almost perfect solution in 2023 then.

Anyway, there are some pitfalls with that solution: IF

- the TPM (owner) changed, or the TPM is broken, then ciphered data is lost
- there is no connection to the remote key storage possible, ciphered data 
can't be accessed unless the connection problem was solved
- the remote stored key part got lost, then ciphered data is lost, too

It's important to have that in mind and implement emergency solutions for such 
(worst case) scenarios to avoid a data loss.