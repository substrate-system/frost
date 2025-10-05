# FROST
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/frost/nodejs.yml?style=flat-square)](https://github.com/substrate-system/frost/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/frost?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/frost)](https://packagephobia.com/result?p=@substrate-system/frost?dummy=unused)
[![gzip size](https://img.shields.io/bundlephobia/minzip/@substrate-system/frost?style=flat-square)](https://bundlephobia.com/@substrate-system/name/frost/route-event)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


A TypeScript implementation of the FROST threshold signature scheme as
specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).

FROST (Flexible Round-Optimized Schnorr Threshold signatures) is a threshold
signature scheme that allows a group of participants to collectively generate
signatures, requiring a minimum number of participants during
the signing process.

A single private key gets split into multiple shards during setup.
Each participant gets one shard of the key. The original private key can
be discarded/lost at this point.

The participants use their individual key shards to
collectively create signatures that are mathematically equivalent to what
the original private key would have produced, but the original private key
itself is never reconstructed.

Even after successful signing ceremonies, no single
participant ever gains access to the complete private key. The threshold
property is maintained permanently &mdash; you always need the minimum number of
participants to create future signatures.


_Featuring:_

- **Simple Key Backup**: Split any Ed25519 key with `split()`, recover
  with `recover()`
- **Easy Signing**: Sign with recovered keys using `sign()` - no
  ceremony complexity
- **Flexible Input**: Accepts CryptoKey, PKCS#8, or raw 32-byte keys
- **Threshold Signatures**: Configurable m-of-n threshold signing for advanced
  use cases
- **RFC 9591 Compliant**: [See the doc](https://www.rfc-editor.org/rfc/rfc9591.html)

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Installation](#installation)
- [Example](#example)
  * [Key Backup and Recovery](#key-backup-and-recovery)
  * [Distributed Threshold Signing](#distributed-threshold-signing)
- [Try it](#try-it)
- [Test](#test)
- [API](#api)
  * [Key Backup](#key-backup)
  * [Distributed Signing](#distributed-signing)
- [Standards](#standards)
- [See Also](#see-also)
- [Internals](#internals)
  * [Signing Protocol](#signing-protocol)
- [Protocol Flow](#protocol-flow)
  * [1. Key Generation (Setup)](#1-key-generation-setup)
  * [2. Signing Ceremony](#2-signing-ceremony)
- [Step-by-Step Guide](#step-by-step-guide)
  * [Example](#example-1)

<!-- tocstop -->

</details>

## Installation

```bash
npm i -S @substrate-system/frost
```

## Example

### Key Backup and Recovery

FROST can be used to backup an existing Ed25519 private key by splitting it
into threshold shares. This is useful for creating secure key storage where
you need multiple shares to recover the original key.

In [Dark Crystal](https://darkcrystal.pw/), for example, the intended use is
to give the shards of your private key to several of your friends, using
the social graph to securely backup your key. But this works just as well
by distributing your key shards amongst multiple of your own devices, in case
you lose one device.

```ts
import { webcrypto } from 'crypto'
import {
    createFrostConfig,
    split,
    recover,
    sign
} from '@substrate-system/frost'

// 1. Generate or use existing Ed25519 keypair
const keyPair = await webcrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,  // extractable so we can split the private key
    ['sign', 'verify']
)

// 2. Split into 3 shares (require 2 to recover)
const config = createFrostConfig(2, 3)
const { groupPublicKey, keyPackages } = await split(
    keyPair.privateKey,
    config
)

// 3. Distribute shares to different locations
// - Share 1: USB drive in safe
// - Share 2: Cloud backup (encrypted)
// - Share 3: Paper backup

// 4. Later, recover using any 2 of 3 shares
const availableShares = [keyPackages[0], keyPackages[2]]
const recoveredKey = recover(availableShares, config)

// 5. Use the recovered key to sign
const message = new TextEncoder().encode('Important message')
const signature = await sign(recoveredKey, message, config)

// 6. Verify the signature with the original public key
const isValid = await webcrypto.subtle.verify(
    'Ed25519',
    keyPair.publicKey,
    signature,
    message
)
```

> [!NOTE]  
>   - `split` accepts CryptoKey, Uint8Array (PKCS#8), or Uint8Array
>     (32-byte raw scalar)
>   - The recovered key will produce the same public key as the original
>   - You need at least the threshold number of shares to recover
>   - Different combinations of shares all recover the same key
> 


-------------


### Distributed Threshold Signing

Collaboratively sign a message. The final signature reveals only that the
threshold was met, not *who* signed. It is cryptographically impossible to
determine which participants signed.

```ts
import {
  createFrostConfig,
  generateKeys,
  thresholdSign
} from '@substrate-system/frost'

// 1. Alice creates a 3-of-4 FROST setup
const config = createFrostConfig(3, 4)  // Need 3 out of 4 to sign
const { groupPublicKey, keyPackages } = generateKeys(config)

// 2. Distribute key packages to participants
const [aliceKey, bobKey, carolKey, desmondKey] = keyPackages

// 3. Later, any 3 participants can create a signature
const message = new TextEncoder().encode('Hello, FROST!')
const signature = await thresholdSign(
    [bobKey, carolKey, desmondKey],  // Any 3 participants
    message,
    groupPublicKey,
    config
)

// 4. Verify signature
const isValid = await crypto.subtle.verify(
    'Ed25519',
    new Uint8Array(groupPublicKey.point),
    signature,
    message
)
```

## Try it

Run the example locally.

```bash
npm run example:node
```

This will execute the complete example showing:
1. Alice creating a 3-of-4 threshold keypair
2. Getting key shares for Alice, Bob, Carol, and Desmond
3. Using any 3 participants to create threshold signatures
4. Verifying the signature is valid


## Test

Run the tests:

```sh
npm test
```

Start the example:

```sh
npm start
```


-------------------------------------------------------


## API

### Key Backup

#### `createFrostConfig`

Creates a FROST configuration with Ed25519 cipher suite.

```ts
function createFrostConfig (
  minSigners: number,
  maxSigners: number
): FrostConfig
```

```ts
const config = createFrostConfig(2, 3)  // 2-of-3 threshold
```

#### `split`

```ts
async function split (
  privateKey: CryptoKey | Uint8Array,
  config: FrostConfig
): Promise<Signers>
```

```ts
const { groupPublicKey, keyPackages } = await split(keyPair.privateKey, config)
```

#### `recover`

Recover the private key from threshold shares.

```ts
function recover (
  keyPackages: KeyPackage[],
  config: FrostConfig
): Uint8Array
```

```ts
const recoveredKey = recover(keyPackages.slice(0, 2), config)
```

#### `sign`

Sign a message with a recovered key.

```ts
async function sign (
  recoveredKey:Uint8Array,
  message:Uint8Array,
  config:FrostConfig
):Promise<Uint8Array<ArrayBuffer>>
```

```ts
const signature = await sign(recoveredKey, message, config)
```

#### `thresholdSign`

Create a threshold signature from multiple participants.

```ts
async function thresholdSign (
  keyPackages:KeyPackage[],
  message:Uint8Array,
  groupPublicKey:GroupElement,
  config:FrostConfig
):Promise<Uint8Array>
```

```ts
const signature = await thresholdSign(
    [aliceKey, bobKey, carolKey],  // Participant key packages
    message,
    groupPublicKey,
    config
)
```

### Distributed Signing

#### `generateKeys`

Generate keys for all participants.

```ts
function generateKeys (config:FrostConfig):Signers
```

```ts
const { groupPublicKey, keyPackages } = generateKeys(config)
// groupPublicKey: The collective public key
// keyPackages: Individual key packages for each participant
```

#### `verifyKeyPackage`

Verifies that a key package is valid.

```ts
function verifyKeyPackage (
  keyPackage:KeyPackage,
  config:FrostConfig
):boolean
```

```ts
const isValid = verifyKeyPackage(keyPackage, config)
```


---------------------------------------------------------------


## Standards

This implementation follows:

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) - The Flexible
  Round-Optimized Schnorr Threshold (FROST) Protocol


## See Also

* [FROST RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
* [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
* [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
* [soatok/frost](https://github.com/soatok/frost) &mdash; Go implementation
* [Lose your device, but keep your keys](https://www.iroh.computer/blog/frost-threshold-signatures)
  &mdash; FROST in [iroh](https://www.iroh.computer/)


-----------------------------------------------------------------------


## Internals

### Signing Protocol

#### `FrostSigner`

Represents an individual participant in the signing ceremony.

```ts
const signer = new FrostSigner(keyPackage, config)

// Round 1: Generate nonce commitments
const round1 = signer.sign_round1()

// Round 2: Generate signature share
const round2 = signer.sign_round2(signingPackage, round1.nonces)
```

#### `FrostCoordinator`

Manages the signing ceremony and aggregates signatures.

```ts
const coordinator = new FrostCoordinator(config)

// Create signing package
const signingPackage = coordinator.createSigningPackage(
    message,
    commitmentShares,
    participantIds
)

// Aggregate signature shares
const signature = coordinator.aggregateSignatures(
    signingPackage,
    signatureShares
)

// Verify signature
const isValid = coordinator.verify(signature, message, groupPublicKey)
```

## Protocol Flow

The FROST protocol consists of the following phases:

### 1. Key Generation (Setup)

```ts
// Generate keys for all participants
const { groupPublicKey, keyPackages } = generateKeys(config)

// Distribute key packages to participants securely
```

### 2. Signing Ceremony

#### Round 1: Commitment Phase

Each participant generates nonces and creates commitments:

```ts
const round1Results = signers.map(signer => signer.sign_round1())
```

#### Round 2: Signature Share Generation

Participants receive the signing package and generate signature shares:

```ts
const signingPackage = coordinator.createSigningPackage(
    message, commitmentShares, participantIds
)

const signatureShares = signers.map((signer, i) =>
    signer.sign_round2(signingPackage, round1Results[i].nonces)
)
```

#### Aggregation

The coordinator combines signature shares into a final signature:

```ts
const signature = coordinator.aggregateSignatures(
    signingPackage,
    signatureShares.map(r => r.signatureShare)
)
```

## Step-by-Step Guide

### Example

Alice can create a threshold keypair and later create signatures
with her trusted friends.

#### Step 1: Alice Creates the Initial Setup

```ts
import {
    createFrostConfig,
    generateKeys,
    FrostCoordinator,
    FrostSigner
} from '@substrate-system/frost'

// Alice decides she wants a 3-of-4 threshold scheme
const config = createFrostConfig(3, 4)  // Need 3 out of 4 to sign
const { groupPublicKey, keyPackages } = generateKeys(config)

// Distribute key shares to Alice, Bob, Carol, and Desmond
const [aliceKey, bobKey, carolKey, desmondKey] = keyPackages
```

#### Step 2: Create a Signature

Later, Alice wants to sign a message but needs help from 3 of her 4
trusted friends:

```ts
// Alice chooses Carol and Desmond to help (any 3 would work)
const participants = [aliceKey, carolKey, desmondKey]
const signers = participants.map(pkg => new FrostSigner(pkg, config))
const coordinator = new FrostCoordinator(config)
```

#### Step 3: Sign

This process creates a threshold signature:

```ts
const message = new TextEncoder().encode('Alice\'s important message')

// Round 1: Each participant generates commitments
const round1 = signers.map(s => s.sign_round1())
const commitmentShares = round1.map((r, i) => ({
    participantId: participants[i].participantId,
    commitment: r.commitment
}))

// Create the signing package
const participantIds = participants.map(p => p.participantId)
const signingPackage = await coordinator.createSigningPackage(
    message,
    commitmentShares,
    participantIds
)

// Round 2: Generate signature shares
const signatureShares = []
for (let i = 0; i < signers.length; i++) {
    const res = await signers[i].sign_round2(signingPackage, round1[i].nonces)
    signatureShares.push(res.signatureShare)
}

// Combine into final signature
const finalSignature = coordinator.aggregateSignatures(
  signingPackage,
  signatureShares
)

// Verify it worked
const valid = await coordinator.verify(finalSignature, message, groupPublicKey)
console.log('Threshold signature valid:', valid)  // Should be true
```

The signature is mathematically equivalent to a single-key signature
