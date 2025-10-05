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

- **Threshold Signatures**: Configurable m-of-n threshold signing
- **Two-Round Protocol**: Efficient signing with commitment and signature rounds
- **Key Backup & Recovery**: Split existing Ed25519 keys for backup, recover with threshold shares
- **RFC 9591 Compliant**: [See the doc](https://www.rfc-editor.org/rfc/rfc9591.html)

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Installation](#installation)
- [Example](#example)
  * [Try it](#try-it)
- [API](#api)
  * [Configuration](#configuration)
  * [Key Generation](#key-generation)
  * [Signing Protocol](#signing-protocol)
- [Protocol Flow](#protocol-flow)
  * [1. Key Generation (Setup)](#1-key-generation-setup)
  * [2. Signing Ceremony](#2-signing-ceremony)
- [Step-by-Step Guide](#step-by-step-guide)
  * [Example](#example-1)
- [Key Backup and Recovery](#key-backup-and-recovery)
  * [Backup Example](#backup-example)
- [Types](#types)
  * [Protocol Types](#protocol-types)
- [Security](#security)
- [Production Considerations](#production-considerations)
- [Testing](#testing)
- [Building](#building)
- [Standards Compliance](#standards-compliance)
- [See Also](#see-also)

<!-- tocstop -->

</details>

## Installation

```bash
npm i -S @substrate-system/frost
```

## Example

A simple scenario: Alice creates threshold keys, then creates
signatures with help from Bob, Carol, and Desmond.

```ts
import {
    createFrostConfig,
    generateKeys,
    FrostCoordinator,
    FrostSigner
} from '@substrate-system/frost'

// 1. Alice creates a 3-of-4 FROST setup
const config = createFrostConfig(3, 4)  // Need 3 out of 4 to sign
const { groupPublicKey, keyPackages } = generateKeys(config)

// Name the participants
const [aliceKey, bobKey, carolKey, desmondKey] = keyPackages

// 2. Later, creates a signature using Bob, Carol, and Desmond
const participants = [bobKey, carolKey, desmondKey]
const signers = participants.map(pkg => new FrostSigner(pkg, config))
const coordinator = new FrostCoordinator(config)

// Generate commitments
const round1Results = signers.map(signer => signer.sign_round1())
const commitmentShares = round1Results.map((result, i) => ({
    participantId: participants[i].participantId,
    commitment: result.commitment
}))

// FROST signing ceremony creates a threshold signature
const message = new TextEncoder().encode('Hello, FROST!')
const participantIds = keyPackages.map(pkg => pkg.participantId)

const signingPackage = await coordinator.createSigningPackage(
  message,
  commitmentShares,
  participantIds,
  groupPublicKey
)

// Generate signature shares
const signatureShares = await Promise.all(
  signers.map(async (signer, i) => {
    const result = await signer.sign_round2(
      signingPackage,
      round1Results[i].nonces,
      groupPublicKey
    )
    return result.signatureShare
  })
)

const finalSignature = coordinator.aggregateSignatures(
  signingPackage,
  signatureShares
)

// Verify signature
const isValid = await coordinator.verify(
    finalSignature,
    message,
    keys.groupPublicKey
)
```

### Try it

Run the example locally.

```bash
npm run example:node
```

This will execute the complete example showing:
1. Alice creating a 3-of-4 threshold keypair
2. Getting key shares for Alice, Bob, Carol, and Desmond
3. Using any 3 participants to create threshold signatures
4. Verifying the signature is valid

## API

### Configuration

#### `createFrostConfig(minSigners:number, maxSigners:number)`

Creates a FROST configuration with Ed25519 cipher suite.

- `minSigners`: Minimum number of participants required for signing
- `maxSigners`: Total number of participants

```ts
const config = createFrostConfig(3, 5)  // 3-of-5 threshold
```

### Key Generation

#### `generateKeys(config: FrostConfig)`

Generates keys for all participants.

```ts
const keyGenResult = generateKeys(config)

// Result contains:
// - groupPublicKey: The collective public key
// - keyPackages: Individual key packages for each participant
```

#### `splitExistingKey(existingKey: Uint8Array, config: FrostConfig)`

Splits an existing Ed25519 private key into FROST shares using trusted dealer.

```ts
const { groupPublicKey, keyPackages } = splitExistingKey(privateScalar, config)

// Use for key backup - splits one key into n shares
// Requires m-of-n shares to recover
```

#### `recoverPrivateKey(keyPackages: KeyPackage[], config: FrostConfig)`

Recovers the original private key from threshold shares using Lagrange interpolation.

```ts
const recoveredKey = recoverPrivateKey(keyPackages, config)

// Requires at least minSigners key packages
// Returns the original 32-byte Ed25519 private scalar
```

#### `verifyKeyPackage(keyPackage:KeyPackage, config:FrostConfig)`

Verifies that a key package is valid.

```typescript
const isValid = verifyKeyPackage(keyPackage, config)
```

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

## Key Backup and Recovery

FROST can be used to backup existing Ed25519 private keys by splitting them
into threshold shares. This is useful for creating resilient key storage where
you need multiple shares to recover the original key.

### Backup Example

```ts
import { webcrypto } from 'crypto'
import {
    generateKeys,
    splitExistingKey,
    recoverPrivateKey
} from '@substrate-system/frost'

// 1. Generate or use existing Ed25519 keypair
const keyPair = await webcrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
)

// 2. Extract the private key seed
const privateKeyBuffer = await webcrypto.subtle.exportKey(
    'pkcs8',
    keyPair.privateKey
)
const pkcs8 = new Uint8Array(privateKeyBuffer)
const privateKeySeed = pkcs8.slice(pkcs8.length - 32)

// 3. Derive the Ed25519 scalar with proper bit clamping
const seedHash = await webcrypto.subtle.digest('SHA-512', privateKeySeed)
const seedHashBytes = new Uint8Array(seedHash)
const privateScalar = seedHashBytes.slice(0, 32)
privateScalar[0] &= 248   // Clear bottom 3 bits
privateScalar[31] &= 127  // Clear top bit
privateScalar[31] |= 64   // Set bit 254

// 4. Split into 3 shares (require 2 to recover)
const config = generateKeys.config(2, 3)
const { groupPublicKey, keyPackages } = splitExistingKey(privateScalar, config)

// 5. Distribute shares to different locations
// - Share 1: USB drive in safe
// - Share 2: Cloud backup (encrypted)
// - Share 3: Paper backup at bank

// 6. Later, recover using any 2 of 3 shares
const availableShares = [keyPackages[0], keyPackages[2]]
const recoveredScalar = recoverPrivateKey(availableShares, config)

// 7. Verify recovery by checking the public key matches
const verification = splitExistingKey(recoveredScalar, config)
// verification.groupPublicKey matches original
```

**Important Notes:**
- The recovered scalar will produce the same public key as the original
- You need at least the threshold number of shares to recover
- Different combinations of shares all recover the same key
- For WebCrypto compatibility, you need to work with the derived scalar,
  not the raw seed

## Types

```ts
import * as types from '@substrate-system/frost/types'
```

- `ParticipantId`: Identifies a participant in the protocol
- `Scalar`: Represents a scalar value in the cryptographic group
- `GroupElement`: Represents a point on the elliptic curve
- `FrostSignature`: The final threshold signature with R and z components

### Protocol Types

- `KeyPackage`: Contains participant's key material and commitments
- `SigningPackage`: Bundles message and commitments for round 2
- `RoundOneOutputs`: Nonces and commitments from round 1
- `RoundTwoOutputs`: Signature share from round 2

## Security

**Secure Random Generation**: `crypto.getRandomValues()` for entropy
**SHA-512 Hashing**: Web Crypto API for secure hash operations


## Production Considerations

1. **Secure Communication**: Ensure secure channels between participants
2. **Input Validation**: All inputs are validated for correct length and format
3. **Error Handling**: Comprehensive error handling for cryptographic failures
4. **Side-Channel Protection**: Consider timing attack mitigations for
   sensitive operations
5. **Key Management**: Implement secure storage and distribution of key packages

## Testing

Run the test suite:

```bash
npm test
```

View the interactive example:

```bash
npm start
```

## Building

Build the library:

```bash
npm run build
```

This generates both CommonJS and ES modules in the `dist/` directory.

## Standards Compliance

This implementation follows:

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) - The Flexible
  Round-Optimized Schnorr Threshold (FROST) Protocol
- Ed25519 signature


## See Also

* [FROST RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
* [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
* [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
* [soatok/frost](https://github.com/soatok/frost) &mdash; Go implementation
* [Lose your device, but keep your keys](https://www.iroh.computer/blog/frost-threshold-signatures)
  &mdash; FROST in [iroh](https://www.iroh.computer/)
