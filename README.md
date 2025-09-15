# FROST
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/frost/nodejs.yml?style=flat-square)](https://github.com/substrate-system/frost/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/frost?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/frost)](https://packagephobia.com/result?p=@substrate-system/frost)
[![gzip size](https://img.shields.io/bundlephobia/minzip/@substrate-system/frost?style=flat-square)](https://bundlephobia.com/@substrate-system/name/frost/route-event)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


A TypeScript implementation of the FROST threshold signature scheme as
specified in [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html).

FROST (Flexible Round-Optimized Schnorr Threshold signatures) is a threshold
signature scheme that allows a group of participants to collectively generate
signatures while requiring only a minimum threshold of participants to be
present during the signing process.

_Featuring:_

- **Threshold Signatures**: Configurable m-of-n threshold signing
- **Two-Round Protocol**: Efficient signing with commitment and signature rounds
- **RFC 9591 Compliant**: [See the doc](https://www.rfc-editor.org/rfc/rfc9591.html)
- **TypeScript**
- **Ed25519 Support**

<details><summary><h2>Contents</h2></summary>
<!-- toc -->

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Protocol Flow](#protocol-flow)
- [Examples](#examples)
- [Types](#types)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Building](#building)

</details>

## Installation

```bash
npm install @substrate-system/frost
```

## Example

A simple scenario: Alice creates a keypair, then recovers it using help from
Bob, Carol, and Desmond.

```ts
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner
} from '@substrate-system/frost'

// 1. Alice creates a 3-of-4 FROST setup
const config = createFrostConfig(3, 4) // Need 3 out of 4 to recover
const dealer = new TrustedDealer(config)
const { groupPublicKey, keyPackages } = dealer.generateKeys()

// Name the participants
const [aliceKey, bobKey, carolKey, desmondKey] = keyPackages

// 2. Later, Alice recovers her key using Bob, Carol, and Desmond
const participants = [bobKey, carolKey, desmondKey]
const signers = participants.map(pkg => new FrostSigner(pkg, config))
const coordinator = new FrostCoordinator(config)

// 3. FROST signing ceremony proves the key recovery worked
const message = new TextEncoder().encode('Alice\'s important message')
// ... (see full example below)
```

### Try it

Run the example to see Alice's key recovery in action:

```bash
npm run example:node
```

This will execute the complete example showing:
1. Alice creating a 3-of-4 threshold keypair
2. Getting key shares for Alice, Bob, Carol, and Desmond
3. Using any 3 participants to recover Alice's signing capability
4. Verifying the recovery worked by creating a valid signature

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

#### `TrustedDealer`

Handles key generation using the trusted dealer approach.

```ts
const dealer = new TrustedDealer(config)
const keyGenResult = dealer.generateKeys()

// Result contains:
// - groupPublicKey: The collective public key
// - keyPackages: Individual key packages for each participant
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
// Trusted dealer generates keys for all participants
const dealer = new TrustedDealer(config)
const { groupPublicKey, keyPackages } = dealer.generateKeys()

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

### Complete Example: Alice's Key Recovery

Here's how Alice can create a keypair and later recover it using her trusted friends:

#### Step 1: Alice Creates the Initial Setup

```ts
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner
} from '@substrate-system/frost'

// Alice decides she wants a 3-of-4 threshold scheme
const config = createFrostConfig(3, 4) // Need 3 out of 4 to recover
const dealer = new TrustedDealer(config)
const { groupPublicKey, keyPackages } = dealer.generateKeys()

// Distribute key shares to Alice, Bob, Carol, and Desmond
const [aliceKey, bobKey, carolKey, desmondKey] = keyPackages
```

#### Step 2: Alice Needs to Recover Her Key

Later, Alice wants to use her key but needs help from 3 of her 4 trusted friends:

```ts
// Alice chooses Bob, Carol, and Desmond to help (any 3 would work)
const participants = [bobKey, carolKey, desmondKey]
const signers = participants.map(pkg => new FrostSigner(pkg, config))
const coordinator = new FrostCoordinator(config)
```

#### Step 3: The FROST Signing Ceremony

This process proves Alice can recover her signing capability:

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
const finalSignature = coordinator.aggregateSignatures(signingPackage, signatureShares)

// Verify it worked
const valid = await coordinator.verify(finalSignature, message, groupPublicKey)
console.log('Key recovery successful:', valid) // Should be true
```

### Key Benefits

- **Threshold Security**: Alice only needs 3 out of 4 friends to recover her key
- **No Single Point of Failure**: Alice's key is protected even if 1 friend is unavailable
- **Cryptographic Proof**: The signature verifies that the recovery worked correctly

## Types

### Core Types

- `ParticipantId`: Identifies a participant in the protocol
- `Scalar`: Represents a scalar value in the cryptographic group
- `GroupElement`: Represents a point on the elliptic curve
- `FrostSignature`: The final threshold signature with R and z components

### Protocol Types

- `KeyPackage`: Contains participant's key material and commitments
- `SigningPackage`: Bundles message and commitments for round 2
- `RoundOneOutputs`: Nonces and commitments from round 1
- `RoundTwoOutputs`: Signature share from round 2

## Security Considerations

This implementation uses cryptographically secure Ed25519 operations via the `@substrate-system/keys` module and the Web Crypto API.

### Security Features

**Secure Random Generation**: Uses `crypto.getRandomValues()` for entropy
**Proper Ed25519 Operations**: Leverages proven ECC library implementations
**SHA-512 Hashing**: Uses Web Crypto API for secure hash operations
**Field Arithmetic**: Proper scalar operations modulo the Ed25519 field order

### Production Considerations

1. **Secure Communication**: Ensure secure channels between participants
2. **Input Validation**: All inputs are validated for correct length and format
3. **Error Handling**: Comprehensive error handling for cryptographic failures
4. **Side-Channel Protection**: Consider timing attack mitigations for sensitive operations
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

This generates both CommonJS and ES module outputs in the `dist/` directory.

## Standards Compliance

This implementation follows:

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) - The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol
- Ed25519 signature scheme specifications
- Modern TypeScript/ES2022 standards

## Contributing

1. Ensure all tests pass: `npm test`
2. Follow the existing code style
3. Add tests for new functionality
4. Update documentation as needed

## References

- [FROST RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
- [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
