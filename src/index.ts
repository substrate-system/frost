/**
 * FROST (Flexible Round-Optimized Schnorr Threshold) Signatures
 *
 * A TypeScript implementation of the FROST threshold signature scheme
 * as specified in RFC 9591.
 */

export type {
    ParticipantId,
    Scalar,
    NonceCommitment,
    Nonces,
    CommitmentShare,
    KeyShare,
    SignatureShare,
    GroupCommitment,
    FrostSignature,
    KeyPackage,
    SigningPackage,
    RoundOneOutputs,
    RoundTwoOutputs,
    CipherSuite,
} from './types.js'

export {
    generateKeys,
    verifyKeyPackage,
    type FrostConfig,
    type Signers
} from './keys.js'
export { FrostSigner, FrostCoordinator } from './signing.js'
export { createEd25519CipherSuite, Ed25519CipherSuite } from './ciphersuite.js'
export {
    encodeGroupCommitmentList,
    deriveInterpolatingValue,
    computeBindingFactor,
    computeChallenge
} from './util.js'
