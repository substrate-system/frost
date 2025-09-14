/**
 * FROST (Flexible Round-Optimized Schnorr Threshold) Signatures
 *
 * A TypeScript implementation of the FROST threshold signature scheme
 * as specified in RFC 9591.
 */

// Import for internal use
import { createEd25519CipherSuite } from './ciphersuite.js'
import type { FrostConfig } from './types.js'

export type {
    ParticipantId,
    Scalar,
    GroupElement,
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
    TrustedDealerOutput,
    CipherSuite,
    FrostConfig
} from './types.js'

export { TrustedDealer, verifyKeyPackage } from './keygen.js'
export { FrostSigner, FrostCoordinator } from './signing.js'
export { createEd25519CipherSuite, Ed25519CipherSuite } from './ciphersuite.js'
export {
    encodeGroupCommitmentList,
    deriveInterpolatingValue,
    computeBindingFactor,
    computeChallenge
} from './utils.js'

/**
 * Create a FROST configuration with Ed25519 cipher suite
 */
export function createFrostConfig (
    minSigners:number,
    maxSigners:number
):FrostConfig {
    return {
        minSigners,
        maxSigners,
        cipherSuite: createEd25519CipherSuite()
    }
}
