/**
 * FROST Key Generation using Trusted Dealer
 */

import type {
    KeyPackage,
    KeyShare,
    NonceCommitment,
    Scalar,
    CipherSuite
} from './types.js'
import { createEd25519Cipher } from './cipher.js'

export interface FrostConfig {
    readonly minSigners:number
    readonly maxSigners:number
    readonly cipherSuite:CipherSuite
}

export interface GroupElement {
    readonly point:Uint8Array
}

export interface Signers {
    readonly groupPublicKey:GroupElement
    readonly keyPackages:KeyPackage[]
}

// overloads
export function generateKeys (config:FrostConfig):Signers
export function generateKeys (params:{ min:number, max:number }):Signers

/**
 * Generate keys.
 * Create a secret key and split it using Shamir's secret sharing
 */
export function generateKeys (configOrParams:FrostConfig|{
    min:number,
    max:number
}):Signers {
    // Handle different parameter types
    const config:FrostConfig = ('cipherSuite' in configOrParams ?
        configOrParams :
        {
            minSigners: configOrParams.min,
            maxSigners: configOrParams.max,
            cipherSuite: createEd25519Cipher()
        })

    const { minSigners, maxSigners, cipherSuite } = config

    // Generate master secret key
    const secretKey = cipherSuite.randomScalar()

    // Generate group public key
    const groupPublicKey = cipherSuite.scalarMultiply(secretKey,
        cipherSuite.baseElement())

    // Generate polynomial coefficients for Shamir's secret sharing
    const coefficients = [secretKey]
    for (let i = 1; i < minSigners; i++) {
        coefficients.push(cipherSuite.randomScalar())
    }

    // Create key packages for each participant
    const keyPackages:KeyPackage[] = []

    for (let participantId = 1; participantId <= maxSigners; participantId++) {
        // Evaluate polynomial at participantId to get secret share
        const privateShare = evaluatePolynomial(
            config,
            coefficients,
            participantId
        )

        // Compute public share
        const publicShare = cipherSuite.scalarMultiply(privateShare,
            cipherSuite.baseElement())

        const keyShare:KeyShare = {
            participantId: { id: participantId },
            privateShare,
            publicShare
        }

        // Pre-generate some signing commitments for this participant
        const signingCommitments = generateSigningCommitments(config, 3)

        const keyPackage:KeyPackage = {
            participantId: { id: participantId },
            keyShare,
            verificationKey: groupPublicKey,
            signingCommitments
        }

        keyPackages.push(keyPackage)
    }

    return {
        groupPublicKey,
        keyPackages
    }
}

/**
 * Create a FROST configuration with Ed25519 cipher suite
 */
generateKeys.config = function createFrostConfig (
    min:number,
    max:number
):FrostConfig {
    return {
        minSigners: min,
        maxSigners: max,
        cipherSuite: createEd25519Cipher()
    }
}

function scalarFromInt (config:FrostConfig, value:number):Scalar {
    const { cipherSuite } = config
    const bytes = new Uint8Array(cipherSuite.scalarSize)
    const view = new DataView(bytes.buffer)
    view.setUint32(bytes.length - 4, value, false)
    return cipherSuite.bytesToScalar(bytes)
}

/**
 * Verify that a key package is valid
 */
export function verifyKeyPackage (
    keyPackage:KeyPackage,
    config:FrostConfig
):boolean {
    const { cipherSuite } = config

    try {
        // Verify that the public share corresponds to the private share
        const computedPublicShare = cipherSuite.scalarMultiply(
            keyPackage.keyShare.privateShare,
            cipherSuite.baseElement()
        )

        // Compare the computed public share with the provided one
        const providedPublicBytes = cipherSuite.elementToBytes(
            keyPackage.keyShare.publicShare)
        const computedPublicBytes = cipherSuite.elementToBytes(
            computedPublicShare)

        if (providedPublicBytes.length !== computedPublicBytes.length) {
            return false
        }

        for (let i = 0; i < providedPublicBytes.length; i++) {
            if (providedPublicBytes[i] !== computedPublicBytes[i]) {
                return false
            }
        }

        return true
    } catch {
        return false
    }
}

function evaluatePolynomial (
    config:FrostConfig,
    coefficients:Scalar[],
    x:number
):Scalar {
    const { cipherSuite } = config

    if (coefficients.length === 0) {
        throw new Error('Polynomial must have at least one coefficient')
    }

    // Start with the constant term
    let result = coefficients[0]

    // Compute x^i for each term
    let xPower = scalarFromInt(config, x)

    for (let i = 1; i < coefficients.length; i++) {
        // result += coefficients[i] * x^i
        const term = cipherSuite.scalarAdd(
            result,
            cipherSuite.scalarMultiplyScalar(coefficients[i], xPower)
        )
        result = term

        if (i < coefficients.length - 1) {
            // Update x^i for next iteration
            xPower = cipherSuite.scalarMultiplyScalar(
                xPower,
                scalarFromInt(config, x)
            )
        }
    }

    return result
}

function generateSigningCommitments (config:FrostConfig, count:number) {
    const { cipherSuite } = config
    const commitments:NonceCommitment[] = []

    for (let i = 0; i < count; i++) {
        const hidingNonce = cipherSuite.randomScalar()
        const bindingNonce = cipherSuite.randomScalar()

        const hidingCommitment = cipherSuite.scalarMultiply(hidingNonce,
            cipherSuite.baseElement())
        const bindingCommitment = cipherSuite.scalarMultiply(bindingNonce,
            cipherSuite.baseElement())

        commitments.push({
            hiding: hidingCommitment,
            binding: bindingCommitment
        })
    }

    return commitments
}

/**
 * Split an existing Ed25519 private key into FROST shares using trusted dealer
 * @param existingKey - The existing 32-byte Ed25519 private key to split
 * @param config - FROST configuration specifying min/max signers
 * @returns Signers object with key packages for each participant
 */
export function splitExistingKey (
    existingKey:Uint8Array,
    config:FrostConfig
):Signers {
    const { minSigners, maxSigners, cipherSuite } = config

    if (existingKey.length !== 32) {
        throw new Error('Ed25519 private key must be 32 bytes')
    }

    // Convert the existing key to a scalar
    const secretKey = cipherSuite.bytesToScalar(existingKey)

    // Generate group public key from the existing secret
    const groupPublicKey = cipherSuite.scalarMultiply(secretKey,
        cipherSuite.baseElement())

    // Generate polynomial coefficients for Shamir's secret sharing
    const coefficients = [secretKey]
    for (let i = 1; i < minSigners; i++) {
        coefficients.push(cipherSuite.randomScalar())
    }

    // Create key packages for each participant
    const keyPackages:KeyPackage[] = []

    for (let participantId = 1; participantId <= maxSigners; participantId++) {
        // Evaluate polynomial at participantId to get secret share
        const privateShare = evaluatePolynomial(
            config,
            coefficients,
            participantId
        )

        // Compute public share
        const publicShare = cipherSuite.scalarMultiply(privateShare,
            cipherSuite.baseElement())

        const keyShare:KeyShare = {
            participantId: { id: participantId },
            privateShare,
            publicShare
        }

        // Pre-generate some signing commitments for this participant
        const signingCommitments = generateSigningCommitments(config, 3)

        const keyPackage:KeyPackage = {
            participantId: { id: participantId },
            keyShare,
            verificationKey: groupPublicKey,
            signingCommitments
        }

        keyPackages.push(keyPackage)
    }

    return {
        groupPublicKey,
        keyPackages
    }
}

/**
 * Recover the original private key from threshold shares using Lagrange interpolation
 * @param keyPackages - At least minSigners key packages to recover the key from
 * @param config - FROST configuration
 * @returns The recovered 32-byte Ed25519 private key
 */
export function recoverPrivateKey (
    keyPackages:KeyPackage[],
    config:FrostConfig
):Uint8Array {
    const { minSigners, cipherSuite } = config

    if (keyPackages.length < minSigners) {
        throw new Error(
            `Need at least ${minSigners} shares to recover key, got ${keyPackages.length}`
        )
    }

    // Use first minSigners packages
    const shares = keyPackages.slice(0, minSigners)

    // Lagrange interpolation at x=0 to recover the secret
    let secret = cipherSuite.bytesToScalar(new Uint8Array(32)) // Start with zero

    for (let i = 0; i < shares.length; i++) {
        const xi = shares[i].participantId.id

        // Compute Lagrange coefficient for this share
        let numerator = scalarFromInt(config, 1)
        let denominator = scalarFromInt(config, 1)

        for (let j = 0; j < shares.length; j++) {
            if (i === j) continue

            const xj = shares[j].participantId.id

            // numerator *= (0 - xj) = -xj
            const negXj = cipherSuite.scalarNegate(scalarFromInt(config, xj))
            numerator = cipherSuite.scalarMultiplyScalar(numerator, negXj)

            // denominator *= (xi - xj)
            const diff = cipherSuite.scalarAdd(
                scalarFromInt(config, xi),
                cipherSuite.scalarNegate(scalarFromInt(config, xj))
            )
            denominator = cipherSuite.scalarMultiplyScalar(denominator, diff)
        }

        // coefficient = numerator / denominator
        const denomInverse = cipherSuite.scalarInvert(denominator)
        const coefficient = cipherSuite.scalarMultiplyScalar(numerator,
            denomInverse)

        // secret += coefficient * share_i
        const term = cipherSuite.scalarMultiplyScalar(
            shares[i].keyShare.privateShare,
            coefficient
        )
        secret = cipherSuite.scalarAdd(secret, term)
    }

    // Convert scalar back to bytes
    return cipherSuite.scalarToBytes(secret)
}
