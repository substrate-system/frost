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
import { createEd25519CipherSuite } from './ciphersuite.js'

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
            cipherSuite: createEd25519CipherSuite()
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
        cipherSuite: createEd25519CipherSuite()
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
