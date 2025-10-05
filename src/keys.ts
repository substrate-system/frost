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
export function createFrostConfig (
    min:number,
    max:number
):FrostConfig {
    return {
        minSigners: min,
        maxSigners: max,
        cipherSuite: createEd25519Cipher()
    }
}

// Also attach to generateKeys for backward compatibility
generateKeys.config = createFrostConfig

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
 * @param privateKey - Ed25519 private key in one of the following formats:
 *   - CryptoKey (will be exported as PKCS#8)
 *   - Uint8Array in PKCS#8 format
 *   - Uint8Array 32-byte raw scalar
 * @param config - FROST configuration specifying min/max signers
 * @returns Signers object with key packages for each participant
 */
export async function split (
    privateKey:CryptoKey|Uint8Array,
    config:FrostConfig
):Promise<Signers> {
    const { minSigners, maxSigners, cipherSuite } = config

    let privateScalar:Uint8Array

    // Handle CryptoKey input
    if (privateKey instanceof CryptoKey) {
        // Export the private key
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', privateKey)
        const pkcs8 = new Uint8Array(privateKeyBuffer)

        // Extract the 32-byte seed from PKCS#8 format
        const privateKeySeed = pkcs8.slice(pkcs8.length - 32)

        // Derive the Ed25519 scalar with proper bit clamping
        const seedHash = await crypto.subtle.digest('SHA-512', privateKeySeed)
        const seedHashBytes = new Uint8Array(seedHash)
        privateScalar = seedHashBytes.slice(0, 32)
        privateScalar[0] &= 248   // Clear bottom 3 bits
        privateScalar[31] &= 127  // Clear top bit
        privateScalar[31] |= 64   // Set bit 254
    } else {
        // Handle Uint8Array input - support both PKCS#8 and raw scalar formats
        if (privateKey.length === 32) {
            // Raw 32-byte scalar
            privateScalar = privateKey
        } else {
            // Assume PKCS#8 format
            const privateKeySeed = privateKey.slice(privateKey.length - 32)

            // Derive the Ed25519 scalar with proper bit clamping
            const seedHash = await crypto.subtle.digest('SHA-512', privateKeySeed)
            const seedHashBytes = new Uint8Array(seedHash)
            privateScalar = seedHashBytes.slice(0, 32)
            privateScalar[0] &= 248   // Clear bottom 3 bits
            privateScalar[31] &= 127  // Clear top bit
            privateScalar[31] |= 64   // Set bit 254
        }
    }

    // Convert the existing key to a scalar
    const secretKey = cipherSuite.bytesToScalar(privateScalar)

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
 * Recover the original private key from threshold shares using
 * Lagrange interpolation.
 * @param keyPackages - At least minSigners key packages to recover the key from
 * @param config - FROST configuration
 * @returns The recovered 32-byte Ed25519 private key
 */
export function recover (
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

/**
 * Sign a message using a recovered private key
 * @param recoveredKey - The 32-byte private key from recover()
 * @param message - The message to sign
 * @param config - FROST configuration
 * @returns Ed25519 signature (64 bytes)
 */
export async function sign (
    recoveredKey:Uint8Array,
    message:Uint8Array,
    config:FrostConfig
):Promise<Uint8Array<ArrayBuffer>> {
    // Import the signing module to avoid circular dependency
    const { FrostSigner, FrostCoordinator } = await import('./signing.js')

    // Split the recovered key to create signers
    const { groupPublicKey, keyPackages } = await split(recoveredKey, config)

    // Use minimum required signers
    const signerPackages = keyPackages.slice(0, config.minSigners)
    const signers = signerPackages.map(pkg => new FrostSigner(pkg, config))
    const coordinator = new FrostCoordinator(config)

    // Round 1: Generate commitments
    const round1Results = signers.map(signer => signer.sign_round1())
    const commitmentShares = round1Results.map((result, i) => ({
        participantId: signerPackages[i].participantId,
        commitment: result.commitment
    }))

    // Create signing package
    const signingPackage = await coordinator.createSigningPackage(
        message,
        commitmentShares,
        signerPackages.map(pkg => pkg.participantId),
        groupPublicKey
    )

    // Round 2: Generate signature shares
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

    // Aggregate into final signature
    return coordinator.aggregateSignatures(signingPackage, signatureShares)
}

/**
 * Create a threshold signature using key packages from multiple participants
 * @param keyPackages - Key packages from participants (must meet threshold)
 * @param message - The message to sign
 * @param groupPublicKey - The group public key
 * @param config - FROST configuration
 * @returns Ed25519 signature (64 bytes)
 */
export async function thresholdSign (
    keyPackages:KeyPackage[],
    message:Uint8Array,
    groupPublicKey:GroupElement,
    config:FrostConfig
):Promise<Uint8Array> {
    const { FrostSigner, FrostCoordinator } = await import('./signing.js')

    if (keyPackages.length < config.minSigners) {
        throw new Error(
            `Need at least ${config.minSigners} signers, got ${keyPackages.length}`
        )
    }

    const signers = keyPackages.map(pkg => new FrostSigner(pkg, config))
    const coordinator = new FrostCoordinator(config)

    // Round 1: Generate commitments
    const round1Results = signers.map(signer => signer.sign_round1())
    const commitmentShares = round1Results.map((result, i) => ({
        participantId: keyPackages[i].participantId,
        commitment: result.commitment
    }))

    // Create signing package
    const signingPackage = await coordinator.createSigningPackage(
        message,
        commitmentShares,
        keyPackages.map(pkg => pkg.participantId),
        groupPublicKey
    )

    // Round 2: Generate signature shares
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

    // Aggregate into final signature
    return coordinator.aggregateSignatures(signingPackage, signatureShares)
}
