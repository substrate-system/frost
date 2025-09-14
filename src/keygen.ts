/**
 * FROST Key Generation using Trusted Dealer
 */

import type {
    TrustedDealerOutput,
    KeyPackage,
    KeyShare,
    NonceCommitment,
    ParticipantId,
    FrostConfig,
    GroupElement,
    Scalar
} from './types.js'

export class TrustedDealer {
    private config: FrostConfig

    constructor (config: FrostConfig) {
        this.config = config
    }

    /**
     * Generate keys using trusted dealer approach
     * Creates a secret key, splits it using Shamir's secret sharing,
     * and distributes shares to participants
     */
    generateKeys (): TrustedDealerOutput {
        const { minSigners, maxSigners, cipherSuite } = this.config

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
        const keyPackages: KeyPackage[] = []

        for (let participantId = 1; participantId <= maxSigners; participantId++) {
            // Evaluate polynomial at participantId to get secret share
            const privateShare = this.evaluatePolynomial(coefficients,
                participantId)

            // Compute public share
            const publicShare = cipherSuite.scalarMultiply(privateShare,
                cipherSuite.baseElement())

            const keyShare: KeyShare = {
                participantId: { id: participantId },
                privateShare,
                publicShare
            }

            // Pre-generate some signing commitments for this participant
            const signingCommitments = this.generateSigningCommitments(3)

            const keyPackage: KeyPackage = {
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

    private evaluatePolynomial (coefficients: Scalar[], x: number): Scalar {
        const { cipherSuite } = this.config

        if (coefficients.length === 0) {
            throw new Error('Polynomial must have at least one coefficient')
        }

        // Start with the constant term
        let result = coefficients[0]

        // Compute x^i for each term
        let xPower = this.scalarFromInt(x)

        for (let i = 1; i < coefficients.length; i++) {
            // result += coefficients[i] * x^i
            const term = cipherSuite.scalarAdd(
                result,
                this.scalarMultiply(coefficients[i], xPower)
            )
            result = term

            if (i < coefficients.length - 1) {
                // Update x^i for next iteration
                xPower = this.scalarMultiply(xPower, this.scalarFromInt(x))
            }
        }

        return result
    }

    private generateSigningCommitments (count: number): NonceCommitment[] {
        const { cipherSuite } = this.config
        const commitments: NonceCommitment[] = []

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

    private scalarFromInt (value: number): Scalar {
        const { cipherSuite } = this.config
        const bytes = new Uint8Array(cipherSuite.scalarSize)
        const view = new DataView(bytes.buffer)
        view.setUint32(bytes.length - 4, value, false)
        return cipherSuite.bytesToScalar(bytes)
    }

    private scalarMultiply (a: Scalar, b: Scalar): Scalar {
        // This is a placeholder - real implementation would use proper
        // scalar multiplication
        const combined = new Uint8Array(a.value.length + b.value.length)
        combined.set(a.value, 0)
        combined.set(b.value, a.value.length)
        return this.config.cipherSuite.hashToScalar(combined)
    }
}

/**
 * Verify that a key package is valid
 */
export function verifyKeyPackage (
    keyPackage: KeyPackage,
    config: FrostConfig
): boolean {
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
