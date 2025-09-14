/**
 * FROST Signing Protocol Implementation
 */

import type {
    KeyPackage,
    RoundOneOutputs,
    RoundTwoOutputs,
    SigningPackage,
    CommitmentShare,
    SignatureShare,
    FrostSignature,
    ParticipantId,
    NonceCommitment,
    Nonces,
    FrostConfig,
    Scalar,
    GroupElement
} from './types.js'
import {
    encodeGroupCommitmentList,
    deriveInterpolatingValue,
    computeBindingFactor,
    computeChallenge
} from './utils.js'

export class FrostSigner {
    private keyPackage: KeyPackage
    private config: FrostConfig

    constructor (keyPackage: KeyPackage, config: FrostConfig) {
        this.keyPackage = keyPackage
        this.config = config
    }

    /**
     * Round 1: Generate nonces and commitments
     */
    sign_round1 (): RoundOneOutputs {
        const { cipherSuite } = this.config

        // Generate random nonces
        const hidingNonce = cipherSuite.randomScalar()
        const bindingNonce = cipherSuite.randomScalar()

        const nonces: Nonces = {
            hiding: hidingNonce,
            binding: bindingNonce
        }

        // Create commitments to nonces
        const hidingCommitment = cipherSuite.scalarMultiply(hidingNonce,
            cipherSuite.baseElement())
        const bindingCommitment = cipherSuite.scalarMultiply(bindingNonce,
            cipherSuite.baseElement())

        const commitment: NonceCommitment = {
            hiding: hidingCommitment,
            binding: bindingCommitment
        }

        return {
            nonces,
            commitment
        }
    }

    /**
     * Round 2: Generate signature share
     */
    sign_round2 (
        signingPackage: SigningPackage,
        nonces: Nonces
    ): RoundTwoOutputs {
        const { cipherSuite } = this.config
        const { message, groupCommitment, participantIds } = signingPackage

        // Verify this participant is included
        const isParticipant = participantIds.some(
            id => id.id === this.keyPackage.participantId.id
        )
        if (!isParticipant) {
            throw new Error('Participant not included in signing ceremony')
        }

        // Get binding factor for this participant
        const bindingFactor = groupCommitment.bindingFactors.get(
            this.keyPackage.participantId.id
        )
        if (!bindingFactor) {
            throw new Error('Binding factor not found for participant')
        }

        // Compute Lagrange interpolation coefficient
        const lambdaI = deriveInterpolatingValue(
            this.keyPackage.participantId,
            participantIds,
            cipherSuite
        )

        // Compute challenge
        const verifyingKeyBytes = cipherSuite.elementToBytes(
            this.keyPackage.verificationKey)
        const groupCommitmentBytes = cipherSuite.elementToBytes(
            groupCommitment.commitment)
        const challenge = computeChallenge(
            groupCommitmentBytes,
            verifyingKeyBytes,
            message,
            cipherSuite
        )

        // Compute signature share:
        // z_i = d_i + (e_i * binding_factor_i) + lambda_i * s_i * c
        const bindingTerm = cipherSuite.scalarAdd(
            nonces.hiding,
            cipherSuite.scalarAdd(nonces.binding, bindingFactor)
        )

        const keyTerm = cipherSuite.scalarAdd(
            lambdaI,
            cipherSuite.scalarAdd(this.keyPackage.keyShare.privateShare,
                challenge)
        )

        const signatureShare = cipherSuite.scalarAdd(bindingTerm, keyTerm)

        return {
            signatureShare: {
                participantId: this.keyPackage.participantId,
                share: signatureShare
            }
        }
    }
}

export class FrostCoordinator {
    private config: FrostConfig

    constructor (config: FrostConfig) {
        this.config = config
    }

    /**
     * Coordinate the signing process by collecting commitments and creating
     * signing package
     */
    createSigningPackage (
        message: Uint8Array,
        commitmentShares: CommitmentShare[],
        participantIds: ParticipantId[]
    ): SigningPackage {
        if (participantIds.length < this.config.minSigners) {
            throw new Error('Insufficient number of signers')
        }

        if (commitmentShares.length !== participantIds.length) {
            throw new Error('Mismatch between commitment shares and' +
                ' participant IDs')
        }

        // Verify all participants have provided commitments
        for (const participantId of participantIds) {
            const hasCommitment = commitmentShares.some(
                share => share.participantId.id === participantId.id
            )
            if (!hasCommitment) {
                throw new Error(
                    `Missing commitment from participant ${participantId.id}`)
            }
        }

        // Create group commitment and binding factors
        const { groupCommitment, bindingFactors } = this.computeGroupCommitment(
            message,
            commitmentShares,
            participantIds
        )

        return {
            participantIds,
            message,
            groupCommitment: {
                commitment: groupCommitment,
                bindingFactors
            }
        }
    }

    /**
     * Aggregate signature shares into final signature
     */
    aggregateSignatures (
        signingPackage: SigningPackage,
        signatureShares: SignatureShare[]
    ): FrostSignature {
        const { cipherSuite } = this.config

        if (signatureShares.length < this.config.minSigners) {
            throw new Error('Insufficient signature shares')
        }

        // Verify all expected participants provided shares
        for (const participantId of signingPackage.participantIds) {
            const hasShare = signatureShares.some(
                share => share.participantId.id === participantId.id
            )
            if (!hasShare) {
                throw new Error(
                    `Missing signature share from participant ${participantId.id}`)
            }
        }

        // Aggregate signature shares
        let z = signatureShares[0].share
        for (let i = 1; i < signatureShares.length; i++) {
            z = cipherSuite.scalarAdd(z, signatureShares[i].share)
        }

        return {
            R: signingPackage.groupCommitment.commitment,
            z
        }
    }

    /**
     * Verify a FROST signature
     */
    verify (
        signature: FrostSignature,
        message: Uint8Array,
        verifyingKey: GroupElement
    ): boolean {
        const { cipherSuite } = this.config

        try {
            // Compute challenge
            const rBytes = cipherSuite.elementToBytes(signature.R)
            const pkBytes = cipherSuite.elementToBytes(verifyingKey)
            const challenge = computeChallenge(rBytes, pkBytes, message,
                cipherSuite)

            // Verify: [z]B = R + [c]PK
            const leftSide = cipherSuite.scalarMultiply(signature.z,
                cipherSuite.baseElement())
            const rightSide = cipherSuite.elementAdd(
                signature.R,
                cipherSuite.scalarMultiply(challenge, verifyingKey)
            )

            // Compare byte representations
            const leftBytes = cipherSuite.elementToBytes(leftSide)
            const rightBytes = cipherSuite.elementToBytes(rightSide)

            if (leftBytes.length !== rightBytes.length) {
                return false
            }

            for (let i = 0; i < leftBytes.length; i++) {
                if (leftBytes[i] !== rightBytes[i]) {
                    return false
                }
            }

            return true
        } catch {
            return false
        }
    }

    private computeGroupCommitment (
        message: Uint8Array,
        commitmentShares: CommitmentShare[],
        participantIds: ParticipantId[]
    ): { groupCommitment: GroupElement; bindingFactors: Map<number, Scalar> } {
        const { cipherSuite } = this.config

        // Encode commitment list for binding factor computation
        const commitmentList = encodeGroupCommitmentList(
            participantIds,
            commitmentShares.map(share =>
                new Uint8Array([
                    ...cipherSuite.elementToBytes(share.commitment.hiding),
                    ...cipherSuite.elementToBytes(share.commitment.binding)
                ])
            )
        )

        // Compute binding factors for each participant
        const bindingFactors = new Map<number, Scalar>()
        const verifyingKeyBytes = new Uint8Array(32) // Placeholder

        for (const participantId of participantIds) {
            const bindingFactor = computeBindingFactor(
                participantId,
                verifyingKeyBytes,
                commitmentList,
                message,
                cipherSuite
            )
            bindingFactors.set(participantId.id, bindingFactor)
        }

        // Compute group commitment
        let groupCommitment = commitmentShares[0].commitment.hiding

        for (let i = 0; i < commitmentShares.length; i++) {
            const share = commitmentShares[i]
            const bindingFactor = bindingFactors.get(share.participantId.id)!

            const bindingTerm = cipherSuite.scalarMultiply(bindingFactor,
                share.commitment.binding)
            const participantCommitment = cipherSuite.elementAdd(
                share.commitment.hiding, bindingTerm)

            if (i === 0) {
                groupCommitment = participantCommitment
            } else {
                groupCommitment = cipherSuite.elementAdd(groupCommitment,
                    participantCommitment)
            }
        }

        return { groupCommitment, bindingFactors }
    }
}
