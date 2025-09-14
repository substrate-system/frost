import type {
    KeyPackage,
    RoundOneOutputs,
    RoundTwoOutputs,
    SigningPackage,
    CommitmentShare,
    SignatureShare,
    ParticipantId,
    NonceCommitment,
    Nonces,
    Scalar,
} from './types.js'
import {
    generateKeys,
    type FrostConfig,
    type GroupElement
} from './keys.js'
import {
    encodeGroupCommitmentList,
    deriveInterpolatingValue,
    computeBindingFactor,
    computeChallenge
} from './util.js'

/**
 * FROST Signer
 *   - The FrostSigner represents one participant in the signing ceremony.
 *   - Each FrostSigner has 1 shard of the private key
 *   - Multiple FrostSigners work together to create a complete, valid signature
 * _Signing Process_
 *   1. Generate random numbers and mathematical commitments
 *   2. Create a signature fragment using the message and the other
 *      participants' commitments.
 */
export class FrostSigner {
    private keyPackage:KeyPackage
    private config:FrostConfig

    constructor (keyPackage:KeyPackage, config:FrostConfig) {
        this.keyPackage = keyPackage
        this.config = config
    }

    /**
     * Round 1: Generate nonces and commitments
     */
    sign_round1 ():RoundOneOutputs {
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
    async sign_round2 (
        signingPackage: SigningPackage,
        nonces: Nonces,
        groupPublicKey: GroupElement
    ): Promise<RoundTwoOutputs> {
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
        const lambdaI = await deriveInterpolatingValue(
            this.keyPackage.participantId,
            participantIds,
            cipherSuite
        )

        // Compute challenge
        const verifyingKeyBytes = cipherSuite.elementToBytes(groupPublicKey)
        const groupCommitmentBytes = cipherSuite.elementToBytes(
            groupCommitment.commitment)
        const challenge = await computeChallenge(
            groupCommitmentBytes,
            verifyingKeyBytes,
            message,
            cipherSuite
        )

        // Compute signature share:
        // z_i = d_i + (e_i * binding_factor_i) + lambda_i * s_i * c
        const bindingTerm = cipherSuite.scalarMultiplyScalar(
            nonces.binding,
            bindingFactor
        )
        const scalar = cipherSuite.scalarMultiplyScalar(
            lambdaI,
            this.keyPackage.keyShare.privateShare
        )
        const keyTerm = cipherSuite.scalarMultiplyScalar(scalar, challenge)
        const scalarAdd = cipherSuite.scalarAdd(nonces.hiding, bindingTerm)
        const signatureShare = cipherSuite.scalarAdd(scalarAdd, keyTerm)

        return {
            signatureShare: {
                participantId: this.keyPackage.participantId,
                share: signatureShare
            }
        }
    }
}

export class FrostCoordinator {
    private config:FrostConfig

    constructor ({ min, max })
    constructor(config:FrostConfig)
    constructor (config:FrostConfig|{ min:number, max:number }) {
        if ('cipherSuite' in config) {
            this.config = config
        } else {
            this.config = generateKeys.config(config.min, config.max)
        }
    }

    /**
     * Coordinate the signing process by collecting commitments and creating
     * signing package
     */
    async createSigningPackage (
        message: Uint8Array,
        commitmentShares: CommitmentShare[],
        participantIds: ParticipantId[],
        groupPublicKey: GroupElement
    ): Promise<SigningPackage> {
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
        const {
            groupCommitment,
            bindingFactors
        } = await this.computeGroupCommitment(
            message,
            commitmentShares,
            participantIds,
            groupPublicKey
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
     * Returns a 64-byte concatenated signature (R || z) like Ed25519
     */
    aggregateSignatures (
        signingPackage: SigningPackage,
        signatureShares: SignatureShare[]
    ): Uint8Array {
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

        // Convert to bytes and concatenate R || z (64 bytes total)
        const rBytes = cipherSuite.elementToBytes(signingPackage.groupCommitment.commitment)
        const zBytes = cipherSuite.scalarToBytes(z)

        const signature = new Uint8Array(64)
        signature.set(rBytes, 0)    // First 32 bytes: R
        signature.set(zBytes, 32)   // Last 32 bytes: z

        return signature
    }

    /**
     * Verify a FROST signature
     * Takes a 64-byte concatenated signature (R || z) like Ed25519
     */
    async verify (
        signature:Uint8Array,
        message:Uint8Array,
        verifyingKey:GroupElement
    ):Promise<boolean> {
        const { cipherSuite } = this.config

        try {
            // Validate signature length
            if (signature.length !== 64) {
                throw new Error('Invalid signature length. Expected 64 bytes.')
            }

            // Split concatenated signature into R and z components
            const rBytes = signature.slice(0, 32)
            const zBytes = signature.slice(32, 64)

            // Convert bytes back to cryptographic objects
            const R = cipherSuite.bytesToElement(rBytes)
            const z = cipherSuite.bytesToScalar(zBytes)

            // Compute challenge
            const pkBytes = cipherSuite.elementToBytes(verifyingKey)
            const challenge = await computeChallenge(rBytes, pkBytes, message,
                cipherSuite)

            // Verify: [z]B = R + [c]PK
            const leftSide = cipherSuite.scalarMultiply(z,
                cipherSuite.baseElement())
            const rightSide = cipherSuite.elementAdd(
                R,
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

    private async computeGroupCommitment (
        message:Uint8Array,
        commitmentShares:CommitmentShare[],
        participantIds:ParticipantId[],
        groupPublicKey:GroupElement
    ):Promise<{
        groupCommitment:GroupElement;
        bindingFactors:Map<number, Scalar>;
    }> {
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
        const verifyingKeyBytes = cipherSuite.elementToBytes(groupPublicKey)

        for (const participantId of participantIds) {
            const bindingFactor = await computeBindingFactor(
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
