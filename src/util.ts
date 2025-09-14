/**
 * Utility functions for FROST implementation
 */

import type { Scalar, ParticipantId, CipherSuite } from './types.js'

export function encodeGroupCommitmentList (
    participantList:ParticipantId[],
    commitmentList:Uint8Array[]
):Uint8Array {
    const encoder = new TextEncoder()
    let result = new Uint8Array(0)

    for (let i = 0; i < participantList.length; i++) {
        const participantBytes = encoder.encode(participantList[i].id.toString())
        const commitment = commitmentList[i]

        // Concatenate participant ID length, participant ID, commitment
        // length, commitment
        const idLength = new Uint8Array([participantBytes.length])
        const commitmentLength = new Uint8Array(4)
        new DataView(commitmentLength.buffer).setUint32(0, commitment.length,
            false)

        const temp = new Uint8Array(
            result.length + idLength.length + participantBytes.length +
            commitmentLength.length + commitment.length
        )
        temp.set(result, 0)
        temp.set(idLength, result.length)
        temp.set(participantBytes, result.length + idLength.length)
        temp.set(commitmentLength, result.length + idLength.length +
            participantBytes.length)
        temp.set(commitment, result.length + idLength.length +
            participantBytes.length + commitmentLength.length)

        result = temp
    }

    return result
}

export async function deriveInterpolatingValue (
    participantId:ParticipantId,
    signerIds:ParticipantId[],
    cipherSuite:CipherSuite
):Promise<Scalar> {
    // Compute Lagrange interpolation coefficient
    let numerator = cipherSuite.scalarToBytes(scalarFromInt(1, cipherSuite))
    let denominator = cipherSuite.scalarToBytes(scalarFromInt(1, cipherSuite))

    for (const otherId of signerIds) {
        if (otherId.id !== participantId.id) {
            // numerator *= otherId
            const otherScalar = scalarFromInt(otherId.id, cipherSuite)
            const scalar = await scalarMultiply(
                cipherSuite.bytesToScalar(numerator),
                otherScalar,
                cipherSuite
            )
            numerator = cipherSuite.scalarToBytes(scalar)

            // denominator *= (otherId - participantId)
            const diff = scalarSubtract(
                otherScalar,
                scalarFromInt(participantId.id, cipherSuite),
                cipherSuite
            )
            denominator = cipherSuite.scalarToBytes(
                await scalarMultiply(
                    cipherSuite.bytesToScalar(denominator),
                    diff,
                    cipherSuite
                )
            )
        }
    }

    // Return numerator / denominator
    const denominatorInverse = scalarInvert(
        cipherSuite.bytesToScalar(denominator),
        cipherSuite
    )

    return scalarMultiply(
        cipherSuite.bytesToScalar(numerator),
        denominatorInverse,
        cipherSuite
    )
}

export function scalarFromInt (value:number, cipherSuite:CipherSuite):Scalar {
    const bytes = new Uint8Array(cipherSuite.scalarSize)
    const view = new DataView(bytes.buffer)
    view.setUint32(bytes.length - 4, value, false) // Big-endian
    return cipherSuite.bytesToScalar(bytes)
}

export async function scalarMultiply (
    a:Scalar,
    b:Scalar,
    cipherSuite:CipherSuite
):Promise<Scalar> {
    // Use the cipher suite's scalar-to-scalar multiplication
    return cipherSuite.scalarMultiplyScalar(a, b)
}

export function scalarSubtract (a:Scalar, b:Scalar,
    cipherSuite:CipherSuite):Scalar {
    // This is a placeholder implementation
    // Real implementation would do proper scalar subtraction
    const negB = cipherSuite.scalarNegate(b)
    return cipherSuite.scalarAdd(a, negB)
}

export function scalarInvert (scalar:Scalar, cipherSuite:CipherSuite):Scalar {
    return cipherSuite.scalarInvert(scalar)
}

export async function computeBindingFactor (
    participantId:ParticipantId,
    verifyingKey:Uint8Array,
    commitmentList:Uint8Array,
    message:Uint8Array,
    cipherSuite:CipherSuite
):Promise<Scalar> {
    const encoder = new TextEncoder()

    // Create binding factor input
    const participantBytes = encoder.encode(participantId.id.toString())
    const combined = new Uint8Array(
        participantBytes.length + verifyingKey.length +
        commitmentList.length + message.length
    )

    let offset = 0
    combined.set(participantBytes, offset)
    offset += participantBytes.length
    combined.set(verifyingKey, offset)
    offset += verifyingKey.length
    combined.set(commitmentList, offset)
    offset += commitmentList.length
    combined.set(message, offset)

    return await cipherSuite.hashToScalar(combined)
}

export async function computeChallenge (
    groupCommitment:Uint8Array,
    verifyingKey:Uint8Array,
    message:Uint8Array,
    cipherSuite:CipherSuite
):Promise<Scalar> {
    const combined = new Uint8Array(
        groupCommitment.length + verifyingKey.length + message.length
    )

    let offset = 0
    combined.set(groupCommitment, offset)
    offset += groupCommitment.length
    combined.set(verifyingKey, offset)
    offset += verifyingKey.length
    combined.set(message, offset)

    return await cipherSuite.hashToScalar(combined)
}
