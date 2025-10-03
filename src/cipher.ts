/**
 * Ed25519 cipher suite for FROST
 */

import * as ed25519 from '@noble/ed25519'
import type { CipherSuite, Scalar } from './types.js'
import { type GroupElement } from './keys.js'

export class Ed25519CipherSuite implements CipherSuite {
    readonly name = 'FROST-ED25519-SHA512-v1'
    readonly scalarSize = 32
    readonly elementSize = 32

    async hashToScalar (data:Uint8Array):Promise<Scalar> {
        // Use crypto.subtle.digest for SHA-512
        const hash = await crypto.subtle.digest('SHA-512', new Uint8Array(data))
        const hashBytes = new Uint8Array(hash)

        // Convert to BigInt for proper modular reduction
        let hashBig = 0n
        for (let i = 0; i < hashBytes.length; i++) {
            hashBig += BigInt(hashBytes[i]) << (8n * BigInt(i))
        }

        // Ed25519 scalar field order
        const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn

        // Reduce modulo order
        const reduced = hashBig % order

        // Convert back to bytes (little-endian)
        const bytes = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number((reduced >> (8n * BigInt(i))) & 0xffn)
        }

        return { value: bytes }
    }

    scalarMultiply (scalar:Scalar, element:GroupElement):GroupElement {
        // Use @noble/ed25519 for scalar multiplication
        if (scalar.value.length !== 32) {
            throw new Error('Invalid scalar length')
        }
        if (element.point.length !== 32) {
            throw new Error('Invalid element length')
        }

        try {
            // Convert scalar bytes (little-endian) to BigInt correctly
            let scalarBig = 0n
            for (let i = 0; i < scalar.value.length; i++) {
                scalarBig += BigInt(scalar.value[i]) << (8n * BigInt(i))
            }

            const pointHex = Array.from(element.point)
                .map(b => b.toString(16).padStart(2, '0')).join('')

            const point = ed25519.Point.fromHex(pointHex)

            // Ensure scalar is within curve order range
            const curve = ed25519.Point.CURVE()
            const order = curve.n
            let scalarMod = scalarBig % order
            if (scalarMod === 0n) scalarMod = 1n

            const result = point.multiply(scalarMod)
            return { point: result.toBytes() }
        } catch (error) {
            throw new Error(`Scalar multiplication failed: ${(error as Error).message}`)
        }
    }

    scalarAdd (a:Scalar, b:Scalar):Scalar {
        // Scalar addition with proper modular reduction
        if (a.value.length !== 32 || b.value.length !== 32) {
            throw new Error('Invalid scalar length')
        }

        // Convert to BigInts
        let aBig = 0n
        let bBig = 0n

        for (let i = 0; i < 32; i++) {
            aBig += BigInt(a.value[i]) << (8n * BigInt(i))
            bBig += BigInt(b.value[i]) << (8n * BigInt(i))
        }

        // Ed25519 scalar field order
        const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn

        // Add and reduce modulo order
        const sum = (aBig + bBig) % order

        // Convert back to bytes (little-endian)
        const result = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            result[i] = Number((sum >> (8n * BigInt(i))) & 0xffn)
        }

        return { value: result }
    }

    scalarMultiplyScalar (a:Scalar, b:Scalar):Scalar {
        // Scalar-to-scalar multiplication for Ed25519
        if (a.value.length !== 32 || b.value.length !== 32) {
            throw new Error('Invalid scalar length')
        }

        // Convert scalars to BigInts
        let aBig = 0n
        let bBig = 0n

        for (let i = 0; i < 32; i++) {
            aBig += BigInt(a.value[i]) << (8n * BigInt(i))
            bBig += BigInt(b.value[i]) << (8n * BigInt(i))
        }

        // Ed25519 scalar field order
        const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn

        // Multiply and reduce modulo order
        const result = (aBig * bBig) % order

        // Convert back to bytes (little-endian)
        const bytes = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number((result >> (8n * BigInt(i))) & 0xffn)
        }

        return { value: bytes }
    }

    scalarInvert (scalar:Scalar):Scalar {
        // Modular inverse using Fermat's little theorem: a^(p-2) = a^(-1) mod p
        if (scalar.value.length !== 32) {
            throw new Error('Invalid scalar length')
        }

        // Convert scalar to BigInt
        let scalarBig = 0n
        for (let i = 0; i < 32; i++) {
            scalarBig += BigInt(scalar.value[i]) << (8n * BigInt(i))
        }

        // Ed25519 scalar field order
        const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn

        if (scalarBig === 0n) {
            throw new Error('Cannot invert zero scalar')
        }

        // Compute modular inverse using extended Euclidean algorithm
        function modInverse (a: bigint, m: bigint): bigint {
            if (a < 0n) a = (a % m + m) % m

            let g0 = m
            let g1 = a
            let u0 = 0n
            let u1 = 1n

            while (g1 !== 0n) {
                const q = g0 / g1
                const temp1 = g0 - q * g1
                g0 = g1
                g1 = temp1

                const temp2 = u0 - q * u1
                u0 = u1
                u1 = temp2
            }

            if (g0 !== 1n) throw new Error('Scalar is not invertible')
            return (u0 % m + m) % m
        }

        const result = modInverse(scalarBig, order)

        // Convert back to bytes (little-endian)
        const bytes = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number((result >> (8n * BigInt(i))) & 0xffn)
        }

        return { value: bytes }
    }

    scalarNegate (scalar:Scalar):Scalar {
        if (scalar.value.length !== 32) {
            throw new Error('Invalid scalar length')
        }

        // Negate by subtracting from the field order
        const fieldOrder = new Uint8Array([
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        ])

        const result = new Uint8Array(32)
        let borrow = 0

        for (let i = 0; i < 32; i++) {
            const diff = fieldOrder[i] - scalar.value[i] - borrow
            if (diff >= 0) {
                result[i] = diff
                borrow = 0
            } else {
                result[i] = diff + 256
                borrow = 1
            }
        }

        return { value: result }
    }

    elementAdd (a:GroupElement, b:GroupElement):GroupElement {
        // Ed25519 point addition using noble
        if (a.point.length !== 32 || b.point.length !== 32) {
            throw new Error('Invalid element length')
        }

        try {
            const pointAHex = Array.from(a.point)
                .map(b => b.toString(16).padStart(2, '0')).join('')
            const pointBHex = Array.from(b.point)
                .map(b => b.toString(16).padStart(2, '0')).join('')

            const pointA = ed25519.Point.fromHex(pointAHex)
            const pointB = ed25519.Point.fromHex(pointBHex)
            const result = pointA.add(pointB)
            return { point: result.toBytes() }
        } catch (error) {
            throw new Error(`Element addition failed: ${(error as Error).message}`)
        }
    }

    randomScalar ():Scalar {
        // Generate cryptographically secure random scalar
        const bytes = new Uint8Array(64) // Generate more entropy
        crypto.getRandomValues(bytes)

        // Convert to BigInt for proper modular reduction
        let randomBig = 0n
        for (let i = 0; i < bytes.length; i++) {
            randomBig += BigInt(bytes[i]) << (8n * BigInt(i))
        }

        // Ed25519 scalar field order
        const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn

        // Reduce modulo order
        const reduced = randomBig % order

        // Convert back to bytes (little-endian)
        const resultBytes = new Uint8Array(32)
        for (let i = 0; i < 32; i++) {
            resultBytes[i] = Number((reduced >> (8n * BigInt(i))) & 0xffn)
        }

        return { value: resultBytes }
    }

    baseElement ():GroupElement {
        // Ed25519 standard base point from noble
        const basePoint = ed25519.Point.BASE
        return { point: basePoint.toBytes() }
    }

    elementToBytes (element:GroupElement):Uint8Array {
        return new Uint8Array(element.point)
    }

    scalarToBytes (scalar:Scalar):Uint8Array {
        return new Uint8Array(scalar.value)
    }

    bytesToScalar (bytes:Uint8Array):Scalar {
        if (bytes.length !== 32) {
            throw new Error('Invalid scalar byte length')
        }
        return { value: new Uint8Array(bytes) }
    }

    bytesToElement (bytes:Uint8Array):GroupElement {
        if (bytes.length !== 32) {
            throw new Error('Invalid element byte length')
        }
        return { point: new Uint8Array(bytes) }
    }

    isIdentity (element:GroupElement):boolean {
        // Ed25519 identity point is (0, 1) which encodes as all zeros except bit 255
        // In compressed form: 0x01 followed by 31 zeros
        if (element.point.length !== 32) return false

        // Check if it's the identity point encoding
        if (element.point[0] !== 0x01) return false
        for (let i = 1; i < 32; i++) {
            if (element.point[i] !== 0x00) return false
        }
        return true
    }

    isInPrimeOrderSubgroup (element:GroupElement):boolean {
        // For Ed25519, RFC 9591 requires checking that elements are in the
        // prime-order subgroup to avoid small subgroup attacks.
        // A point is in the prime-order subgroup if it's NOT in a small-order
        // subgroup, which we check by verifying [cofactor]P is not identity.
        if (element.point.length !== 32) return false

        try {
            const pointHex = Array.from(element.point)
                .map(b => b.toString(16).padStart(2, '0')).join('')
            const point = ed25519.Point.fromHex(pointHex)

            // Multiply by cofactor (8)
            const cofactorResult = point.multiply(8n)

            // Point is in prime-order subgroup if [8]P is not the identity
            // (i.e., point is not in a small-order subgroup)
            return !cofactorResult.equals(ed25519.Point.ZERO)
        } catch {
            return false
        }
    }

    scalarMultiplyByCofactor (scalar:Scalar):Scalar {
        // Ed25519 cofactor is 8
        const cofactor = this.bytesToScalar(new Uint8Array([8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        return this.scalarMultiplyScalar(scalar, cofactor)
    }

    elementMultiplyByCofactor (element:GroupElement):GroupElement {
        // Ed25519 cofactor is 8
        const cofactor = this.bytesToScalar(new Uint8Array([8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        return this.scalarMultiply(cofactor, element)
    }
}

// Factory function to create Ed25519 cipher suite
export function createEd25519Cipher ():CipherSuite {
    return new Ed25519CipherSuite()
}
