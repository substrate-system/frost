import { test } from '@substrate-system/tapzero'
import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    FrostCoordinator,
    FrostSigner,
    generateKeys,
    splitExistingKey,
    recoverPrivateKey
} from '../src/index.js'

test('FROST key generation', async t => {
    const keys = generateKeys({ min: 2, max: 3 })

    t.ok(keys.groupPublicKey, 'should generate group public key')
    t.equal(keys.keyPackages.length, 3, 'should generate 3 key packages')

    // Verify each key package has the correct structure
    for (const keyPackage of keys.keyPackages) {
        t.ok(keyPackage.participantId,
            'key package should have participant ID')
        t.ok(keyPackage.keyShare, 'key package should have key share')
        t.ok(keyPackage.verificationKey,
            'key package should have verification key')
        t.ok(keyPackage.signingCommitments,
            'key package should have signing commitments')
    }
})

test('FROST signing protocol', async t => {
    const config = generateKeys.config(2, 3)
    const coordinator = new FrostCoordinator(config)

    // Generate keys
    const keys = generateKeys(config)

    // Use first 2 participants
    const keyPackages = keys.keyPackages.slice(0, 2)

    // Create signers
    const signers = keyPackages.map(pkg => new FrostSigner(pkg, config))

    // Round 1: Generate commitments
    const round1Results = signers.map(signer => signer.sign_round1())
    const commitmentShares = round1Results.map((result, i) => ({
        participantId: keyPackages[i].participantId,
        commitment: result.commitment
    }))

    // Create signing package
    const message = new TextEncoder().encode('Hello, FROST!')
    const participantIds = keyPackages.map(pkg => pkg.participantId)

    const signingPackage = await coordinator.createSigningPackage(
        message,
        commitmentShares,
        participantIds,
        keys.groupPublicKey
    )

    t.ok(signingPackage, 'should create signing package')
    t.equal(signingPackage.participantIds.length, 2,
        'should have 2 participants')

    // Round 2: Generate signature shares
    const signatureShares = await Promise.all(
        signers.map(async (signer, i) => {
            const result = await signer.sign_round2(
                signingPackage,
                round1Results[i].nonces,
                keys.groupPublicKey
            )
            return result.signatureShare
        })
    )

    t.equal(signatureShares.length, 2, 'should generate 2 signature shares')

    // Aggregate signatures
    const finalSignature = coordinator.aggregateSignatures(
        signingPackage,
        signatureShares
    )

    t.ok(finalSignature, 'signature should be generated')
    t.equal(finalSignature.length, 64, 'signature should be 64 bytes')

    // Verify signature
    const isValid = await coordinator.verify(
        finalSignature,
        message,
        keys.groupPublicKey
    )

    t.ok(isValid, 'signature should be valid')

    // Verify signature with WebCrypto API (standard Ed25519 method)
    const pkBytes = new Uint8Array(keys.groupPublicKey.point)

    const publicKey = await webcrypto.subtle.importKey(
        'raw',
        pkBytes,
        { name: 'Ed25519' },
        false,
        ['verify']
    )

    const webcryptoValid = await webcrypto.subtle.verify(
        'Ed25519',
        publicKey,
        finalSignature,
        message
    )

    t.ok(webcryptoValid, 'signature should verify with standard WebCrypto API')
})

test('FROST threshold requirement', async t => {
    const config = generateKeys.config(3, 4)  // Require 3 of 4 signers
    const coordinator = new FrostCoordinator(config)
    const keyGenResult = generateKeys(config)

    // Try to sign with only 2 signers (should fail)
    const insufficientKeyPackages = keyGenResult.keyPackages.slice(0, 2)
    const insufficientSigners = insufficientKeyPackages.map(pkg => {
        return new FrostSigner(pkg, config)
    })

    const round1Results = insufficientSigners.map(signer => signer.sign_round1())
    const commitmentShares = round1Results.map((result, i) => ({
        participantId: insufficientKeyPackages[i].participantId,
        commitment: result.commitment
    }))

    const message = new TextEncoder().encode('Test message')
    const participantIds = insufficientKeyPackages.map(pkg => pkg.participantId)

    try {
        await coordinator.createSigningPackage(
            message,
            commitmentShares,
            participantIds,
            keyGenResult.groupPublicKey
        )
        t.fail('should reject insufficient signers')
    } catch (error) {
        t.ok(error, 'should throw error for insufficient signers')
    }

    // Now try with sufficient signers (3 of 4)
    const sufficientKeyPackages = keyGenResult.keyPackages.slice(0, 3)
    const sufficientSigners = sufficientKeyPackages.map(pkg => {
        return new FrostSigner(pkg, config)
    })

    const sufficientRound1Results = sufficientSigners.map(signer => {
        return signer.sign_round1()
    })
    const sufficientCommitmentShares = sufficientRound1Results.map((result, i) => {
        return {
            participantId: sufficientKeyPackages[i].participantId,
            commitment: result.commitment
        }
    })

    const sufficientParticipantIds = sufficientKeyPackages.map(pkg => {
        return pkg.participantId
    })

    const signingPackage = await coordinator.createSigningPackage(
        message,
        sufficientCommitmentShares,
        sufficientParticipantIds,
        keyGenResult.groupPublicKey
    )

    t.ok(signingPackage,
        'should create signing package with sufficient signers')
})

test('WebCrypto key backup with FROST (2-of-3 recovery)', async t => {
    // Step 1: Generate an Ed25519 keypair with WebCrypto
    const keyPair = await webcrypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify']
    )

    // Extract the raw private key (32 bytes)
    const privateKeyBuffer = await webcrypto.subtle.exportKey(
        'pkcs8',
        keyPair.privateKey
    )

    // PKCS#8 format has overhead - extract the 32-byte seed
    // For Ed25519, the seed is at a fixed offset in PKCS#8
    const pkcs8 = new Uint8Array(privateKeyBuffer)
    const seedOffset = pkcs8.length - 32
    const privateKeySeed = pkcs8.slice(seedOffset)

    t.equal(privateKeySeed.length, 32, 'private key seed should be 32 bytes')

    // Ed25519 derives the scalar from SHA-512(seed) with bit clamping
    // The first 32 bytes of SHA-512(seed) is clamped to form the scalar
    const seedHash = await webcrypto.subtle.digest('SHA-512', privateKeySeed)
    const seedHashBytes = new Uint8Array(seedHash)
    const privateScalar = seedHashBytes.slice(0, 32)

    // Ed25519 bit clamping: clear bits 0, 1, 2, set bit 254, clear bit 255
    privateScalar[0] &= 248  // Clear bottom 3 bits
    privateScalar[31] &= 127 // Clear top bit
    privateScalar[31] |= 64  // Set bit 254

    // Step 2: Split the private scalar into 3 shares (require 2 to recover)
    const config = generateKeys.config(2, 3)
    const { groupPublicKey, keyPackages } = splitExistingKey(
        privateScalar,
        config
    )

    t.equal(keyPackages.length, 3, 'should create 3 key shares')

    // Verify the group public key matches the original
    const originalPublicKeyBuffer = await webcrypto.subtle.exportKey(
        'raw',
        keyPair.publicKey
    )
    const originalPublicKey = new Uint8Array(originalPublicKeyBuffer)

    t.deepEqual(
        new Uint8Array(groupPublicKey.point),
        originalPublicKey,
        'group public key should match original'
    )

    // Step 3: Lose one share (simulate losing access to share #3)
    const availableShares = keyPackages.slice(0, 2) // Only have shares 1 and 2

    // Step 4: Recover the private scalar using 2 of 3 shares
    const recoveredScalar = recoverPrivateKey(availableShares, config)

    t.equal(recoveredScalar.length, 32, 'recovered scalar should be 32 bytes')

    // Step 5: Verify the recovered scalar produces the same public key
    // The scalar values may differ slightly due to modular arithmetic in Lagrange
    // interpolation, but what matters is they produce the same public key
    const config2 = generateKeys.config(2, 3)
    const testSplit = splitExistingKey(recoveredScalar, config2)

    t.deepEqual(
        new Uint8Array(testSplit.groupPublicKey.point),
        originalPublicKey,
        'public key from recovered scalar should match original'
    )

    // Step 6: Verify different combinations of shares work
    const differentShares = [keyPackages[0], keyPackages[2]] // shares 1 and 3
    const recoveredScalar2 = recoverPrivateKey(differentShares, config)
    const testSplit2 = splitExistingKey(recoveredScalar2, config2)

    t.deepEqual(
        new Uint8Array(testSplit2.groupPublicKey.point),
        originalPublicKey,
        'different share combination should also recover correctly'
    )
})

test('all done', () => {
    // @ts-expect-error tests
    window.testsFinished = true
})
