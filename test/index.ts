import { test } from '@substrate-system/tapzero'
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner
} from '../src/index.js'

test('FROST key generation', async t => {
    const config = createFrostConfig(2, 3)
    const dealer = new TrustedDealer(config)

    const keyGenResult = dealer.generateKeys()

    t.ok(keyGenResult.groupPublicKey, 'should generate group public key')
    t.equal(keyGenResult.keyPackages.length, 3, 'should generate 3 key packages')

    // Verify each key package has the correct structure
    for (const keyPackage of keyGenResult.keyPackages) {
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
    const config = createFrostConfig(2, 3)
    const dealer = new TrustedDealer(config)
    const coordinator = new FrostCoordinator(config)

    // Generate keys
    const keyGenResult = dealer.generateKeys()
    // Use first 2 participants
    const keyPackages = keyGenResult.keyPackages.slice(0, 2)

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
        keyGenResult.groupPublicKey
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
                keyGenResult.groupPublicKey
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

    t.ok(finalSignature.R, 'signature should have R component')
    t.ok(finalSignature.z, 'signature should have z component')

    // Verify signature
    const isValid = await coordinator.verify(
        finalSignature,
        message,
        keyGenResult.groupPublicKey
    )

    t.ok(isValid, 'signature should be valid')
})

test('FROST threshold requirement', async t => {
    const config = createFrostConfig(3, 4)  // Require 3 of 4 signers
    const dealer = new TrustedDealer(config)
    const coordinator = new FrostCoordinator(config)

    const keyGenResult = dealer.generateKeys()

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
