import {
    createFrostConfig,
    generateKeys,
    FrostCoordinator,
    FrostSigner
} from '../dist/index.js'

async function run () {
    console.log('FROST Example: Alice creates a 3-of-4 threshold signature system\n')

    // Step 1: Alice creates a 3-of-4 FROST setup
    console.log('1. Alice creates a 3-of-4 FROST threshold signature system')
    const config = createFrostConfig(3, 4) // Need 3 out of 4 to sign
    const { groupPublicKey, keyPackages } = generateKeys(config)

    // Name the participants
    const [_aliceKey, bobKey, carolKey, desmondKey] = keyPackages
    console.log('   - Alice, Bob, Carol, and Desmond each get a key share')
    console.log(`   - Group public key: ${Buffer.from(groupPublicKey.point)
        .toString('hex').slice(0, 16)}...`)

    // Step 2: Later, Alice wants to create a signature using 3 participants
    console.log('\n2. Alice creates a signature using 3 of the 4 participants')

    // Using Bob, Carol, and Desmond
    const participants = [bobKey, carolKey, desmondKey]
    const signers = participants.map(pkg => new FrostSigner(pkg, config))
    const coordinator = new FrostCoordinator(config)
    console.log('   - Bob, Carol, and Desmond will collaborate to create' +
        ' the signature')

    // Step 3: FROST signing ceremony
    console.log('\n3. Running FROST signing ceremony')
    const message = new TextEncoder().encode('Alice\'s important message')

    // Round 1: Generate commitments
    const round1 = signers.map(s => s.sign_round1())
    const commitmentShares = round1.map((r, i) => ({
        participantId: participants[i].participantId,
        commitment: r.commitment
    }))

    // Create signing package
    const participantIds = participants.map(p => p.participantId)
    const signingPackage = await coordinator.createSigningPackage(
        message,
        commitmentShares,
        participantIds,
        groupPublicKey
    )

    // Round 2: Generate signature shares
    const signatureShares = []
    for (let i = 0; i < signers.length; i++) {
        const res = await signers[i].sign_round2(
            signingPackage,
            round1[i].nonces,
            groupPublicKey
        )
        signatureShares.push(res.signatureShare)
    }

    // Aggregate and verify
    const finalSignature = coordinator.aggregateSignatures(
        signingPackage,
        signatureShares
    )
    const valid = await coordinator.verify(
        finalSignature,
        message,
        groupPublicKey
    )

    console.log('\n4. Results:')
    console.log("   - Signature created using Bob, Carol, and Desmond's shares")
    console.log(`   - Signature valid: ${valid}`)
    console.log('   - This demonstrates 3-of-4 threshold signing')

    if (valid) {
        console.log('\nSuccess! FROST threshold signature is valid.')
        console.log('The signature is mathematically equivalent to what a single')
        console.log('private key would produce, but was created collaboratively.')
    } else {
        console.log('\nSomething went wrong with the signature creation.')
    }
}

run().catch(err => {
    console.error('Example run failed:', err); process.exit(1)
})
