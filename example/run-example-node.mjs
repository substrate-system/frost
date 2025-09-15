import { EccKeys } from '@substrate-system/keys/ecc'
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner
} from '../dist/index.js'

async function run () {
    console.log('FROST Example: Alice creates a keypair using @substrate-system/keys,' +
        ' then Bob and Carol help recover it\n')

    // Step 1: Alice creates her Ed25519 keypair using @substrate-system/keys
    console.log('1. Alice creates her Ed25519 keypair using @substrate-system/keys')
    const aliceKeys = await EccKeys.create(false, true) // not session, extractable for backup
    console.log(`   - Alice's DID: ${aliceKeys.DID}`)
    console.log('   - Keys are extractable for backup purposes')

    // Step 2: Alice creates a 3-of-4 FROST setup for key recovery
    console.log('\n2. Alice creates a 3-of-4 FROST setup for key recovery')
    const config = createFrostConfig(3, 4) // Need 3 out of 4 to recover
    const dealer = new TrustedDealer(config)
    const { groupPublicKey, keyPackages } = dealer.generateKeys()

    // Name the participants
    const [_aliceKey, bobKey, carolKey, desmondKey] = keyPackages
    console.log('   - Alice, Bob, Carol, and Desmond each get a key share')
    console.log(`   - Group public key: ${groupPublicKey.point.slice(0, 8).join('')}...`)

    // Step 2: Later, Alice needs to recover her key using 3 of the 4 shares
    console.log('\n2. Alice needs to recover her keypair using 3 participants')

    // Using Bob, Carol, and Desmond
    const participants = [bobKey, carolKey, desmondKey]
    const signers = participants.map(pkg => new FrostSigner(pkg, config))
    const coordinator = new FrostCoordinator(config)
    console.log('   - Bob, Carol, and Desmond will help recover Alice\'s key')

    // Step 3: FROST signing ceremony (this demonstrates the key recovery)
    console.log('\n3. Running FROST signing ceremony to prove key recovery')
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
    console.log("   - This proves Alice's key can be recovered with any " +
        '3 of the 4 shares')

    if (valid) {
        console.log('\nSuccess! Alice can recover her keypair using' +
            ' any 3 participants.')
    } else {
        console.log('\nSomething went wrong with the key recovery.')
    }
}

run().catch(err => {
    console.error('Example run failed:', err); process.exit(1)
})
