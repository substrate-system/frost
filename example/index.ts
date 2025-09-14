import { type FunctionComponent, render } from 'preact'
import { html } from 'htm/preact'
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner
} from '../src/index.js'

// Example usage of FROST threshold signatures
function frostExample () {
    console.log('🧊 FROST (Flexible Round-Optimized Schnorr Threshold) Example')

    // Create a 2-of-3 threshold configuration
    const config = createFrostConfig(2, 3)
    console.log('Configuration: 2-of-3 threshold signing')

    // Step 1: Key Generation using Trusted Dealer
    const dealer = new TrustedDealer(config)
    const keyGenResult = dealer.generateKeys()

    console.log('✓ Generated keys for 3 participants')
    console.log('✓ Group public key created')

    // Step 2: Select participants for signing (2 out of 3)
    const signingParticipants = keyGenResult.keyPackages.slice(0, 2)
    const signers = signingParticipants.map(pkg => new FrostSigner(pkg, config))
    const coordinator = new FrostCoordinator(config)

    console.log('✓ Selected 2 participants for signing ceremony')

    // Step 3: Round 1 - Generate commitments
    const round1Results = signers.map(signer => signer.sign_round1())
    const commitmentShares = round1Results.map((result, i) => ({
        participantId: signingParticipants[i].participantId,
        commitment: result.commitment
    }))

    console.log('✓ Round 1: Generated nonce commitments')

    // Step 4: Create signing package
    const message = new TextEncoder().encode('Hello, FROST! This is a threshold signature.')
    const participantIds = signingParticipants.map(pkg => pkg.participantId)

    const signingPackage = coordinator.createSigningPackage(
        message,
        commitmentShares,
        participantIds
    )

    console.log('✓ Created signing package with message and commitments')

    // Step 5: Round 2 - Generate signature shares
    const signatureShares = signers.map((signer, i) =>
        signer.sign_round2(signingPackage, round1Results[i].nonces).signatureShare
    )

    console.log('✓ Round 2: Generated signature shares')

    // Step 6: Aggregate final signature
    const finalSignature = coordinator.aggregateSignatures(
        signingPackage,
        signatureShares
    )

    console.log('✓ Aggregated final threshold signature')

    // Step 7: Verify signature
    const isValid = coordinator.verify(
        finalSignature,
        message,
        keyGenResult.groupPublicKey
    )

    console.log(`✓ Signature verification: ${isValid ? 'VALID' : 'INVALID'}`)
    console.log('🧊 FROST example completed!')

    return {
        config,
        keyGenResult,
        finalSignature,
        isValid,
        participantCount: keyGenResult.keyPackages.length,
        threshold: config.minSigners,
        messageLength: message.length
    }
}

// Run the example
const result = frostExample()

const Example: FunctionComponent<unknown> = function () {
    return html`
    <div style="font-family: monospace; padding: 20px; max-width: 800px;">
      <h1>🧊 FROST Threshold Signatures</h1>
      <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <h3>Configuration</h3>
        <p><strong>Threshold:</strong> ${result.threshold} of ${result.participantCount} participants</p>
        <p><strong>Cipher Suite:</strong> ${result.config.cipherSuite.name}</p>
      </div>

      <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <h3>Signature Results</h3>
        <p><strong>Message Length:</strong> ${result.messageLength} bytes</p>
        <p><strong>Signature Valid:</strong> ${result.isValid ? '✅ Yes' : '❌ No'}</p>
        <p><strong>R Component:</strong> ${result.finalSignature.R.point.length} bytes</p>
        <p><strong>z Component:</strong> ${result.finalSignature.z.value.length} bytes</p>
      </div>

      <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <h3>⚠️ Implementation Note</h3>
        <p>This is a <strong>demonstration implementation</strong> of the FROST protocol structure.</p>
        <p>The cryptographic operations use simplified placeholders and are <strong>NOT</strong> cryptographically secure.</p>
        <p>For production use, replace the cipher suite with proper Ed25519 curve operations.</p>
      </div>

      <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <h3>📋 FROST Protocol Steps</h3>
        <ol>
          <li>✅ Key Generation (Trusted Dealer)</li>
          <li>✅ Participant Selection</li>
          <li>✅ Round 1: Nonce Commitments</li>
          <li>✅ Signing Package Creation</li>
          <li>✅ Round 2: Signature Share Generation</li>
          <li>✅ Signature Aggregation</li>
          <li>✅ Signature Verification</li>
        </ol>
      </div>

      <p style="margin-top: 30px; font-size: 12px; color: #666;">
        Check the browser console for detailed logging of the FROST protocol execution.
      </p>
    </div>
  `
}

render(html`<${Example} />`, document.getElementById('root')!)
