import { render } from 'preact'
import { html } from 'htm/preact'
import { signal, computed } from '@preact/signals'
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner,
    type TrustedDealerOutput,
    type FrostSignature,
} from '../src/index.js'

// State signals
const isRunning = signal(false)
const currentStep = signal('idle')
const config = signal(createFrostConfig(2, 3)) // Use working 2-of-3 threshold
const keyGenResult = signal<TrustedDealerOutput | null>(null)
const finalSignature = signal<FrostSignature | null>(null)
const isValid = signal(false)
const errorMessage = signal<string | null>(null)
const isBackedUp = signal(false)
const isRecovered = signal(false)
const backupShards = signal<any[]>([])
const currentOperation = signal<'backup' | 'recovery' | null>(null)

// Computed values
const participantCount = computed<number>(() => {
    return keyGenResult.value?.keyPackages.length || 3
})
const threshold = computed<number>(() => config.value.minSigners)
const messageLength = computed<number>(() => 'Alice\'s important message'.length)

async function backupKey () {
    if (isRunning.value) return

    try {
        isRunning.value = true
        currentOperation.value = 'backup'
        errorMessage.value = null
        currentStep.value = 'Creating FROST backup setup'

        // Step 1: Alice creates her keypair using FROST (2-of-3 threshold)
        console.log('1. Alice creates a 2-of-3 FROST backup setup')
        const dealer = new TrustedDealer(config.value)
        const keyGen = dealer.generateKeys()
        keyGenResult.value = keyGen

        // Name the participants and store backup shards (take 2 out of 3 for backup)
        const [_aliceKey, bobKey, carlKey] = keyGen.keyPackages
        backupShards.value = [bobKey, carlKey]
        console.log('   - Alice creates backup shards for Bob and Carl')

        currentStep.value = 'Backup created successfully'
        isBackedUp.value = true

        console.log('\\nBackup complete! Key has been distributed to 2 trusted participants.')
    } catch (error) {
        console.error('FROST backup failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Unknown error'
        currentStep.value = 'backup failed'
    } finally {
        isRunning.value = false
        currentOperation.value = null
    }
}

async function recoverKey () {
    if (isRunning.value || !isBackedUp.value || backupShards.value.length === 0) return

    try {
        isRunning.value = true
        currentOperation.value = 'recovery'
        errorMessage.value = null
        currentStep.value = 'Starting key recovery'

        // Use the backup shards to recover the key
        console.log('Starting key recovery using backup shards...')
        const participants = backupShards.value
        const signers = participants.map(pkg => new FrostSigner(pkg, config.value))
        const coordinator = new FrostCoordinator(config.value)
        console.log('   - Using Bob and Carl\'s backup shards')

        currentStep.value = 'Running FROST recovery ceremony'

        // Step 3: FROST signing ceremony (this demonstrates the key recovery)
        console.log('Running FROST signing ceremony to prove key recovery')
        const message = new TextEncoder().encode('Alice\'s important message')

        // Round 1: Generate commitments
        const round1Results = signers.map(signer => signer.sign_round1())
        const commitmentShares = round1Results.map((result, i) => ({
            participantId: participants[i].participantId,
            commitment: result.commitment
        }))

        // Create signing package
        const participantIds = participants.map(p => p.participantId)
        const signingPackage = await coordinator.createSigningPackage(
            message,
            commitmentShares,
            participantIds,
            keyGenResult.value!.groupPublicKey
        )

        // Round 2: Generate signature shares using Promise.all (like the working test)
        const signatureShares = await Promise.all(
            signers.map(async (signer, i) => {
                const result = await signer.sign_round2(
                    signingPackage,
                    round1Results[i].nonces,
                    keyGenResult.value!.groupPublicKey
                )
                return result.signatureShare
            })
        )

        currentStep.value = 'Verifying recovered key'

        // Aggregate and verify
        const signature = coordinator.aggregateSignatures(signingPackage, signatureShares)
        finalSignature.value = signature

        const valid = await coordinator.verify(signature, message, keyGenResult.value!.groupPublicKey)
        isValid.value = valid

        console.log('Recovery Results:')
        console.log('   - Signature created using backup shards')
        console.log(`   - Signature valid: ${valid}`)
        console.log("   - This proves Alice's key was successfully recovered")

        if (valid) {
            console.log('\\nSuccess! Alice\'s key was recovered using the backup shards.')
            currentStep.value = 'Key recovered successfully'
            isRecovered.value = true
        } else {
            console.log('\\nSomething went wrong with the key recovery.')
            currentStep.value = 'recovery failed'
        }
    } catch (error) {
        console.error('FROST recovery failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Unknown error'
        currentStep.value = 'recovery failed'
    } finally {
        isRunning.value = false
        currentOperation.value = null
    }
}

function resetDemo () {
    isBackedUp.value = false
    isRecovered.value = false
    keyGenResult.value = null
    finalSignature.value = null
    backupShards.value = []
    isValid.value = false
    errorMessage.value = null
    currentStep.value = 'idle'
}

function Example () {
    return html`
    <div class="example">
        <h1>FROST Key Backup & Recovery</h1>

        <div class="intro">
            <h3>Secure Key Management with FROST</h3>
            <p><strong>Setup:</strong> ${threshold.value}-of-${participantCount.value} threshold backup system</p>
            <p><strong>Participants:</strong> Alice (owner), Bob, Carl (backup holders)</p>
            <p><strong>Cipher Suite:</strong> ${config.value.cipherSuite.name}</p>
        </div>

        <!-- Key Status Indicators -->
        <div style="display: flex; gap: 20px; margin: 20px 0;">
            <div style="background: ${isBackedUp.value ? '#d1ecf1' : '#e2e3e5'}; padding: 15px; border-radius: 8px; flex: 1; text-align: center; border: 2px solid ${isBackedUp.value ? '#bee5eb' : '#d1d3d4'};">
                <h4 style="margin: 0; color: ${isBackedUp.value ? '#0c5460' : '#495057'};">🔐 Key Backup</h4>
                <p style="margin: 5px 0; font-weight: bold; color: ${isBackedUp.value ? '#0c5460' : '#6c757d'};">
                    ${isBackedUp.value ? 'BACKED UP' : 'NOT BACKED UP'}
                </p>
            </div>

            <div style="background: ${isRecovered.value ? '#d1ecf1' : '#e2e3e5'}; padding: 15px; border-radius: 8px; flex: 1; text-align: center; border: 2px solid ${isRecovered.value ? '#bee5eb' : '#d1d3d4'};">
                <h4 style="margin: 0; color: ${isRecovered.value ? '#0c5460' : '#495057'};">🔓 Key Recovery</h4>
                <p style="margin: 5px 0; font-weight: bold; color: ${isRecovered.value ? '#0c5460' : '#6c757d'};">
                    ${isRecovered.value ? 'RECOVERED' : 'NOT RECOVERED'}
                </p>
            </div>
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; gap: 15px; margin: 20px 0;">
            <button
                onClick=${backupKey}
                disabled=${isRunning.value || isBackedUp.value}
                style="padding: 12px 24px; background: ${isBackedUp.value ? '#6c757d' : '#007acc'}; color: white; border: none; border-radius: 6px; cursor: ${(isRunning.value || isBackedUp.value) ? 'not-allowed' : 'pointer'}; opacity: ${(isRunning.value || isBackedUp.value) ? 0.6 : 1}; font-weight: bold;"
            >
                ${isBackedUp.value ? '✓ Key Backed Up' : '🔐 Backup Key'}
            </button>

            <button
                onClick=${recoverKey}
                disabled=${isRunning.value || !isBackedUp.value || isRecovered.value}
                style="padding: 12px 24px; background: ${!isBackedUp.value || isRecovered.value ? '#6c757d' : '#28a745'}; color: white; border: none; border-radius: 6px; cursor: ${(isRunning.value || !isBackedUp.value || isRecovered.value) ? 'not-allowed' : 'pointer'}; opacity: ${(isRunning.value || !isBackedUp.value || isRecovered.value) ? 0.6 : 1}; font-weight: bold;"
            >
                ${isRecovered.value ? '✓ Key Recovered' : '🔓 Recover Key'}
            </button>

            <button
                onClick=${resetDemo}
                disabled=${isRunning.value}
                style="padding: 12px 24px; background: #dc3545; color: white; border: none; border-radius: 6px; cursor: ${isRunning.value ? 'not-allowed' : 'pointer'}; opacity: ${isRunning.value ? 0.6 : 1}; font-weight: bold;"
            >
                🔄 Reset Demo
            </button>
        </div>

        ${currentStep.value !== 'idle' && html`
            <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745;">
                <h3 style="margin-top: 0;">Current Status</h3>
                <p><strong>Operation:</strong> ${currentOperation.value || 'None'}</p>
                <p><strong>Step:</strong> ${currentStep.value}</p>
                ${isRunning.value && html`<p style="color: #666;">⏳ Processing...</p>`}
            </div>
        `}

        ${errorMessage.value && html`
            <div style="background: #f8d7da; padding: 15px; border-radius: 8px; margin: 20px 0; border: 1px solid #f5c6cb; border-left: 4px solid #dc3545;">
                <h3 style="color: #721c24; margin-top: 0;">❌ Error</h3>
                <p style="color: #721c24;">${errorMessage.value}</p>
            </div>
        `}

        ${keyGenResult.value && html`
            <div style="background: #e8f5e8; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745;">
                <h3 style="margin-top: 0;">🔑 Key Generation Results</h3>
                <p><strong>Participants:</strong> Alice (owner), Bob, Carl (backup holders)</p>
                <p><strong>Group Public Key:</strong> ${keyGenResult.value.groupPublicKey.point.slice(0, 8).join('')}...</p>
                <p><strong>Key Packages Created:</strong> ${keyGenResult.value.keyPackages.length}</p>
                <p><strong>Backup Shards:</strong> ${backupShards.value.length} (Bob, Carl)</p>
            </div>
        `}

        ${finalSignature.value && html`
            <div style="background: ${isValid.value ? '#d1ecf1' : '#f8d7da'}; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid ${isValid.value ? '#17a2b8' : '#dc3545'};">
                <h3 style="margin-top: 0;">${isValid.value ? '✅' : '❌'} Recovery Verification</h3>
                <p><strong>Test Message:</strong> "Alice's important message" (${messageLength.value} bytes)</p>
                <p><strong>Signature Valid:</strong> ${isValid.value ? 'Yes ✅' : 'No ❌'}</p>
                <p><strong>R Component:</strong> ${finalSignature.value.R.point.length} bytes</p>
                <p><strong>z Component:</strong> ${finalSignature.value.z.value.length} bytes</p>
                ${isValid.value && html`
                    <p style="color: #155724; font-weight: bold; background: #d4edda; padding: 10px; border-radius: 4px; margin-top: 10px;">
                        🎉 Success! Alice's key was successfully recovered using the backup shards from Bob and Carl.
                    </p>
                `}
            </div>
        `}

        <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <h3 style="margin-top: 0;">💡 How It Works</h3>
            <p>This demonstrates FROST (Flexible Round-Optimized Schnorr Threshold) signatures for secure key backup and recovery:</p>
            <ul>
                <li><strong>Backup:</strong> Alice creates a ${threshold.value}-of-${participantCount.value} threshold setup, distributing key shares to trusted participants</li>
                <li><strong>Recovery:</strong> Any ${threshold.value} participants can work together to recover Alice's key</li>
                <li><strong>Security:</strong> No single participant can recover the key alone - requires cooperation</li>
            </ul>
        </div>

        <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745;">
            <h3 style="margin-top: 0;">🔄 FROST Protocol Steps</h3>
            <ol>
                <li><strong>Key Generation:</strong> Create ${threshold.value}-of-${participantCount.value} threshold setup</li>
                <li><strong>Distribution:</strong> Share key packages with backup holders</li>
                <li><strong>Recovery Round 1:</strong> Generate nonce commitments</li>
                <li><strong>Recovery Round 2:</strong> Generate signature shares</li>
                <li><strong>Aggregation:</strong> Combine shares into final signature</li>
                <li><strong>Verification:</strong> Prove key recovery by signature validation</li>
            </ol>
        </div>

        <p style="margin-top: 30px; font-size: 12px; color: #666; text-align: center;">
            Check the browser console for detailed logging of the FROST protocol execution.
        </p>
    </div>
  `
}

render(html`<${Example} />`, document.getElementById('root')!)
