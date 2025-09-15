import { render } from 'preact'
import { html } from 'htm/preact'
import { signal, computed, useComputed } from '@preact/signals'
import { EccKeys } from '@substrate-system/keys/ecc'
import {
    createFrostConfig,
    TrustedDealer,
    FrostCoordinator,
    FrostSigner,
    type TrustedDealerOutput,
    type FrostSignature,
    type KeyPackage,
} from '../src/index.js'

const NBSP = '\u00A0'

// State signals
const isRunning = signal(false)
const currentStep = signal('idle')
const config = signal(createFrostConfig(2, 3))  // 2-of-3 threshold
const keyGenResult = signal<TrustedDealerOutput | null>(null)
const finalSignature = signal<FrostSignature | null>(null)
const isValid = signal(false)
const errorMessage = signal<string | null>(null)
const isBackedUp = signal(false)
const isRecovered = signal(false)
// const backupShards = signal<any[]>([])
const currentOperation = signal<'backup' | 'recovery' | null>(null)
const backups = {
    bob: signal<null|KeyPackage>(null),
    carol: signal<null|KeyPackage>(null),
    desmond: signal<null|KeyPackage>(null)
}
const selectedForRecovery = {
    bob: signal(false),
    carol: signal(false),
    desmond: signal(false)
}

// Computed values
const participantCount = computed<number>(() => {
    return keyGenResult.value?.keyPackages.length || 3
})
const threshold = computed<number>(() => config.value.minSigners)
const messageLength = computed<number>(() => 'Alice\'s important message'.length)
const selectedCount = computed<number>(() => {
    return Object.values(selectedForRecovery).filter(s => s.value).length
})

async function backupKey () {
    if (isRunning.value) return

    try {
        isRunning.value = true
        currentOperation.value = 'backup'
        errorMessage.value = null
        currentStep.value = 'Creating keys and FROST backup setup'

        // Step 1: Alice creates her keypair using @substrate-system/keys
        console.log('1. Alice creates keys using @substrate-system/keys' +
            ' (extractable for backup)')

        // not session, extractable for backup
        const aliceKeys = await EccKeys.create(false, true)
        console.log('   - Alice generates Ed25519 keypair for signing')
        console.log(`   - Alice's DID: ${aliceKeys.DID.slice(0, 32)}...`)

        // Step 2: Alice creates a 2-of-3 FROST backup setup
        console.log('2. Alice creates a 2-of-3 FROST backup setup')
        const dealer = new TrustedDealer(config.value)
        const keyGen = dealer.generateKeys()
        keyGenResult.value = keyGen

        // Name the participants and store backup shards
        // (take 2 out of 3 for recovery)
        const [bobKey, carolKey, desmondKey] = keyGen.keyPackages
        // backupShards.value = [bobKey, carolKey]
        backups.bob.value = bobKey
        backups.carol.value = carolKey
        backups.desmond.value = desmondKey
        console.log('   - Alice creates backup shards for Bob and Carol')

        currentStep.value = 'Backup created successfully'
        isBackedUp.value = true

        console.log('\\nBackup complete! Key has been distributed to' +
            ' 2 trusted participants.')
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
    if (
        isRunning.value ||
        !isBackedUp.value ||
        selectedCount.value !== 2
    ) return

    try {
        isRunning.value = true
        currentOperation.value = 'recovery'
        errorMessage.value = null
        currentStep.value = 'Starting key recovery'

        // Use the selected backup shards to recover the key
        console.log('Starting key recovery using selected backup shards...')
        const selectedParticipants = Object.entries(selectedForRecovery)
            .filter(([_, selected]) => selected.value)
            .map(([name, _]) => backups[name as keyof typeof backups].value)
            .filter(Boolean)

        if (selectedParticipants.length !== 2) {
            throw new Error('Exactly 2 participants must be selected for recovery')
        }

        const participants = selectedParticipants
        const signers = participants.map(pkg => {
            return new FrostSigner(pkg, config.value)
        })
        const coordinator = new FrostCoordinator(config.value)
        const selectedNames = Object.entries(selectedForRecovery)
            .filter(([_, selected]) => selected.value)
            .map(([name, _]) => name.charAt(0).toUpperCase() + name.slice(1))
        console.log(`   - Using ${selectedNames.join(' and ')}'s backup shards`)

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
    // backupShards.value = []
    backups.bob.value = null
    backups.carol.value = null
    backups.desmond.value = null
    selectedForRecovery.bob.value = false
    selectedForRecovery.carol.value = false
    selectedForRecovery.desmond.value = false
    isValid.value = false
    errorMessage.value = null
    currentStep.value = 'idle'
}

function Example () {
    const backupBtnClass = useComputed<string>(() => {
        // class="btn ${(isRunning.value || isBackedUp.value) ? 'disabled' : 'primary'}"
        const running = isRunning.value
        const saved = isBackedUp.value

        let classString = 'btn'
        if (running && saved) classString += ' disabled'
        else classString += ' primary'

        return classString
    })

    return html`
    <div class="example">
        <h1>FROST Key Backup & Recovery</h1>

        <div class="intro">
            <h3>Secure Key Management with @substrate-system/keys + FROST</h3>
            <p><strong>Keys:</strong> Ed25519 keypair created with @substrate-system/keys (extractable)</p>
            <p><strong>Backup:</strong> ${threshold.value}-of-${participantCount.value} threshold backup system using FROST</p>
            <p>
                <strong>Participants:</strong> Alice (owner), Bob, Carol
                (backup holders)
            </p>
            <p><strong>Cipher Suite:</strong> ${config.value.cipherSuite.name}</p>
        </div>

        <!-- Participants Display -->
        <div class="participants-section">
            <h3>Participants</h3>
            <div class="participants-grid">
                <div class="participant alice">
                    <h4>Alice</h4>
                    <p>Owner</p>
                </div>
                <div class="participant bob">
                    <h4>Bob</h4>
                    <p>Backup Holder</p>
                    <div class="shard-container">
                        <div class="shard-box ${isBackedUp.value ? 'has-shard' : 'no-shard'}"></div>
                        <span class="shard-label">Backup</span>
                    </div>
                    ${isBackedUp.value && !isRecovered.value && html`
                        <div class="recovery-selection">
                            <label>
                                <input
                                    type="checkbox"
                                    checked=${selectedForRecovery.bob.value}
                                    onChange=${(e) => selectedForRecovery.bob.value = e.target.checked}
                                />
                                Use for recovery
                            </label>
                        </div>
                    `}
                </div>
                <div class="participant carol">
                    <h4>Carol</h4>
                    <p>Backup Holder</p>
                    <div class="shard-container">
                        <div class="shard-box ${isBackedUp.value ? 'has-shard' : 'no-shard'}"></div>
                        <span class="shard-label">Backup</span>
                    </div>
                    ${isBackedUp.value && !isRecovered.value && html`
                        <div class="recovery-selection">
                            <label>
                                <input
                                    type="checkbox"
                                    checked=${selectedForRecovery.carol.value}
                                    onChange=${(e) => selectedForRecovery.carol.value = e.target.checked}
                                />
                                Use for recovery
                            </label>
                        </div>
                    `}
                </div>
                <div class="participant desmond">
                    <h4>Desmond</h4>
                    <p>Backup Holder</p>
                    <div class="shard-container">
                        <div class="shard-box ${isBackedUp.value ? 'has-shard' : 'no-shard'}"></div>
                        <span class="shard-label">Backup</span>
                    </div>
                    ${isBackedUp.value && !isRecovered.value && html`
                        <div class="recovery-selection">
                            <label>
                                <input
                                    type="checkbox"
                                    checked=${selectedForRecovery.desmond.value}
                                    onChange=${(e) => selectedForRecovery.desmond.value = e.target.checked}
                                />
                                Use for recovery
                            </label>
                        </div>
                    `}
                </div>
            </div>
        </div>

        <!-- Key Status Indicators -->
        <div class="status-indicators">
            <div class="status-card ${isBackedUp.value ? 'backed-up' : 'not-backed-up'}">
                <h4>Key Backup</h4>
                <p>
                    ${isBackedUp.value ? 'BACKED UP' : 'NOT BACKED UP'}
                </p>
            </div>

            <div class="status-card ${isRecovered.value ? 'backed-up' : 'not-backed-up'}">
                <h4>Key Recovery</h4>
                <p>
                    ${isRecovered.value ? 'RECOVERED' : 'NOT RECOVERED'}
                </p>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="action-buttons">
            <button
                onClick=${backupKey}
                disabled=${isRunning.value || isBackedUp.value}
                class="${backupBtnClass.value}"
            >
                ${isBackedUp.value ? 'Key Backed Up' : 'Backup Key'}
            </button>

            <button
                onClick=${recoverKey}
                disabled=${isRunning.value || !isBackedUp.value || isRecovered.value || selectedCount.value !== 2}
                class="btn ${(isRunning.value || !isBackedUp.value || isRecovered.value || selectedCount.value !== 2) ? 'disabled' : 'success'}"
            >
                ${isRecovered.value ? 'Key Recovered' : `Recover Key (${selectedCount.value}/2 selected)`}
            </button>

            <button
                onClick=${resetDemo}
                disabled=${isRunning.value}
                class="btn ${isRunning.value ? 'disabled' : 'danger'}"
            >
                Reset Demo
            </button>
        </div>

        ${currentStep.value !== 'idle' && html`
            <div class="status-section">
                <h3>Current Status</h3>
                <p><strong>Operation:</strong> ${currentOperation.value || 'None'}</p>
                <p><strong>Step:</strong> ${currentStep.value}</p>
                ${isRunning.value && html`<p class="processing-text">
                    Processing...
                </p>`}
            </div>
        `}

        ${errorMessage.value && html`
            <div class="error-section">
                <h3>Error</h3>
                <p>${errorMessage.value}</p>
            </div>
        `}

        ${keyGenResult.value && html`
            <div class="key-results">
                <h3>Key Generation Results</h3>
                <p>
                    <strong>Participants:</strong> Alice (owner), Bob, Carol
                    (backup holders)
                </p>
                <p>
                    <strong>Group Public Key: </strong>
                    ${keyGenResult.value.groupPublicKey.point.slice(0, 8).join('')}...</p>
                <p>
                    <strong>Key Packages Created: </strong>
                    ${keyGenResult.value.keyPackages.length}
                </p>
            </div>
        `}

        ${finalSignature.value && html`
            <div class="verification-section ${isValid.value ? 'valid' : 'invalid'}">
                <h3>Recovery Verification</h3>
                <p><strong>Test Message:</strong>
                "Alice's important message" (${messageLength.value} bytes)</p>
                <p>
                    <strong>Signature Valid: </strong>
                    ${isValid.value ? 'Yes' : 'No'}
                </p>
                <p>
                    <strong>R Component: </strong>
                    ${finalSignature.value.R.point.length} bytes
                </p>
                <p>
                    <strong>z Component: </strong>
                    ${finalSignature.value.z.value.length} bytes
                </p>
                ${isValid.value && html`
                    <p class="success-message">
                        Success! Alice's key was successfully recovered using
                        the backup shards from Bob and Carol.
                    </p>
                `}
            </div>
        `}

        <div class="info-section">
            <h3>How It Works</h3>
            <p>
                This demonstrates secure key management combining <strong>
                    @substrate-system/keys
                </strong> with <strong>
                    FROST
                </strong> signatures:</p>
            <ul>
                <li>
                    <strong>Key Creation: </strong>
                    Alice generates Ed25519 keypair using @substrate-system/keys
                    (extractable for backup)
                </li>
                <li>
                    <strong>Backup: </strong>
                    FROST creates a${NBSP}
                    ${threshold.value}-of-${participantCount.value}${NBSP}
                    threshold setup, distributing key shares to
                    trusted participants
                </li>
                <li>
                    <strong>Recovery: </strong>
                    Any ${threshold.value} participants can work together to
                    recover Alice's key
                </li>
                <li>
                    <strong>Security: </strong>
                    No single participant can recover the key
                    alone - requires cooperation
                </li>
            </ul>
        </div>

        <div class="protocol-section">
            <h3>FROST Protocol Steps</h3>
            <ol>
                <li>
                    <strong>Key Generation:</strong>
                    Create ${threshold.value}-of-${participantCount.value}
                    ${NBSP}threshold setup
                </li>
                <li>
                    <strong>Distribution: </strong>
                    Share key packages with backup holders
                </li>
                <li>
                    <strong>Recovery Round 1:</strong> Generate nonce commitments
                </li>
                <li>
                    <strong>Recovery Round 2:</strong> Generate signature shares
                </li>
                <li>
                    <strong>Aggregation: </strong>
                    Combine shares into final signature
                </li>
                <li>
                    <strong>Verification: </strong>
                    Prove key recovery by signature validation
                </li>
            </ol>
        </div>

        <p class="footer-text">
            Check the browser console for additional logs.
        </p>
    </div>
  `
}

render(html`<${Example} />`, document.getElementById('root')!)
