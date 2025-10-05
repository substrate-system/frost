import { render } from 'preact'
import { html } from 'htm/preact'
import { useCallback } from 'preact/hooks'
import { signal, computed, useComputed } from '@preact/signals'
import * as u8 from 'uint8arrays'
import Debug from '@substrate-system/debug'
import {
    FrostCoordinator,
    FrostSigner,
    generateKeys,
    type KeyPackage,
    type Signers
} from '../src/index.js'
const debug = Debug(import.meta.env.DEV)

const NBSP = '\u00A0'
const EM_DASH = '\u2014'

// State signals
const isRunning = signal(false)
const currentStep = signal('idle')
const config = signal(generateKeys.config(2, 4))  // 2 of 4 threshold
const keyGenResult = signal<Signers|null>(null)
const finalSignature = signal<Uint8Array|null>(null)
const isValid = signal(false)
const errorMessage = signal<string|null>(null)
const frostExists = signal(false)
const hasSigned = signal(false)
const customMessage = signal('My important message')
const customSignature = signal<Uint8Array|null>(null)
const customVerificationResult = signal<boolean|null>(null)
const shards = {
    alice: signal<null|KeyPackage>(null),
    bob: signal<null|KeyPackage>(null),
    carol: signal<null|KeyPackage>(null),
    desmond: signal<null|KeyPackage>(null)
}
const selectedForSigning = {
    alice: signal(false),
    bob: signal(false),
    carol: signal(false),
    desmond: signal(false)
}

const participantCount = computed<number>(() => {
    return keyGenResult.value?.keyPackages.length || 4
})
const threshold = computed<number>(() => config.value.minSigners)
const selectedCount = computed<number>(() => {
    return Object.values(selectedForSigning).filter(s => s.value).length
})

function Example () {
    const backupBtnClass = useComputed<string>(() => {
        const running = isRunning.value
        const saved = frostExists.value

        let classString = 'btn'
        if (running && saved) classString += ' disabled'
        else classString += ' primary'

        return classString
    })

    const handleMsgInput = useCallback((ev:InputEvent) => {
        customMessage.value = (ev.target as HTMLInputElement).value
    }, [])

    const selectForSigning = useCallback((_ev:InputEvent) => {
        const target = _ev.target as HTMLInputElement
        const id = target.dataset.id!
        selectedForSigning[id].value = target.checked
    }, [])

    debug('render')

    return html`
        <h1>FROST ${EM_DASH} Quorum Signatures</h1>
        <div class="example">
            <div class="row">
                <div class="col-half">
                    <p class="description">
                        Create a signature that proves
                        at least x number of people signed,
                        without revealing the identities of who did or
                        did not sign.
                        The final signature looks identical to a standard
                        ed25519 signature.
                    </p>

                </div>

                <div class="col-half">
                    <div class="info-section">
                        <h3>How It Works</h3>

                        <ul>
                            <li>
                                <strong>Key Creation: </strong>
                                Generate a new public key and array of signer
                                packages.
                            </li>
                            <li>
                                <strong>Signing: </strong>
                                Any ${threshold.value} participants can work
                                together to create valid signatures. (This
                                number is a parameter.)
                            </li>
                            <li>
                                <strong>Security: </strong>
                                <ul>
                                    <li>
                                        No single participant can sign things
                                        alone - requires cooperation.
                                    </li>
                                    <li>
                                        It is impossible to tell who signed the message,
                                        only that at least n of the total possible
                                        people did sign it.
                                    </li>
                                    <li>
                                        A FROST signature is indistinguishable
                                        from a standard ed25519 signature.
                                    </li>
                                </ul>
                            </li>
                        </ul>
                    </div>

                    <div class="info-section">
                        <h3>FROST Protocol Steps</h3>
                        <ol>
                            <li>
                                <strong>Key Generation: </strong>
                                Create a ${threshold.value}-of-${participantCount.value}
                                ${NBSP}threshold system
                            </li>
                            <li>
                                <strong>Distribution: </strong>
                                Share key packages with others
                            </li>
                            <li>
                                <strong>Signing Round 1: </strong>
                                Generate nonce commitments
                            </li>
                            <li>
                                <strong>Signing Round 2: </strong>
                                Generate signature shares
                            </li>
                            <li>
                                <strong>Aggregation: </strong>
                                Combine shares into final signature
                            </li>
                            <li>
                                <strong>Verification: </strong>
                                Validate the threshold signature
                            </li>
                        </ol>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="data col-half">
                    <p>
                        <strong>Keys: </strong>
                        Ed25519 keypair created with <a
                            href="https://github.com/paulmillr/noble-ed25519"
                        >
                            @noble/ed25519
                        </a>
                    </p>
                    <p>
                        <strong>Quorum: </strong>
                        ${threshold.value}-of-${participantCount.value} threshold
                        signature
                    </p>
                    <p>
                        <strong>Participants:</strong> Alice, Bob,
                        Carol, Desmond
                    </p>
                    <p>
                        <strong>Cipher Suite: </strong>
                        ${config.value.cipherSuite.name}
                    </p>
                    <p>
                        <a href="https://www.rfc-editor.org/rfc/rfc9591.html">
                            Read more about FROST
                        </a>
                    </p>
                </div>

                <div class="status-section col-half">
                    <h3>Current Status</h3>
                    <p>
                        <strong>Step: </strong>
                        ${currentStep.value}
                    </p>
                        ${isRunning.value && html`<p class="processing-text">
                            Processing...
                    </p>`}

                    ${keyGenResult.value && html`
                        <div class="key-results">
                            <h3>Results</h3>
                            <p>
                                <strong>Participants: </strong>
                                Alice, Bob, Carol, Desmond
                                (shard holders)
                            </p>
                            <p>
                                <strong>Key Packages Created: </strong>
                                ${keyGenResult.value.keyPackages.length}
                            </p>
                        </div>
                    `}
                </div>
            </div>


            <!-- Participants Display -->
            <section class="section participants">
                <h3>Participants</h3>
                <div class="participants-grid">
                    <div class="participant alice">
                        <h4>Alice</h4>
                        <p>Shard Holder</p>
                        <div class="shard-container">
                            <div class="shard-box ${frostExists.value ?
                                'has-shard' :
                                'no-shard'}">
                            </div>
                            <span class="shard-label">Shard</span>
                        </div>

                        ${shards.alice.value?.keyShare.privateShare.value ?
                            html`<p class="key-shard-material">
                                ${u8.toString(shards.alice.value
                                    .keyShare.privateShare.value, 'hex')}
                            </p>` :
                            ''
                        }

                        ${frostExists.value && html`
                            <div class="signing-selection">
                                <label>
                                    <input
                                        data-id="alice"
                                        type="checkbox"
                                        checked=${selectedForSigning.alice.value}
                                        onChange=${selectForSigning}
                                    />
                                    Use for signing
                                </label>
                            </div>
                        `}
                    </div>

                    <div class="participant bob">
                        <h4>Bob</h4>
                        <p>Shard Holder</p>
                        <div class="shard-container">
                            <div class="shard-box ${frostExists.value ?
                                'has-shard' :
                                'no-shard'}">
                            </div>
                            <span class="shard-label">Shard</span>
                        </div>

                        ${shards.bob.value?.keyShare.privateShare.value ?
                            html`<p class="key-shard-material">
                                ${u8.toString(shards.bob.value.keyShare.privateShare.value, 'hex')}
                            </p>` :
                            ''
                        }

                        ${frostExists.value && html`
                            <div class="signing-selection">
                                <label>
                                    <input
                                        data-id="bob"
                                        type="checkbox"
                                        checked=${selectedForSigning.bob.value}
                                        onChange=${selectForSigning}
                                    />
                                    Use for signing
                                </label>
                            </div>
                        `}
                    </div>

                    <div class="participant carol">
                        <h4>Carol</h4>
                        <p>Shard Holder</p>
                        <div class="shard-container">
                            <div class="shard-box ${frostExists.value ?
                                'has-shard' :
                                'no-shard'
                            }"></div>
                            <span class="shard-label">Shard</span>
                        </div>

                        ${shards.carol.value?.keyShare.privateShare.value ?
                            html`<p class="key-shard-material">
                                ${u8.toString(
                                    shards.carol.value
                                        .keyShare.privateShare.value, 'hex'
                                )}
                            </p>` :
                            ''
                        }

                        ${frostExists.value && html`
                            <div class="signing-selection">
                                <label>
                                    <input
                                        type="checkbox"
                                        data-id="carol"
                                        checked=${selectedForSigning.carol.value}
                                        onChange=${selectForSigning}
                                    />
                                    Use for signing
                                </label>
                            </div>
                        `}
                    </div>

                    <div class="participant desmond">
                        <h4>Desmond</h4>
                        <p>Shard Holder</p>
                        <div class="shard-container">
                            <div class="shard-box ${frostExists.value ?
                                'has-shard' :
                                'no-shard'}">
                            </div>
                            <span class="shard-label">Shard</span>
                        </div>

                        ${shards.desmond.value?.keyShare.privateShare.value ?
                            html`<p class="key-shard-material">
                                ${u8.toString(
                                    shards.desmond.value.keyShare
                                        .privateShare.value,
                                    'hex'
                                )}
                            </p>` :
                            ''
                        }

                        ${frostExists.value && html`
                            <div class="signing-selection">
                                <label>
                                    <input
                                        type="checkbox"
                                        data-id="desmond"
                                        checked=${selectedForSigning.desmond.value}
                                        onChange=${selectForSigning}
                                    />
                                    Use for signing
                                </label>
                            </div>
                        `}
                    </div>
                </div>
            </section>

            <!-- Key Status Indicators -->
            <div class="backup status-indicators">
                <div class="status-card ${frostExists.value ?
                    'true' :
                    'false'
                }">
                    <h4>FROST Shards</h4>
                    <p>
                        ${frostExists.value ?
                            html`
                                <strong>Public Key: </strong>
                                ${
                                    u8.toString(
                                        keyGenResult.value!.groupPublicKey.point,
                                        'hex'
                                    )
                                }
                            ` :
                            ''
                        }
                    </p>
                </div>

                <div class="signing status-card ${hasSigned.value ?
                        'true' :
                        'false'}"
                    >
                    <h4>Multi-Party Signing</h4>
                    ${hasSigned.value ?
                        html`<strong>signature: </strong>
                        ${u8.toString(finalSignature.value!, 'hex')}` :
                        'NOT SIGNED'
                    }


                    ${customVerificationResult.value ?
                        html`
                            <p><strong>Signature Valid: </strong>
                                ${customVerificationResult.value ? 'Yes' : 'No'}
                            </p>
                            <p>
                                <strong>Verified with: </strong>
                                FROST Group Key
                            </p>
                            ${customVerificationResult.value && html`
                                <p class="success-message">
                                    Signature verification successful!
                                </p>
                            `}
                        ` :
                        null
                    }
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="action-buttons">
                <button
                    onClick=${createShards}
                    disabled=${isRunning.value || frostExists.value}
                    class="${backupBtnClass.value}"
                >
                    ${frostExists.value ?
                        'Key created' :
                        'Create FROST key shards'
                    }
                </button>

                <button
                    onClick=${resetDemo}
                    disabled=${isRunning.value}
                    class="btn ${isRunning.value ? 'disabled' : 'danger'}"
                >
                    Reset Demo
                </button>
            </div>

            ${errorMessage.value && html`
                <div class="error-section">
                    <h3>Error</h3>
                    <p>${errorMessage.value}</p>
                </div>
            `}

            <!-- Custom Verification Section -->
            <div class="verification-controls">
                <h3>Signature Verification</h3>
                <div class="verification-form">
                    <div class="form-group">
                        <label for="message-input">
                            Message to sign/verify:
                        </label>
                        <input
                            id="message-input"
                            type="text"
                            value=${customMessage.value}
                            onInput=${handleMsgInput}
                            placeholder="Enter message to sign"
                            class="message-input"
                        />
                    </div>


                    <div class="verification-buttons">
                        <button
                            onClick=${createSignature}
                            disabled=${
                                isRunning.value ||
                                !frostExists.value ||
                                hasSigned.value ||
                                selectedCount.value !== 2 ||
                                !customMessage.value
                            }
                            class="btn ${isRunning.value ? 'disabled' : 'primary'}"
                        >
                            Sign Message
                        </button>

                        <button
                            onClick=${verifyCustomSignature}
                            disabled=${isRunning.value || !customSignature.value}
                            class="btn ${(isRunning.value || !customSignature.value) ? 'disabled' : 'success'}"
                        >
                            Verify Signature
                        </button>
                    </div>

                    ${customSignature.value && html`
                        <div class="signature-display">
                            <h4>Generated Signature:</h4>
                            <div class="signature-data">
                                <p><strong>Signature (64 bytes):</strong> ${u8.toString(customSignature.value, 'hex')}</p>
                                <p><strong>R (first 32 bytes):</strong> ${u8.toString(customSignature.value.slice(0, 32), 'hex')}</p>
                                <p><strong>Z (last 32 bytes):</strong> ${u8.toString(customSignature.value.slice(32), 'hex')}</p>
                            </div>
                        </div>
                    `}
                </div>
            </div>
        </div>`
}

render(html`<${Example} />`, document.getElementById('root')!)

/**
 * Convert a CryptoKey to Uint8Array.
 */
export async function keyToU8 (key:CryptoKey):Promise<Uint8Array> {
    return new Uint8Array(await window.crypto.subtle.exportKey('raw', key))
}

/**
 * Use FROST to create a threshold signature from several shards.
 */
async function createSignature (ev:MouseEvent) {
    if (
        isRunning.value ||
        !frostExists.value ||
        selectedCount.value !== 2
    ) return

    ev.preventDefault()

    try {
        isRunning.value = true
        errorMessage.value = null
        currentStep.value = 'Starting signature creation'

        // Use the selected backup shards to create a signature
        console.log('Starting signature creation using selected backup shards...')
        const pkgs:KeyPackage[] = Object.entries(selectedForSigning)
            .filter(([_, selected]) => selected.value)
            // map names to keyPackage
            .map(([name]) => shards[name as keyof typeof shards].value)
            .filter(Boolean)

        if (pkgs.length !== 2) {
            throw new Error('Exactly 2 participants must be selected for signing')
        }

        const signers = pkgs.map(pkg => {
            return new FrostSigner(pkg, config.value)
        })
        const coordinator = new FrostCoordinator(config.value)
        const selectedNames = Object.entries(selectedForSigning)
            .filter(([_, selected]) => selected.value)
            .map(([name, _]) => name.charAt(0).toUpperCase() + name.slice(1))
        console.log(`   - Using ${selectedNames.join(' and ')}'s backup shards`)

        currentStep.value = 'Running FROST signing ceremony'

        // Step 3: FROST signing ceremony (this creates a threshold signature)
        console.log('Running FROST signing ceremony to create threshold signature')
        const message = new TextEncoder().encode(customMessage.value)

        // Round 1: Generate commitments
        const round1Results = signers.map(signer => signer.sign_round1())
        const commitmentShares = round1Results.map((result, i) => ({
            participantId: pkgs[i].participantId,
            commitment: result.commitment
        }))

        // Create signing package
        const participantIds = pkgs.map(p => p.participantId)
        const signingPackage = await coordinator.createSigningPackage(
            message,
            commitmentShares,
            participantIds,
            keyGenResult.value!.groupPublicKey
        )

        // Round 2: Generate signature shares using Promise.all
        // (like the test)
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

        currentStep.value = 'Verifying threshold signature'

        // Aggregate and verify
        const signature = coordinator.aggregateSignatures(
            signingPackage,
            signatureShares
        )
        // The library now returns a Uint8Array signature directly
        finalSignature.value = signature
        customSignature.value = signature

        const valid = await coordinator.verify(
            signature,
            message,
            keyGenResult.value!.groupPublicKey
        )
        isValid.value = valid

        console.log('Signing Results:')
        console.log('   - Threshold signature created using backup shards')
        console.log(`   - Signature valid: ${valid}`)
        console.log('   - This demonstrates multi-party threshold signing')

        if (valid) {
            console.log('\\nSuccess! Threshold signature created using the' +
                ' backup shards.')
            currentStep.value = 'Signature created successfully'
            hasSigned.value = true
        } else {
            console.log('\\nSomething went wrong with signature creation.')
            currentStep.value = 'signing failed'
        }
    } catch (error) {
        console.error('FROST signing failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Unknown error'
        currentStep.value = 'signing failed'
    } finally {
        isRunning.value = false
    }
}

async function resetDemo () {
    frostExists.value = false
    hasSigned.value = false
    keyGenResult.value = null
    finalSignature.value = null
    shards.alice.value = null
    shards.bob.value = null
    shards.carol.value = null
    shards.desmond.value = null
    selectedForSigning.bob.value = false
    selectedForSigning.carol.value = false
    selectedForSigning.desmond.value = false
    isValid.value = false
    errorMessage.value = null
    currentStep.value = 'idle'
    customMessage.value = 'My important message'
    customSignature.value = null
    customVerificationResult.value = null
}

async function verifyCustomSignature () {
    if (isRunning.value || !customSignature.value) return

    try {
        isRunning.value = true
        errorMessage.value = null

        const message = new TextEncoder().encode(customMessage.value)
        const coordinator = new FrostCoordinator(config.value)

        // Verify with FROST group public key using the Uint8Array signature
        const result = await coordinator.verify(
            customSignature.value,
            message,
            keyGenResult.value!.groupPublicKey
        )

        customVerificationResult.value = result
        console.log(`Verification result: ${result}`)
    } catch (error) {
        console.error('Verification failed:', error)
        errorMessage.value = error instanceof Error ?
            error.message :
            'Unknown verification error'
        customVerificationResult.value = false
    } finally {
        isRunning.value = false
    }
}

async function createShards () {
    if (isRunning.value) return

    try {
        isRunning.value = true
        errorMessage.value = null

        // Step 1: Alice creates a 2-of-4 FROST system
        console.log('1. Alice creates a 2-of-4 FROST system')
        const keyGen = generateKeys(config.value)
        debug('keygen result', keyGen)
        keyGenResult.value = keyGen

        // Name the participants and store backup shards
        // (take 2 out of 4 for recovery)
        const [aliceKey, bobKey, carolKey, desmondKey] = keyGen.keyPackages
        shards.bob.value = bobKey
        shards.carol.value = carolKey
        shards.desmond.value = desmondKey
        shards.alice.value = aliceKey
        console.log('   - Create the key shards.')

        currentStep.value = 'Shards created successfully'
        frostExists.value = true

        console.log('\\nShards created! Key pieces have been distributed to' +
            ' 2 trusted participants.')
    } catch (error) {
        console.error('FROST backup failed:', error)
        errorMessage.value = error instanceof Error ?
            error.message :
            'Unknown error'
        currentStep.value = 'backup failed'
    } finally {
        isRunning.value = false
    }
}
