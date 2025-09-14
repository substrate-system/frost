/**
 * Core types and interfaces for FROST implementation
 */

export interface ParticipantId {
    readonly id:number
}

export interface Scalar {
    readonly value:Uint8Array
}

export interface GroupElement {
    readonly point:Uint8Array
}

export interface NonceCommitment {
    readonly hiding:GroupElement
    readonly binding:GroupElement
}

export interface Nonces {
    readonly hiding:Scalar
    readonly binding:Scalar
}

export interface CommitmentShare {
    readonly participantId:ParticipantId
    readonly commitment:NonceCommitment
}

export interface KeyShare {
    readonly participantId:ParticipantId
    readonly privateShare:Scalar
    readonly publicShare:GroupElement
}

export interface SignatureShare {
    readonly participantId:ParticipantId
    readonly share:Scalar
}

export interface GroupCommitment {
    readonly commitment:GroupElement
    readonly bindingFactors:Map<number, Scalar>
}

export interface FrostSignature {
    readonly R:GroupElement
    readonly z:Scalar
}

export interface KeyPackage {
    readonly participantId:ParticipantId
    readonly keyShare:KeyShare
    readonly verificationKey:GroupElement
    readonly signingCommitments:NonceCommitment[]
}

export interface SigningPackage {
    readonly participantIds:ParticipantId[]
    readonly message:Uint8Array
    readonly groupCommitment:GroupCommitment
}

export interface RoundOneOutputs {
    readonly nonces:Nonces
    readonly commitment:NonceCommitment
}

export interface RoundTwoOutputs {
    readonly signatureShare:SignatureShare
}

export interface TrustedDealerOutput {
    readonly groupPublicKey:GroupElement
    readonly keyPackages:KeyPackage[]
}

export interface CipherSuite {
    readonly name:string
    readonly scalarSize:number
    readonly elementSize:number
    readonly hashToScalar:(data:Uint8Array) => Scalar
    readonly scalarMultiply:(scalar:Scalar, element:GroupElement) => GroupElement
    readonly scalarAdd:(a:Scalar, b:Scalar) => Scalar
    readonly scalarNegate:(scalar:Scalar) => Scalar
    readonly elementAdd:(a:GroupElement, b:GroupElement) => GroupElement
    readonly randomScalar:() => Scalar
    readonly baseElement:() => GroupElement
    readonly elementToBytes:(element:GroupElement) => Uint8Array
    readonly scalarToBytes:(scalar:Scalar) => Uint8Array
    readonly bytesToScalar:(bytes:Uint8Array) => Scalar
    readonly bytesToElement:(bytes:Uint8Array) => GroupElement
}

export interface FrostConfig {
    readonly minSigners:number
    readonly maxSigners:number
    readonly cipherSuite:CipherSuite
}
