import { secp256k1 } from '@noble/curves/secp256k1'

export interface EphemeralKeypair {
  privKey: Uint8Array
  pubKeyX: Uint8Array // 32-byte x-only public key
}

export function generateEphemeralKeypair(): EphemeralKeypair {
  const privKey = secp256k1.utils.randomPrivateKey()
  const pubKeyFull = secp256k1.getPublicKey(privKey, true) // compressed 33 bytes
  const pubKeyX = pubKeyFull.slice(1) // drop 02/03 prefix → 32 bytes
  return { privKey, pubKeyX }
}

export function zeroKey(key: Uint8Array): void {
  key.fill(0)
}
