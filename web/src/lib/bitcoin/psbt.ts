import * as btc from '@scure/btc-signer'
import { hex, base64 } from '@scure/base'
import type { UTXO } from '../../types/wallet'
import { DUST_LIMIT } from './fees'

/**
 * Derive the scriptPubKey from a Bitcoin address.
 * Used when the wallet doesn't provide scriptPk with UTXOs (e.g. Xverse).
 */
export function scriptFromAddress(address: string, network: typeof btc.NETWORK): Uint8Array {
  const decoded = btc.Address(network).decode(address)
  return btc.OutScript.encode(decoded)
}

/**
 * Build an unsigned commit PSBT for wallet signing.
 *
 * The commit tx spends a P2WPKH (or P2TR) UTXO from the user's wallet and creates:
 *   - output 0: P2TR inscription address (commitOutputAmount sats)
 *   - output 1: change back to sender (if above dust)
 *
 * Returns PSBT as hex string (wallet adapters convert to base64 as needed).
 */
export function buildCommitPsbtFull(params: {
  utxo: UTXO
  inscriptionScript: Uint8Array
  commitOutputAmount: number  // sats
  commitFee: number           // sats
  changeAddress: string
  network: typeof btc.NETWORK
}): string {
  const { utxo, inscriptionScript, commitOutputAmount, commitFee, changeAddress, network } = params

  const utxoScript = utxo.scriptPk
    ? hex.decode(utxo.scriptPk)
    : scriptFromAddress(utxo.address, network)

  const changeAmount = utxo.satoshis - commitOutputAmount - commitFee

  const tx = new btc.Transaction()

  tx.addInput({
    txid: utxo.txid,
    index: utxo.vout,
    witnessUtxo: {
      script: utxoScript,
      amount: BigInt(utxo.satoshis),
    },
    sequence: 0xFFFFFFFD, // signal RBF (BIP125) so retries with higher fee are allowed
  })

  tx.addOutput({ script: inscriptionScript, amount: BigInt(commitOutputAmount) })

  if (changeAmount >= DUST_LIMIT && changeAddress) {
    const changeScript = scriptFromAddress(changeAddress, network)
    tx.addOutput({ script: changeScript, amount: BigInt(changeAmount) })
  }

  return hex.encode(tx.toPSBT())
}

export function psbtHexToBase64(psbtHex: string): string {
  return base64.encode(hex.decode(psbtHex))
}

export function psbtBase64ToHex(psbtBase64: string): string {
  return hex.encode(base64.decode(psbtBase64))
}

/**
 * Extract the raw signed transaction hex from a signed PSBT.
 *
 * Wallets differ in what they return:
 * - Unisat (autoFinalized:true): returns a PSBT with PSBT_IN_FINAL_SCRIPTWITNESS already set
 *   — calling finalize() again would fail with "Not enough partial sign"
 * - Xverse / Leather: returns a partially-signed PSBT that still needs finalize()
 *
 * Strategy: try extract() first (works if wallet already finalized), then fall back
 * to finalize() + extract() for partially-signed PSBTs.
 */
export function extractSignedTxFromPsbt(signedPsbtHex: string): string {
  const psbtBytes = hex.decode(signedPsbtHex)
  const tx = btc.Transaction.fromPSBT(psbtBytes)
  try {
    // Already finalized by wallet (Unisat autoFinalized:true)
    return hex.encode(tx.extract())
  } catch {
    // Partially signed — finalize ourselves (Xverse, Leather)
    tx.finalize()
    return hex.encode(tx.extract())
  }
}
