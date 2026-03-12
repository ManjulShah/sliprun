import * as btc from '@scure/btc-signer'
import { hex } from '@scure/base'
import { OutOrdinalReveal } from 'micro-ordinals'
import { DUST_LIMIT } from './fees'
import { scriptFromAddress } from './psbt'
import type { InscriptionPayment } from './inscription'

/**
 * Build and sign the reveal transaction using the ephemeral private key.
 *
 * The reveal tx spends the P2TR inscription output (commit output 0) via
 * script path, embedding the inscription in the witness.
 *
 * Returns the signed raw transaction hex.
 */
export function buildAndSignReveal(params: {
  privKey: Uint8Array
  pubKeyX: Uint8Array
  payment: InscriptionPayment
  commitTxHex: string     // signed commit tx hex (after wallet signs)
  commitVout?: number     // which output in commit tx is the inscription (default 0)
  commitOutputAmount: number  // sats in the commit output
  revealFee: number
  recipient: string
  network: typeof btc.NETWORK
}): string {
  const {
    privKey,
    pubKeyX: _pubKeyX,
    payment,
    commitTxHex,
    commitVout = 0,
    commitOutputAmount,
    revealFee,
    recipient,
    network,
  } = params

  const revealAmount = commitOutputAmount - revealFee
  if (revealAmount < DUST_LIMIT) {
    throw new Error(
      `Reveal output (${revealAmount} sat) would be below dust limit (${DUST_LIMIT} sat). ` +
      `Increase UTXO value or lower fee rate.`
    )
  }

  // Parse the commit tx to extract its txid
  const commitTxBytes = hex.decode(commitTxHex)
  const commitTx = btc.Transaction.fromRaw(commitTxBytes, { allowUnknownOutputs: true })
  const commitTxid = commitTx.id

  const recipientScript = scriptFromAddress(recipient, network)

  const revealTx = new btc.Transaction({ customScripts: [OutOrdinalReveal] })

  revealTx.addInput({
    txid: commitTxid,
    index: commitVout,
    witnessUtxo: {
      script: payment.script,
      amount: BigInt(commitOutputAmount),
    },
    sequence: 0xFFFFFFFD, // signal RBF (BIP125) so fee can be bumped if stuck
    // Do NOT set tapInternalKey here.
    // When tapInternalKey == schnorrPub and tapMerkleRoot is absent, btc-signer tweaks
    // privKey with an empty merkle root and sets tapKeySig (key-path spend).
    // During finalization tapKeySig takes priority over tapLeafScript, producing a witness
    // signed against tweak(pubKeyX, empty) — but the commit output key was tweaked with
    // the real merkle root, so Bitcoin Core rejects it as "Invalid Schnorr signature".
    // The control block inside tapLeafScript already carries the internal key; btc-signer
    // only needs tapLeafScript to sign and finalize the script-path spend correctly.
    tapLeafScript: payment.tapLeafScript as Parameters<typeof revealTx.addInput>[0]['tapLeafScript'],
  })

  revealTx.addOutput({
    script: recipientScript,
    amount: BigInt(revealAmount),
  })

  revealTx.sign(privKey)
  revealTx.finalize()

  return hex.encode(revealTx.extract())
}
