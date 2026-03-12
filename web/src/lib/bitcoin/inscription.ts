import * as btc from '@scure/btc-signer'
import { p2tr_ord_reveal, OutOrdinalReveal } from 'micro-ordinals'

export { OutOrdinalReveal }

// P2TR_TREE is not re-exported from the main @scure/btc-signer index,
// so we derive the return type from btc.p2tr directly.
type P2TROut = ReturnType<typeof btc.p2tr>

export type InscriptionPayment = P2TROut & {
  address: string
  tapLeafScript: NonNullable<P2TROut['tapLeafScript']>
}

/**
 * Build the P2TR commit output for an Ordinal inscription.
 *
 * micro-ordinals v0.3 p2tr_ord_reveal() returns only { type, script } where
 * `script` is the raw tapscript leaf (not the P2TR wrapper). We then call
 * btc.p2tr() ourselves to get the full output including tapLeafScript, address,
 * etc., which are needed to build and sign the reveal transaction.
 */
export function buildInscriptionPayment(
  pubKeyX: Uint8Array,
  contentType: string,
  content: Uint8Array,
  network: typeof btc.NETWORK
): InscriptionPayment {
  // Returns { type: 'tr', script: leafScript } — the raw tapscript leaf
  const { script: leafScript } = p2tr_ord_reveal(pubKeyX, [
    { tags: { contentType }, body: content },
  ])

  // Build the full P2TR output: tweaks the internal key, computes merkle root,
  // and generates tapLeafScript for script-path spending.
  // tweaked=false (default) so btc-signer derives outputKey = tweak(pubKeyX, merkle_root),
  // which is required for the control block in the reveal tx to verify correctly.
  const p2trOut = btc.p2tr(pubKeyX, { script: leafScript }, network, false, [
    OutOrdinalReveal,
  ])

  if (!p2trOut.tapLeafScript || !p2trOut.address) {
    throw new Error(
      'btc.p2tr did not return expected tapLeafScript/address. ' +
        'Check that micro-ordinals and @scure/btc-signer versions are compatible.'
    )
  }

  return p2trOut as InscriptionPayment
}

export function getBtcNetwork(network: 'mainnet' | 'testnet'): typeof btc.NETWORK {
  return network === 'mainnet' ? btc.NETWORK : btc.TEST_NETWORK
}
