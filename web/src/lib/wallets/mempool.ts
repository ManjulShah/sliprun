import type { Network } from '../../types/wallet'

export interface MempoolUTXO {
  txid: string
  vout: number
  status: { confirmed: boolean; block_height?: number }
  value: number
}

export function mempoolBase(network: Network): string {
  // Both 'testnet' and 'testnet4' map to testnet4 — testnet3 is effectively retired
  if (network === 'testnet' || network === 'testnet4') return 'https://mempool.space/testnet4/api'
  return 'https://mempool.space/api'
}

export async function fetchUTXOs(address: string, network: Network) {
  const resp = await fetch(`${mempoolBase(network)}/address/${address}/utxo`)
  if (!resp.ok) throw new Error(`Failed to fetch UTXOs: ${resp.statusText}`)
  const raw: MempoolUTXO[] = await resp.json()
  return raw.map((u) => ({
    txid: u.txid,
    vout: u.vout,
    satoshis: u.value,
    address,
    confirmations: u.status.confirmed ? (u.status.block_height ?? 1) : 0,
  }))
}
