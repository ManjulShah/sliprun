import type { UTXO } from './wallet'

export interface InscriptionParams {
  contentType: string
  content: Uint8Array
  feeRate: number
  recipient: string
  utxo: UTXO
  clientCode?: string
}

export interface FeeEstimate {
  commitFee: number
  revealFee: number
  commitOutputAmount: number
  totalRequired: number
}

export interface InscriptionResult {
  commitTxHex: string
  revealTxHex: string
  commitTxid: string
  revealTxid: string
  inscriptionAddress: string
}

export interface FeeRates {
  low: number
  medium: number
  high: number
}
