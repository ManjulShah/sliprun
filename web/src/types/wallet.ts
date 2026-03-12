export interface UTXO {
  txid: string
  vout: number
  satoshis: number
  address: string
  scriptPk?: string
  confirmations?: number
}

export interface InputToSign {
  index: number
  address?: string
  publicKey?: string
  disableTweakSigner?: boolean
}

export type Network = 'mainnet' | 'testnet' | 'testnet4'

export interface WalletState {
  address: string       // payment address (P2WPKH bc1q) — used for funding UTXOs
  ordinalsAddress?: string  // taproot address (P2TR bc1p) — where inscription should land
  publicKey: string
  network: Network
}

export interface WalletAdapter {
  name: string
  connect(): Promise<WalletState>
  getUTXOs(address: string): Promise<UTXO[]>
  signPsbt(psbtHex: string, inputsToSign: InputToSign[]): Promise<string>
}

export type WalletType = 'unisat' | 'xverse' | 'leather' | 'okx'
