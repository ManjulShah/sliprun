import type { WalletAdapter, WalletState, UTXO, InputToSign, Network } from '../../types/wallet'

// OKX wallet injects window.okxwallet.bitcoin

interface OKXBitcoin {
  connect(): Promise<{ address: string; publicKey: string }>
  getNetwork(): Promise<string>
  getUtxos(address?: string, amount?: number): Promise<Array<{
    txid: string
    vout: number
    satoshis: number
    scriptPk: string
    addressType?: string
  }>>
  signPsbt(
    psbtHex: string,
    options?: {
      autoFinalized?: boolean
      toSignInputs?: Array<{
        index: number
        address?: string
        publicKey?: string
        disableTweakSigner?: boolean
      }>
    }
  ): Promise<string>
}

interface OKXWindow {
  okxwallet?: {
    bitcoin: OKXBitcoin
    bitcoinTestnet?: OKXBitcoin
  }
}

declare const window: Window & OKXWindow

export class OKXAdapter implements WalletAdapter {
  name = 'OKX'
  private network: Network = 'mainnet'

  private get btc(): OKXBitcoin {
    if (!window.okxwallet) throw new Error('OKX wallet not found')
    return this.network === 'testnet' && window.okxwallet.bitcoinTestnet
      ? window.okxwallet.bitcoinTestnet
      : window.okxwallet.bitcoin
  }

  async connect(): Promise<WalletState> {
    if (!window.okxwallet) throw new Error('OKX wallet not found')
    const { address, publicKey } = await window.okxwallet.bitcoin.connect()
    const networkStr = await window.okxwallet.bitcoin.getNetwork()
    const n = networkStr.toLowerCase()
    this.network = n.includes('testnet4') ? 'testnet4' : n.includes('test') ? 'testnet' : 'mainnet'
    const isTaproot = address.startsWith('bc1p') || address.startsWith('tb1p')
    return { address, ordinalsAddress: isTaproot ? address : undefined, publicKey, network: this.network }
  }

  async getUTXOs(_address: string): Promise<UTXO[]> {
    const raw = await this.btc.getUtxos(_address)
    return raw.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      satoshis: u.satoshis,
      address: _address,
      scriptPk: u.scriptPk,
    }))
  }

  async signPsbt(psbtHex: string, inputsToSign: InputToSign[]): Promise<string> {
    return this.btc.signPsbt(psbtHex, {
      autoFinalized: true,
      toSignInputs: inputsToSign.map((i) => ({
        index: i.index,
        address: i.address,
        publicKey: i.publicKey,
        disableTweakSigner: i.disableTweakSigner,
      })),
    })
  }
}
