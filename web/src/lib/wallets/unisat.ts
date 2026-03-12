import type { WalletAdapter, WalletState, UTXO, InputToSign, Network } from '../../types/wallet'
import { fetchUTXOs } from './mempool'

interface UnisatWindow {
  unisat: {
    requestAccounts(): Promise<string[]>
    getPublicKey(): Promise<string>
    getNetwork(): Promise<string>
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
}

declare const window: Window & UnisatWindow

export class UnisatAdapter implements WalletAdapter {
  name = 'Unisat'
  private network: Network = 'mainnet'

  async connect(): Promise<WalletState> {
    if (!window.unisat) throw new Error('Unisat wallet not found')
    const accounts = await window.unisat.requestAccounts()
    if (!accounts.length) throw new Error('No accounts returned from Unisat')
    const publicKey = await window.unisat.getPublicKey()
    const networkStr = await window.unisat.getNetwork().then((s) => s.toLowerCase())
    this.network = networkStr.includes('testnet4') ? 'testnet4'
      : networkStr.includes('testnet') ? 'testnet'
      : 'mainnet'
    const address = accounts[0]
    // If the active account is taproot (bc1p/tb1p), it's already the ordinals address
    const isTaproot = address.startsWith('bc1p') || address.startsWith('tb1p')
    return {
      address,
      ordinalsAddress: isTaproot ? address : undefined,
      publicKey,
      network: this.network,
    }
  }

  async getUTXOs(address: string): Promise<UTXO[]> {
    return fetchUTXOs(address, this.network)
  }

  async signPsbt(psbtHex: string, inputsToSign: InputToSign[]): Promise<string> {
    if (!window.unisat) throw new Error('Unisat wallet not found')
    return window.unisat.signPsbt(psbtHex, {
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
