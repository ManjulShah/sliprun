import type { WalletAdapter, WalletState, UTXO, InputToSign, Network } from '../../types/wallet'
import { psbtBase64ToHex } from '../bitcoin/psbt'
import { fetchUTXOs } from './mempool'

// Leather (formerly Hiro) injects window.btc
// Docs: https://leather.io/developers

interface LeatherRequest {
  btc: {
    request(method: string, params?: unknown): Promise<{
      result: Record<string, unknown>
    }>
  }
}

declare const window: Window & LeatherRequest

export class LeatherAdapter implements WalletAdapter {
  name = 'Leather'
  private network: Network = 'mainnet'
  private _address = ''

  async connect(): Promise<WalletState> {
    if (!window.btc) throw new Error('Leather wallet not found')

    const resp = await window.btc.request('getAddresses', null)
    const addresses = resp.result.addresses as Array<{
      address: string
      publicKey: string
      type: string
      network?: string
    }>

    // Prefer native segwit payment address
    const paymentAddr =
      addresses.find((a) => a.type === 'p2wpkh') ??
      addresses.find((a) => a.address.startsWith('bc1q') || a.address.startsWith('tb1q')) ??
      addresses[0]

    if (!paymentAddr) throw new Error('No address returned from Leather')

    const taprootAddr =
      addresses.find((a) => a.type === 'p2tr') ??
      addresses.find((a) => a.address.startsWith('bc1p') || a.address.startsWith('tb1p'))

    const net = paymentAddr.network?.toLowerCase() ?? ''
    this.network = net.includes('testnet4') ? 'testnet4'
      : (paymentAddr.address.startsWith('tb1') || net.includes('testnet')) ? 'testnet4'
      : 'mainnet'
    this._address = paymentAddr.address

    return {
      address: paymentAddr.address,
      ordinalsAddress: taprootAddr?.address,
      publicKey: paymentAddr.publicKey,
      network: this.network,
    }
  }

  async getUTXOs(address: string): Promise<UTXO[]> {
    return fetchUTXOs(address, this.network)
  }

  async signPsbt(psbtHex: string, inputsToSign: InputToSign[]): Promise<string> {
    if (!window.btc) throw new Error('Leather wallet not found')

    // Leather expects hex PSBT and signAtIndex array
    const signAtIndex = inputsToSign.map((i) => i.index)

    const resp = await window.btc.request('signPsbt', {
      hex: psbtHex,
      signAtIndex,
      network: this.network,
      broadcast: false,
    })

    // Leather returns signed PSBT hex or base64
    const result = resp.result as { hex?: string; psbt?: string }
    if (result.hex) return result.hex
    if (result.psbt) return psbtBase64ToHex(result.psbt)
    throw new Error('Leather did not return a signed PSBT')
  }
}
