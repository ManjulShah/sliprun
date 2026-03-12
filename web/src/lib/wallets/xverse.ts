import type { WalletAdapter, WalletState, UTXO, InputToSign, Network } from '../../types/wallet'
import { psbtHexToBase64, psbtBase64ToHex } from '../bitcoin/psbt'
import { request, AddressPurpose } from 'sats-connect'
import { fetchUTXOs } from './mempool'

// Xverse provider ID (registered in window.btc_providers by the extension)
export const XVERSE_PROVIDER_ID = 'XverseProviders.BitcoinProvider'

export class XverseAdapter implements WalletAdapter {
  name = 'Xverse'
  private network: Network = 'mainnet'

  async connect(): Promise<WalletState> {
    // Try Payment + Ordinals first; fall back to Payment-only if Xverse rejects the Ordinals purpose
    let resp = await request(
      'getAddresses',
      { purposes: [AddressPurpose.Payment, AddressPurpose.Ordinals] },
      XVERSE_PROVIDER_ID
    )

    if (resp.status !== 'success') {
      resp = await request(
        'getAddresses',
        { purposes: [AddressPurpose.Payment] },
        XVERSE_PROVIDER_ID
      )
    }

    if (resp.status !== 'success') {
      const err = (resp as { status: 'error'; error: { code: number; message: string } }).error
      throw new Error(
        err?.message
          ? `Xverse: ${err.message} (code ${err.code})`
          : 'Xverse connection failed or was cancelled'
      )
    }

    const addresses = resp.result.addresses
    const paymentAddr = addresses.find((a) => a.purpose === AddressPurpose.Payment)
    const ordinalsAddr = addresses.find((a) => a.purpose === AddressPurpose.Ordinals)

    if (!paymentAddr) throw new Error('No payment address returned from Xverse')

    const addr = paymentAddr.address
    const isTestnet = addr.startsWith('tb1') || addr.startsWith('m') || addr.startsWith('n') || addr.startsWith('2')
    this.network = isTestnet ? 'testnet4' : 'mainnet'

    return {
      address: paymentAddr.address,
      ordinalsAddress: ordinalsAddr?.address,
      publicKey: paymentAddr.publicKey,
      network: this.network,
    }
  }

  async getUTXOs(address: string): Promise<UTXO[]> {
    return fetchUTXOs(address, this.network)
  }

  async signPsbt(psbtHex: string, inputsToSign: InputToSign[]): Promise<string> {
    // Xverse expects base64 PSBT
    const psbtBase64 = psbtHexToBase64(psbtHex)

    // Build signInputs map: { address: [inputIndex, ...] }
    const signInputs: Record<string, number[]> = {}
    for (const input of inputsToSign) {
      if (input.address) {
        if (!signInputs[input.address]) signInputs[input.address] = []
        signInputs[input.address].push(input.index)
      }
    }

    const response = await request(
      'signPsbt',
      { psbt: psbtBase64, signInputs, broadcast: false },
      XVERSE_PROVIDER_ID
    )

    if (response.status !== 'success') {
      const err = (response as { status: 'error'; error: { code: number; message: string } }).error
      throw new Error(
        err?.message
          ? `Xverse sign failed: ${err.message} (code ${err.code})`
          : 'Xverse PSBT signing failed or was cancelled'
      )
    }

    return psbtBase64ToHex(response.result.psbt)
  }
}
