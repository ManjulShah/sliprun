import type { WalletAdapter, WalletType } from '../../types/wallet'
import { UnisatAdapter } from './unisat'
import { XverseAdapter, XVERSE_PROVIDER_ID } from './xverse'
import { LeatherAdapter } from './leather'
import { OKXAdapter } from './okx'

interface WalletDetection {
  type: WalletType
  name: string
  icon: string
  available: boolean
}

// sats-connect v4 registers providers in window.btc_providers
// Each provider has an `id` field matching the path in window (e.g. "XverseProviders.BitcoinProvider")
function isSatsConnectProviderInstalled(providerId: string): boolean {
  const w = window as unknown as {
    btc_providers?: Array<{ id: string }>
    XverseProviders?: { BitcoinProvider?: unknown }
  }

  // Check the btc_providers registry first (sats-connect v4 standard)
  if (w.btc_providers?.some((p) => p.id === providerId)) return true

  // Fallback: check window.XverseProviders.BitcoinProvider directly
  if (providerId === XVERSE_PROVIDER_ID && w.XverseProviders?.BitcoinProvider) return true

  return false
}

export function detectAvailableWallets(): WalletDetection[] {
  const w = window as unknown as Record<string, unknown>
  return [
    {
      type: 'unisat',
      name: 'Unisat',
      icon: '🟠',
      available: !!(w.unisat),
    },
    {
      type: 'xverse',
      name: 'Xverse',
      icon: '✕',
      available: isSatsConnectProviderInstalled(XVERSE_PROVIDER_ID),
    },
    {
      type: 'leather',
      name: 'Leather',
      icon: '🟤',
      available: !!(w.btc || w.leather),
    },
    {
      type: 'okx',
      name: 'OKX',
      icon: '⬛',
      available: !!(w.okxwallet && (w.okxwallet as Record<string, unknown>).bitcoin),
    },
  ]
}

export function createAdapter(type: WalletType): WalletAdapter {
  switch (type) {
    case 'unisat':
      return new UnisatAdapter()
    case 'xverse':
      return new XverseAdapter()
    case 'leather':
      return new LeatherAdapter()
    case 'okx':
      return new OKXAdapter()
    default:
      throw new Error(`Unknown wallet type: ${type}`)
  }
}

export { UnisatAdapter, XverseAdapter, LeatherAdapter, OKXAdapter }
