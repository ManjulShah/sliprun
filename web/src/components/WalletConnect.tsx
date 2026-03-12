import { useState } from 'react'
import type { WalletAdapter, WalletState, WalletType } from '../types/wallet'
import { detectAvailableWallets, createAdapter } from '../lib/wallets/index'

interface Props {
  onConnected: (adapter: WalletAdapter, state: WalletState) => void
}

export function WalletConnect({ onConnected }: Props) {
  const [connecting, setConnecting] = useState<WalletType | null>(null)
  const [error, setError] = useState<string | null>(null)

  const wallets = detectAvailableWallets()

  async function handleConnect(type: WalletType) {
    setError(null)
    setConnecting(type)
    try {
      const adapter = createAdapter(type)
      const state = await adapter.connect()
      onConnected(adapter, state)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed')
    } finally {
      setConnecting(null)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-gray-400 text-sm">
        Connect your Bitcoin wallet extension to get started.
      </p>

      <div className="grid grid-cols-2 gap-3">
        {wallets.map((w) => (
          <button
            key={w.type}
            onClick={() => handleConnect(w.type)}
            disabled={!w.available || connecting !== null}
            className={`
              flex items-center gap-3 p-4 rounded-xl border transition-all
              ${w.available
                ? 'border-gray-700 bg-gray-800 hover:border-bitcoin hover:bg-gray-750 cursor-pointer'
                : 'border-gray-800 bg-gray-900 opacity-40 cursor-not-allowed'}
              ${connecting === w.type ? 'border-bitcoin animate-pulse' : ''}
            `}
          >
            <span className="text-2xl">{w.icon}</span>
            <div className="text-left">
              <div className="font-medium text-gray-100">{w.name}</div>
              <div className="text-xs text-gray-500">
                {w.available ? 'Detected' : 'Not installed'}
              </div>
            </div>
            {connecting === w.type && (
              <div className="ml-auto w-4 h-4 border-2 border-bitcoin border-t-transparent rounded-full animate-spin" />
            )}
          </button>
        ))}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      )}

      <p className="text-xs text-gray-600 text-center">
        No wallet extension? Install{' '}
        <a href="https://unisat.io" target="_blank" rel="noopener noreferrer" className="text-bitcoin hover:underline">
          Unisat
        </a>{' '}
        or{' '}
        <a href="https://xverse.app" target="_blank" rel="noopener noreferrer" className="text-bitcoin hover:underline">
          Xverse
        </a>
      </p>
    </div>
  )
}
