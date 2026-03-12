import { useState, useEffect } from 'react'
import type { UTXO, WalletAdapter } from '../types/wallet'

interface Props {
  adapter: WalletAdapter
  address: string
  minSatoshis: number
  onUTXOSelected: (utxo: UTXO) => void
}

export function UTXOSelector({ adapter, address, minSatoshis, onUTXOSelected }: Props) {
  const [utxos, setUtxos] = useState<UTXO[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    adapter
      .getUTXOs(address)
      .then((list) => {
        // Sort: sufficient+confirmed first, then by value desc
        const sorted = [...list].sort((a, b) => {
          const aOk = a.satoshis >= minSatoshis
          const bOk = b.satoshis >= minSatoshis
          if (aOk !== bOk) return bOk ? 1 : -1
          return b.satoshis - a.satoshis
        })
        setUtxos(sorted)
        setLoading(false)
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load UTXOs')
        setLoading(false)
      })
  }, [adapter, address])

  function handleSelect(utxo: UTXO) {
    const key = `${utxo.txid}:${utxo.vout}`
    setSelected(key)
    onUTXOSelected(utxo)
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-gray-400">
        <div className="w-4 h-4 border-2 border-gray-600 border-t-bitcoin rounded-full animate-spin" />
        Loading UTXOs from wallet...
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
        {error}
      </div>
    )
  }

  if (utxos.length === 0) {
    return (
      <div className="p-4 rounded-xl bg-gray-800 border border-gray-700 text-gray-400 text-sm text-center">
        No UTXOs found. Fund your wallet with at least{' '}
        <span className="text-bitcoin font-mono">{minSatoshis.toLocaleString()} sat</span>.
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <p className="text-sm text-gray-400">
        Need at least <span className="text-bitcoin font-mono">{minSatoshis.toLocaleString()} sat</span>.
        Highlighted UTXOs are sufficient.
      </p>

      <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
        {utxos.map((utxo) => {
          const key = `${utxo.txid}:${utxo.vout}`
          const sufficient = utxo.satoshis >= minSatoshis
          const isSelected = selected === key
          const confirmed = (utxo.confirmations ?? 1) > 0

          return (
            <button
              key={key}
              onClick={() => handleSelect(utxo)}
              className={`
                w-full p-3 rounded-lg border text-left transition-all
                ${isSelected
                  ? 'border-bitcoin bg-bitcoin/10'
                  : sufficient
                    ? 'border-gray-600 bg-gray-800 hover:border-gray-500'
                    : 'border-gray-800 bg-gray-900 opacity-60 hover:opacity-80'}
              `}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-xs text-gray-400 truncate">
                    {utxo.txid.slice(0, 16)}…{utxo.txid.slice(-8)}:{utxo.vout}
                  </div>
                  <div className="text-sm font-semibold mt-0.5">
                    <span className={sufficient ? 'text-bitcoin' : 'text-gray-400'}>
                      {utxo.satoshis.toLocaleString()} sat
                    </span>
                    <span className="text-gray-600 text-xs ml-1">
                      ({(utxo.satoshis / 100_000_000).toFixed(8)} BTC)
                    </span>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  {confirmed ? (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-800">
                      confirmed
                    </span>
                  ) : (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-400 border border-yellow-800">
                      unconfirmed
                    </span>
                  )}
                  {!sufficient && (
                    <span className="text-xs text-red-400">insufficient</span>
                  )}
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
