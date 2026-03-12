import { useState, useEffect } from 'react'
import { getRates } from '../lib/slipstream'
import { estimateTotalCost } from '../lib/bitcoin/fees'
import type { FeeRates } from '../types/bitcoin'

interface Props {
  contentBytes: number
  network: 'mainnet' | 'testnet' | 'testnet4'
  onFeeRateSelected: (rate: number) => void
}

const PRESET_LABELS: Record<keyof FeeRates, string> = {
  low: 'Economy',
  medium: 'Standard',
  high: 'Priority',
}

export function FeeSelector({ contentBytes, network, onFeeRateSelected }: Props) {
  const [rates, setRates] = useState<FeeRates | null>(null)
  const [selected, setSelected] = useState<keyof FeeRates | 'custom'>('medium')
  const [custom, setCustom] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const MIN_FEE_RATE = 2.1

  useEffect(() => {
    getRates(undefined, network)
      .then((r) => {
        const clamped = {
          low: Math.max(MIN_FEE_RATE, r.low),
          medium: Math.max(MIN_FEE_RATE, r.medium),
          high: Math.max(MIN_FEE_RATE, r.high),
        }
        setRates(clamped)
        setLoading(false)
        onFeeRateSelected(clamped.medium)
      })
      .catch(() => {
        setRates({ low: 2, medium: 10, high: 30 })
        setError('Could not fetch live rates — using defaults')
        setLoading(false)
        onFeeRateSelected(10)
      })
  }, [])

  function handlePreset(key: keyof FeeRates) {
    setSelected(key)
    if (rates) onFeeRateSelected(rates[key])
  }

  function handleCustom(val: string) {
    setCustom(val)
    const n = parseFloat(val)
    if (!isNaN(n) && n > 0) {
      setSelected('custom')
      onFeeRateSelected(n)
    }
  }

  const currentRate =
    selected === 'custom' ? parseFloat(custom) || 0
    : rates ? rates[selected] : 0

  const cost = contentBytes > 0 ? estimateTotalCost(contentBytes, currentRate) : null

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-gray-400">
        <div className="w-4 h-4 border-2 border-gray-600 border-t-bitcoin rounded-full animate-spin" />
        Fetching current fee rates...
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 rounded-lg bg-yellow-900/30 border border-yellow-800 text-yellow-300 text-sm">
          {error}
        </div>
      )}

      <div className="grid grid-cols-3 gap-3">
        {rates && (Object.keys(PRESET_LABELS) as (keyof FeeRates)[]).map((key) => {
          const cost = estimateTotalCost(contentBytes, rates[key])
          return (
            <button
              key={key}
              onClick={() => handlePreset(key)}
              className={`
                p-4 rounded-xl border text-left transition-all
                ${selected === key
                  ? 'border-bitcoin bg-bitcoin/10'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-500'}
              `}
            >
              <div className="font-semibold text-gray-100">{PRESET_LABELS[key]}</div>
              <div className="text-bitcoin font-mono font-bold mt-1">{rates[key]} sat/vB</div>
              {contentBytes > 0 && (
                <div className="text-xs text-gray-400 mt-1">≈ {cost.totalRequired.toLocaleString()} sat</div>
              )}
            </button>
          )
        })}
      </div>

      <div
        onClick={() => {
          if (selected !== 'custom') {
            const init = rates ? String(rates.medium) : '10'
            setCustom((c) => c || init)
            setSelected('custom')
            const n = parseFloat(custom || init)
            if (!isNaN(n) && n > 0) onFeeRateSelected(n)
          }
        }}
        className={`
          p-4 rounded-xl border transition-all cursor-pointer
          ${selected === 'custom'
            ? 'border-bitcoin bg-bitcoin/10'
            : 'border-gray-700 bg-gray-800 hover:border-gray-500'}
        `}
      >
        <div className="font-semibold text-gray-100 mb-2">Custom</div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); handleCustom(String(Math.max(2, (parseFloat(custom) || 0) - 1))) }}
            className="w-8 h-8 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-200 font-bold text-lg flex items-center justify-center shrink-0"
          >−</button>
          <input
            type="number"
            min="2.1"
            step="1"
            value={custom}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => handleCustom(e.target.value)}
            placeholder={rates ? String(rates.medium) : '10'}
            className="flex-1 min-w-0 px-2 py-1 rounded-lg bg-gray-900 border border-gray-600 text-gray-100 text-sm font-mono text-center focus:outline-none focus:border-bitcoin"
          />
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); handleCustom(String((parseFloat(custom) || 0) + 1)) }}
            className="w-8 h-8 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-200 font-bold text-lg flex items-center justify-center shrink-0"
          >+</button>
          <span className="text-gray-400 text-xs shrink-0">sat/vB</span>
        </div>
        {selected === 'custom' && custom && contentBytes > 0 && (
          <div className="text-xs text-gray-400 mt-2">
            ≈ {estimateTotalCost(contentBytes, parseFloat(custom) || 0).totalRequired.toLocaleString()} sat
          </div>
        )}
      </div>

      {cost && currentRate > 0 && (
        <div className="p-4 rounded-xl bg-gray-800 border border-gray-700 text-sm space-y-1">
          <div className="text-gray-400 mb-2">Cost at {currentRate} sat/vB:</div>
          <div className="flex justify-between">
            <span className="text-gray-400">Commit fee (154 vB)</span>
            <span className="text-gray-200">{cost.commitFee.toLocaleString()} sat</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Reveal fee ({105 + Math.floor(contentBytes/4)} vB)</span>
            <span className="text-gray-200">{cost.revealFee.toLocaleString()} sat</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Dust (546 sat)</span>
            <span className="text-gray-200">546 sat</span>
          </div>
          <hr className="border-gray-700 my-1" />
          <div className="flex justify-between font-semibold">
            <span className="text-gray-300">Total UTXO needed</span>
            <span className="text-bitcoin">{cost.totalRequired.toLocaleString()} sat</span>
          </div>
        </div>
      )}
    </div>
  )
}
