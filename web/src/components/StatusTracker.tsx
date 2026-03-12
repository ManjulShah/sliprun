import { useState, useEffect, useCallback } from 'react'
import { getTransactionStatus, type TxStatus } from '../lib/slipstream'

type Network = 'mainnet' | 'testnet' | 'testnet4'

interface Props {
  commitTxid: string
  revealTxid: string
  network: Network
}

function explorerUrl(txid: string, network: Network): string {
  const base = network === 'mainnet' ? 'https://mempool.space' : 'https://mempool.space/testnet4'
  return `${base}/tx/${txid}`
}

function slipstreamStatusUrl(txid: string, network: Network): string {
  const base = network === 'mainnet' ? 'https://slipstream.mara.com' : 'https://testnet-slipstream.mara.com'
  return `${base}/status?txid=${txid}`
}

function ordinalsUrl(revealTxid: string, network: Network): string {
  // Inscription ID = revealTxid + "i0" (index of inscription in the reveal tx)
  const inscriptionId = `${revealTxid}i0`
  const base = network === 'mainnet' ? 'https://ordinals.com' : 'https://testnet.ordinals.com'
  return `${base}/inscription/${inscriptionId}`
}

function StatusBadge({ status }: { status?: string }) {
  const s = status?.toLowerCase() ?? ''
  if (s.includes('confirmed') || s.includes('mined')) {
    return <span className="px-2 py-1 rounded bg-green-900/40 text-green-400 border border-green-800 text-xs">{status}</span>
  }
  if (s.includes('mempool') || s.includes('pending') || s.includes('broadcast')) {
    return <span className="px-2 py-1 rounded bg-yellow-900/40 text-yellow-400 border border-yellow-800 text-xs">{status}</span>
  }
  if (s.includes('error') || s.includes('failed')) {
    return <span className="px-2 py-1 rounded bg-red-900/40 text-red-400 border border-red-800 text-xs">{status}</span>
  }
  return <span className="px-2 py-1 rounded bg-gray-800 text-gray-400 border border-gray-700 text-xs">{status ?? 'unknown'}</span>
}

export function StatusTracker({ commitTxid, revealTxid, network }: Props) {
  const [commitStatus, setCommitStatus] = useState<TxStatus | null>(null)
  const [revealStatus, setRevealStatus] = useState<TxStatus | null>(null)
  const [countdown, setCountdown] = useState(30)
  const [error, setError] = useState<string | null>(null)

  const fetchStatus = useCallback(async () => {
    setError(null)
    try {
      const [cs, rs] = await Promise.allSettled([
        getTransactionStatus(commitTxid, network),
        getTransactionStatus(revealTxid, network),
      ])
      if (cs.status === 'fulfilled') setCommitStatus(cs.value)
      if (rs.status === 'fulfilled') setRevealStatus(rs.value)
      setCountdown(30)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Status check failed')
    }
  }, [commitTxid, revealTxid])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          fetchStatus()
          return 30
        }
        return c - 1
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-400">Auto-refreshing every 30s</span>
        <div className="flex items-center gap-2">
          <span className="text-gray-500 font-mono text-xs">next in {countdown}s</span>
          <button
            onClick={fetchStatus}
            className="px-3 py-1 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 text-xs hover:border-gray-500 transition-colors"
          >
            Refresh now
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-yellow-900/30 border border-yellow-800 text-yellow-300 text-sm">
          {error}
        </div>
      )}

      {[
        { label: 'Commit tx', txid: commitTxid, status: commitStatus },
        { label: 'Reveal tx', txid: revealTxid, status: revealStatus },
      ].map(({ label, txid, status }) => (
        <div key={txid} className="p-4 rounded-xl bg-gray-800 border border-gray-700 space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-gray-200">{label}</span>
            {status && <StatusBadge status={status.status} />}
          </div>

          <div className="font-mono text-xs text-gray-400 break-all">
            {txid}
          </div>

          <div className="flex gap-2">
            <a
              href={explorerUrl(txid, network)}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 text-center py-2 rounded-lg bg-gray-700 text-gray-300 text-sm hover:bg-gray-600 transition-colors"
            >
              mempool.space ↗
            </a>
            <a
              href={slipstreamStatusUrl(txid, network)}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 text-center py-2 rounded-lg bg-gray-700 text-gray-300 text-sm hover:bg-gray-600 transition-colors"
            >
              Slipstream ↗
            </a>
          </div>

          {status?.message && (
            <p className="text-xs text-gray-500">{status.message}</p>
          )}
        </div>
      ))}

      <div className="p-4 rounded-xl bg-green-900/20 border border-green-800 text-center space-y-3">
        <div className="text-2xl">🎉</div>
        <p className="text-green-300 font-semibold">Inscription submitted!</p>
        <p className="text-gray-400 text-sm">
          Your Ordinal inscription is on its way to the Bitcoin blockchain.
          Once the reveal tx is confirmed, view it on ordinals.com:
        </p>
        <a
          href={ordinalsUrl(revealTxid, network)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block px-4 py-2 rounded-lg bg-green-800/40 border border-green-700 text-green-300 text-sm hover:bg-green-700/40 transition-colors font-mono break-all"
        >
          {revealTxid}i0 ↗
        </a>
      </div>
    </div>
  )
}
