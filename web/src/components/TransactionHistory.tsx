import { useState } from 'react'
import { loadHistory, deleteHistoryEntry, type HistoryEntry } from '../lib/history'

type Network = 'mainnet' | 'testnet' | 'testnet4'

function explorerUrl(txid: string, network: Network) {
  const base = network === 'mainnet' ? 'https://mempool.space' : 'https://mempool.space/testnet4'
  return `${base}/tx/${txid}`
}

function ordinalsUrl(revealTxid: string, network: Network) {
  const base = network === 'mainnet' ? 'https://ordinals.com' : 'https://testnet.ordinals.com'
  return `${base}/inscription/${revealTxid}i0`
}

function formatDate(ts: number) {
  return new Date(ts).toLocaleString()
}

export function TransactionHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>(() => loadHistory())

  function handleDelete(id: string) {
    deleteHistoryEntry(id)
    setEntries(loadHistory())
  }

  if (entries.length === 0) {
    return (
      <div className="text-center py-16 text-gray-500">
        <p className="text-4xl mb-4">📭</p>
        <p>No inscriptions yet. Submit one and it'll appear here.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-500">
        {entries.length} inscription{entries.length !== 1 ? 's' : ''} — stored locally in your browser
      </p>

      {entries.map((entry) => (
        <div key={entry.id} className="p-4 rounded-xl bg-gray-800 border border-gray-700 space-y-3 text-sm">
          <div className="flex items-start justify-between gap-2">
            <div className="space-y-0.5">
              <div className="font-mono text-xs text-gray-400">{formatDate(entry.timestamp)}</div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 rounded bg-gray-700 text-gray-300 text-xs font-mono">{entry.contentType}</span>
                <span className="text-gray-500 text-xs">{(entry.contentBytes / 1024).toFixed(1)} KB</span>
                <span className={`px-2 py-0.5 rounded text-xs ${entry.network === 'mainnet' ? 'bg-bitcoin/20 text-bitcoin' : 'bg-blue-900/40 text-blue-400'}`} title={entry.network}>
                  {entry.network}
                </span>
              </div>
            </div>
            <button
              onClick={() => handleDelete(entry.id)}
              className="text-gray-600 hover:text-red-400 text-xs transition-colors shrink-0"
              title="Remove from history"
            >
              ✕
            </button>
          </div>

          <div className="space-y-1">
            {[
              { label: 'Commit', txid: entry.commitTxid },
              { label: 'Reveal', txid: entry.revealTxid },
            ].map(({ label, txid }) => (
              <div key={label} className="flex items-center gap-2">
                <span className="text-gray-500 text-xs w-12 shrink-0">{label}</span>
                <span className="font-mono text-xs text-gray-400 truncate flex-1">{txid}</span>
              </div>
            ))}
          </div>

          <div className="flex gap-2 flex-wrap">
            <a href={explorerUrl(entry.revealTxid, entry.network)} target="_blank" rel="noopener noreferrer"
              className="px-3 py-1.5 rounded-lg bg-gray-700 text-gray-300 text-xs hover:bg-gray-600 transition-colors">
              mempool.space ↗
            </a>
            <a href={ordinalsUrl(entry.revealTxid, entry.network)} target="_blank" rel="noopener noreferrer"
              className="px-3 py-1.5 rounded-lg bg-bitcoin/20 text-bitcoin text-xs hover:bg-bitcoin/30 transition-colors">
              ordinals.com ↗
            </a>
          </div>
        </div>
      ))}
    </div>
  )
}
