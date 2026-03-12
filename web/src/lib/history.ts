const STORAGE_KEY = 'sliprun_history'

export interface HistoryEntry {
  id: string
  timestamp: number
  network: 'mainnet' | 'testnet' | 'testnet4'
  commitTxid: string
  revealTxid: string
  inscriptionAddress: string
  contentType: string
  contentBytes: number
}

export function loadHistory(): HistoryEntry[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]')
  } catch {
    return []
  }
}

export function saveHistoryEntry(entry: Omit<HistoryEntry, 'id' | 'timestamp'>): HistoryEntry {
  const full: HistoryEntry = {
    ...entry,
    id: Math.random().toString(36).slice(2),
    timestamp: Date.now(),
  }
  const history = loadHistory()
  localStorage.setItem(STORAGE_KEY, JSON.stringify([full, ...history]))
  return full
}

export function deleteHistoryEntry(id: string): void {
  const history = loadHistory().filter((e) => e.id !== id)
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history))
}
