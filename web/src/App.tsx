import { Component, useState, type ReactNode } from 'react'
import { InscribeWizard } from './components/InscribeWizard'
import { TransactionHistory } from './components/TransactionHistory'

// ── Error boundary to surface crashes instead of blank screen ────────────────
class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="max-w-2xl mx-auto px-6 py-16">
          <div className="bg-red-900/30 border border-red-700 rounded-2xl p-6 space-y-4">
            <h2 className="text-red-300 font-bold text-lg">Something went wrong</h2>
            <pre className="text-red-200 text-xs font-mono whitespace-pre-wrap break-all bg-black/30 rounded-lg p-4">
              {(this.state.error as Error).message}
              {'\n\n'}
              {(this.state.error as Error).stack}
            </pre>
            <button
              onClick={() => this.setState({ error: null })}
              className="px-4 py-2 rounded-lg bg-red-800 text-red-100 text-sm hover:bg-red-700 transition-colors"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

// ── App ───────────────────────────────────────────────────────────────────────
type Network = 'mainnet' | 'testnet' | 'testnet4'

function NetworkBadge({ network }: { network: Network | null }) {
  if (!network || network === 'mainnet') return null
  return (
    <span className="px-2 py-1 rounded-lg bg-blue-900/40 border border-blue-700 text-blue-300 text-xs font-mono">
      {network}
    </span>
  )
}

export function App() {
  const [tab, setTab] = useState<'inscribe' | 'history'>('inscribe')
  const [network, setNetwork] = useState<Network | null>(null)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-bitcoin flex items-center justify-center text-black font-bold text-sm">
              ₿
            </div>
            <div>
              <h1 className="font-bold text-gray-100 leading-none">sliprun</h1>
              <p className="text-xs text-gray-500 leading-none mt-0.5">
                Bitcoin Ordinal Inscriptions
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <NetworkBadge network={network} />
            <a
              href="https://slipstream.mara.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              Powered by Slipstream ↗
            </a>
          </div>
        </div>

        <div className="max-w-2xl mx-auto mt-4 flex gap-1">
          {(['inscribe', 'history'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors capitalize ${
                tab === t
                  ? 'bg-gray-800 text-gray-100'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {t === 'history' ? 'History' : 'Inscribe'}
            </button>
          ))}
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-6 py-8">
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-xl">
          <ErrorBoundary>
            {tab === 'inscribe' ? <InscribeWizard onNetworkDetected={setNetwork} /> : <TransactionHistory />}
          </ErrorBoundary>
        </div>
      </main>

      <footer className="text-center text-xs text-gray-700 pb-8">
        <p>Transactions are signed locally. Private keys never leave your device.</p>
        <p className="mt-1">
          <a
            href="https://github.com/ManjulShah/sliprun"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-gray-500 transition-colors"
          >
            github.com/ManjulShah/sliprun
          </a>
        </p>
      </footer>
    </div>
  )
}
