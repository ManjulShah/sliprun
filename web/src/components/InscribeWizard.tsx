import { useState } from 'react'
import type { WalletAdapter, WalletState, UTXO } from '../types/wallet'
import { WalletConnect } from './WalletConnect'
import { ImageUpload } from './ImageUpload'
import { FeeSelector } from './FeeSelector'
import { UTXOSelector } from './UTXOSelector'
import { StatusTracker } from './StatusTracker'
import * as btc from '@scure/btc-signer'
import { generateEphemeralKeypair, zeroKey } from '../lib/bitcoin/keys'
import { buildInscriptionPayment, getBtcNetwork } from '../lib/bitcoin/inscription'
import { buildCommitPsbtFull, extractSignedTxFromPsbt, psbtHexToBase64 } from '../lib/bitcoin/psbt'
import { buildAndSignReveal } from '../lib/bitcoin/reveal'
import { estimateTotalCost, DUST_LIMIT } from '../lib/bitcoin/fees'
import { submitPackage } from '../lib/slipstream'
import { saveHistoryEntry } from '../lib/history'
import { hex } from '@scure/base'

// ─────────────────────────────────────────────────────────────────────────────
// Wizard state
// ─────────────────────────────────────────────────────────────────────────────

interface WizardData {
  // Step 1
  adapter: WalletAdapter | null
  walletState: WalletState | null
  // Step 2
  content: Uint8Array | null
  contentType: string
  contentBytes: number
  // Step 3
  feeRate: number
  // Step 4
  selectedUTXO: UTXO | null
  // Step 5
  recipient: string
  clientCode: string
  // Step 6 result
  commitTxid: string
  revealTxid: string
  inscriptionAddress: string
}

const STEPS = [
  'Connect Wallet',
  'Upload Image',
  'Select Fee Rate',
  'Select UTXO',
  'Review Details',
  'Inscribe',
  'Track Status',
] as const

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function StepHeader({ step, total }: { step: number; total: number }) {
  return (
    <div className="mb-6">
      <div className="flex items-center gap-2 mb-3">
        {Array.from({ length: total }, (_, i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-all ${
              i < step ? 'bg-bitcoin' : i === step ? 'bg-bitcoin/50' : 'bg-gray-700'
            }`}
          />
        ))}
      </div>
      <p className="text-xs text-gray-500 text-right">
        Step {step + 1} of {total} — {STEPS[step]}
      </p>
    </div>
  )
}

function NavButtons({
  onBack,
  onNext,
  nextLabel = 'Next →',
  nextDisabled = false,
  loading = false,
}: {
  onBack?: () => void
  onNext?: () => void
  nextLabel?: string
  nextDisabled?: boolean
  loading?: boolean
}) {
  return (
    <div className="flex gap-3 mt-6">
      {onBack && (
        <button
          onClick={onBack}
          className="px-4 py-2 rounded-lg border border-gray-700 text-gray-400 hover:border-gray-500 hover:text-gray-300 transition-colors text-sm"
        >
          ← Back
        </button>
      )}
      {onNext && (
        <button
          onClick={onNext}
          disabled={nextDisabled || loading}
          className={`
            flex-1 py-2 px-6 rounded-lg font-semibold text-sm transition-all
            ${nextDisabled || loading
              ? 'bg-gray-700 text-gray-500 cursor-not-allowed'
              : 'bg-bitcoin text-black hover:bg-bitcoin/90 active:scale-95'}
          `}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
              Processing…
            </span>
          ) : (
            nextLabel
          )}
        </button>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Main wizard
// ─────────────────────────────────────────────────────────────────────────────

export function InscribeWizard({ onNetworkDetected }: { onNetworkDetected?: (n: 'mainnet' | 'testnet' | 'testnet4') => void }) {
  const [step, setStep] = useState(0)
  const [data, setData] = useState<WizardData>({
    adapter: null,
    walletState: null,
    content: null,
    contentType: 'image/png',
    contentBytes: 0,
    feeRate: 10,
    selectedUTXO: null,
    recipient: '',
    clientCode: '',
    commitTxid: '',
    revealTxid: '',
    inscriptionAddress: '',
  })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [psbtCopied, setPsbtCopied] = useState(false)

  function update(partial: Partial<WizardData>) {
    setData((d) => ({ ...d, ...partial }))
  }

  // ── Step 0: Connect wallet ────────────────────────────────────────────────

  function renderStep0() {
    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Connect your wallet</h2>
        <WalletConnect
          onConnected={(adapter, walletState) => {
            update({ adapter, walletState, recipient: walletState.ordinalsAddress ?? '' })
            onNetworkDetected?.(walletState.network)
            setStep(1)
          }}
        />
      </>
    )
  }

  // ── Step 1: Upload image ──────────────────────────────────────────────────

  function renderStep1() {
    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Upload your image</h2>
        <ImageUpload
          feeRate={data.feeRate}
          onImageSelected={(_file, content, contentType) => {
            update({ content, contentType, contentBytes: content.length })
          }}
        />
        <NavButtons
          onBack={() => setStep(0)}
          onNext={() => setStep(2)}
          nextDisabled={!data.content}
        />
      </>
    )
  }

  // ── Step 2: Select fee rate ───────────────────────────────────────────────

  function renderStep2() {
    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Choose fee rate</h2>
        <FeeSelector
          contentBytes={data.contentBytes}
          network={data.walletState?.network ?? 'mainnet'}
          onFeeRateSelected={(feeRate) => update({ feeRate })}
        />
        <NavButtons
          onBack={() => setStep(1)}
          onNext={() => setStep(3)}
          nextDisabled={data.feeRate <= 0}
        />
      </>
    )
  }

  // ── Step 3: Select UTXO ───────────────────────────────────────────────────

  function renderStep3() {
    const cost = estimateTotalCost(data.contentBytes, data.feeRate)

    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Select funding UTXO</h2>
        {data.adapter && data.walletState && (
          <UTXOSelector
            adapter={data.adapter}
            address={data.walletState.address}
            minSatoshis={cost.totalRequired}
            onUTXOSelected={(utxo) => update({ selectedUTXO: utxo })}
          />
        )}
        <NavButtons
          onBack={() => setStep(2)}
          onNext={() => setStep(4)}
          nextDisabled={!data.selectedUTXO}
        />
      </>
    )
  }

  // ── Step 4: Review details ────────────────────────────────────────────────

  async function handleCopyPsbt() {
    if (!data.content || !data.selectedUTXO || !data.walletState) return
    try {
      const network = getBtcNetwork(data.walletState.network)
      const cost = estimateTotalCost(data.contentBytes, data.feeRate)
      const { pubKeyX } = generateEphemeralKeypair()
      const payment = buildInscriptionPayment(pubKeyX, data.contentType, data.content, network)
      const psbtHex = buildCommitPsbtFull({
        utxo: data.selectedUTXO,
        inscriptionScript: payment.script,
        commitOutputAmount: cost.commitOutputAmount,
        commitFee: cost.commitFee,
        changeAddress: data.walletState.address,
        network,
      })
      const psbtB64 = psbtHexToBase64(psbtHex)
      await navigator.clipboard.writeText(psbtB64)
      setPsbtCopied(true)
      setTimeout(() => setPsbtCopied(false), 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function renderStep4() {
    const cost = estimateTotalCost(data.contentBytes, data.feeRate)

    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Review & confirm</h2>

        <div className="space-y-3 text-sm">
          {/* Recipient */}
          <div className="p-3 rounded-lg bg-gray-800 border border-gray-700 space-y-2">
            <label className="text-gray-400 block text-xs uppercase tracking-wider">Recipient address</label>
            <input
              type="text"
              value={data.recipient}
              onChange={(e) => update({ recipient: e.target.value })}
              placeholder={data.walletState?.ordinalsAddress ?? 'bc1p... (taproot / ordinals address)'}
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-600 text-gray-100 font-mono text-xs focus:outline-none focus:border-bitcoin"
            />
            <p className="text-xs text-gray-500">
              Where the inscribed sat will land.{' '}
              {!data.walletState?.ordinalsAddress && (
                <span className="text-yellow-500">
                  In Unisat: switch to a <strong>Native Taproot</strong> account to auto-fill, or paste your <code className="font-mono">bc1p…</code> address below.
                </span>
              )}
            </p>
            {data.recipient && !data.recipient.startsWith('bc1p') && !data.recipient.startsWith('tb1p') && (
              <div className="flex gap-2 p-2 rounded-lg bg-amber-900/30 border border-amber-700/50">
                <span className="text-amber-400 shrink-0">⚠</span>
                <p className="text-xs text-amber-300">
                  {data.walletState?.ordinalsAddress
                    ? <>Your ordinals address (<code className="font-mono">{data.walletState.ordinalsAddress.slice(0, 14)}…</code>) has been pre-filled. Changing it to a payment address means your wallet may accidentally spend the inscribed sat.</>
                    : <>Use a <strong>taproot address</strong> (starts with <code className="font-mono">bc1p</code>) so your wallet treats this UTXO as an inscription and won't accidentally spend it.</>
                  }
                </p>
              </div>
            )}
          </div>

          {/* Client code */}
          <div className="p-3 rounded-lg bg-gray-800 border border-gray-700 space-y-2">
            <label className="text-gray-400 block text-xs uppercase tracking-wider">Slipstream client code (optional)</label>
            <input
              type="text"
              value={data.clientCode}
              onChange={(e) => update({ clientCode: e.target.value })}
              placeholder="For fee discounts"
              className="w-full px-3 py-2 rounded-lg bg-gray-900 border border-gray-600 text-gray-100 text-sm focus:outline-none focus:border-bitcoin"
            />
          </div>

          {/* Summary */}
          <div className="p-3 rounded-lg bg-gray-800 border border-gray-700 space-y-1.5">
            <div className="flex justify-between">
              <span className="text-gray-400">Content</span>
              <span className="text-gray-200 font-mono text-xs">{data.contentType}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Size</span>
              <span className="text-gray-200">{data.contentBytes.toLocaleString()} bytes</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Fee rate</span>
              <span className="text-gray-200">{data.feeRate} sat/vB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">UTXO</span>
              <span className="text-gray-200 font-mono text-xs">
                {data.selectedUTXO?.txid.slice(0, 8)}…:{data.selectedUTXO?.vout}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">UTXO value</span>
              <span className="text-gray-200">{data.selectedUTXO?.satoshis.toLocaleString()} sat</span>
            </div>
            <hr className="border-gray-700 my-1" />
            <div className="flex justify-between font-semibold">
              <span className="text-gray-300">Total cost</span>
              <span className="text-bitcoin">{cost.totalRequired.toLocaleString()} sat</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-gray-500">Change back</span>
              <span className="text-gray-400">
                {((data.selectedUTXO?.satoshis ?? 0) - cost.totalRequired).toLocaleString()} sat
              </span>
            </div>
          </div>
        </div>

        <div className="text-center">
          <button
            onClick={handleCopyPsbt}
            disabled={!data.content || !data.selectedUTXO}
            className="text-xs text-gray-500 hover:text-gray-300 underline underline-offset-2 disabled:no-underline disabled:cursor-not-allowed transition-colors"
          >
            {psbtCopied ? '✓ PSBT copied!' : 'Copy unsigned commit PSBT'}
          </button>
        </div>

        {error && (
          <div className="mt-3 p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
            {error}
          </div>
        )}

        <NavButtons
          onBack={() => setStep(3)}
          onNext={handleInscribe}
          nextLabel="Sign & Inscribe →"
          nextDisabled={!data.recipient || !data.selectedUTXO || !data.content}
          loading={loading}
        />
      </>
    )
  }

  // ── Step 5: In progress (handled by handleInscribe, shows status) ─────────

  function renderStep5() {
    return (
      <div className="text-center space-y-4 py-8">
        <div className="w-12 h-12 border-4 border-gray-700 border-t-bitcoin rounded-full animate-spin mx-auto" />
        <p className="text-gray-300 font-semibold">Processing inscription…</p>
        <p className="text-gray-500 text-sm">
          Your wallet will prompt you to sign the commit transaction.
          <br />The reveal transaction is signed automatically.
        </p>
        {error && (
          <div className="p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm max-w-sm mx-auto text-left">
            {error}
            <button onClick={() => setStep(4)} className="block mt-2 text-xs underline">
              Go back and retry
            </button>
          </div>
        )}
      </div>
    )
  }

  // ── Step 6: Status tracker ────────────────────────────────────────────────

  function renderStep6() {
    return (
      <>
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Inscription submitted!</h2>
        <StatusTracker
          commitTxid={data.commitTxid}
          revealTxid={data.revealTxid}
          network={data.walletState?.network ?? 'mainnet'}
        />
        <div className="mt-6 text-center">
          <button
            onClick={() => {
              setStep(0)
              setData({ adapter: null, walletState: null, content: null, contentType: 'image/png', contentBytes: 0, feeRate: 10, selectedUTXO: null, recipient: '', clientCode: '', commitTxid: '', revealTxid: '', inscriptionAddress: '' })
              setError(null)
            }}
            className="text-gray-400 text-sm hover:text-gray-300 underline"
          >
            Inscribe another
          </button>
        </div>
      </>
    )
  }

  // ── Core inscription logic ────────────────────────────────────────────────

  async function handleInscribe() {
    if (!data.adapter || !data.walletState || !data.content || !data.selectedUTXO) return

    setError(null)
    setLoading(true)
    setStep(5) // show spinner

    try {
      const network = getBtcNetwork(data.walletState.network)
      const cost = estimateTotalCost(data.contentBytes, data.feeRate)

      // 1. Generate ephemeral keypair
      const { privKey, pubKeyX } = generateEphemeralKeypair()

      try {
        // 2. Build inscription P2TR address
        const payment = buildInscriptionPayment(pubKeyX, data.contentType, data.content, network)

        // 3. Build unsigned commit PSBT
        const psbtHex = buildCommitPsbtFull({
          utxo: data.selectedUTXO,
          inscriptionScript: payment.script,
          commitOutputAmount: cost.commitOutputAmount,
          commitFee: cost.commitFee,
          changeAddress: data.walletState.address,
          network,
        })

        // 4. Send to wallet for signing
        const signedPsbtHex = await data.adapter.signPsbt(psbtHex, [
          {
            index: 0,
            address: data.selectedUTXO.address,
            disableTweakSigner: false,
          },
        ])

        // 5. Extract signed commit tx hex from finalized PSBT
        const commitTxHex = extractSignedTxFromPsbt(signedPsbtHex)

        // 6. Build and sign reveal tx with ephemeral key
        const revealTxHex = buildAndSignReveal({
          privKey,
          pubKeyX,
          payment,
          commitTxHex,
          commitVout: 0,
          commitOutputAmount: cost.commitOutputAmount,
          revealFee: cost.revealFee,
          recipient: data.recipient,
          network,
        })

        // Compute txids from the signed tx hexes (don't rely on API response shape)
        const commitTxid = btc.Transaction.fromRaw(hex.decode(commitTxHex)).id
        const revealTxid = btc.Transaction.fromRaw(hex.decode(revealTxHex)).id

        // 7. Submit commit + reveal as a package to Slipstream
        await submitPackage(
          [commitTxHex, revealTxHex],
          data.clientCode || undefined,
          data.walletState.network
        )

        update({
          commitTxid,
          revealTxid,
          inscriptionAddress: payment.address,
        })

        saveHistoryEntry({
          network: data.walletState.network,
          commitTxid,
          revealTxid,
          inscriptionAddress: payment.address,
          contentType: data.contentType,
          contentBytes: data.contentBytes,
        })

        setStep(6)
      } finally {
        // Zero out ephemeral key regardless of success/failure
        zeroKey(privKey)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
      setLoading(false)
      // Stay on step 5 to show the error with a back button
    }

    setLoading(false)
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="max-w-lg mx-auto">
      <StepHeader step={step} total={STEPS.length} />

      {step === 0 && renderStep0()}
      {step === 1 && renderStep1()}
      {step === 2 && renderStep2()}
      {step === 3 && renderStep3()}
      {step === 4 && renderStep4()}
      {step === 5 && renderStep5()}
      {step === 6 && renderStep6()}
    </div>
  )
}
