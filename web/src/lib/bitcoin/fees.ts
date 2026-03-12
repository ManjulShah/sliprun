// Ported from sliprun/bitcoin/transaction.py

// Ordinals commit: 1-input P2WPKH → 1-output P2TR + optional change
// Padded slightly above the theoretical minimum to ensure we meet Slipstream's fee floor
const COMMIT_BASE_VBYTES = 160

// Ordinals reveal: 1-input P2TR (script path) → 1-output
// Base ~105 vbytes + witness discount on inscription content
const REVEAL_BASE_VBYTES = 112

// Dust limit for a P2TR output
export const DUST_LIMIT = 546

// Slipstream rejects packages below 2 sat/vByte; add 0.1 buffer
const MIN_FEE_RATE = 2.1

export function estimateCommitFee(feeRate: number): number {
  const rate = Math.max(feeRate, MIN_FEE_RATE)
  return Math.ceil(COMMIT_BASE_VBYTES * rate)
}

export function estimateRevealFee(contentBytes: number, feeRate: number): number {
  const rate = Math.max(feeRate, MIN_FEE_RATE)
  // Witness data is discounted 4x under segwit rules
  const witnessVbytes = Math.ceil(contentBytes / 4)
  return Math.ceil((REVEAL_BASE_VBYTES + witnessVbytes) * rate)
}

export function estimateTotalCost(
  contentBytes: number,
  feeRate: number
): { commitFee: number; revealFee: number; commitOutputAmount: number; totalRequired: number } {
  const commitFee = estimateCommitFee(feeRate)
  const revealFee = estimateRevealFee(contentBytes, feeRate)
  const commitOutputAmount = DUST_LIMIT + revealFee
  const totalRequired = commitOutputAmount + commitFee
  return { commitFee, revealFee, commitOutputAmount, totalRequired }
}
