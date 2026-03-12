// Slipstream API client — ported from sliprun/api/slipstream.py
// Mainnet: slipstream.mara.com  Testnet: teststream.mara.com

export class SlipstreamError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string
  ) {
    super(`Slipstream API error ${status}: ${body}`)
    this.name = 'SlipstreamError'
  }
}

function resolveUrl(path: string, network: 'mainnet' | 'testnet' | 'testnet4'): string {
  if (network === 'testnet' || network === 'testnet4') {
    const base = import.meta.env.VITE_TESTSTREAM_URL ?? ''
    // path is e.g. /api/rates — rewrite to /testapi/rates for Vite proxy
    return base.startsWith('http') ? `${base}${path}` : path.replace(/^\/api/, '/testapi')
  }
  const base = import.meta.env.VITE_SLIPSTREAM_URL ?? ''
  return base.startsWith('http') ? `${base}${path}` : path
}

async function apiFetch(path: string, network: 'mainnet' | 'testnet' | 'testnet4' = 'mainnet', init?: RequestInit): Promise<unknown> {
  const url = resolveUrl(path, network)
  const resp = await fetch(url, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    ...init,
  })

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    throw new SlipstreamError(resp.status, body)
  }

  return resp.json()
}

export interface FeeRates {
  low: number
  medium: number
  high: number
}

export async function getRates(clientCode?: string, network: 'mainnet' | 'testnet' | 'testnet4' = 'mainnet'): Promise<FeeRates> {
  const params = clientCode ? `?client_code=${encodeURIComponent(clientCode)}` : ''
  const data = (await apiFetch(`/api/rates${params}`, network)) as Record<string, number>
  // Slipstream returns: submit_fee_rate, market_rate, slipstream_rate (effective_rate)
  return {
    low: data.submit_fee_rate ?? data.low ?? data.economy ?? 2,
    medium: data.market_rate ?? data.medium ?? data.normal ?? 5,
    high: data.slipstream_rate ?? data.effective_rate ?? data.high ?? data.priority ?? 10,
  }
}

export interface TxStatus {
  txid?: string
  status?: string
  message?: string
  [key: string]: unknown
}

export async function getTransactionStatus(txId: string, network: 'mainnet' | 'testnet' | 'testnet4' = 'mainnet'): Promise<TxStatus> {
  return apiFetch(`/api/transactions/status?tx_id=${encodeURIComponent(txId)}`, network) as Promise<TxStatus>
}

export interface PackageResult {
  [txid: string]: unknown
}

export async function submitPackage(
  txHexes: [string, string],
  clientCode?: string,
  network: 'mainnet' | 'testnet' | 'testnet4' = 'mainnet'
): Promise<PackageResult> {
  const payload: Record<string, unknown> = { tx_hexes: txHexes }
  if (clientCode) payload.client_code = clientCode
  return apiFetch('/api/transactions/packages', network, {
    method: 'POST',
    body: JSON.stringify(payload),
  }) as Promise<PackageResult>
}

export async function testTransactions(txHexes: string[]): Promise<unknown> {
  return apiFetch('/api/mempool/tests', {
    method: 'POST',
    body: JSON.stringify({ tx_hexes: txHexes }),
  })
}
