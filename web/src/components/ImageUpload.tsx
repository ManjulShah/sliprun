import { useState, useCallback, useRef } from 'react'
import { estimateTotalCost } from '../lib/bitcoin/fees'

interface Props {
  feeRate: number
  onImageSelected: (file: File, content: Uint8Array, contentType: string) => void
}

const SUPPORTED_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml', 'text/plain']
const MAX_SIZE_BYTES = 390 * 1024 // ~390 KB practical limit

const EXT_MIME_MAP: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  txt: 'text/plain',
  html: 'text/html',
  json: 'application/json',
  mp4: 'video/mp4',
  mp3: 'audio/mpeg',
  pdf: 'application/pdf',
}

function guessTypeFromExtension(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  return EXT_MIME_MAP[ext] ?? 'application/octet-stream'
}

export function ImageUpload({ feeRate, onImageSelected }: Props) {
  const [dragging, setDragging] = useState(false)
  const [preview, setPreview] = useState<string | null>(null)
  const [fileInfo, setFileInfo] = useState<{ name: string; size: number } | null>(null)
  const [contentType, setContentType] = useState<string>('')
  const [error, setError] = useState<string | null>(null)
  // Store bytes so we can re-call onImageSelected when the user edits contentType
  const storedRef = useRef<{ file: File; bytes: Uint8Array } | null>(null)

  const processFile = useCallback(async (file: File) => {
    setError(null)

    if (file.size > MAX_SIZE_BYTES) {
      setError(`File too large: ${(file.size / 1024).toFixed(1)} KB. Max ~390 KB.`)
      return
    }

    const detectedType = file.type || guessTypeFromExtension(file.name)
    const bytes = new Uint8Array(await file.arrayBuffer())

    storedRef.current = { file, bytes }
    setFileInfo({ name: file.name, size: file.size })
    setContentType(detectedType)

    if (detectedType.startsWith('image/') && detectedType !== 'image/svg+xml') {
      const url = URL.createObjectURL(file)
      setPreview(url)
    } else {
      setPreview(null)
    }

    onImageSelected(file, bytes, detectedType)
  }, [onImageSelected])

  const handleContentTypeChange = useCallback((newType: string) => {
    // Normalise bare extensions to full MIME types (e.g. "jpeg" → "image/jpeg")
    const normalised = '/' in newType ? newType : (EXT_MIME_MAP[newType.toLowerCase().replace(/^\./, '')] ?? newType)
    setContentType(normalised)
    if (storedRef.current) {
      const { file, bytes } = storedRef.current
      onImageSelected(file, bytes, normalised)
    }
  }, [onImageSelected])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) processFile(file)
  }, [processFile])

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) processFile(file)
  }, [processFile])

  const cost = fileInfo ? estimateTotalCost(fileInfo.size, feeRate) : null


  return (
    <div className="space-y-4">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer
          ${dragging ? 'border-bitcoin bg-bitcoin/10' : 'border-gray-700 hover:border-gray-500'}
        `}
      >
        <input
          type="file"
          accept={SUPPORTED_TYPES.join(',')}
          onChange={handleFileChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />

        {preview ? (
          <img src={preview} alt="Preview" className="max-h-40 mx-auto rounded-lg object-contain" />
        ) : (
          <div className="space-y-2">
            <div className="text-4xl">🖼️</div>
            <p className="text-gray-300 font-medium">Drop image here or click to browse</p>
            <p className="text-xs text-gray-500">PNG, JPEG, GIF, WebP, SVG, TXT — max ~390 KB</p>
          </div>
        )}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      )}

      {fileInfo && cost && (
        <div className="p-4 rounded-xl bg-gray-800 border border-gray-700 space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-400">File</span>
            <span className="text-gray-200 font-mono text-xs truncate max-w-[200px]">{fileInfo.name}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Size</span>
            <span className="text-gray-200">{(fileInfo.size / 1024).toFixed(2)} KB ({fileInfo.size.toLocaleString()} bytes)</span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <label className="text-gray-400 shrink-0">Content type</label>
            <input
              type="text"
              value={contentType}
              onChange={(e) => handleContentTypeChange(e.target.value)}
              className="flex-1 min-w-0 px-2 py-1 rounded bg-gray-900 border border-gray-600 text-gray-100 font-mono text-xs focus:outline-none focus:border-bitcoin text-right"
              placeholder="image/png"
            />
          </div>
          <hr className="border-gray-700" />
          <div className="flex justify-between">
            <span className="text-gray-400">Commit fee</span>
            <span className="text-gray-200">{cost.commitFee.toLocaleString()} sat</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Reveal fee</span>
            <span className="text-gray-200">{cost.revealFee.toLocaleString()} sat</span>
          </div>
          <div className="flex justify-between font-semibold">
            <span className="text-gray-300">Total required</span>
            <span className="text-bitcoin">{cost.totalRequired.toLocaleString()} sat</span>
          </div>
        </div>
      )}
    </div>
  )
}
