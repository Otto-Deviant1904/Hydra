import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { crackHashes, CrackResponse } from '../api/client'

const MAX_HASHES = 1000

export default function CrackPage() {
  const [hashes, setHashes] = useState('')
  const [hashType, setHashType] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: crackHashes,
  })

  const hashList = hashes.split('\n').map(h => h.trim()).filter(Boolean)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setValidationError(null)

    if (!hashList.length) {
      setValidationError('Please enter at least one hash.')
      return
    }
    if (hashList.length > MAX_HASHES) {
      setValidationError(`Too many hashes — maximum is ${MAX_HASHES.toLocaleString()} per request (you entered ${hashList.length.toLocaleString()}).`)
      return
    }

    mutation.mutate({
      hashes: hashList,
      ...(hashType ? { hash_type: hashType } : {}),
      ...(wordlist ? { wordlists: [wordlist] } : {}),
    })
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold text-white">Crack Hashes</h1>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-sm text-gray-400">Hashes (one per line)</label>
            {hashList.length > 0 && (
              <span className={`text-xs ${hashList.length > MAX_HASHES ? 'text-red-400' : 'text-gray-500'}`}>
                {hashList.length.toLocaleString()} / {MAX_HASHES.toLocaleString()}
              </span>
            )}
          </div>
          <textarea
            className={`w-full h-40 bg-gray-900 border rounded-lg p-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none ${
              hashList.length > MAX_HASHES
                ? 'border-red-600 focus:border-red-500'
                : 'border-gray-700 focus:border-hydra-500'
            }`}
            placeholder="5d41402abc4b2a76b9719d911017c592&#10;$2y$10$..."
            value={hashes}
            onChange={e => { setHashes(e.target.value); setValidationError(null) }}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Hash type (optional)</label>
            <input
              className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white placeholder-gray-600 focus:border-hydra-500 focus:outline-none"
              placeholder="auto-detect"
              value={hashType}
              onChange={e => setHashType(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Wordlist path (optional)</label>
            <input
              className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white placeholder-gray-600 focus:border-hydra-500 focus:outline-none"
              placeholder="/wordlists/rockyou.txt"
              value={wordlist}
              onChange={e => setWordlist(e.target.value)}
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={mutation.isPending || !hashes.trim() || hashList.length > MAX_HASHES}
          className="bg-hydra-600 hover:bg-hydra-700 disabled:bg-gray-700 disabled:text-gray-500 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors"
        >
          {mutation.isPending ? 'Cracking...' : 'Start Attack'}
        </button>
      </form>

      {validationError && (
        <div className="bg-yellow-900/50 border border-yellow-700 rounded-lg p-4 text-sm text-yellow-300">
          {validationError}
        </div>
      )}

      {mutation.isError && (
        <div className="bg-red-900/50 border border-red-800 rounded-lg p-4 text-sm text-red-300">
          {mutation.error.message}
        </div>
      )}

      {mutation.data && <ResultPanel result={mutation.data} />}
    </div>
  )
}

function ResultPanel({ result }: { result: CrackResponse }) {
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-5 space-y-3">
      <h2 className="text-lg font-semibold text-green-400">Crack Complete</h2>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span className="text-gray-500">Session: </span>
          <span className="text-white font-mono">{result.session_id}</span>
        </div>
        <div>
          <span className="text-gray-500">Hash type: </span>
          <span className="text-white">{result.hash_type}</span>
        </div>
        <div>
          <span className="text-gray-500">Cracked: </span>
          <span className="text-green-400 font-bold">{result.cracked}/{result.total}</span>
        </div>
        <div>
          <span className="text-gray-500">Phases: </span>
          <span className="text-white">{result.phases_completed}</span>
        </div>
      </div>
      {result.results.length > 0 && (
        <div className="mt-3">
          <h3 className="text-sm font-semibold text-green-400 mb-2">Cracked Passwords</h3>
          <div className="space-y-1">
            {result.results.map((r, i) => (
              <div key={i} className="bg-gray-950 rounded px-3 py-2 text-sm font-mono flex justify-between">
                <span className="text-gray-400">{r.hash}...</span>
                <span className="text-green-300 font-bold">{r.password}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <pre className="bg-gray-950 rounded p-3 text-xs text-gray-400 font-mono whitespace-pre-wrap mt-2">
        {result.summary}
      </pre>
    </div>
  )
}
