import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getSessions } from '../api/client'

export default function SessionsPage() {
  const [filter, setFilter] = useState('')
  const sessions = useQuery({
    queryKey: ['sessions', filter],
    queryFn: () => getSessions(filter || undefined),
  })

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Sessions</h1>
        <input
          className="bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white placeholder-gray-600 focus:border-hydra-500 focus:outline-none w-48"
          placeholder="Filter by hash type..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      {sessions.isLoading && (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <div
              key={i}
              className="bg-gray-900 rounded-lg border border-gray-800 p-4 flex items-center justify-between animate-pulse"
            >
              <div className="space-y-2">
                <div className="w-48 h-4 bg-gray-700 rounded" />
                <div className="w-16 h-3 bg-gray-800 rounded" />
              </div>
              <div className="space-y-2 text-right">
                <div className="w-12 h-4 bg-gray-700 rounded ml-auto" />
                <div className="w-24 h-3 bg-gray-800 rounded" />
              </div>
            </div>
          ))}
        </div>
      )}

      {sessions.isError && (
        <div className="bg-red-900/50 border border-red-800 rounded-lg p-4 text-sm text-red-300">
          Failed to load sessions:{' '}
          {sessions.error instanceof Error ? sessions.error.message : 'Unknown error'}
        </div>
      )}

      {!sessions.isLoading && sessions.data?.sessions.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="text-4xl mb-3">🔍</div>
          <p className="text-gray-400 font-medium">No sessions yet</p>
          <p className="text-gray-600 text-sm mt-1">
            Submit hashes on the <strong className="text-gray-400">Crack</strong> page to get started.
          </p>
        </div>
      )}

      <div className="space-y-2">
        {sessions.data?.sessions.map(s => (
          <div
            key={s.id}
            className="bg-gray-900 rounded-lg border border-gray-800 p-4 flex items-center justify-between"
          >
            <div className="space-y-1">
              <div className="font-mono text-sm text-white">{s.id}</div>
              <div className="text-xs text-gray-500">{s.hash_type}</div>
            </div>
            <div className="text-right">
              <div className="text-sm font-bold text-green-400">
                {s.cracked}/{s.total}
              </div>
              <div className="text-xs text-gray-600">
                {s.started ? new Date(s.started).toLocaleString() : 'N/A'}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
