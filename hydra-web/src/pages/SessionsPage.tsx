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

      {sessions.isLoading && <p className="text-gray-500">Loading...</p>}

      {sessions.data?.sessions.length === 0 && (
        <p className="text-gray-500">No sessions yet.</p>
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
