import { useQuery } from '@tanstack/react-query'
import { getEngines, getStats } from '../api/client'

export default function Dashboard() {
  const engines = useQuery({ queryKey: ['engines'], queryFn: getEngines })
  const stats = useQuery({ queryKey: ['stats'], queryFn: getStats })

  const isLoading = engines.isLoading || stats.isLoading
  const fetchError = engines.error || stats.error

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">HYDRA</h1>
        <p className="text-gray-400">
          Next-generation password security research framework
        </p>
      </div>

      {fetchError && (
        <div className="bg-red-900/50 border border-red-800 rounded-lg p-4 text-sm text-red-300">
          Failed to load dashboard data:{' '}
          {fetchError instanceof Error ? fetchError.message : 'Unknown error'}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-5">
          <div className="text-sm text-gray-500 mb-1">Engines</div>
          <div className="text-2xl font-bold text-hydra-500">
            {isLoading ? (
              <span className="inline-block w-8 h-6 bg-gray-700 rounded animate-pulse" />
            ) : (
              engines.data?.engines.length ?? '—'
            )}
          </div>
          <div className="text-xs text-gray-600 mt-1">
            {isLoading ? (
              <span className="inline-block w-24 h-3 bg-gray-800 rounded animate-pulse" />
            ) : (
              engines.data?.engines.join(', ') ?? '—'
            )}
          </div>
        </div>

        <div className="bg-gray-900 rounded-lg border border-gray-800 p-5">
          <div className="text-sm text-gray-500 mb-1">Status</div>
          <div className="text-2xl font-bold text-green-400">Online</div>
          <div className="text-xs text-gray-600 mt-1">API connected</div>
        </div>

        <div className="bg-gray-900 rounded-lg border border-gray-800 p-5">
          <div className="text-sm text-gray-500 mb-1">Crack Rate (MD5)</div>
          <div className="text-2xl font-bold text-purple-400">
            {isLoading ? (
              <span className="inline-block w-12 h-6 bg-gray-700 rounded animate-pulse" />
            ) : stats.data ? (
              `${(stats.data.avg_crack_rate['MD5'] * 100).toFixed(0)}%`
            ) : (
              '—'
            )}
          </div>
          <div className="text-xs text-gray-600 mt-1">historical average</div>
        </div>
      </div>

      <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Quick Start</h2>
        <div className="space-y-3 text-sm text-gray-400">
          <p>
            1. Go to <strong className="text-white">Crack</strong> to submit hashes
          </p>
          <p>
            2. HYDRA auto-detects hash type and builds an optimal attack plan
          </p>
          <p>
            3. Results are stored in the Knowledge Base for future sessions
          </p>
          <p>
            4. Check <strong className="text-white">Sessions</strong> for history
          </p>
        </div>
      </div>
    </div>
  )
}
