const API = '/api'

export async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status}: ${body.slice(0, 200)}`)
  }
  return res.json()
}

export interface HealthStatus {
  status: string
}

export interface EngineList {
  engines: string[]
}

export interface CrackRequest {
  hashes: string[]
  hash_type?: string
  wordlists?: string[]
  timeout?: number
}

export interface CrackResponse {
  session_id: string
  hash_type: string
  total: number
  cracked: number
  phases_completed: number
  summary: string
  results: { hash: string; password: string }[]
}

export interface SessionInfo {
  id: string
  hash_type: string
  cracked: number
  total: number
  started: string | null
}

export interface SessionsResponse {
  sessions: SessionInfo[]
}

export interface StatsResponse {
  engines: string[]
  avg_crack_rate: Record<string, number>
}

export function getHealth(): Promise<HealthStatus> {
  return fetchJson('/health')
}

export function getEngines(): Promise<EngineList> {
  return fetchJson('/engines')
}

export function crackHashes(req: CrackRequest): Promise<CrackResponse> {
  return fetchJson('/crack', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

export function getSessions(hashType?: string): Promise<SessionsResponse> {
  const qs = hashType ? `?hash_type=${hashType}` : ''
  return fetchJson(`/sessions${qs}`)
}

export function getStats(): Promise<StatsResponse> {
  return fetchJson('/stats')
}
