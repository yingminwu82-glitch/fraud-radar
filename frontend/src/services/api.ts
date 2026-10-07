import type { Analysis, RiskProfile } from '../types'

const request = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) throw new Error((await response.json()).detail ?? `Request failed (${response.status})`)
  return response.json()
}

export const api = {
  health: () => request<{status: string; service: string}>('/api/health'),
  profiles: () => request<RiskProfile[]>('/api/risk-profiles'),
  updateProfile: (profile: RiskProfile) => request<RiskProfile>(`/api/risk-profiles/${profile.id}`, {method:'PUT', body:JSON.stringify(profile)}),
  analyze: (body: Record<string, unknown>) => request<Analysis>('/api/analyze', {method:'POST', body:JSON.stringify(body)}),
  transactions: () => request<Record<string, unknown>[]>('/api/transactions'),
}
