import type { AIReport, Analysis, ChatContextType, ChatMessage, ChatReply, ProviderStatus, RiskProfile } from '../types'

const request = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) { const body=await response.json(); const detail=body.detail; throw new Error(typeof detail==='string'?detail:detail?.message??`Request failed (${response.status})`) }
  return response.json()
}

export const api = {
  health: () => request<{status: string; service: string}>('/api/health'),
  profiles: () => request<RiskProfile[]>('/api/risk-profiles'),
  updateProfile: (profile: RiskProfile) => request<RiskProfile>(`/api/risk-profiles/${profile.id}`, {method:'PUT', body:JSON.stringify(profile)}),
  analyze: (body: Record<string, unknown>) => request<Analysis>('/api/analyze', {method:'POST', body:JSON.stringify(body)}),
  transactions: () => request<Record<string, unknown>[]>('/api/transactions'),
  providerStatus: () => request<ProviderStatus[]>('/api/providers/status'),
  aiReport: (id:number) => request<AIReport>(`/api/ai/report/${id}`),
  generateAIReport: (id:number,regenerate=false) => request<AIReport>(`/api/ai/report/${id}`,{method:'POST',body:JSON.stringify({regenerate})}),
  chat: (id:number,question:string,session_id:number|null,context_type:ChatContextType='report') => request<ChatReply>(`/api/ai/chat/${id}`,{method:'POST',body:JSON.stringify({question,session_id,context_type})}),
  chatHistory: (id:number,sessionId:number) => request<{analysis_id:number;session_id:number;messages:ChatMessage[]}>(`/api/ai/chat/${id}/${sessionId}`),
  clearChat: (id:number,sessionId:number) => request<{status:string}>(`/api/ai/chat/${id}/${sessionId}`,{method:'DELETE'}),
}
