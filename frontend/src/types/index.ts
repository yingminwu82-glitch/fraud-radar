export type RiskProfile = {
  id: number
  profile_name: string
  ip_reputation: number
  network_anonymity: number
  malicious_infrastructure: number
  geographic_risk: number
  transaction_behavior: number
  account_characteristics: number
  sensitivity: 'conservative' | 'balanced' | 'aggressive'
}

export type Analysis = {
  transaction_id: string
  risk_score: number
  risk_level: string
  risk_profile: string
  factor_scores: {factor: string; raw_signal: string; risk_score: number; user_preference: number; weight: number; contribution: number; providers: string[]}[]
  provider_results: {provider: string; signal_count: number}[]
  provider_agreement: string[]
  missing_signals: string[]
  explanation: string[]
}
