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
  analysis_id:number
  transaction_id: string
  risk_score: number
  risk_level: string
  risk_profile: string
  factor_scores: {factor: string; raw_signal: string; risk_score: number; user_preference: number; weight: number; contribution: number; providers: string[]; evidence_strength:number; risk_coefficient:number}[]
  categories: {category:string;score:number|null;preference:number;weight:number;evidence_strength:number;risk_coefficient:number;contribution:number|null;evidence:{factor:string;score:number;providers:string[];values:unknown[]}[];dimension_name?:string;evidence_status?:string;evidence_coverage?:number;available_signal_types?:{signal_id:string;display_name:string}[];missing_signal_types?:{signal_id:string;display_name:string}[];valid_signal_count?:number;total_expected_signal_count?:number;risk_level?:string}[]
  provider_results: {provider: string; status:string; latency_ms:number|null;signal_count: number;signals:{category:string;factor:string;value:unknown;risk_score:number|null;confidence:number;provider:string;missing:boolean}[];raw_result:Record<string,unknown>|null;error:string|null;cached:boolean}[]
  provider_agreement: string[]
  missing_signals: string[]
  explanation: string[]
}

export type AnalysisSelection={
  result:Analysis
  transaction:{ip_address:string;amount:number;currency:string;user_country:string|null;transaction_country:string|null;transaction_velocity:number|null;account_age_days:number|null}
}

export type ProviderStatus={provider:string;status:string;latency_ms:number|null;error:string|null;last_checked:string|null;mode:string}

export type AIReport={id:number;analysis_id:number;model_name:string;report:{executive_summary:string;overall_interpretation:string;sections:Record<string,string>;multi_source_analysis:string;risk_contribution_analysis:string;user_preference_impact:string;positive_signals:string[];limitations:string[];recommended_actions:string[];key_risk_drivers:string[];confidence_explanation:string;risk_score:number;risk_level:string;evidence_strength:string;analysis_data?:Record<string,any>};created_at:string;updated_at:string}
export type ChatContextType='report'|'provider_evidence'
export type ChatReply={analysis_id:number;session_id:number;answer:string;created_at:string}
export type ChatMessage={role:'user'|'assistant';content:string;created_at:string}
