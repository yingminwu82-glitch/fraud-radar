import { useState } from 'react'
import { ArrowRight, CheckCircle2, LoaderCircle, ShieldAlert } from 'lucide-react'
import type { AnalysisSelection, RiskProfile } from '../types'
import { api } from '../services/api'

type Props={profiles:RiskProfile[];selected:AnalysisSelection|null;onSelectionChange:(value:AnalysisSelection|null)=>void}

export default function TransactionAnalysis({profiles,selected,onSelectionChange}:Props) {
 const result=selected?.result??null
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[refresh,setRefresh]=useState(false)
 const [form,setForm]=useState({transaction_id:'TX-2026-1042',ip_address:'203.0.113.42',transaction_amount:'2500',currency:'USD',user_country:'US',transaction_country:'US',transaction_velocity:'2',account_age_days:'450',risk_profile_id:''})

 const submit=async(event:React.FormEvent)=>{
  event.preventDefault();setBusy(true);setError('');onSelectionChange(null)
  const request={...form,transaction_amount:Number(form.transaction_amount),transaction_velocity:form.transaction_velocity===''?null:Number(form.transaction_velocity),account_age_days:form.account_age_days===''?null:Number(form.account_age_days),risk_profile_id:Number(form.risk_profile_id||profiles[0]?.id||1),refresh_provider_data:refresh}
  try{
   const analysis=await api.analyze(request)
   onSelectionChange({result:analysis,transaction:{ip_address:form.ip_address,amount:Number(form.transaction_amount),currency:form.currency,user_country:form.user_country||null,transaction_country:form.transaction_country||null,transaction_velocity:request.transaction_velocity,account_age_days:request.account_age_days}})
  }catch(err){setError(err instanceof Error?err.message:'Analysis failed')}
  finally{setBusy(false)}
 }

 return <div className="analysis-layout">
  <section className="panel form-panel"><div className="panel-head"><div><h3>Transaction details</h3><p>Enter available context to assess the transaction</p></div></div><form onSubmit={submit} className="analysis-form">
   <label>Transaction ID<input value={form.transaction_id} onChange={event=>setForm({...form,transaction_id:event.target.value})}/></label>
   <label>IP address<input value={form.ip_address} onChange={event=>setForm({...form,ip_address:event.target.value})} required/><small>Mock mode uses deterministic test indicators. Real mode queries configured providers.</small></label>
   <div className="form-two"><label>Amount<input type="number" min="0" value={form.transaction_amount} onChange={event=>setForm({...form,transaction_amount:event.target.value})}/></label><label>Currency<input value={form.currency} maxLength={3} onChange={event=>setForm({...form,currency:event.target.value.toUpperCase()})}/></label></div>
   <div className="form-two"><label>User country<input maxLength={2} value={form.user_country} onChange={event=>setForm({...form,user_country:event.target.value.toUpperCase()})}/></label><label>Transaction country<input maxLength={2} value={form.transaction_country} onChange={event=>setForm({...form,transaction_country:event.target.value.toUpperCase()})}/></label></div>
   <div className="form-two"><label>Recent transaction count<input type="number" min="0" value={form.transaction_velocity} onChange={event=>setForm({...form,transaction_velocity:event.target.value})}/></label><label>Account age (days)<input type="number" min="0" value={form.account_age_days} onChange={event=>setForm({...form,account_age_days:event.target.value})}/></label></div>
   <label>Risk profile<select value={form.risk_profile_id||String(profiles[0]?.id||'')} onChange={event=>setForm({...form,risk_profile_id:event.target.value})}>{profiles.map(profile=><option key={profile.id} value={profile.id}>{profile.profile_name}</option>)}</select></label>
   <label style={{display:'flex',alignItems:'center',gap:8}}><input type="checkbox" checked={refresh} onChange={event=>setRefresh(event.target.checked)}/> Refresh provider data (skip cache)</label>
   {error&&<div className="error-box">{error}</div>}<button className="primary-button submit-button" disabled={busy}>{busy?<LoaderCircle className="spin" size={17}/>:<>Run risk assessment <ArrowRight size={16}/></>}</button>
  </form></section>
  <section className="analysis-result">{result?<>
   <div className="panel result-overview"><div className="result-title"><span className="eyebrow">RISK ENGINE ASSESSMENT</span><span className={`risk-badge ${result.risk_level.split(' ')[0].toLowerCase()}`}>{result.risk_level}</span></div><div className="result-score-row"><div className="result-score">{result.risk_score}<small>/100</small></div><div><h2>{result.risk_level}</h2><p>{result.transaction_id} · {result.risk_profile} profile</p></div></div><div className="result-meter"><i style={{width:`${result.risk_score}%`}}/></div><div className="provider-pills">{result.provider_results.map(provider=><span key={provider.provider} title={provider.error||undefined}><CheckCircle2 size={14}/>{provider.provider}: {provider.status}{provider.cached?' · cached':''}</span>)}</div></div>
   <div className="panel factor-panel"><div className="panel-head"><div><h3>Risk dimensions</h3><p>Risk severity is separate from evidence coverage; unavailable scores are not zero risk.</p></div></div>{result.categories.map(category=><div className="factor-row" key={category.category}><div className="factor-name"><b>{category.dimension_name??category.category.replace(/_/g,' ')}</b><small>{category.evidence.map(evidence=>`${evidence.factor} (${evidence.providers.join(', ')})`).join('; ')||'Unknown / Insufficient Evidence'}</small><small>{category.evidence_status??'Coverage unavailable'} · coverage {category.evidence_coverage===undefined?'N/A':`${Math.round(category.evidence_coverage*100)}%`}</small></div><div className="factor-score">{category.score===null?<small>N/A</small>:<><div className="score-track"><i style={{width:`${category.score}%`}}/></div><b>{Math.round(category.score)}</b></>}</div><div className="factor-weight"><small>Weight</small><b>{(category.weight*100).toFixed(1)}%</b></div><div className="factor-contribution"><small>Strength / points</small><b>{(category.evidence_strength*100).toFixed(0)}% / {category.contribution?.toFixed(1)??'—'}</b></div></div>)}{result.missing_signals.length>0&&<div className="missing-note"><ShieldAlert size={15}/> Unknown / Insufficient Evidence: {result.missing_signals.join(', ')}</div>}</div>
   <div className="panel explanation-panel"><h3>Risk Engine explanation</h3>{result.explanation.map(line=><p key={line}>{line}</p>)}{result.provider_agreement.map(line=><p key={line}>{line}</p>)}<p>Full provider fields and normalized evidence are in Provider Evidence. The professional explanation is in AI Reports.</p></div>
  </>:<div className="empty-state panel"><span className="empty-icon"><ShieldAlert size={25}/></span><h3>Your assessment will appear here</h3><p>Submit transaction context to review the Risk Engine score and dimension results. Open AI Reports for the report and Provider Evidence for provider details.</p><div className="empty-steps"><span>01 &nbsp; Enter transaction details</span><span>02 &nbsp; Select a risk profile</span><span>03 &nbsp; Review analysis</span></div></div>}</section>
 </div>
}
