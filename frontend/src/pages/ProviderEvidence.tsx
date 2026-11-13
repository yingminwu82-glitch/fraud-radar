import { AlertCircle, CheckCircle2, Database, ShieldAlert } from 'lucide-react'
import ContextChat from '../components/ContextChat'
import type { AnalysisSelection } from '../types'

const PROVIDERS=['FFraud','IP-DB','VirusTotal'] as const
const DIRECT_FIELD_FACTORS:Record<string,Record<string,string>>={
 FFraud:{fraud_score:'Fraud score',vpn:'VPN',proxy:'Proxy',tor:'Tor',hosting:'Hosting',is_abuser:'Known abuser',recent_abuse:'Recent abuse',threat_tags:'Threat tags'},
 'IP-DB':{abuseConfidenceScore:'Abuse confidence',blacklistSources:'Blacklist sources',networkType:'Network type'},
 VirusTotal:{reputation:'Community reputation',last_analysis_stats:'Malicious scan ratio'},
}
const COUNTRY_FIELDS:Record<string,string[]>={FFraud:['geo.country','geo.country_code','geo.country_name'],'IP-DB':['countryCode','countryName'],VirusTotal:['country']}

function printable(value:unknown){return typeof value==='string'?value:JSON.stringify(value)??'N/A'}
function providerFields(provider:string,raw:Record<string,unknown>|null){
 if(!raw)return[]
 return Object.entries(raw).flatMap(([field,value])=>{
  if(provider==='FFraud'&&field==='geo'&&value&&typeof value==='object'&&!Array.isArray(value))return Object.entries(value as Record<string,unknown>).map(([subfield,subvalue])=>[`geo.${subfield}`,subvalue] as [string,unknown])
  return [[field,value] as [string,unknown]]
 })
}

export default function ProviderEvidence({selected}:{selected:AnalysisSelection|null}) {
 const analysis=selected?.result??null
 const results=new Map((analysis?.provider_results??[]).map(provider=>[provider.provider,provider]))
 const geographicCategory=analysis?.categories.find(category=>category.category==='geographic_risk')
 const hasGeographicMapping=Boolean(geographicCategory?.evidence.some(evidence=>evidence.factor==='IP Country Mismatch'))

 return <div className="provider-evidence-page">
  <section className="panel provider-evidence-panel">
   <div className="panel-head"><div><span className="eyebrow">CURRENT ANALYSIS EVIDENCE</span><h3 style={{marginTop:5}}><Database size={15} style={{verticalAlign:'-3px',marginRight:6}}/>Provider Evidence</h3><p>{analysis?`Analysis ${analysis.analysis_id} · ${analysis.transaction_id}. Provider values and normalized score signals are shown separately.`:'No analysis selected. Run Transaction Analysis to populate provider evidence.'}</p></div></div>
   <div className="provider-evidence-list">{PROVIDERS.map(name=>{
    const provider=results.get(name)
    const raw=provider?.raw_result??null
    const fields=providerFields(name,raw)
    const signals=provider?.signals??[]
    return <details className="provider-evidence-card" key={name} open={false}>
     <summary><span><b>{name}</b><small>{provider?`${provider.status} · ${provider.signal_count} signals`:'N/A · no current analysis'}</small></span>{provider?.error?<AlertCircle size={16} className="provider-error-icon"/>:<CheckCircle2 size={16} className="provider-ok-icon"/>}</summary>
     <div className="provider-evidence-details">
      <div className="provider-evidence-meta"><span>Status</span><b>{provider?.status??'N/A'}</b><span>Signal count</span><b>{provider?provider.signal_count:'N/A'}</b>{provider?.latency_ms!==null&&provider?.latency_ms!==undefined&&<><span>Latency</span><b>{provider.latency_ms} ms</b></>}</div>
      {provider?.error&&<div className="provider-error-note"><AlertCircle size={14}/>{provider.error}</div>}
      <h4>Raw provider evidence</h4>{fields.length?fields.map(([field,value])=>{
       const nestedCountry=COUNTRY_FIELDS[name]?.includes(field)
       const mappedFactor=DIRECT_FIELD_FACTORS[name]?.[field]
       const linkedSignal=mappedFactor?signals.find(signal=>signal.factor===mappedFactor):undefined
       const geoMapped=Boolean(nestedCountry&&hasGeographicMapping)
       const category=linkedSignal?analysis?.categories.find(item=>item.category===linkedSignal.category):geoMapped?geographicCategory:undefined
       const classification=linkedSignal&&linkedSignal.risk_score!==null&&!linkedSignal.missing?'Scoreable signal':geoMapped?'Mapped through geographic comparison':'Contextual / not scoreable'
       return <div className="provider-field-row" key={field}><div className="provider-field-name">{field}</div><code>{printable(value)}</code><div className="provider-field-mapping"><span>{category?.dimension_name??'No Risk Dimension mapping'}</span><b>{classification}</b></div></div>
      }):<p className="provider-no-data">{provider?.status==='success'?'No raw provider fields were returned.':'Raw evidence unavailable for this analysis.'}</p>}
      <h4>Backend-normalized signals</h4>{signals.length?signals.map((signal,index)=>{
       const category=analysis?.categories.find(item=>item.category===signal.category)
       const scoreable=signal.risk_score!==null&&!signal.missing
       return <div className="provider-signal-row" key={`${signal.factor}-${index}`}><div><b>{signal.factor}</b><small>{signal.category} · {category?.dimension_name??'Risk Dimension unavailable'}</small></div><span>{signal.risk_score===null||signal.missing?'N/A':`${signal.risk_score}/100`}</span><b className={scoreable?'evidence-scoreable':'evidence-contextual'}>{scoreable?'Scoreable':'Contextual / unavailable'}</b><small>Value: {signal.value===null?'N/A':printable(signal.value)}</small></div>
      }):<p className="provider-no-data">No normalized signals available. This does not mean zero risk.</p>}
     </div>
    </details>
   })}</div>
   {!analysis&&<div className="missing-note"><ShieldAlert size={15}/> Provider fields, signals and errors remain N/A until an analysis is selected.</div>}
  </section>
  <ContextChat key={`${analysis?.analysis_id??'none'}-provider-evidence`} analysisId={analysis?.analysis_id??null} contextType="provider_evidence" title="Provider Evidence · DeepSeek Q&A" description="Ask about FFraud, IP-DB and VirusTotal fields, normalized signals, dimension mappings, provider differences, and what contributed to the score." placeholder="Ask about a provider value or signal…"/>
 </div>
}
