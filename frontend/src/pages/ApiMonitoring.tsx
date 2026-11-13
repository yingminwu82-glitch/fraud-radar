import { useEffect, useState } from 'react'
import { Activity, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import type { ProviderStatus } from '../types'

export default function ApiMonitoring(){
 const [items,setItems]=useState<ProviderStatus[]>([]),[error,setError]=useState('')
 const load=()=>api.providerStatus().then(setItems).catch(e=>setError(e instanceof Error?e.message:'Could not load provider status'))
 useEffect(()=>{void load();const id=window.setInterval(()=>void load(),15000);return()=>window.clearInterval(id)},[])
 return <section className="panel placeholder-list"><div className="panel-head"><div><h3>Intelligence provider health</h3><p>Latest backend request status and response time</p></div><button className="icon-button" aria-label="Refresh provider statuses" onClick={()=>void load()}><RefreshCw size={15}/></button></div>{error&&<div className="error-box">{error}</div>}{items.map((item,i)=><div className="status-row" key={item.provider}><span className="status-index">0{i+1}</span><span><b>{item.provider}</b><small style={{display:'block',color:'#7f93a5',marginTop:4}}>{item.mode} · {item.last_checked?new Date(item.last_checked).toLocaleString():'Not queried yet'}</small></span><span className={item.status==='success'||item.status==='mock_ready'?'status-ready':'status-planned'}><Activity size={13}/>{item.status}{item.latency_ms!==null?` · ${item.latency_ms} ms`:''}</span>{item.error&&<small style={{color:'#ff9a9a'}}>{item.error}</small>}</div>)}</section>
}
