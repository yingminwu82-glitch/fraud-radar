import { useEffect, useMemo, useState } from 'react'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import Dashboard from './pages/Dashboard'
import TransactionAnalysis from './pages/TransactionAnalysis'
import RiskPreferences from './pages/RiskPreferences'
import Placeholder from './pages/Placeholder'
import { api } from './services/api'
import type { RiskProfile } from './types'

const descriptions:Record<string,string>={Overview:'Monitor risk signals and transaction activity across your workspace.', 'Transaction Analysis':'Evaluate a transaction with transparent, profile-based risk scoring.','Risk Preferences':'Configure the signals that matter most to your institution.','API Monitoring':'Review the status of connected and planned intelligence providers.','AI Reports':'Explore the explainable reporting layer for analyst-ready insights.','Fraud Detective':'Investigate suspicious indicators with guided analyst assistance.','Settings':'Manage configuration for your Fraud Radar prototype.'}
export default function App(){
 const [page,setPage]=useState('Overview'),[online,setOnline]=useState(false),[profiles,setProfiles]=useState<RiskProfile[]>([]),[loadError,setLoadError]=useState('')
 useEffect(()=>{let active=true;const load=async()=>{try{const [health,loadedProfiles]=await Promise.all([api.health(),api.profiles()]);if(active){setOnline(health.status==='ok');setProfiles(loadedProfiles)}}catch{if(active){setOnline(false);setLoadError('Start the FastAPI service to connect the dashboard.')}}};void load();const timer=window.setInterval(()=>void api.health().then(()=>setOnline(true)).catch(()=>setOnline(false)),30000);return()=>{active=false;window.clearInterval(timer)}},[])
 const title=useMemo(()=>page,[page])
 const setProfile=(updated:RiskProfile)=>setProfiles(current=>current.map(profile=>profile.id===updated.id?updated:profile))
 return <div className="app-shell"><Sidebar page={page} setPage={setPage} online={online}/><main className="main-area"><Header title={title} subtitle={descriptions[page]}/><div className="page-content">{loadError&&!online&&<div className="connection-notice">{loadError} &nbsp; Start with <code>uvicorn app.main:app --reload</code> from the backend folder.</div>}{page==='Overview'?<Dashboard onAnalyze={()=>setPage('Transaction Analysis')}/>:page==='Transaction Analysis'?<TransactionAnalysis profiles={profiles}/>:page==='Risk Preferences'?<RiskPreferences profiles={profiles} onSaved={setProfile}/>:<Placeholder page={page}/>}</div></main></div>
}
