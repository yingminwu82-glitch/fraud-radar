import { Activity, Bell, Bot, CircleHelp, FileText, Gauge, Network, Settings2, SlidersHorizontal, WalletCards } from 'lucide-react'

const items = [
  {group:'WORKSPACE', links:[['Overview', Gauge], ['Transaction Analysis', WalletCards], ['Risk Preferences', SlidersHorizontal]]},
  {group:'INTELLIGENCE', links:[['API Monitoring', Network], ['AI Reports', FileText], ['Fraud Detective', Bot]]},
  {group:'SYSTEM', links:[['Settings', Settings2]]},
] as const

export default function Sidebar({page, setPage, online}:{page:string;setPage:(page:string)=>void;online:boolean}) {
 return <aside className="sidebar">
   <div className="brand"><span className="brand-mark"><RadarMark /></span><span><b>fraud radar</b><small>RISK INTELLIGENCE</small></span></div>
   <div className="workspace-select"><div className="workspace-icon">N</div><span><b>Northstar Bank</b><small>Workspace</small></span><span className="chevrons">⌃<br/>⌄</span></div>
   {items.map(section=><div className="nav-section" key={section.group}><div className="nav-label">{section.group}</div>{section.links.map(([label,Icon])=><button key={label} onClick={()=>setPage(label)} className={`nav-link ${page===label?'active':''}`}><Icon size={17}/><span>{label}</span>{label==='Transaction Analysis'&&<span className="nav-dot"/>}</button>)}</div>)}
   <div className="sidebar-bottom"><div className="system-status"><span className={`status-dot ${online?'':'offline'}`}/><span><b>{online?'All systems operational':'API unavailable'}</b><small>{online?'Last checked just now':'Check backend connection'}</small></span><Activity size={16}/></div><button className="nav-link help"><CircleHelp size={17}/> Help center</button><div className="profile-row"><div className="avatar">JM</div><span><b>Jamie Morgan</b><small>Risk Analyst</small></span><Bell size={17}/></div></div>
 </aside>
}

function RadarMark(){return <div className="radar-mark"><span/><i/><i/><i/></div>}
