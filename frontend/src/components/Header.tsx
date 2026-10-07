import { ChevronDown, Search, ShieldCheck } from 'lucide-react'

export default function Header({title,subtitle}:{title:string;subtitle:string}){return <header className="topbar"><div><div className="breadcrumbs">WORKSPACE <span>/</span> {title.toUpperCase()}</div><h1>{title}</h1><p>{subtitle}</p></div><div className="top-actions"><div className="secure-badge"><ShieldCheck size={15}/> Secure session</div><button className="icon-button"><Search size={18}/></button><button className="date-button">Last 24 hours <ChevronDown size={15}/></button></div></header>}
