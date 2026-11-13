import { useEffect, useState } from 'react'
import { LoaderCircle, MessageCircle, Send, Trash2 } from 'lucide-react'
import type { ChatContextType, ChatMessage } from '../types'
import { api } from '../services/api'

type Props = {
  analysisId: number|null
  contextType: ChatContextType
  title: string
  description: string
  placeholder: string
}

export default function ContextChat({analysisId,contextType,title,description,placeholder}:Props) {
  const [input,setInput]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [failedQuestion,setFailedQuestion]=useState('')
  const [sessionId,setSessionId]=useState<number|null>(null)
  const [messages,setMessages]=useState<ChatMessage[]>([])
  const [historyBusy,setHistoryBusy]=useState(false)
  const storageKey=analysisId?`fraud-radar-chat:${analysisId}:${contextType}`:null

  useEffect(()=>{
    let active=true
    setMessages([]);setSessionId(null)
    if(!analysisId||!storageKey)return()=>{active=false}
    let savedId:number|null=null
    try{const stored=sessionStorage.getItem(storageKey);if(stored)savedId=Number(stored)}catch{/* Browser storage can be disabled. */}
    if(!savedId||!Number.isInteger(savedId)||savedId<1)return()=>{active=false}
    setSessionId(savedId);setHistoryBusy(true)
    void api.chatHistory(analysisId,savedId).then(history=>{
      if(active&&history.analysis_id===analysisId&&history.session_id===savedId)setMessages(history.messages)
    }).catch(()=>{
      if(active){setSessionId(null);try{sessionStorage.removeItem(storageKey)}catch{/* Ignore unavailable browser storage. */}}
    }).finally(()=>{if(active)setHistoryBusy(false)})
    return()=>{active=false}
  },[analysisId,contextType,storageKey])

  const ask=async(question=input)=>{
    const trimmed=question.trim()
    if(!analysisId||!trimmed||busy)return
    setBusy(true);setError('');setFailedQuestion('')
    setMessages(current=>{
      const last=current[current.length-1]
      return last?.role==='user'&&last.content===trimmed?current:[...current,{role:'user',content:trimmed,created_at:new Date().toISOString()}]
    })
    setInput('')
    try {
      const reply=await api.chat(analysisId,trimmed,sessionId,contextType)
      setSessionId(reply.session_id)
      try{if(storageKey)sessionStorage.setItem(storageKey,String(reply.session_id))}catch{/* Backend history remains available for this mounted session. */}
      setMessages(current=>[...current,{role:'assistant',content:reply.answer,created_at:reply.created_at}])
    } catch(err) {
      setFailedQuestion(trimmed)
      setError(err instanceof Error?err.message:'Fraud Detective is temporarily unavailable.')
    } finally { setBusy(false) }
  }

  const clear=async()=>{
    if(sessionId&&analysisId)try{await api.clearChat(analysisId,sessionId)}catch{/* Clear local conversation even if the API is unavailable. */}
    try{if(storageKey)sessionStorage.removeItem(storageKey)}catch{/* Ignore unavailable browser storage. */}
    setSessionId(null);setMessages([]);setError('');setFailedQuestion('')
  }

  return <section className="panel fraud-chat-panel">
    <div className="panel-head"><div><span className="eyebrow">{contextType==='provider_evidence'?'PROVIDER EVIDENCE ONLY':'CURRENT REPORT ONLY'}</span><h3 style={{marginTop:5}}><MessageCircle size={15} style={{verticalAlign:'-3px',marginRight:6}}/>{title}</h3><p>{description}</p></div><button className="icon-button" title="Clear conversation" onClick={()=>void clear()} disabled={busy}><Trash2 size={15}/></button></div>
    <div className="chat-messages">{messages.length===0&&!busy?<div className="chat-empty">{historyBusy?'Restoring this analysis conversation…':!analysisId?'Run a transaction analysis to start a chat for its current results.':contextType==='provider_evidence'?'Ask about provider fields, statuses, differences, or how mapped evidence connects to a Risk Engine dimension.':'Ask about the score, dimension contributions, evidence interpretation, or recommendations.'}</div>:messages.map((message,index)=><div className={`chat-message ${message.role}`} key={`${message.created_at}-${index}`}><b>{message.role==='assistant'?'DeepSeek · AI explanation':'You'}</b><p>{message.content}</p></div>)}{busy&&<div className="chat-message assistant"><b>DeepSeek</b><p><LoaderCircle className="spin" size={14}/> Thinking…</p></div>}</div>
    {error&&<div className="error-box" style={{marginBottom:8}}>{error}{failedQuestion&&<button className="text-button" onClick={()=>void ask(failedQuestion)}>Retry</button>}</div>}
    <form className="chat-input-row" onSubmit={event=>{event.preventDefault();void ask()}}><input value={input} maxLength={1000} onChange={event=>setInput(event.target.value)} placeholder={placeholder} disabled={busy||!analysisId}/><button className="primary-button" disabled={busy||!analysisId||!input.trim()} aria-label="Send question">{busy?<LoaderCircle className="spin" size={15}/>:<Send size={15}/>}</button></form>
  </section>
}
