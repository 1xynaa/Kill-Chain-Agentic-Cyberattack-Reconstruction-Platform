import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useInvestigation } from './hooks/useInvestigation'
import type { Finding, Stage, IOCEntry } from './api/types'
import { STAGE_SHORT } from './api/types'
import type { AgentStep, StageStatus, AppState } from './hooks/useInvestigation'


// ─────────────────────────────────────────────────────────────────────────────
// Palette — used directly, not threaded through variables
// ─────────────────────────────────────────────────────────────────────────────
const BG    = '#0A0B0D'
const PANEL = '#12141A'
const PANEL2= '#0E1014'
const EDGE  = '#1E222A'
const EDGE2 = '#262B34'

// Text
const T0 = '#D4D8DF'   // primary
const T1 = '#8B92A0'   // secondary
const T2 = '#4B5363'   // tertiary/ghost

// Accents — used sparingly
const CYAN  = '#5B6AF5'
const GREEN = '#2EC27E'
const AMBER = '#E09B2E'
const RED   = '#E04060'

const a = (hex: string, o: number) => {
  const n = parseInt(hex.replace('#',''), 16)
  return `rgba(${n>>16&255},${n>>8&255},${n&255},${o})`
}

// ─────────────────────────────────────────────────────────────────────────────
// Types for graph visualization
// ─────────────────────────────────────────────────────────────────────────────
type NodeKind  = 'ip' | 'host' | 'domain' | 'file' | 'hash' | 'process'

interface GNode   { id: string; label: string; sub: string; kind: NodeKind; r: number; col: string }
interface GEdge   { id: string; from: string; to: string; label: string; col: string }
interface Phys    { x: number; y: number; vx: number; vy: number }

// ─────────────────────────────────────────────────────────────────────────────
// Stage data
// ─────────────────────────────────────────────────────────────────────────────
const STAGES = [
  { id:'recon',   label:'Reconnaissance' },
  { id:'weapon',  label:'Weaponization' },
  { id:'deliver', label:'Delivery' },
  { id:'exploit', label:'Exploitation' },
  { id:'install', label:'Installation' },
  { id:'c2',      label:'C2' },
  { id:'actions', label:'Actions' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic graph builder — creates nodes/edges from findings + IOCs
// ─────────────────────────────────────────────────────────────────────────────
function buildGraph(findings: Finding[], iocs: IOCEntry[]): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = []
  const edges: GEdge[] = []
  const nodeIds = new Set<string>()

  function addNode(id: string, label: string, sub: string, kind: NodeKind, col: string, r = 11) {
    if (nodeIds.has(id)) return
    nodeIds.add(id)
    nodes.push({ id, label, sub, kind, r, col })
  }

  // Add IOC nodes
  for (const ioc of iocs) {
    const id = `ioc-${ioc.value.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 20)}`
    switch (ioc.type) {
      case 'ip':
        addNode(id, ioc.value, 'IP Address', 'ip', RED, 12)
        break
      case 'domain':
        addNode(id, ioc.value.length > 20 ? ioc.value.slice(0, 18) + '…' : ioc.value, 'Domain', 'domain', RED, 12)
        break
      case 'sha256':
        addNode(id, ioc.value.slice(0, 12) + '…', 'SHA-256', 'hash', GREEN, 10)
        break
      case 'url':
        addNode(id, ioc.value.length > 20 ? '…' + ioc.value.slice(-18) : ioc.value, 'URL', 'domain', AMBER, 10)
        break
    }
  }

  // Add finding nodes (one per source_file + stage combo)
  for (const f of findings) {
    if (f.source_file) {
      const fileId = `file-${f.source_file.replace(/[^a-zA-Z0-9]/g, '_')}`
      addNode(fileId, f.source_file.length > 16 ? f.source_file.slice(0, 14) + '…' : f.source_file, 'Evidence', 'file', AMBER, 14)

      // Link file to its IOCs
      for (const iocVal of f.iocs) {
        const iocId = `ioc-${iocVal.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 20)}`
        if (nodeIds.has(iocId)) {
          const edgeId = `e-${fileId}-${iocId}`
          if (!edges.find(e => e.id === edgeId)) {
            edges.push({ id: edgeId, from: fileId, to: iocId, label: 'contains', col: AMBER })
          }
        }
      }

      // Link file to its stage
      if (f.stage) {
        const stageId = `stage-${f.stage.replace(/[^a-zA-Z0-9]/g, '_')}`
        const shortLabel = STAGE_SHORT[f.stage] || f.stage
        addNode(stageId, shortLabel, `${(f.confidence * 100).toFixed(0)}%`, 'host', CYAN, 16)
        const edgeId = `e-${fileId}-${stageId}`
        if (!edges.find(e => e.id === edgeId)) {
          edges.push({ id: edgeId, from: fileId, to: stageId, label: f.title.split(' ')[0], col: CYAN })
        }
      }
    }
  }

  // If empty, return empty
  return { nodes, edges }
}


// ─────────────────────────────────────────────────────────────────────────────
// Force graph
// ─────────────────────────────────────────────────────────────────────────────
function useGraph(nodes: GNode[], edges: GEdge[], W: number, H: number) {
  const [pos, setPos] = useState<Record<string,{x:number;y:number}>>({})
  const state = useRef<Record<string,Phys>>({})
  const raf   = useRef(0)
  const key   = nodes.map(n=>n.id).join()

  useEffect(()=>{
    if (!W||!H) return
    let tick = 0
    nodes.forEach(n=>{
      if (!state.current[n.id]) {
        state.current[n.id] = {
          x: W/2+(Math.random()-.5)*W*.6,
          y: H/2+(Math.random()-.5)*H*.6,
          vx: 0, vy: 0,
        }
      }
    })
    // Clean removed nodes
    for (const id of Object.keys(state.current)) {
      if (!nodes.find(n => n.id === id)) {
        delete state.current[id]
      }
    }

    const run = ()=>{
      const live = nodes.filter(n=>state.current[n.id])
      tick++
      // repulsion
      for (let i=0;i<live.length;i++) for (let j=i+1;j<live.length;j++) {
        const aa=state.current[live[i].id], b=state.current[live[j].id]
        const dx=aa.x-b.x, dy=aa.y-b.y, d=Math.sqrt(dx*dx+dy*dy)||1, f=2200/(d*d)
        aa.vx+=(dx/d)*f; aa.vy+=(dy/d)*f; b.vx-=(dx/d)*f; b.vy-=(dy/d)*f
      }
      // springs
      const REST = Math.min(W,H)*.30
      edges.forEach(e=>{
        const aa=state.current[e.from], b=state.current[e.to]; if(!aa||!b)return
        const dx=b.x-aa.x, dy=b.y-aa.y, d=Math.sqrt(dx*dx+dy*dy)||1, f=(d-REST)*.016
        aa.vx+=(dx/d)*f; aa.vy+=(dy/d)*f; b.vx-=(dx/d)*f; b.vy-=(dy/d)*f
      })
      // gentle center pull
      live.forEach(n=>{
        state.current[n.id].vx += (W*.5-state.current[n.id].x)*.001
        state.current[n.id].vy += (H*.5-state.current[n.id].y)*.001
      })
      const PAD = 32
      live.forEach(n=>{
        const nd=state.current[n.id]
        nd.vx*=.80; nd.vy*=.80
        nd.x=Math.max(PAD,Math.min(W-PAD,nd.x+nd.vx))
        nd.y=Math.max(PAD,Math.min(H-PAD,nd.y+nd.vy))
      })
      if (tick%2===0) setPos(Object.fromEntries(live.map(n=>[n.id,{x:state.current[n.id].x,y:state.current[n.id].y}])))
      if (tick<280) raf.current = requestAnimationFrame(run)
    }
    raf.current = requestAnimationFrame(run)
    return ()=>cancelAnimationFrame(raf.current)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[key,W,H])

  return pos
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared components
// ─────────────────────────────────────────────────────────────────────────────

function Label({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ fontSize:10, fontWeight:500, color:T1, letterSpacing:'0.06em', textTransform:'uppercase' }}>
      {children}
    </span>
  )
}

function Mono({ children, col }: { children: React.ReactNode; col?: string }) {
  return (
    <span style={{ fontFamily:'JetBrains Mono', fontSize:11, color: col||T0 }}>
      {children}
    </span>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Top bar
// ─────────────────────────────────────────────────────────────────────────────
function TopBar({ state, elapsed, calls, investigationId, onReset }: { state:AppState; elapsed:number; calls:number; investigationId:string|null; onReset:()=>void }) {
  const [search, setSearch] = useState('')
  const [searchFocus, setSearchFocus] = useState(false)
  const [notifOpen, setNotifOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const pct = Math.min(calls, 100)
  const meterCol = pct>80 ? RED : pct>55 ? AMBER : T2
  const fmt = (s:number) => `${String(Math.floor(s/60)).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`

  const shortId = investigationId ? investigationId.split('-')[0].toUpperCase() : '—'

  return (
    <header style={{
      height:52, flexShrink:0,
      background:PANEL, borderBottom:`1px solid ${EDGE}`,
      display:'flex', alignItems:'center', padding:'0 20px',
      position:'relative', zIndex:20,
    }}>
      {/* Logo */}
      <div style={{ display:'flex', alignItems:'center', gap:10, flex:'none' }}>
        <svg width="28" height="18" viewBox="0 0 40 24" fill="none">
          <circle cx="14" cy="12" r="9.5" stroke={CYAN} strokeWidth="2" fill="none"/>
          <circle cx="26" cy="12" r="9.5" stroke="rgba(255,255,255,0.45)" strokeWidth="2" fill="none"/>
          <line x1="22" y1="2" x2="18" y2="22" stroke={RED} strokeWidth="2" strokeLinecap="round"/>
        </svg>
        <span style={{ display:'flex', alignItems:'baseline', gap:0, lineHeight:1 }}>
          <span style={{ fontFamily:'Poppins', fontSize:15, fontWeight:800, letterSpacing:'-0.02em', color:'#fff' }}>kill</span>
          <span style={{ fontFamily:'Poppins', fontSize:15, fontWeight:300, letterSpacing:'-0.02em', color:'rgba(255,255,255,0.6)' }}>chain</span>
        </span>
        {state !== 'empty' && (
          <div style={{ display:'flex', alignItems:'center', gap:5 }}>
            <span className="live-dot" style={{ width:5, height:5, borderRadius:'50%', background: state === 'active' ? GREEN : state === 'complete' ? CYAN : AMBER }}/>
            <span style={{ fontSize:10, color:T2, letterSpacing:'0.05em' }}>
              {state === 'active' ? 'Live' : state === 'complete' ? 'Done' : state === 'uploading' ? 'Uploading' : 'Error'}
            </span>
          </div>
        )}
      </div>

      {/* Center */}
      {state !== 'empty' && (
        <div style={{ position:'absolute', left:'50%', transform:'translateX(-50%)', display:'flex', alignItems:'center', gap:24 }}>
          {state === 'complete' && (
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="6" stroke={GREEN} strokeWidth="1.3"/>
                <path d="M4 7l2.5 2.5 3.5-3.5" stroke={GREEN} strokeWidth="1.5" strokeLinecap="round" className="check-draw"/>
              </svg>
              <span style={{ fontSize:12, fontWeight:500, color:GREEN }}>Investigation complete</span>
            </div>
          )}
          <div style={{ display:'flex', gap:24 }}>
            <div>
              <div style={{ fontSize:10, color:T2, marginBottom:1 }}>Case</div>
              <Mono col={T0}>INV-{shortId}</Mono>
            </div>
            <div style={{ width:1, background:EDGE }}/>
            <div>
              <div style={{ fontSize:10, color:T2, marginBottom:1 }}>Elapsed</div>
              <Mono>{fmt(elapsed)}</Mono>
            </div>
            <div style={{ width:1, background:EDGE }}/>
            <div>
              <div style={{ fontSize:10, color:T2, marginBottom:1 }}>Target</div>
              <Mono col={AMBER}>{investigationId ? 'Evidence' : '—'}</Mono>
            </div>
          </div>
        </div>
      )}

      {/* Right */}
      <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:8 }}>

        {/* Search */}
        <div style={{
          display:'flex', alignItems:'center', gap:7,
          background: searchFocus ? a('#fff',.06) : a('#fff',.03),
          border:`1px solid ${searchFocus ? EDGE2 : EDGE}`,
          borderRadius:5, padding:'0 10px', height:30,
          transition:'background .15s, border-color .15s',
          width: searchFocus ? 220 : 160,
        }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" style={{ flexShrink:0 }}>
            <circle cx="5" cy="5" r="3.5" stroke="rgba(255,255,255,0.6)" strokeWidth="1.3"/>
            <line x1="7.8" y1="7.8" x2="10.5" y2="10.5" stroke="rgba(255,255,255,0.6)" strokeWidth="1.3" strokeLinecap="round"/>
          </svg>
          <input
            value={search} onChange={e=>setSearch(e.target.value)}
            onFocus={()=>setSearchFocus(true)} onBlur={()=>setSearchFocus(false)}
            placeholder="Search cases, IOCs…"
            style={{
              background:'transparent', border:'none', outline:'none',
              fontFamily:'Inter', fontSize:11, color:T0, width:'100%',
            }}
          />
          {search && (
            <button onClick={()=>setSearch('')} style={{ background:'none', border:'none', cursor:'pointer', padding:0, color:T2, fontSize:12, lineHeight:1 }}>×</button>
          )}
        </div>

        {state !== 'empty' && <>
          <div style={{ display:'flex', flexDirection:'column', gap:3, minWidth:100 }}>
            <div style={{ display:'flex', justifyContent:'space-between' }}>
              <span style={{ fontSize:10, color:T2 }}>Tool calls</span>
              <Mono col={meterCol}>{calls}/100</Mono>
            </div>
            <div style={{ height:2, background:EDGE, borderRadius:1, overflow:'hidden' }}>
              <div className="bar-fill" style={{ height:'100%', width:`${pct}%`, background:meterCol, borderRadius:1 }}/>
            </div>
          </div>

          <button style={{
            padding:'5px 14px', background:'transparent',
            border:`1px solid ${EDGE2}`, borderRadius:3,
            fontSize:11, color:T1, cursor:'pointer',
            transition:'border-color .15s, color .15s',
          }}
          onClick={onReset}
          onMouseEnter={e=>{ e.currentTarget.style.borderColor=T1; e.currentTarget.style.color=T0 }}
          onMouseLeave={e=>{ e.currentTarget.style.borderColor=EDGE2; e.currentTarget.style.color=T1 }}>
            New
          </button>
        </>}

        <div style={{ width:1, height:20, background:EDGE, margin:'0 4px' }}/>

        {/* Notifications */}
        <div style={{ position:'relative' }}>
          <button onClick={()=>{ setNotifOpen(o=>!o); setSettingsOpen(false) }} style={{
            width:30, height:30, display:'flex', alignItems:'center', justifyContent:'center',
            background: notifOpen ? a('#fff',.06) : 'transparent',
            border:`1px solid ${notifOpen ? EDGE2 : 'transparent'}`,
            borderRadius:5, cursor:'pointer', position:'relative', transition:'background .15s',
          }}
          onMouseEnter={e=>{ if(!notifOpen) e.currentTarget.style.background=a('#fff',.04) }}
          onMouseLeave={e=>{ if(!notifOpen) e.currentTarget.style.background='transparent' }}>
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <path d="M7.5 1.5C5 1.5 3 3.5 3 6v3.5L1.5 11h12L12 9.5V6c0-2.5-2-4.5-4.5-4.5z" stroke="rgba(255,255,255,0.85)" strokeWidth="1.3" fill="none"/>
              <path d="M6 11.5c0 .83.67 1.5 1.5 1.5S9 12.33 9 11.5" stroke="rgba(255,255,255,0.85)" strokeWidth="1.3" strokeLinecap="round" fill="none"/>
            </svg>
          </button>

          {notifOpen && (
            <div className="fade-up" style={{
              position:'absolute', top:'calc(100% + 8px)', right:0,
              width:280, background:PANEL, border:`1px solid ${EDGE2}`,
              borderRadius:6, overflow:'hidden', zIndex:100,
              boxShadow:'0 8px 32px rgba(0,0,0,0.5)',
            }}>
              <div style={{ padding:'10px 14px 8px', borderBottom:`1px solid ${EDGE}`, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                <Label>Notifications</Label>
              </div>
              <div style={{ padding:'16px 14px', textAlign:'center', color:T2, fontSize:11 }}>
                No notifications yet
              </div>
            </div>
          )}
        </div>

        {/* Settings */}
        <div style={{ position:'relative' }}>
          <button onClick={()=>{ setSettingsOpen(o=>!o); setNotifOpen(false) }} style={{
            width:30, height:30, display:'flex', alignItems:'center', justifyContent:'center',
            background: settingsOpen ? a('#fff',.06) : 'transparent',
            border:`1px solid ${settingsOpen ? EDGE2 : 'transparent'}`,
            borderRadius:5, cursor:'pointer', transition:'background .15s',
          }}
          onMouseEnter={e=>{ if(!settingsOpen) e.currentTarget.style.background=a('#fff',.04) }}
          onMouseLeave={e=>{ if(!settingsOpen) e.currentTarget.style.background='transparent' }}>
            <svg width="15" height="15" viewBox="0 0 16 16">
              <path fillRule="evenodd" fill="rgba(255,255,255,0.85)" d="M8 4.754a3.246 3.246 0 1 0 0 6.492 3.246 3.246 0 0 0 0-6.492zM5.754 8a2.246 2.246 0 1 1 4.492 0 2.246 2.246 0 0 1-4.492 0z"/>
              <path fillRule="evenodd" fill="rgba(255,255,255,0.85)" d="M9.796 1.343c-.527-1.79-3.065-1.79-3.592 0l-.094.319a.873.873 0 0 1-1.255.52l-.292-.16c-1.64-.892-3.433.902-2.54 2.541l.159.292a.873.873 0 0 1-.52 1.255l-.319.094c-1.79.527-1.79 3.065 0 3.592l.319.094a.873.873 0 0 1 .52 1.255l-.16.292c-.892 1.64.901 3.434 2.541 2.54l.292-.159a.873.873 0 0 1 1.255.52l.094.319c.527 1.79 3.065 1.79 3.592 0l.094-.319a.873.873 0 0 1 1.255-.52l.292.16c1.64.892 3.433-.902 2.54-2.541l-.159-.292a.873.873 0 0 1 .52-1.255l.319-.094c1.79-.527 1.79-3.065 0-3.592l-.319-.094a.873.873 0 0 1-.52-1.255l.16-.292c.892-1.64-.901-3.433-2.541-2.54l-.292.159a.873.873 0 0 1-1.255-.52l-.094-.319z"/>
            </svg>
          </button>

          {settingsOpen && (
            <div className="fade-up" style={{
              position:'absolute', top:'calc(100% + 8px)', right:0,
              width:200, background:PANEL, border:`1px solid ${EDGE2}`,
              borderRadius:6, overflow:'hidden', zIndex:100,
              boxShadow:'0 8px 32px rgba(0,0,0,0.5)',
            }}>
              {['Preferences','API Keys','Integrations','Appearance'].map((label,i,arr) => (
                <button key={label} style={{
                  width:'100%', display:'flex', alignItems:'center',
                  padding:'10px 14px', background:'transparent', border:'none',
                  borderBottom: i < arr.length-1 ? `1px solid ${EDGE}` : 'none',
                  cursor:'pointer', fontSize:12, color:'rgba(255,255,255,0.8)',
                  textAlign:'left', transition:'background .1s', letterSpacing:'0.01em',
                }}
                onMouseEnter={e=>(e.currentTarget.style.background=a('#fff',.05))}
                onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>

      </div>
    </header>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Reasoning feed — driven by live WebSocket steps
// ─────────────────────────────────────────────────────────────────────────────
function ReasoningFeed({ steps, thinking }: { steps:AgentStep[]; thinking:boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const prev = useRef(0)

  useEffect(()=>{
    if (steps.length !== prev.current) {
      prev.current = steps.length
      requestAnimationFrame(()=>{ if (ref.current) ref.current.scrollTop = ref.current.scrollHeight })
    }
  },[steps.length])

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:PANEL }}>
      <div style={{ padding:'14px 16px 12px', borderBottom:`1px solid ${EDGE}`, flexShrink:0 }}>
        <Label>Agent reasoning</Label>
        <span style={{ marginLeft:10, fontSize:10, color:T2 }}>{steps.length} steps</span>
      </div>

      <div ref={ref} style={{ flex:1, overflowY:'auto', padding:'8px 10px', display:'flex', flexDirection:'column', gap:3 }}>
        {steps.map((step, i) => (
          <StepCard key={step.id} step={step} isNew={i===steps.length-1 && steps.length>1}/>
        ))}
        {thinking && (
          <div style={{ padding:'8px 12px', display:'flex', alignItems:'center', gap:6 }}>
            <span className="d1" style={{ width:4, height:4, borderRadius:'50%', background:CYAN }}/>
            <span className="d2" style={{ width:4, height:4, borderRadius:'50%', background:CYAN }}/>
            <span className="d3" style={{ width:4, height:4, borderRadius:'50%', background:CYAN }}/>
            <span style={{ fontSize:11, color:T2, marginLeft:2 }}>Reasoning<span className="blink" style={{ color:CYAN }}>▌</span></span>
          </div>
        )}
      </div>
    </div>
  )
}

function StepCard({ step, isNew }: { step:AgentStep; isNew:boolean }) {
  const [open, setOpen] = useState(isNew)

  const toolColors: Record<string,string> = {
    network:CYAN, file:AMBER, hash:GREEN, process:RED, intel:AMBER,
    file_triage:AMBER, grep_indicators:CYAN, strings_extract:AMBER,
    sha256sum:GREEN, tshark_summary:CYAN, tshark_details:CYAN,
    volatility_info:RED,
  }
  const col = toolColors[step.tool] || CYAN

  return (
    <div
      className={isNew ? 'card-in' : undefined}
      style={{
        borderRadius:3,
        border:`1px solid ${open ? EDGE2 : EDGE}`,
        overflow:'hidden', transition:'border-color .25s',
      }}>
      {/* Header — always visible */}
      <button
        onClick={()=>setOpen(o=>!o)}
        style={{
          width:'100%', display:'flex', alignItems:'flex-start', gap:8,
          padding:'8px 10px', background:'transparent', border:'none', cursor:'pointer',
          textAlign:'left',
        }}>
        <span style={{ width:5, height:5, borderRadius:'50%', background:col, flexShrink:0, marginTop:4 }}/>
        <span style={{ flex:1, fontSize:11, color:T1, lineHeight:1.5 }}>
          {step.thought || `Running ${step.tool}…`}
        </span>
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none"
          style={{ transform:open?'rotate(180deg)':'none', transition:'transform .2s', flexShrink:0, marginTop:2, opacity:.4 }}>
          <path d="M1.5 3l3.5 3.5L8.5 3" stroke={T1} strokeWidth="1.3" strokeLinecap="round"/>
        </svg>
      </button>

      {/* Expanded: action + observation */}
      {open && (
        <div style={{ borderTop:`1px solid ${EDGE}`, padding:'8px 10px', display:'flex', flexDirection:'column', gap:6 }}>
          {/* Action */}
          <div style={{ borderLeft:`2px solid ${a(CYAN,.4)}`, paddingLeft:8 }}>
            <code style={{ fontFamily:'JetBrains Mono', fontSize:10, color:CYAN, wordBreak:'break-all', lineHeight:1.6, display:'block' }}>
              {step.action}
            </code>
          </div>
          {/* Observation */}
          <div style={{ paddingLeft:10 }}>
            <div style={{ fontSize:9, color:T2, marginBottom:3, fontFamily:'JetBrains Mono' }}>{step.ts}</div>
            <code style={{ fontFamily:'JetBrains Mono', fontSize:10, color:T0, wordBreak:'break-all', lineHeight:1.65, display:'block', opacity:.75, maxHeight:120, overflow:'auto' }}>
              {step.obs.length > 500 ? step.obs.slice(0, 500) + '…' : step.obs}
            </code>
          </div>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Kill chain stepper — driven by live stage updates
// ─────────────────────────────────────────────────────────────────────────────
function Stepper({ status, sel, onSel }: { status:Record<string,StageStatus>; sel:string; onSel:(id:string)=>void }) {
  return (
    <div style={{ position:'relative', padding:'6px 0 20px' }}>
      {/* connecting line */}
      <div style={{ position:'absolute', top:14, left:0, right:0, height:1, background:EDGE }}/>
      {/* confirmed fill */}
      {(() => {
        const confirmedCount = STAGES.filter(s=>status[s.id]==='confirmed').length
        const totalPct = confirmedCount / (STAGES.length - 1) * 100
        return <div style={{ position:'absolute', top:14, left:0, height:1, width:`${totalPct}%`, background:GREEN, transition:'width .6s ease-out' }}/>
      })()}
      <div style={{ display:'flex', justifyContent:'space-between', position:'relative' }}>
        {STAGES.map((stage) => {
          const st = status[stage.id] || 'pending'
          const isActive  = st === 'active'
          const isDone    = st === 'confirmed'
          const isSel     = sel === stage.id
          const dotColor  = isDone ? GREEN : isActive ? CYAN : EDGE2

          return (
            <button key={stage.id}
              onClick={()=>onSel(stage.id===sel?'':stage.id)}
              style={{
                display:'flex', flexDirection:'column', alignItems:'center', gap:6,
                background:'transparent', border:'none', cursor:'pointer', padding:0,
              }}>
              {/* dot */}
              <div style={{
                width:11, height:11, borderRadius:'50%',
                background: isDone ? GREEN : isActive ? a(CYAN,.2) : PANEL2,
                border:`1.5px solid ${dotColor}`,
                outline: isSel ? `2px solid ${a(dotColor,.3)}` : 'none',
                outlineOffset:2,
                transition:'all .2s',
                zIndex:1, position:'relative',
              }}/>
              {/* label */}
              <span style={{
                fontSize:9, color: isDone ? GREEN : isActive ? CYAN : T2,
                letterSpacing:'0.03em', whiteSpace:'nowrap',
                fontWeight: isSel ? 500 : 400,
              }}>
                {stage.label}
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence graph — built dynamically from findings
// ─────────────────────────────────────────────────────────────────────────────
function Graph({ nodes, edges, sel }: { nodes:GNode[]; edges:GEdge[]; sel:string }) {
  const ref = useRef<HTMLDivElement>(null)
  const [sz, setSz] = useState({ w:0, h:0 })

  useEffect(()=>{
    const obs = new ResizeObserver(e=>{ const r=e[0]?.contentRect; if(r)setSz({w:r.width,h:r.height}) })
    if (ref.current) obs.observe(ref.current)
    return ()=>obs.disconnect()
  },[])

  const pos = useGraph(nodes, edges, sz.w, sz.h)

  const hl = useMemo(()=>{
    if (!sel) return new Set<string>()
    // Highlight nodes connected to the selected stage
    const stageMap: Record<string,string[]> = {}
    for (const stage of STAGES) {
      const stageNodeId = nodes.find(n => n.id.startsWith(`stage-`) && n.label.toLowerCase().includes(stage.label.toLowerCase().slice(0,4)))?.id
      if (stageNodeId) {
        const connected = new Set<string>([stageNodeId])
        edges.forEach(e => {
          if (e.from === stageNodeId || e.to === stageNodeId) {
            connected.add(e.from)
            connected.add(e.to)
          }
        })
        stageMap[stage.id] = [...connected]
      }
    }
    return new Set(stageMap[sel]||[])
  },[sel, nodes, edges])

  function drawNode(n: GNode) {
    const p = pos[n.id]; if (!p) return null
    const faded = hl.size > 0 && !hl.has(n.id)
    const opacity = faded ? 0.18 : 1
    const fill = a(n.col,.1)
    const stroke = n.col

    let shape: React.ReactNode
    if (n.kind==='host') {
      shape = <rect x={p.x-n.r} y={p.y-n.r} width={n.r*2} height={n.r*2} rx={2} fill={fill} stroke={stroke} strokeWidth={1.5}/>
    } else if (n.kind==='hash') {
      const pts = Array.from({length:6},(_,k)=>{ const angle=k/6*Math.PI*2-Math.PI/2; return `${p.x+n.r*Math.cos(angle)},${p.y+n.r*Math.sin(angle)}` }).join(' ')
      shape = <polygon points={pts} fill={fill} stroke={stroke} strokeWidth={1.5}/>
    } else if (n.kind==='domain'||n.kind==='file') {
      const s=n.r*1.05
      shape = <polygon points={`${p.x},${p.y-s} ${p.x+s},${p.y} ${p.x},${p.y+s} ${p.x-s},${p.y}`} fill={fill} stroke={stroke} strokeWidth={1.5}/>
    } else if (n.kind==='process') {
      const s=n.r*.9
      shape = <polygon points={`${p.x},${p.y-s} ${p.x+s*.87},${p.y+s*.5} ${p.x-s*.87},${p.y+s*.5}`} fill={fill} stroke={stroke} strokeWidth={1.5}/>
    } else {
      shape = <circle cx={p.x} cy={p.y} r={n.r} fill={fill} stroke={stroke} strokeWidth={1.5}/>
    }

    return (
      <g key={n.id} className="node-in" style={{ opacity, transition:'opacity .3s' }}>
        <title>{n.label}</title>
        {shape}
        <text x={p.x} y={p.y+n.r+10} textAnchor="middle"
          style={{ fontFamily:'JetBrains Mono', fontSize:8, fill:n.col }}>{n.label}</text>
        <text x={p.x} y={p.y+n.r+18} textAnchor="middle"
          style={{ fontFamily:'JetBrains Mono', fontSize:7, fill:T2 }}>{n.sub}</text>
      </g>
    )
  }

  return (
    <div ref={ref} style={{ flex:1, minHeight:0, background:PANEL2, position:'relative' }}>
      {sz.w > 0 && (
        <svg width={sz.w} height={sz.h} style={{ display:'block', userSelect:'none' }}>
          {edges.map((e,i)=>{
            const A=pos[e.from], B=pos[e.to]; if(!A||!B) return null
            const mx=(A.x+B.x)/2, my=(A.y+B.y)/2
            const ox=(B.y-A.y)*.08, oy=-(B.x-A.x)*.08
            const faded = hl.size>0 && (!hl.has(e.from)||!hl.has(e.to))
            return (
              <g key={e.id} style={{ opacity:faded?.2:1, transition:'opacity .3s' }}>
                <path d={`M${A.x},${A.y} Q${mx+ox},${my+oy} ${B.x},${B.y}`}
                  fill="none" stroke={e.col} strokeWidth={1} strokeOpacity={.35}
                  className="edge-in" style={{ animationDelay:`${i*.1}s` }}/>
                <text x={mx+ox} y={my+oy-5} textAnchor="middle"
                  style={{ fontFamily:'JetBrains Mono', fontSize:7, fill:e.col, opacity:.55 }}>
                  {e.label}
                </text>
              </g>
            )
          })}
          {nodes.map(n => drawNode(n))}
        </svg>
      )}
      {/* Legend */}
      <div style={{ position:'absolute', bottom:8, right:8, display:'flex', gap:8,
        background:a(PANEL,.95), border:`1px solid ${EDGE}`, borderRadius:2, padding:'3px 8px' }}>
        {[{c:CYAN,s:'■',l:'Stage'},{c:RED,s:'●',l:'IP'},{c:AMBER,s:'◆',l:'File'},{c:GREEN,s:'⬡',l:'Hash'}].map(x=>(
          <div key={x.l} style={{ display:'flex', alignItems:'center', gap:3 }}>
            <span style={{ color:x.c, fontSize:8, lineHeight:1 }}>{x.s}</span>
            <span style={{ fontSize:8, color:T2, fontFamily:'JetBrains Mono' }}>{x.l}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Center panel
// ─────────────────────────────────────────────────────────────────────────────
function CenterPanel({ state, status, sel, onSel, findings, iocs }: { state:AppState; status:Record<string,StageStatus>; sel:string; onSel:(id:string)=>void; findings:Finding[]; iocs:IOCEntry[] }) {
  const { nodes, edges } = useMemo(() => buildGraph(findings, iocs), [findings, iocs])
  const done  = Object.values(status).filter(s=>s==='confirmed').length

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:BG }}>
      {/* Kill chain */}
      <div style={{ padding:'14px 20px 0', borderBottom:`1px solid ${EDGE}`, flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom:2 }}>
          <Label>Kill chain</Label>
          <span style={{ fontSize:10, color:T2 }}>{done}/7 confirmed</span>
        </div>
        <Stepper status={status} sel={sel} onSel={onSel}/>
      </div>

      {/* Graph */}
      <div style={{ display:'flex', flexDirection:'column', flex:1, minHeight:0, padding:'14px 16px 12px' }}>
        <div style={{ display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom:10, flexShrink:0 }}>
          <Label>Evidence graph</Label>
          <span style={{ fontSize:10, color:T2 }}>{nodes.length} nodes · {edges.length} edges</span>
        </div>
        <div style={{ flex:1, minHeight:0, border:`1px solid ${EDGE}`, borderRadius:3, overflow:'hidden', display:'flex', flexDirection:'column' }}>
          <Graph nodes={nodes} edges={edges} sel={sel}/>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Right panel — live findings + IOCs
// ─────────────────────────────────────────────────────────────────────────────
function RightPanel({ finds, iocs, investigationId }: { finds:Finding[]; iocs:IOCEntry[]; investigationId:string|null }) {
  const [iocOpen, setIocOpen] = useState(false)
  const critical = finds.filter(f=>f.confidence >= 0.9).length

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:PANEL }}>
      <div style={{ padding:'14px 16px 12px', borderBottom:`1px solid ${EDGE}`, flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'baseline', gap:8 }}>
          <Label>Findings</Label>
          <span style={{ fontSize:10, color:T2 }}>{finds.length} total</span>
          {critical > 0 && (
            <span style={{ fontSize:10, color:RED }}>{critical} high-conf</span>
          )}
        </div>
      </div>

      <div style={{ flex:1, overflowY:'auto', padding:'10px 12px', display:'flex', flexDirection:'column', gap:5 }}>
        {finds.map(f => <FindCard key={f.id} f={f} investigationId={investigationId}/>)}
        {finds.length === 0 && (
          <div style={{ padding:20, textAlign:'center', color:T2, fontSize:11 }}>
            Waiting for findings…
          </div>
        )}
      </div>

      {/* IOC section */}
      <div style={{ borderTop:`1px solid ${EDGE}`, flexShrink:0 }}>
        <button onClick={()=>setIocOpen(o=>!o)} style={{
          width:'100%', display:'flex', alignItems:'center', justifyContent:'space-between',
          padding:'10px 16px', background:'transparent', border:'none', cursor:'pointer',
        }}
        onMouseEnter={e=>(e.currentTarget.style.background=a('#fff',.02))}
        onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
          <div style={{ display:'flex', alignItems:'baseline', gap:8 }}>
            <Label>IOCs</Label>
            <span style={{ fontSize:10, color:T2 }}>{iocs.length} indicators</span>
          </div>
          <svg width="11" height="11" viewBox="0 0 11 11" fill="none"
            style={{ transform:iocOpen?'rotate(180deg)':'none', transition:'transform .2s' }}>
            <path d="M1.5 3.5l4 4 4-4" stroke={T2} strokeWidth="1.3" strokeLinecap="round"/>
          </svg>
        </button>

        {iocOpen && (
          <div className="fade-up" style={{ borderTop:`1px solid ${EDGE}`, maxHeight:190, overflowY:'auto' }}>
            <table style={{ width:'100%', borderCollapse:'collapse', fontFamily:'JetBrains Mono', fontSize:10 }}>
              <thead>
                <tr style={{ borderBottom:`1px solid ${EDGE}` }}>
                  <th style={{ padding:'6px 16px', textAlign:'left', fontSize:9, color:T2, fontWeight:400 }}>Type</th>
                  <th style={{ padding:'6px 8px', textAlign:'left', fontSize:9, color:T2, fontWeight:400 }}>Indicator</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc,i)=>(
                  <tr key={i} style={{ borderBottom:`1px solid ${EDGE}`, cursor:'pointer' }}
                    onMouseEnter={e=>(e.currentTarget.style.background=a('#fff',.02))}
                    onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                    <td style={{ padding:'7px 16px', color: ioc.type === 'ip' ? RED : AMBER }}>{ioc.type.toUpperCase()}</td>
                    <td style={{ padding:'7px 8px', color:T0, maxWidth:170, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{ioc.value}</td>
                  </tr>
                ))}
                {iocs.length === 0 && (
                  <tr><td colSpan={2} style={{ padding:'12px 16px', color:T2, textAlign:'center' }}>No IOCs yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function FindCard({ f, investigationId }: { f: Finding; investigationId:string|null }) {
  const confPct = Math.round(f.confidence * 100)
  const conf_col = confPct >= 95 ? GREEN : confPct >= 80 ? T0 : AMBER
  const stageLabel = f.stage ? (STAGE_SHORT[f.stage] || f.stage) : '—'

  return (
    <div style={{
      padding:'10px 12px', borderRadius:3,
      background:PANEL2, border:`1px solid ${EDGE}`,
      cursor:'pointer', transition:'border-color .15s',
    }}
    onMouseEnter={e=>(e.currentTarget.style.borderColor=EDGE2)}
    onMouseLeave={e=>(e.currentTarget.style.borderColor=EDGE)}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:8, marginBottom:6 }}>
        <div style={{ display:'flex', alignItems:'center', gap:6 }}>
          {confPct >= 90 && <span style={{ width:5, height:5, borderRadius:'50%', background:RED, flexShrink:0 }}/>}
          <span style={{ fontSize:10, color:T1 }}>{stageLabel}</span>
          {f.tentative && <span style={{ fontSize:9, color:AMBER, fontStyle:'italic' }}>tentative</span>}
        </div>
        <Mono col={T2}>{f.source_file || '—'}</Mono>
      </div>
      <p style={{ fontSize:11, color:T0, lineHeight:1.5, margin:'0 0 8px', maxHeight:60, overflow:'hidden', textOverflow:'ellipsis' }}>
        {f.description.length > 200 ? f.description.slice(0, 200) + '…' : f.description}
      </p>
      <div style={{ display:'flex', alignItems:'center', gap:10 }}>
        <div style={{ flex:1, display:'flex', flexDirection:'column', gap:3 }}>
          <div style={{ display:'flex', justifyContent:'space-between' }}>
            <span style={{ fontSize:9, color:T2 }}>Confidence</span>
            <span style={{ fontFamily:'JetBrains Mono', fontSize:9, color:conf_col }}>{confPct}%</span>
          </div>
          <div style={{ height:1.5, background:EDGE, borderRadius:1, overflow:'hidden' }}>
            <div className="bar-fill" style={{ height:'100%', width:`${confPct}%`, background:conf_col, borderRadius:1 }}/>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Bottom drawer — real report from backend
// ─────────────────────────────────────────────────────────────────────────────
function Drawer({ state, report, toolCalls, elapsed }: { state: AppState; report:any; toolCalls:number; elapsed:number }) {
  const done = state === 'complete'
  const [open, setOpen] = useState(false)
  useEffect(()=>{ if(done){const t=setTimeout(()=>setOpen(true),800);return()=>clearTimeout(t)}else setOpen(false) },[done])

  const fmt = (s:number) => `${String(Math.floor(s/60)).padStart(2,'0')}m ${String(s%60).padStart(2,'0')}s`

  return (
    <div style={{
      flexShrink:0, background:PANEL,
      borderTop:`1px solid ${EDGE}`,
      maxHeight: open ? 320 : 42,
      overflow:'hidden', transition:'max-height .35s cubic-bezier(.4,0,.2,1)',
    }}>
      <button onClick={()=>setOpen(o=>!o)} style={{
        width:'100%', height:42, display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 20px', background:'transparent', border:'none', cursor:'pointer',
      }}
      onMouseEnter={e=>(e.currentTarget.style.background=a('#fff',.02))}
      onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <Label>Final report</Label>
          {!done && <span style={{ fontSize:10, color:T2 }}>Available at convergence</span>}
          {done && <span style={{ fontSize:10, color:GREEN }}>Ready to export</span>}
        </div>
        <svg width="11" height="11" viewBox="0 0 11 11" fill="none"
          style={{ transform:open?'rotate(180deg)':'none', transition:'transform .25s' }}>
          <path d="M1.5 3.5l4 4 4-4" stroke={T2} strokeWidth="1.3" strokeLinecap="round"/>
        </svg>
      </button>

      {open && report && (
        <div className="fade-up" style={{ padding:'0 20px 20px', display:'grid', gridTemplateColumns:'1fr 180px', gap:16, maxHeight:270, overflow:'hidden' }}>
          {/* Narrative */}
          <div style={{ background:PANEL2, border:`1px solid ${EDGE}`, borderRadius:3, padding:16, overflowY:'auto' }}>
            <div style={{ fontSize:10, color:T2, marginBottom:10 }}>{report.investigation_id}</div>
            <h3 style={{ fontSize:13, fontWeight:600, color:T0, margin:'0 0 10px', lineHeight:1.4 }}>
              Investigation Report
            </h3>
            <p style={{ fontSize:12, color:T1, lineHeight:1.75, margin:'0 0 12px' }}>
              {report.narrative}
            </p>
            <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
              {[
                {l:`${report.timeline?.length || 0} findings`, c:T1},
                {l:`${report.iocs?.length || 0} IOCs`, c:T1},
                {l:`${Object.keys(report.stages || {}).length}/7 stages`, c:GREEN},
              ].map(b=>(
                <span key={b.l} style={{ fontSize:10, color:b.c, padding:'2px 8px', border:`1px solid ${a(b.c,.25)}`, borderRadius:2 }}>{b.l}</span>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {[{l:'Export PDF',c:T0},{l:'Export JSON',c:T0},{l:'Export STIX 2.1',c:T0}].map(btn=>(
              <button key={btn.l} style={{
                padding:'9px 14px', textAlign:'left',
                background:PANEL2, border:`1px solid ${EDGE}`, borderRadius:3,
                fontSize:11, color:btn.c, cursor:'pointer', transition:'border-color .15s',
              }}
              onMouseEnter={e=>{ e.currentTarget.style.borderColor=EDGE2; e.currentTarget.style.color=T0 }}
              onMouseLeave={e=>{ e.currentTarget.style.borderColor=EDGE; e.currentTarget.style.color=btn.c }}>
                {btn.l}
              </button>
            ))}
            <div style={{ marginTop:'auto', paddingTop:12, borderTop:`1px solid ${EDGE}` }}>
              <div style={{ fontSize:10, color:T2, marginBottom:2 }}>Stats</div>
              <Mono col={T1}>{fmt(elapsed)} · {toolCalls} tool calls</Mono>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Static stardust background — fixed positions, twinkle only
// ─────────────────────────────────────────────────────────────────────────────
function ParticleNet() {
  const canvas = useRef<HTMLCanvasElement>(null)
  const raf    = useRef(0)

  const mouse = useRef({ x: -9999, y: -9999 })

  useEffect(() => {
    const el = canvas.current; if (!el) return
    const ctx = el.getContext('2d')!
    let W = 0, H = 0
    let dpr = 1

    const COLS: [number,number,number][] = [
      [255,255,255],[255,255,255],[255,255,255],[255,255,255],[255,255,255],
      [255,255,255],[255,255,255],[255,255,255],[255,255,255],[255,255,255],
      [210,225,255],[210,225,255],[210,225,255],
      [185,205,245],[185,205,245],
      [91,106,245],[91,106,245],
    ]

    interface Star {
      x: number; y: number
      r: number
      col: [number,number,number]
      baseAlpha: number
      twinkle: number
      twinkleSpeed: number
      twinkleAmp: number
    }

    let stars: Star[] = []
    let rCurrent: number[] = []

    function init() {
      if (!el) return
      dpr = Math.max(window.devicePixelRatio || 1, 2)
      W = el.offsetWidth; H = el.offsetHeight
      el.width  = W * dpr
      el.height = H * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

      const N = Math.floor((W * H) / 1800)
      stars = Array.from({ length: N }, () => {
        const col = COLS[Math.floor(Math.random() * COLS.length)]
        const r = Math.random() < .08
          ? Math.random() * .9 + .7
          : Math.random() * .55 + .15
        return {
          x: Math.random() * W,
          y: Math.random() * H,
          r,
          col,
          baseAlpha: Math.random() * .35 + .12,
          twinkle: Math.random() * Math.PI * 2,
          twinkleSpeed: Math.random() * .012 + .003,
          twinkleAmp: Math.random() * .14 + .04,
        }
      })
      rCurrent = stars.map(s => s.r)
    }

    const MAG_RADIUS = 320
    const MAG_PEAK   = 8

    function draw() {
      ctx.clearRect(0, 0, W, H)
      const mx = mouse.current.x, my = mouse.current.y

      stars.forEach((s, i) => {
        s.twinkle += s.twinkleSpeed
        const alpha = s.baseAlpha + Math.sin(s.twinkle) * s.twinkleAmp

        const dx = s.x - mx, dy = s.y - my
        const dist = Math.sqrt(dx*dx + dy*dy)
        const t = Math.max(0, 1 - dist / MAG_RADIUS)
        const scale = 1 + (MAG_PEAK - 1) * (t * t * (3 - 2 * t))
        const target = s.r * scale
        rCurrent[i] += (target - rCurrent[i]) * .14
        const cr = rCurrent[i]

        const [r,g,b] = s.col
        const enlarged = cr > s.r * 1.25

        if (enlarged || s.r > 0.6) {
          const haloR = cr * (enlarged ? 2.2 : 3.5)
          const grd = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, haloR)
          grd.addColorStop(0, `rgba(${r},${g},${b},${alpha * (enlarged ? .3 : .18)})`)
          grd.addColorStop(1, `rgba(${r},${g},${b},0)`)
          ctx.beginPath()
          ctx.arc(s.x, s.y, haloR, 0, Math.PI*2)
          ctx.fillStyle = grd
          ctx.fill()
        }

        ctx.beginPath()
        ctx.arc(s.x, s.y, Math.max(cr, .1), 0, Math.PI*2)
        ctx.fillStyle = `rgba(${r},${g},${b},${Math.min(alpha, 1)})`
        ctx.fill()
      })

      raf.current = requestAnimationFrame(draw)
    }

    init()
    draw()

    const ro = new ResizeObserver(() => { ctx.setTransform(1,0,0,1,0,0); init() })
    ro.observe(el)

    const onMove = (e: MouseEvent) => {
      const rect = el.getBoundingClientRect()
      mouse.current = { x: e.clientX - rect.left, y: e.clientY - rect.top }
    }
    const onLeave = () => { mouse.current = { x: -9999, y: -9999 } }
    el.addEventListener('mousemove', onMove)
    el.addEventListener('mouseleave', onLeave)

    return () => {
      cancelAnimationFrame(raf.current)
      ro.disconnect()
      el.removeEventListener('mousemove', onMove)
      el.removeEventListener('mouseleave', onLeave)
    }
  }, [])

  return (
    <canvas ref={canvas} style={{ position:'absolute', inset:0, width:'100%', height:'100%', display:'block' }}/>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty state — wired to real file upload
// ─────────────────────────────────────────────────────────────────────────────
function EmptyState({ onUpload }: { onUpload:(files:File[])=>void }) {
  const [drag, setDrag] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDrag(false)
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) onUpload(files)
  }, [onUpload])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    if (files.length > 0) onUpload(files)
  }, [onUpload])

  return (
    <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', background:BG, position:'relative', overflow:'hidden' }}>
      <ParticleNet/>
      <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:40, maxWidth:700, width:'100%', padding:40, position:'relative', zIndex:1 }}>
        <div style={{ textAlign:'center', display:'flex', flexDirection:'column', alignItems:'center', gap:24 }}>
          <svg width="130" height="80" viewBox="0 0 40 24" fill="none">
            {/* left ring */}
            <circle cx="14" cy="12" r="9.5" stroke={CYAN} strokeWidth="2" fill="none"/>
            {/* right ring */}
            <circle cx="26" cy="12" r="9.5" stroke="rgba(255,255,255,0.45)" strokeWidth="2" fill="none"/>
            {/* cut */}
            <line x1="22" y1="2" x2="18" y2="22" stroke={RED} strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:16 }}>
            {/* wordmark — big, tight, personality from weight contrast */}
            <div style={{ display:'flex', alignItems:'baseline', gap:0, lineHeight:.9 }}>
              <span style={{
                fontFamily:'Poppins', fontSize:'clamp(64px,9vw,108px)', fontWeight:800,
                letterSpacing:'-0.03em', color:'#fff',
              }}>kill</span>
              <span style={{
                fontFamily:'Poppins', fontSize:'clamp(64px,9vw,108px)', fontWeight:300,
                letterSpacing:'-0.03em', color:'rgba(255,255,255,0.65)',
              }}>chain</span>
            </div>
            <div style={{ fontSize:14, color:'rgba(255,255,255,0.5)', fontFamily:'Poppins', fontWeight:400, letterSpacing:'0.18em', textTransform:'uppercase' }}>
              AI · Incident Reconstruction
            </div>
          </div>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".pcap,.pcapng,.log,.evtx,.raw,.dmp,.mem,.txt,.csv,.json,.apk"
          onChange={handleFileSelect}
          style={{ display:'none' }}
        />

        <div
          onDragOver={e=>{e.preventDefault();setDrag(true)}}
          onDragLeave={()=>setDrag(false)}
          onDrop={handleDrop}
          onClick={()=>fileInputRef.current?.click()}
          style={{
            width:'100%', minHeight:160,
            border:`1.5px dashed ${drag ? CYAN : 'rgba(255,255,255,0.22)'}`,
            borderRadius:8, cursor:'pointer',
            display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:14,
            background: drag ? a(CYAN,.06) : 'rgba(255,255,255,0.03)',
            transition:'border-color .2s, background .2s',
          }}
          onMouseEnter={e=>{ if(!drag){ e.currentTarget.style.borderColor='rgba(255,255,255,0.4)'; e.currentTarget.style.background='rgba(255,255,255,0.05)' }}}
          onMouseLeave={e=>{ if(!drag){ e.currentTarget.style.borderColor='rgba(255,255,255,0.22)'; e.currentTarget.style.background='rgba(255,255,255,0.03)' }}}>
          <svg width="32" height="32" viewBox="0 0 28 28" fill="none">
            <path d="M14 3v16M7 12l7-9 7 9" stroke="rgba(255,255,255,0.7)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M4 22h20" stroke="rgba(255,255,255,0.7)" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
          <div style={{ textAlign:'center' }}>
            <div style={{ fontSize:14, fontFamily:'Poppins', fontWeight:500, color:'rgba(255,255,255,0.85)', marginBottom:6 }}>
              {drag ? 'Drop to begin analysis' : 'Drop log files or artifacts here'}
            </div>
            <div style={{ fontSize:12, color:'rgba(255,255,255,0.35)', fontFamily:'Poppins', letterSpacing:'0.04em' }}>
              auth.log · syslog · PCAP · EVTX · memory dump
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// App — wired to real backend via useInvestigation hook
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const inv = useInvestigation()
  const [sel, setSel] = useState('')

  const handleUpload = useCallback((files: File[]) => {
    inv.upload(files)
  }, [inv])

  const dashState = inv.appState === 'uploading' ? 'active' : inv.appState

  return (
    <div className="root-bg" style={{ width:'100vw', height:'100vh', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <div style={{ display:'flex', flexDirection:'column', height:'100%', position:'relative', zIndex:1 }}>
        <TopBar
          state={inv.appState}
          elapsed={inv.elapsed}
          calls={inv.toolCalls}
          investigationId={inv.investigationId}
          onReset={inv.reset}
        />

        {(inv.appState === 'empty')
          ? <EmptyState onUpload={handleUpload}/>
          : <>
              <div style={{ flex:1, minHeight:0, display:'flex' }}>
                <div style={{ width:'30%', flexShrink:0, borderRight:`1px solid ${EDGE}`, overflow:'hidden', display:'flex', flexDirection:'column' }}>
                  <ReasoningFeed steps={inv.steps} thinking={inv.thinking}/>
                </div>
                <div style={{ flex:1, minWidth:0, borderRight:`1px solid ${EDGE}`, overflow:'hidden', display:'flex', flexDirection:'column' }}>
                  <CenterPanel
                    state={dashState}
                    status={inv.stages}
                    sel={sel}
                    onSel={id=>setSel(p=>p===id?'':id)}
                    findings={inv.findings}
                    iocs={inv.iocs}
                  />
                </div>
                <div style={{ width:'30%', flexShrink:0, overflow:'hidden', display:'flex', flexDirection:'column' }}>
                  <RightPanel finds={inv.findings} iocs={inv.iocs} investigationId={inv.investigationId}/>
                </div>
              </div>
              <Drawer state={dashState} report={inv.report} toolCalls={inv.toolCalls} elapsed={inv.elapsed}/>

              {/* Error banner */}
              {inv.error && (
                <div style={{
                  position:'fixed', bottom:14, left:'50%', transform:'translateX(-50%)',
                  padding:'8px 20px', background:a(RED,.15), border:`1px solid ${a(RED,.3)}`,
                  borderRadius:4, zIndex:100, fontSize:11, color:RED,
                  boxShadow:'0 4px 24px rgba(0,0,0,0.5)',
                }}>
                  {inv.error}
                </div>
              )}
            </>
        }
      </div>
    </div>
  )
}
