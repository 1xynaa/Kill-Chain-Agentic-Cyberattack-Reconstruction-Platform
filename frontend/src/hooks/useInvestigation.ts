// ─────────────────────────────────────────────────────────────────────────────
// useInvestigation — orchestrates the full investigation lifecycle
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useRef, useCallback, useEffect } from 'react'
import type {
  Investigation,
  InvestigationEvent,
  Finding,
  Stage,
  ReportResponse,
  IOCEntry,
} from '../api/types'
import { STAGE_ORDER } from '../api/types'
import { uploadEvidence, startInvestigation, getReport } from '../api/client'
import { connectInvestigation } from '../api/websocket'

export type AppState = 'empty' | 'uploading' | 'active' | 'complete' | 'failed'

export interface AgentStep {
  id: number
  tool: string
  ts: string
  thought: string
  action: string
  obs: string
}

export type StageStatus = 'pending' | 'active' | 'confirmed'

export interface InvestigationState {
  appState: AppState
  investigationId: string | null
  steps: AgentStep[]
  findings: Finding[]
  stages: Record<string, StageStatus>
  stageScores: Partial<Record<Stage, number>>
  iocs: IOCEntry[]
  report: ReportResponse | null
  elapsed: number
  toolCalls: number
  thinking: boolean
  wsStatus: string
  error: string | null

  // actions
  upload: (files: File[]) => Promise<void>
  reset: () => void
}

function deriveStageStatuses(
  stageScores: Partial<Record<Stage, number>>,
  isRunning: boolean,
): Record<string, StageStatus> {
  const result: Record<string, StageStatus> = {}
  const ids = ['recon', 'weapon', 'deliver', 'exploit', 'install', 'c2', 'actions']
  let lastConfirmedIdx = -1

  STAGE_ORDER.forEach((stage, idx) => {
    if (stageScores[stage] !== undefined) {
      result[ids[idx]] = 'confirmed'
      lastConfirmedIdx = idx
    } else {
      result[ids[idx]] = 'pending'
    }
  })

  // Mark the next unconfirmed stage as active if investigation is running
  if (isRunning && lastConfirmedIdx + 1 < ids.length) {
    result[ids[lastConfirmedIdx + 1]] = 'active'
  }

  return result
}

function extractIOCs(findings: Finding[]): IOCEntry[] {
  const seen = new Set<string>()
  const iocs: IOCEntry[] = []
  for (const f of findings) {
    for (const val of f.iocs) {
      if (seen.has(val)) continue
      seen.add(val)
      // Classify
      let type: IOCEntry['type'] = 'domain'
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) type = 'ip'
      else if (/^https?:\/\//.test(val)) type = 'url'
      else if (/^[a-fA-F0-9]{64}$/.test(val)) type = 'sha256'
      iocs.push({ type, value: val })
    }
  }
  return iocs
}

export function useInvestigation(): InvestigationState {
  const [appState, setAppState] = useState<AppState>('empty')
  const [investigationId, setInvestigationId] = useState<string | null>(null)
  const [steps, setSteps] = useState<AgentStep[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [stageScores, setStageScores] = useState<Partial<Record<Stage, number>>>({})
  const [report, setReport] = useState<ReportResponse | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const [toolCalls, setToolCalls] = useState(0)
  const [thinking, setThinking] = useState(false)
  const [wsStatus, setWsStatus] = useState('disconnected')
  const [error, setError] = useState<string | null>(null)

  const wsRef = useRef<{ close: () => void } | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const stepCounter = useRef(0)

  // Pending thought/action state for assembling steps
  const pendingThought = useRef('')
  const pendingAction = useRef('')
  const pendingTool = useRef('')
  const pendingTs = useRef('')

  const handleEvent = useCallback((event: InvestigationEvent) => {
    const { type, payload } = event

    switch (type) {
      case 'status': {
        if (payload.status === 'completed') {
          setAppState('complete')
          setThinking(false)
        } else if (payload.status === 'failed') {
          setAppState('failed')
          setThinking(false)
          setError(payload.error || 'Investigation failed')
        } else if (payload.status === 'running') {
          setThinking(true)
        } else if (payload.status === 'budget_exhausted') {
          setThinking(false)
        }
        if (payload.tool_calls !== undefined) {
          setToolCalls(payload.tool_calls)
        }
        break
      }

      case 'thought': {
        pendingThought.current = payload.text || ''
        pendingTs.current = new Date(event.timestamp).toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
        setThinking(true)
        break
      }

      case 'action': {
        pendingAction.current = `${payload.tool}("${payload.path}")`
        pendingTool.current = payload.tool || ''
        setToolCalls((c) => c + 1)
        break
      }

      case 'observation': {
        stepCounter.current += 1
        const step: AgentStep = {
          id: stepCounter.current,
          tool: pendingTool.current || payload.tool || 'unknown',
          ts: pendingTs.current || new Date(event.timestamp).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }),
          thought: pendingThought.current,
          action: pendingAction.current,
          obs: payload.stdout || payload.stderr || payload.error || JSON.stringify(payload),
        }
        setSteps((prev) => [...prev, step])
        // Reset pending
        pendingThought.current = ''
        pendingAction.current = ''
        pendingTool.current = ''
        break
      }

      case 'finding': {
        const finding: Finding = {
          id: payload.id,
          title: payload.title,
          description: payload.description,
          source_file: payload.source_file,
          stage: payload.stage,
          confidence: payload.confidence,
          tentative: payload.tentative,
          timestamp: payload.timestamp,
          iocs: payload.iocs || [],
        }
        setFindings((prev) => [...prev, finding])
        break
      }

      case 'stage_update': {
        if (!payload.tentative) {
          setStageScores((prev) => ({
            ...prev,
            [payload.stage as Stage]: Math.max(
              prev[payload.stage as Stage] || 0,
              payload.confidence,
            ),
          }))
        }
        break
      }

      case 'skill_select':
      case 'memory_recall':
      case 'provider_error':
        // These could be shown in a notification area; for now we consume silently
        break

      default:
        break
    }
  }, [])

  // Derive computed state
  const isRunning = appState === 'active'
  const stages = deriveStageStatuses(stageScores, isRunning)
  const iocs = extractIOCs(findings)

  // Elapsed timer
  useEffect(() => {
    if (appState === 'active') {
      timerRef.current = setInterval(() => setElapsed((e) => e + 1), 1000)
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [appState])

  // Fetch report on completion
  useEffect(() => {
    if (appState === 'complete' && investigationId && !report) {
      getReport(investigationId)
        .then(setReport)
        .catch((err) => console.warn('Failed to fetch report:', err))
    }
  }, [appState, investigationId, report])

  const upload = useCallback(async (files: File[]) => {
    try {
      setAppState('uploading')
      setError(null)

      // Upload files
      const inv = await uploadEvidence(files)
      setInvestigationId(inv.id)

      // Start investigation
      await startInvestigation(inv.id)
      setAppState('active')

      // Connect WebSocket
      const conn = connectInvestigation(inv.id, handleEvent, setWsStatus)
      wsRef.current = conn
    } catch (err) {
      setAppState('failed')
      setError(err instanceof Error ? err.message : 'Upload failed')
    }
  }, [handleEvent])

  const reset = useCallback(() => {
    wsRef.current?.close()
    wsRef.current = null
    if (timerRef.current) clearInterval(timerRef.current)
    setAppState('empty')
    setInvestigationId(null)
    setSteps([])
    setFindings([])
    setStageScores({})
    setReport(null)
    setElapsed(0)
    setToolCalls(0)
    setThinking(false)
    setError(null)
    stepCounter.current = 0
  }, [])

  return {
    appState,
    investigationId,
    steps,
    findings,
    stages,
    stageScores,
    iocs,
    report,
    elapsed,
    toolCalls,
    thinking,
    wsStatus,
    error,
    upload,
    reset,
  }
}
