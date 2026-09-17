// ─────────────────────────────────────────────────────────────────────────────
// TypeScript interfaces mirroring backend Pydantic models
// ─────────────────────────────────────────────────────────────────────────────

export type Stage =
  | 'Reconnaissance'
  | 'Weaponization'
  | 'Delivery'
  | 'Exploitation'
  | 'Installation'
  | 'Command & Control (C2)'
  | 'Credential Access'
  | 'Lateral Movement'
  | 'Actions on Objectives'

export const STAGE_ORDER: Stage[] = [
  'Reconnaissance',
  'Weaponization',
  'Delivery',
  'Exploitation',
  'Installation',
  'Command & Control (C2)',
  'Credential Access',
  'Lateral Movement',
  'Actions on Objectives',
]

export const STAGE_SHORT: Record<Stage, string> = {
  'Reconnaissance': 'Reconnaissance',
  'Weaponization': 'Weaponization',
  'Delivery': 'Delivery',
  'Exploitation': 'Exploitation',
  'Installation': 'Installation',
  'Command & Control (C2)': 'C2',
  'Credential Access': 'Credential Access',
  'Lateral Movement': 'Lateral Movement',
  'Actions on Objectives': 'Actions',
}

export interface EvidenceFile {
  id: string
  original_name: string
  stored_name: string
  size: number
  sha256: string
  file_type: string | null
}

export interface Finding {
  id: string
  title: string
  description: string
  source_file: string | null
  stage: Stage | null
  confidence: number
  tentative: boolean
  timestamp: string | null
  iocs: string[]
}

export interface InvestigationEvent {
  investigation_id: string
  sequence: number
  timestamp: string
  type: string
  payload: Record<string, any>
  evidence_refs: string[]
  confidence: number | null
}

export interface Investigation {
  id: string
  status: string
  created_at: string
  files: EvidenceFile[]
  events: InvestigationEvent[]
  findings: Finding[]
  stages: Partial<Record<Stage, number>>
  report: Record<string, any> | null
}

export interface StartResponse {
  investigation_id: string
  status: string
}

export interface MemoryRecord {
  id: string
  kind: string
  content: string
  tags: string[]
  source_investigation_id: string | null
  source_finding_id: string | null
  confidence: number
  created_at: string
  updated_at: string
}

export interface ModelConfig {
  provider: string
  model: string
  base_url: string | null
  api_key: string | null
}

export interface ReportResponse {
  investigation_id: string
  status: string
  narrative: string
  timeline: Finding[]
  iocs: { type: string; value: string }[]
  stages: Partial<Record<Stage, number>>
}

export interface ToolInfo {
  function: {
    name: string
    description: string
    parameters: Record<string, any>
  }
  type: string
}

export interface SkillInfo {
  name: string
  description: string
  overview: string
  when_to_use: string
  tools: string[]
}

/** IOC extracted from findings for display */
export interface IOCEntry {
  type: 'ip' | 'url' | 'sha256' | 'domain' | 'process_name' | 'file_path' | 'registry_key' | 'service_name' | 'username' | 'dll_name'
  value: string
}
