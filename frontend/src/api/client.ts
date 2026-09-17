// ─────────────────────────────────────────────────────────────────────────────
// REST API client — type-safe wrappers for every backend endpoint
// ─────────────────────────────────────────────────────────────────────────────

import type {
  Investigation,
  StartResponse,
  ReportResponse,
  MemoryRecord,
  ModelConfig,
  ToolInfo,
  SkillInfo,
} from './types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json() as Promise<T>
}

/** Upload one or more evidence files. Returns the created Investigation. */
export async function uploadEvidence(files: File[]): Promise<Investigation> {
  const form = new FormData()
  files.forEach((f) => form.append('files', f))
  return request<Investigation>('/upload', { method: 'POST', body: form })
}

/** Kick off the agentic investigation loop. */
export async function startInvestigation(id: string): Promise<StartResponse> {
  return request<StartResponse>(`/investigate/start/${id}`, { method: 'POST' })
}

/** Poll the current investigation state. */
export async function getInvestigation(id: string): Promise<Investigation> {
  return request<Investigation>(`/investigation/${id}`)
}

/** Fetch the final report (available after status === 'completed'). */
export async function getReport(id: string): Promise<ReportResponse> {
  return request<ReportResponse>(`/report/${id}`)
}

/** List available forensic tools. */
export async function getTools(): Promise<ToolInfo[]> {
  return request<ToolInfo[]>('/tools')
}

/** List the skill catalog. */
export async function getSkills(): Promise<SkillInfo[]> {
  return request<SkillInfo[]>('/skills')
}

/** Semantic search over analyst memory. */
export async function searchMemory(q: string, limit = 5): Promise<MemoryRecord[]> {
  return request<MemoryRecord[]>(`/memory/search?q=${encodeURIComponent(q)}&limit=${limit}`)
}

/** Submit analyst feedback on a finding. */
export async function submitFeedback(
  investigationId: string,
  findingId: string,
  label: 'confirmed' | 'rejected',
  note = '',
): Promise<MemoryRecord> {
  return request<MemoryRecord>(`/feedback/${investigationId}/${findingId}`, {
    method: 'POST',
    body: JSON.stringify({ label, note }),
  })
}

/** Switch the model provider / model. */
export async function configureModel(config: Partial<ModelConfig>): Promise<ModelConfig> {
  return request<ModelConfig>('/config/model', {
    method: 'POST',
    body: JSON.stringify(config),
  })
}

/** Replay a completed investigation's events over the WebSocket. */
export async function replayInvestigation(id: string, speed = 1.0): Promise<void> {
  await request<{ status: string }>(`/replay/${id}?speed=${speed}`, { method: 'POST' })
}

/** Health check. */
export async function healthCheck(): Promise<{ status: string }> {
  return request<{ status: string }>('/health')
}
