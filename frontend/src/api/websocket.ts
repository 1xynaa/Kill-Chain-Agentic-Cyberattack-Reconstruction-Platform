// ─────────────────────────────────────────────────────────────────────────────
// WebSocket handler — real-time event stream from the backend
// ─────────────────────────────────────────────────────────────────────────────

import type { InvestigationEvent } from './types'

export type EventHandler = (event: InvestigationEvent) => void
export type StatusHandler = (status: 'connecting' | 'connected' | 'disconnected' | 'error') => void

interface WSConnection {
  ws: WebSocket
  close: () => void
}

/**
 * Connect to the investigation's WebSocket stream.
 * Returns a handle with a `close()` method.
 *
 * The backend sends every past event on connect, then streams new ones.
 */
export function connectInvestigation(
  investigationId: string,
  onEvent: EventHandler,
  onStatus?: StatusHandler,
): WSConnection {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const url = `${protocol}//${host}/ws/investigate/${investigationId}`

  onStatus?.('connecting')

  const ws = new WebSocket(url)

  ws.onopen = () => {
    onStatus?.('connected')
  }

  ws.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data) as InvestigationEvent
      onEvent(event)
    } catch {
      console.warn('[ws] failed to parse event:', msg.data)
    }
  }

  ws.onerror = () => {
    onStatus?.('error')
  }

  ws.onclose = () => {
    onStatus?.('disconnected')
  }

  return {
    ws,
    close: () => {
      ws.close()
    },
  }
}
