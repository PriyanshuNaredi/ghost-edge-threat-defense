export type ThreatType =
  | 'NONE'
  | 'SQL_INJECTION'
  | 'XSS'
  | 'PATH_TRAVERSAL'
  | 'RATE_LIMIT'
  | 'ANOMALY'

export type ActionTaken = 'ALLOW' | 'BLOCK' | 'THROTTLE' | 'BLACKLIST'

export interface SecurityEvent {
  timestamp: string
  client_ip: string
  route: string
  threat_type: ThreatType
  score: number
  action_taken: ActionTaken
  payload?: string
  confidence?: number
  headers?: [string, string][]
}

export interface GatewayStats {
  total_requests: number
  allowed: number
  blocked: number
  throttled: number
  blacklisted: number
  uptime_seconds: number
  ws_clients: number
}

export const THREAT_COLORS: Record<ThreatType, string> = {
  NONE: '#34d399',
  SQL_INJECTION: '#f43f5e',
  XSS: '#fb923c',
  PATH_TRAVERSAL: '#fbbf24',
  RATE_LIMIT: '#a78bfa',
  ANOMALY: '#22d3ee',
}

export const THREAT_LABELS: Record<ThreatType, string> = {
  NONE: 'CLEAN',
  SQL_INJECTION: 'SQLi',
  XSS: 'XSS',
  PATH_TRAVERSAL: 'TRAVERSAL',
  RATE_LIMIT: 'RATE',
  ANOMALY: 'ANOMALY',
}
