// Mirrors the JSON shapes custos-control's handlers actually return (see
// crates/custos-control/src/*.rs). Kept hand-written rather than generated
// - the backend is small enough that this hasn't drifted, and a codegen
// step is more machinery than this project needs yet.

export type Role = 'admin' | 'approver' | 'viewer'

export interface Me {
  role: Role
  csrf_token: string
}

export interface LoginResponse {
  csrf_token: string
  role: Role
}

export type AgentStatus = 'active' | 'disabled'

export interface Agent {
  id: string
  name: string
  owner_user_id: string | null
  description: string | null
  status: AgentStatus
  expiry_date: string | null
  created_at: string
  updated_at: string
}

export interface DecisionCounts {
  allow: number
  block: number
  hold: number
}

export interface CountedName {
  name: string
  count: number
}

export type ChainStatus = 'ok' | 'gap' | 'broken'

export interface Gateway {
  id: string
  name: string
  enrolled_at: string
  last_heartbeat_at: string | null
  last_version: string | null
  last_policy_version: string | null
  decisions_allowed: number
  decisions_blocked: number
  last_ingested_seq: number | null
  chain_status: ChainStatus
  chain_issue: string | null
}

export interface Overview {
  decisions_today: DecisionCounts
  blocked_percent: number
  top_blocked_agents: CountedName[]
  top_blocked_tools: CountedName[]
  gateways: Gateway[]
}
