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

export interface CreateAgentInput {
  name: string
  description?: string | null
  expiry_date?: string | null
}

export interface UpdateAgentInput {
  name?: string
  description?: string
  status?: AgentStatus
  expiry_date?: string
}

export interface IssuedToken {
  token: string
}

export interface Overview {
  decisions_today: DecisionCounts
  blocked_percent: number
  top_blocked_agents: CountedName[]
  top_blocked_tools: CountedName[]
  gateways: Gateway[]
}

export interface PolicyVersion {
  id: string
  version: number
  policy_text: string
  schema_text: string | null
  message: string | null
  valid: boolean
  validation_error: string | null
  published: boolean
  created_at: string
}

export interface SavePolicyDraftInput {
  policy_text: string
  schema_text?: string | null
  message?: string | null
}

export interface ValidateResult {
  valid: boolean
  validation_error: string | null
}

// The exact JSON a gateway wrote, plus Control's best-effort extraction of
// the searchable fields (crates/custos-control/src/audit.rs).
export interface AuditRecordSummary {
  id: string
  tenant_id: string
  gateway_id: string
  seq: number
  ts: string | null
  agent: string | null
  owner: string | null
  tool: string | null
  verdict: string | null
  policy_version: string | null
  findings: unknown
  record: unknown
  ingested_at: string
}

export interface AuditSearchResult {
  records: AuditRecordSummary[]
  next_cursor: string | null
}

export interface AuditSearchFilters {
  agent?: string
  tool?: string
  verdict?: string
  policy_version?: string
  from?: string
  to?: string
  cursor?: string
  limit?: number
}

export type ApprovalStatus = 'pending' | 'approved' | 'rejected'

export interface Approval {
  id: string
  gateway_id: string
  agent: string
  tool: string
  findings: unknown
  reason: string
  four_eyes: boolean
  status: ApprovalStatus
  comment: string | null
  created_at: string
}
