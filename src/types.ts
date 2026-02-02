/**
 * Molt Guard - Type Definitions
 * Communication protocol for Zero Trust AI Agent Security Middleware
 */

// ============================================================================
// ENUMS & CONSTANTS
// ============================================================================

/**
 * Decision outcomes from the Guard Server
 */
export enum GuardDecision {
  ALLOW = 'ALLOW',
  DENY = 'DENY',
  FLAG = 'FLAG', // Allow but flag for review
}

/**
 * Supported service types for JIT token vending
 */
export enum ServiceType {
  AWS = 'AWS',
  STRIPE = 'STRIPE',
  MOLTBOOK = 'MOLTBOOK',
  GENERIC = 'GENERIC',
}

/**
 * User roles for authorization checks
 */
export enum UserRole {
  ADMIN = 'ADMIN',
  USER = 'USER',
  SERVICE = 'SERVICE',
  READONLY = 'READONLY',
}

/**
 * Severity levels for moderation
 */
export enum ModerationSeverity {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

// ============================================================================
// REQUEST TYPES
// ============================================================================

/**
 * Metadata attached to every guard request for context and audit
 */
export interface RequestMetadata {
  /** Unique identifier for the user/agent making the request */
  userId: string;
  /** Session identifier for request correlation */
  sessionId?: string;
  /** Current budget consumed in this session/period */
  budgetUsed: number;
  /** Estimated cost of this specific operation */
  cost?: number;
  /** Role of the user/agent */
  userRole?: UserRole;
  /** Timestamp of the request */
  timestamp: number;
  /** Request trace ID for distributed tracing */
  traceId?: string;
  /** Additional custom metadata */
  custom?: Record<string, unknown>;
}

/**
 * The core request sent from AI Agent to Guard Server
 */
export interface GuardRequest {
  /** Human-readable description of what the agent intends to do */
  intent: string;
  /** Name of the tool/function being called */
  toolName: string;
  /** Arguments being passed to the tool */
  parameters: Record<string, unknown>;
  /** Contextual metadata for policy evaluation */
  metadata: RequestMetadata;
  /** Target service type for JIT token vending */
  targetService?: ServiceType;
  /** Content to be moderated (if applicable) */
  content?: string;
}

// ============================================================================
// RESPONSE TYPES
// ============================================================================

/**
 * JIT (Just-In-Time) Token for ephemeral credentials
 */
export interface JitToken {
  /** The temporary credential/token value */
  token: string;
  /** Token type identifier */
  type: ServiceType;
  /** Expiration timestamp (Unix epoch) */
  expiresAt: number;
  /** Scopes/permissions granted */
  scopes?: string[];
  /** AWS-specific: Access Key ID */
  accessKeyId?: string;
  /** AWS-specific: Secret Access Key */
  secretAccessKey?: string;
  /** AWS-specific: Session Token */
  sessionToken?: string;
  /** Additional token metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Moderation result for content checks
 */
export interface ModerationResult {
  /** Whether content passed moderation */
  passed: boolean;
  /** Severity level of any issues found */
  severity: ModerationSeverity;
  /** Categories of issues detected */
  categories: string[];
  /** Detailed notes about moderation decision */
  notes: string;
  /** Confidence score (0-1) */
  confidence: number;
}

/**
 * The response sent from Guard Server back to AI Agent
 */
export interface GuardResponse {
  /** The decision: ALLOW, DENY, or FLAG */
  decision: GuardDecision;
  /** Ephemeral credential if allowed and required */
  jitToken?: JitToken;
  /** Human-readable notes about the decision */
  moderationNotes: string;
  /** Detailed moderation result if content was checked */
  moderationResult?: ModerationResult;
  /** Unique ID for this decision (for audit trail) */
  decisionId: string;
  /** Timestamp of the decision */
  timestamp: number;
  /** Time-to-live for caching this decision */
  cacheTtl?: number;
  /** Suggested retry delay if rate limited */
  retryAfter?: number;
}

// ============================================================================
// POLICY CONFIGURATION
// ============================================================================

/**
 * Condition operators for policy rules
 */
export enum ConditionOperator {
  EQUALS = 'EQUALS',
  NOT_EQUALS = 'NOT_EQUALS',
  CONTAINS = 'CONTAINS',
  NOT_CONTAINS = 'NOT_CONTAINS',
  GREATER_THAN = 'GREATER_THAN',
  LESS_THAN = 'LESS_THAN',
  MATCHES_REGEX = 'MATCHES_REGEX',
  IN_LIST = 'IN_LIST',
  NOT_IN_LIST = 'NOT_IN_LIST',
}

/**
 * A single condition within a policy rule
 */
export interface PolicyCondition {
  /** Field to evaluate (supports dot notation: metadata.userId) */
  field: string;
  /** Comparison operator */
  operator: ConditionOperator;
  /** Value to compare against */
  value: unknown;
}

/**
 * Action to take when a policy rule matches
 */
export interface PolicyAction {
  /** Decision to enforce */
  decision: GuardDecision;
  /** Message to include in response */
  message: string;
  /** Whether to require content moderation */
  requireModeration?: boolean;
  /** Whether to require JIT token */
  requireJitToken?: boolean;
  /** Required user roles for this action */
  requiredRoles?: UserRole[];
  /** Maximum allowed budget for this action */
  maxBudget?: number;
}

/**
 * A single policy rule
 */
export interface PolicyRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Description of what this rule does */
  description: string;
  /** Priority (lower = higher priority) */
  priority: number;
  /** Whether this rule is active */
  enabled: boolean;
  /** Tool names this rule applies to (empty = all tools) */
  targetTools: string[];
  /** Conditions that must ALL be true for rule to match (AND logic) */
  conditions: PolicyCondition[];
  /** Action to take when rule matches */
  action: PolicyAction;
}

/**
 * Budget limits configuration
 */
export interface BudgetConfig {
  /** Daily spending limit */
  dailyLimit: number;
  /** Per-request maximum cost */
  perRequestLimit: number;
  /** Hourly rate limit */
  hourlyLimit?: number;
  /** Monthly limit */
  monthlyLimit?: number;
  /** Alert threshold (percentage of daily limit) */
  alertThreshold?: number;
}

/**
 * Content moderation configuration
 */
export interface ModerationConfig {
  /** Enable PII detection */
  detectPii: boolean;
  /** Enable offensive content detection */
  detectOffensive: boolean;
  /** Enable sentiment analysis */
  analyzeSentiment: boolean;
  /** Minimum sentiment score for posting (-1 to 1) */
  minSentimentScore?: number;
  /** Custom blocked terms */
  blockedTerms?: string[];
  /** Custom allowed terms (override blocks) */
  allowedTerms?: string[];
}

/**
 * Service-specific configuration for token vending
 */
export interface ServiceConfig {
  /** Service type */
  type: ServiceType;
  /** Whether this service is enabled */
  enabled: boolean;
  /** Default token TTL in seconds */
  tokenTtl: number;
  /** Maximum allowed scopes */
  allowedScopes?: string[];
  /** AWS-specific: Role ARN to assume */
  roleArn?: string;
  /** Custom configuration */
  custom?: Record<string, unknown>;
}

/**
 * Complete policy configuration structure
 */
export interface PolicyConfig {
  /** Policy version for compatibility */
  version: string;
  /** Policy set name */
  name: string;
  /** Policy description */
  description: string;
  /** When this policy was last updated */
  updatedAt: number;
  /** Whether strict mode is enabled (deny by default) */
  strictMode: boolean;
  /** Budget configuration */
  budget: BudgetConfig;
  /** Content moderation settings */
  moderation: ModerationConfig;
  /** Ordered list of policy rules */
  rules: PolicyRule[];
  /** Service configurations for token vending */
  services: ServiceConfig[];
  /** Tools that are always allowed without checks */
  allowlistedTools?: string[];
  /** Tools that are always denied */
  denylistedTools?: string[];
}

// ============================================================================
// SDK CONFIGURATION
// ============================================================================

/**
 * Configuration for the Molt Guard SDK
 */
export interface MoltGuardConfig {
  /** Guard server URL */
  serverUrl: string;
  /** API key for authenticating with Guard server */
  apiKey: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Whether to fail open (allow) if Guard is unreachable */
  failOpen?: boolean;
  /** Enable debug logging */
  debug?: boolean;
  /** Retry configuration */
  retry?: {
    maxAttempts: number;
    backoffMs: number;
  };
}

// ============================================================================
// EXCEPTIONS
// ============================================================================

/**
 * Security exception thrown when a request is denied
 */
export class SecurityException extends Error {
  public readonly decision: GuardDecision;
  public readonly decisionId: string;
  public readonly moderationNotes: string;
  public readonly toolName: string;
  public readonly timestamp: number;

  constructor(
    message: string,
    decision: GuardDecision,
    decisionId: string,
    moderationNotes: string,
    toolName: string
  ) {
    super(message);
    this.name = 'SecurityException';
    this.decision = decision;
    this.decisionId = decisionId;
    this.moderationNotes = moderationNotes;
    this.toolName = toolName;
    this.timestamp = Date.now();

    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SecurityException);
    }
  }
}

/**
 * Configuration exception for invalid setup
 */
export class ConfigurationException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationException';
  }
}

/**
 * Token vending exception
 */
export class TokenVendingException extends Error {
  public readonly service: ServiceType;

  constructor(message: string, service: ServiceType) {
    super(message);
    this.name = 'TokenVendingException';
    this.service = service;
  }
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Generic tool function type
 */
export type ToolFunction = (...args: unknown[]) => unknown;

/**
 * Tool wrapper type that preserves the original function signature
 */
export type WrappedTool<T extends ToolFunction> = T;

/**
 * Map of tool names to their functions
 */
export interface ToolsMap {
  [toolName: string]: ToolFunction;
}

/**
 * Audit log entry for compliance
 */
export interface AuditLogEntry {
  timestamp: number;
  requestId: string;
  decisionId: string;
  toolName: string;
  intent: string;
  userId: string;
  decision: GuardDecision;
  moderationNotes: string;
  executionTimeMs: number;
  jitTokenIssued: boolean;
  parameters: Record<string, unknown>;
}
