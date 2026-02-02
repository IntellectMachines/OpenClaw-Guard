/**
 * Molt Guard - Decision Engine
 * The intelligence layer for evaluating requests against policies
 */

import {
  GuardRequest,
  GuardResponse,
  GuardDecision,
  PolicyConfig,
  PolicyCondition,
  ConditionOperator,
  ModerationResult,
  ModerationSeverity,
  JitToken,
  UserRole,
  ServiceType,
} from './types';
import { TokenVendingMachine } from './token-vendor';

/**
 * Budget tracker for rate limiting
 */
interface BudgetState {
  dailyUsed: number;
  hourlyUsed: number;
  lastReset: number;
  lastHourlyReset: number;
}

/**
 * Decision Engine - The Guard Server's brain
 * 
 * Evaluates incoming requests against policies and returns decisions.
 * Implements a chain of checks: Budget -> Content Moderation -> Auth -> Policy Rules
 */
export class DecisionEngine {
  private policy: PolicyConfig;
  private tokenVendor: TokenVendingMachine;
  private budgetState: Map<string, BudgetState> = new Map();

  constructor(policy: PolicyConfig, tokenVendor?: TokenVendingMachine) {
    this.policy = policy;
    this.tokenVendor = tokenVendor || new TokenVendingMachine();
  }

  /**
   * Main entry point: Evaluate a request and return a decision
   */
  public async evaluateRequest(req: GuardRequest): Promise<GuardResponse> {
    const decisionId = this.generateDecisionId();

    try {
      // Step 0: Check denylist
      if (this.policy.denylistedTools?.includes(req.toolName)) {
        return this.createResponse(
          GuardDecision.DENY,
          decisionId,
          'Tool is denylisted by policy'
        );
      }

      // Step 0.5: Check allowlist (skip all other checks)
      if (this.policy.allowlistedTools?.includes(req.toolName)) {
        return this.createResponse(
          GuardDecision.ALLOW,
          decisionId,
          'Tool is allowlisted'
        );
      }

      // Step 1: Budget Circuit Breaker
      const budgetCheck = this.checkBudget(req);
      if (!budgetCheck.passed) {
        return this.createResponse(
          GuardDecision.DENY,
          decisionId,
          budgetCheck.reason
        );
      }

      // Step 2: Content Moderation (if applicable)
      let moderationResult: ModerationResult | undefined;
      if (this.requiresModeration(req.toolName) && req.content) {
        moderationResult = await this.moderateContent(req.content);
        if (!moderationResult.passed) {
          return this.createResponse(
            moderationResult.severity === ModerationSeverity.CRITICAL
              ? GuardDecision.DENY
              : GuardDecision.FLAG,
            decisionId,
            moderationResult.notes,
            undefined,
            moderationResult
          );
        }
      }

      // Step 3: Authorization Check
      const authCheck = this.checkAuthorization(req);
      if (!authCheck.passed) {
        return this.createResponse(
          GuardDecision.DENY,
          decisionId,
          authCheck.reason
        );
      }

      // Step 4: Policy Rules Evaluation
      const ruleResult = this.evaluateRules(req);
      if (ruleResult.matched && ruleResult.decision !== GuardDecision.ALLOW) {
        return this.createResponse(
          ruleResult.decision,
          decisionId,
          ruleResult.message,
          undefined,
          moderationResult
        );
      }

      // Step 5: Vend JIT Token if needed
      let jitToken: JitToken | undefined;
      if (this.requiresJitToken(req)) {
        try {
          jitToken = await this.tokenVendor.vendToken(
            req.targetService || ServiceType.GENERIC,
            {
              userId: req.metadata.userId,
              toolName: req.toolName,
              intent: req.intent,
            }
          );
        } catch (error) {
          return this.createResponse(
            GuardDecision.DENY,
            decisionId,
            `Token vending failed: ${(error as Error).message}`
          );
        }
      }

      // All checks passed - ALLOW
      return this.createResponse(
        GuardDecision.ALLOW,
        decisionId,
        'All security checks passed',
        jitToken,
        moderationResult
      );
    } catch (error) {
      // Fail closed by default
      return this.createResponse(
        GuardDecision.DENY,
        decisionId,
        `Evaluation error: ${(error as Error).message}`
      );
    }
  }

  /**
   * Budget Circuit Breaker
   * Prevents overspending by checking against daily/hourly limits
   */
  private checkBudget(req: GuardRequest): { passed: boolean; reason: string } {
    const userId = req.metadata.userId;
    const cost = req.metadata.cost || 0;
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;
    const hourMs = 60 * 60 * 1000;

    // Get or initialize budget state for user
    let state = this.budgetState.get(userId);
    if (!state) {
      state = {
        dailyUsed: 0,
        hourlyUsed: 0,
        lastReset: now,
        lastHourlyReset: now,
      };
      this.budgetState.set(userId, state);
    }

    // Reset daily budget if needed
    if (now - state.lastReset > dayMs) {
      state.dailyUsed = 0;
      state.lastReset = now;
    }

    // Reset hourly budget if needed
    if (now - state.lastHourlyReset > hourMs) {
      state.hourlyUsed = 0;
      state.lastHourlyReset = now;
    }

    // Check per-request limit
    if (cost > this.policy.budget.perRequestLimit) {
      return {
        passed: false,
        reason: `Request cost ($${cost}) exceeds per-request limit ($${this.policy.budget.perRequestLimit})`,
      };
    }

    // Check daily limit
    if (state.dailyUsed + cost > this.policy.budget.dailyLimit) {
      return {
        passed: false,
        reason: `Daily budget limit ($${this.policy.budget.dailyLimit}) would be exceeded`,
      };
    }

    // Check hourly limit if configured
    if (
      this.policy.budget.hourlyLimit &&
      state.hourlyUsed + cost > this.policy.budget.hourlyLimit
    ) {
      return {
        passed: false,
        reason: `Hourly rate limit ($${this.policy.budget.hourlyLimit}) would be exceeded`,
      };
    }

    // Update budget state
    state.dailyUsed += cost;
    state.hourlyUsed += cost;

    // Check alert threshold
    const usagePercent = (state.dailyUsed / this.policy.budget.dailyLimit) * 100;
    if (
      this.policy.budget.alertThreshold &&
      usagePercent >= this.policy.budget.alertThreshold
    ) {
      console.warn(
        `[MOLT-GUARD] Budget alert: User ${userId} has used ${usagePercent.toFixed(1)}% of daily budget`
      );
    }

    return { passed: true, reason: '' };
  }

  /**
   * Content Moderation Check
   * Analyzes content for PII, offensive material, and sentiment
   */
  private async moderateContent(content: string): Promise<ModerationResult> {
    const issues: string[] = [];
    let severity = ModerationSeverity.NONE;
    let confidence = 1.0;

    // PII Detection (mock implementation)
    if (this.policy.moderation.detectPii) {
      const piiPatterns = {
        email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
        ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
        creditCard: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
      };

      for (const [type, pattern] of Object.entries(piiPatterns)) {
        if (pattern.test(content)) {
          issues.push(`PII detected: ${type}`);
          severity = ModerationSeverity.HIGH;
        }
      }
    }

    // Offensive Content Detection (mock implementation)
    if (this.policy.moderation.detectOffensive) {
      const blockedTerms = this.policy.moderation.blockedTerms || [];
      const lowerContent = content.toLowerCase();

      for (const term of blockedTerms) {
        if (lowerContent.includes(term.toLowerCase())) {
          // Check if it's in allowed terms
          const allowedTerms = this.policy.moderation.allowedTerms || [];
          if (!allowedTerms.some((a) => lowerContent.includes(a.toLowerCase()))) {
            issues.push(`Blocked term detected: ${term}`);
            severity = ModerationSeverity.CRITICAL;
          }
        }
      }
    }

    // Sentiment Analysis (mock implementation)
    if (this.policy.moderation.analyzeSentiment) {
      const sentiment = this.analyzeSentiment(content);
      if (
        this.policy.moderation.minSentimentScore !== undefined &&
        sentiment < this.policy.moderation.minSentimentScore
      ) {
        issues.push(`Negative sentiment detected (score: ${sentiment.toFixed(2)})`);
        severity =
          severity === ModerationSeverity.NONE
            ? ModerationSeverity.MEDIUM
            : severity;
      }
    }

    const passed = severity === ModerationSeverity.NONE;

    return {
      passed,
      severity,
      categories: issues,
      notes: issues.length > 0 ? issues.join('; ') : 'Content passed moderation',
      confidence,
    };
  }

  /**
   * Mock sentiment analysis
   * Returns a score from -1 (negative) to 1 (positive)
   */
  private analyzeSentiment(content: string): number {
    // Simple mock: count positive vs negative words
    const positiveWords = ['good', 'great', 'excellent', 'happy', 'love', 'amazing', 'wonderful'];
    const negativeWords = ['bad', 'terrible', 'awful', 'hate', 'horrible', 'disgusting', 'angry'];

    const lowerContent = content.toLowerCase();
    let score = 0;

    for (const word of positiveWords) {
      if (lowerContent.includes(word)) score += 0.2;
    }
    for (const word of negativeWords) {
      if (lowerContent.includes(word)) score -= 0.2;
    }

    return Math.max(-1, Math.min(1, score));
  }

  /**
   * Authorization Check
   * Verifies user has required role for the operation
   */
  private checkAuthorization(req: GuardRequest): { passed: boolean; reason: string } {
    const toolName = req.toolName.toLowerCase();
    const userRole = req.metadata.userRole || UserRole.USER;

    // Tool-specific role requirements
    const roleRequirements: Record<string, UserRole[]> = {
      stripe_charge: [UserRole.ADMIN],
      stripe_refund: [UserRole.ADMIN],
      aws_deploy: [UserRole.ADMIN, UserRole.SERVICE],
      delete_user: [UserRole.ADMIN],
      modify_permissions: [UserRole.ADMIN],
    };

    const requiredRoles = roleRequirements[toolName];
    if (requiredRoles && !requiredRoles.includes(userRole)) {
      return {
        passed: false,
        reason: `Insufficient permissions: ${toolName} requires role(s): ${requiredRoles.join(', ')}`,
      };
    }

    return { passed: true, reason: '' };
  }

  /**
   * Evaluate policy rules against the request
   */
  private evaluateRules(req: GuardRequest): {
    matched: boolean;
    decision: GuardDecision;
    message: string;
  } {
    // Sort rules by priority (lower = higher priority)
    const sortedRules = [...this.policy.rules]
      .filter((r) => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      // Check if rule applies to this tool
      if (
        rule.targetTools.length > 0 &&
        !rule.targetTools.includes(req.toolName)
      ) {
        continue;
      }

      // Check all conditions (AND logic)
      const allConditionsMet = rule.conditions.every((condition) =>
        this.evaluateCondition(condition, req)
      );

      if (allConditionsMet) {
        return {
          matched: true,
          decision: rule.action.decision,
          message: rule.action.message,
        };
      }
    }

    // No rules matched - use default based on strict mode
    if (this.policy.strictMode) {
      return {
        matched: true,
        decision: GuardDecision.DENY,
        message: 'No matching rule found (strict mode)',
      };
    }

    return {
      matched: false,
      decision: GuardDecision.ALLOW,
      message: 'No matching rule found',
    };
  }

  /**
   * Evaluate a single policy condition
   */
  private evaluateCondition(condition: PolicyCondition, req: GuardRequest): boolean {
    const value = this.getNestedValue(req, condition.field);

    switch (condition.operator) {
      case ConditionOperator.EQUALS:
        return value === condition.value;

      case ConditionOperator.NOT_EQUALS:
        return value !== condition.value;

      case ConditionOperator.CONTAINS:
        return String(value).includes(String(condition.value));

      case ConditionOperator.NOT_CONTAINS:
        return !String(value).includes(String(condition.value));

      case ConditionOperator.GREATER_THAN:
        return Number(value) > Number(condition.value);

      case ConditionOperator.LESS_THAN:
        return Number(value) < Number(condition.value);

      case ConditionOperator.MATCHES_REGEX:
        return new RegExp(String(condition.value)).test(String(value));

      case ConditionOperator.IN_LIST:
        return Array.isArray(condition.value) && condition.value.includes(value);

      case ConditionOperator.NOT_IN_LIST:
        return Array.isArray(condition.value) && !condition.value.includes(value);

      default:
        return false;
    }
  }

  /**
   * Get nested value from object using dot notation
   */
  private getNestedValue(obj: unknown, path: string): unknown {
    return path.split('.').reduce((current: unknown, key) => {
      if (current && typeof current === 'object') {
        return (current as Record<string, unknown>)[key];
      }
      return undefined;
    }, obj);
  }

  /**
   * Check if tool requires content moderation
   */
  private requiresModeration(toolName: string): boolean {
    const moderatedTools = [
      'post_to_moltbook',
      'send_message',
      'create_post',
      'comment',
      'reply',
      'publish',
    ];
    return moderatedTools.some((t) => toolName.toLowerCase().includes(t));
  }

  /**
   * Check if request requires JIT token
   */
  private requiresJitToken(req: GuardRequest): boolean {
    const tokenRequiredTools = [
      'stripe',
      'aws',
      'payment',
      'deploy',
      's3',
      'lambda',
    ];
    const toolLower = req.toolName.toLowerCase();
    return tokenRequiredTools.some((t) => toolLower.includes(t));
  }

  /**
   * Create a standardized GuardResponse
   */
  private createResponse(
    decision: GuardDecision,
    decisionId: string,
    moderationNotes: string,
    jitToken?: JitToken,
    moderationResult?: ModerationResult
  ): GuardResponse {
    return {
      decision,
      jitToken,
      moderationNotes,
      moderationResult,
      decisionId,
      timestamp: Date.now(),
      cacheTtl: decision === GuardDecision.ALLOW ? 60 : 0,
    };
  }

  /**
   * Generate unique decision ID
   */
  private generateDecisionId(): string {
    return `dec_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Update policy configuration
   */
  public updatePolicy(policy: PolicyConfig): void {
    this.policy = policy;
  }

  /**
   * Get current policy
   */
  public getPolicy(): PolicyConfig {
    return this.policy;
  }

  /**
   * Reset budget state for a user
   */
  public resetBudget(userId: string): void {
    this.budgetState.delete(userId);
  }

  /**
   * Get budget state for a user
   */
  public getBudgetState(userId: string): BudgetState | undefined {
    return this.budgetState.get(userId);
  }
}

/**
 * Factory function to create a decision engine with default policy
 */
export function createDecisionEngine(
  policyOverrides?: Partial<PolicyConfig>
): DecisionEngine {
  const defaultPolicy: PolicyConfig = {
    version: '1.0.0',
    name: 'default-policy',
    description: 'Default Molt Guard security policy',
    updatedAt: Date.now(),
    strictMode: false,
    budget: {
      dailyLimit: 1000,
      perRequestLimit: 100,
      hourlyLimit: 200,
      alertThreshold: 80,
    },
    moderation: {
      detectPii: true,
      detectOffensive: true,
      analyzeSentiment: true,
      minSentimentScore: -0.5,
      blockedTerms: [],
    },
    rules: [],
    services: [],
    allowlistedTools: ['read_file', 'search_web', 'get_time'],
    denylistedTools: ['delete_all', 'format_disk'],
  };

  const mergedPolicy = { ...defaultPolicy, ...policyOverrides };
  return new DecisionEngine(mergedPolicy);
}
