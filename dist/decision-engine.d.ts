/**
 * Molt Guard - Decision Engine
 * The intelligence layer for evaluating requests against policies
 */
import { GuardRequest, GuardResponse, PolicyConfig } from './types';
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
export declare class DecisionEngine {
    private policy;
    private tokenVendor;
    private budgetState;
    constructor(policy: PolicyConfig, tokenVendor?: TokenVendingMachine);
    /**
     * Main entry point: Evaluate a request and return a decision
     */
    evaluateRequest(req: GuardRequest): Promise<GuardResponse>;
    /**
     * Budget Circuit Breaker
     * Prevents overspending by checking against daily/hourly limits
     */
    private checkBudget;
    /**
     * Content Moderation Check
     * Analyzes content for PII, offensive material, and sentiment
     */
    private moderateContent;
    /**
     * Mock sentiment analysis
     * Returns a score from -1 (negative) to 1 (positive)
     */
    private analyzeSentiment;
    /**
     * Authorization Check
     * Verifies user has required role for the operation
     */
    private checkAuthorization;
    /**
     * Evaluate policy rules against the request
     */
    private evaluateRules;
    /**
     * Evaluate a single policy condition
     */
    private evaluateCondition;
    /**
     * Get nested value from object using dot notation
     */
    private getNestedValue;
    /**
     * Check if tool requires content moderation
     */
    private requiresModeration;
    /**
     * Check if request requires JIT token
     */
    private requiresJitToken;
    /**
     * Create a standardized GuardResponse
     */
    private createResponse;
    /**
     * Generate unique decision ID
     */
    private generateDecisionId;
    /**
     * Update policy configuration
     */
    updatePolicy(policy: PolicyConfig): void;
    /**
     * Get current policy
     */
    getPolicy(): PolicyConfig;
    /**
     * Reset budget state for a user
     */
    resetBudget(userId: string): void;
    /**
     * Get budget state for a user
     */
    getBudgetState(userId: string): BudgetState | undefined;
}
/**
 * Factory function to create a decision engine with default policy
 */
export declare function createDecisionEngine(policyOverrides?: Partial<PolicyConfig>): DecisionEngine;
export {};
//# sourceMappingURL=decision-engine.d.ts.map