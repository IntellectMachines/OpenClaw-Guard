/**
 * Molt Guard - Main Entry Point
 * "One Command" integration for AI Agent security
 *
 * @packageDocumentation
 * @module molt-guard
 */
import { DecisionEngine } from './decision-engine';
import { TokenVendingMachine } from './token-vendor';
import { GuardRequest, GuardResponse, PolicyConfig, MoltGuardConfig, ServiceType, UserRole, ToolsMap } from './types';
export * from './types';
export { MoltGuardProxy, MoltGuard } from './proxy';
export { DecisionEngine, createDecisionEngine } from './decision-engine';
export { TokenVendingMachine } from './token-vendor';
/**
 * Initialization options
 */
export interface GuardInitOptions {
    /** Policy configuration */
    policy?: Partial<PolicyConfig>;
    /** SDK configuration */
    sdk?: Partial<MoltGuardConfig>;
    /** Start embedded server */
    startServer?: boolean;
    /** Server port (default: 3001) */
    serverPort?: number;
    /** Enable debug logging */
    debug?: boolean;
}
/**
 * Guard - The main facade for Molt Guard SDK
 *
 * Provides a simple, unified API for protecting AI agent tools.
 *
 * @example
 * ```typescript
 * import { guard } from 'molt-guard';
 *
 * // Initialize the guard
 * await guard.init();
 *
 * // Protect your tools
 * const protectedTools = guard.protect(myToolsList);
 *
 * // Use tools as normal - they're now secured!
 * await protectedTools.stripe.charge({ amount: 1000 });
 * ```
 */
export declare const guard: {
    /**
     * Initialize the Molt Guard system
     *
     * @param options - Initialization options
     */
    init(options?: GuardInitOptions): Promise<void>;
    /**
     * Start the embedded Guard Server
     *
     * @param port - Port to listen on (default: 3001)
     */
    startServer(port?: number): Promise<void>;
    /**
     * Protect a single tool or API
     *
     * @param tool - The tool object to protect
     * @param policyName - Optional policy name to apply
     * @returns Protected tool with security checks
     */
    protect<T extends object>(tool: T, policyName?: string): T;
    /**
     * Protect multiple tools at once
     *
     * @param tools - Map of tool names to tool objects
     * @param defaultPolicy - Default policy to apply
     * @returns Map of protected tools
     */
    protectAll<T extends ToolsMap>(tools: T, defaultPolicy?: string): T;
    /**
     * Set the current user/session context
     *
     * @param context - User context information
     */
    setContext(context: {
        userId: string;
        sessionId?: string;
        userRole?: UserRole;
        budgetUsed?: number;
    }): void;
    /**
     * Evaluate a request directly (for testing or custom flows)
     *
     * @param request - The guard request to evaluate
     * @returns Guard response with decision
     */
    evaluate(request: GuardRequest): Promise<GuardResponse>;
    /**
     * Update the policy configuration
     *
     * @param policy - New policy configuration
     */
    updatePolicy(policy: Partial<PolicyConfig>): void;
    /**
     * Get the current policy configuration
     */
    getPolicy(): PolicyConfig | null;
    /**
     * Vend a JIT token directly
     *
     * @param service - Target service type
     * @param context - Token request context
     * @returns JIT token
     */
    vendToken(service: ServiceType, context: {
        userId: string;
        toolName: string;
        intent: string;
    }): Promise<import("./types").JitToken>;
    /**
     * Check if the guard is initialized
     */
    isInitialized(): boolean;
    /**
     * Check if the embedded server is running
     */
    isServerRunning(): boolean;
    /**
     * Get the token vendor instance (for advanced use)
     */
    getTokenVendor(): TokenVendingMachine | null;
    /**
     * Get the decision engine instance (for advanced use)
     */
    getDecisionEngine(): DecisionEngine | null;
    /**
     * Reset the guard (for testing)
     */
    reset(): void;
};
/**
 * Quick start helper - creates a protected tool in one line
 *
 * @example
 * ```typescript
 * import { createProtectedTool } from 'molt-guard';
 *
 * const securedStripe = await createProtectedTool(stripeApi, {
 *   policy: 'financial',
 *   userId: 'user_123',
 * });
 * ```
 */
export declare function createProtectedTool<T extends object>(tool: T, options?: {
    policy?: string;
    userId?: string;
    userRole?: UserRole;
}): Promise<T>;
/**
 * Decorator for protecting class methods
 *
 * @example
 * ```typescript
 * class PaymentService {
 *   @Protected('financial')
 *   async charge(amount: number) {
 *     // ...
 *   }
 * }
 * ```
 */
export declare function Protected(policyName?: string): (_target: unknown, propertyKey: string, descriptor: PropertyDescriptor) => PropertyDescriptor;
export default guard;
//# sourceMappingURL=index.d.ts.map