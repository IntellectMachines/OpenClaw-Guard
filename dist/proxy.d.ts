/**
 * Molt Guard SDK - Proxy Wrapper
 * Intercepts tool calls and enforces security policies via Guard Server
 */
import { MoltGuardConfig, UserRole, ToolsMap } from './types';
/**
 * Context for the current request/session
 */
interface RequestContext {
    userId: string;
    sessionId: string;
    userRole: UserRole;
    budgetUsed: number;
}
/**
 * MoltGuardProxy - The "One Command" SDK
 *
 * Wraps tool calls with security checks via the Guard Server.
 * Uses JavaScript Proxy to intercept function calls transparently.
 *
 * @example
 * ```typescript
 * const securedStripe = MoltGuard.wrap(stripeApi, 'financial_policy');
 * await securedStripe.charge({ amount: 1000 }); // Automatically secured
 * ```
 */
export declare class MoltGuardProxy {
    private static config;
    private static context;
    private static initialized;
    private static guardServerUrl;
    /**
     * Initialize the Molt Guard SDK
     */
    static init(config?: Partial<MoltGuardConfig>): Promise<void>;
    /**
     * Set the current request context
     */
    static setContext(context: Partial<RequestContext>): void;
    /**
     * Wrap a single tool with security checks
     *
     * @param tool - The tool object to wrap
     * @param policyName - Name of the policy to apply
     * @returns Proxied tool with security interception
     */
    static wrap<T extends object>(tool: T, policyName: string): T;
    /**
     * Wrap multiple tools at once
     *
     * @param tools - Map of tool names to tool objects
     * @param defaultPolicy - Default policy to apply
     * @returns Map of wrapped tools
     */
    static wrapAll<T extends ToolsMap>(tools: T, defaultPolicy?: string): T;
    /**
     * Create an intercepted function that checks with Guard before execution
     */
    private static createInterceptedFunction;
    /**
     * Build a GuardRequest from function call details
     */
    private static buildGuardRequest;
    /**
     * Send request to Guard Server
     */
    private static sendToGuard;
    /**
     * Inject JIT token into function arguments
     * Looks for null/undefined placeholders or specific token fields
     */
    private static injectJitToken;
    /**
     * Infer intent from tool name and parameters
     */
    private static inferIntent;
    /**
     * Infer target service from tool name
     */
    private static inferService;
    /**
     * Estimate cost of an operation (mock implementation)
     */
    private static estimateCost;
    /**
     * Extract content for moderation from parameters
     */
    private static extractContent;
    /**
     * Ensure SDK is initialized
     */
    private static ensureInitialized;
    /**
     * Generate a unique session ID
     */
    private static generateSessionId;
    /**
     * Generate a trace ID for request correlation
     */
    private static generateTraceId;
    /**
     * Debug logging
     */
    private static log;
    /**
     * Audit logging for compliance
     */
    private static logAudit;
    /**
     * Get current configuration (for testing)
     */
    static getConfig(): MoltGuardConfig | null;
    /**
     * Reset SDK state (for testing)
     */
    static reset(): void;
}
/**
 * Alias for backwards compatibility
 */
export declare const MoltGuard: typeof MoltGuardProxy;
export {};
//# sourceMappingURL=proxy.d.ts.map