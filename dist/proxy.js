"use strict";
/**
 * Molt Guard SDK - Proxy Wrapper
 * Intercepts tool calls and enforces security policies via Guard Server
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MoltGuard = exports.MoltGuardProxy = void 0;
const types_1 = require("./types");
/**
 * Default configuration values
 */
const DEFAULT_CONFIG = {
    timeout: 5000,
    failOpen: false,
    debug: false,
    retry: {
        maxAttempts: 3,
        backoffMs: 1000,
    },
};
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
class MoltGuardProxy {
    static config = null;
    static context = null;
    static initialized = false;
    static guardServerUrl = 'http://localhost:3001';
    /**
     * Initialize the Molt Guard SDK
     */
    static async init(config) {
        this.config = {
            serverUrl: config?.serverUrl || this.guardServerUrl,
            apiKey: config?.apiKey || process.env.MOLT_GUARD_API_KEY || '',
            ...DEFAULT_CONFIG,
            ...config,
        };
        // Initialize default context
        this.context = {
            userId: 'system',
            sessionId: this.generateSessionId(),
            userRole: types_1.UserRole.USER,
            budgetUsed: 0,
        };
        this.initialized = true;
        this.log('Molt Guard SDK initialized');
    }
    /**
     * Set the current request context
     */
    static setContext(context) {
        if (!this.context) {
            this.context = {
                userId: 'system',
                sessionId: this.generateSessionId(),
                userRole: types_1.UserRole.USER,
                budgetUsed: 0,
            };
        }
        this.context = { ...this.context, ...context };
    }
    /**
     * Wrap a single tool with security checks
     *
     * @param tool - The tool object to wrap
     * @param policyName - Name of the policy to apply
     * @returns Proxied tool with security interception
     */
    static wrap(tool, policyName) {
        this.ensureInitialized();
        return new Proxy(tool, {
            get: (target, prop, receiver) => {
                const original = Reflect.get(target, prop, receiver);
                // Only intercept function calls
                if (typeof original !== 'function') {
                    return original;
                }
                // Return wrapped function
                return this.createInterceptedFunction(original.bind(target), prop.toString(), policyName);
            },
        });
    }
    /**
     * Wrap multiple tools at once
     *
     * @param tools - Map of tool names to tool objects
     * @param defaultPolicy - Default policy to apply
     * @returns Map of wrapped tools
     */
    static wrapAll(tools, defaultPolicy = 'default') {
        this.ensureInitialized();
        const wrapped = {};
        for (const [name, tool] of Object.entries(tools)) {
            if (typeof tool === 'function') {
                wrapped[name] = this.createInterceptedFunction(tool, name, defaultPolicy);
            }
            else if (typeof tool === 'object' && tool !== null) {
                wrapped[name] = this.wrap(tool, defaultPolicy);
            }
            else {
                wrapped[name] = tool;
            }
        }
        return wrapped;
    }
    /**
     * Create an intercepted function that checks with Guard before execution
     */
    static createInterceptedFunction(originalFn, toolName, policyName) {
        const self = this;
        return async function intercepted(...args) {
            const startTime = Date.now();
            // Build the guard request
            const request = self.buildGuardRequest(toolName, args, policyName);
            self.log(`Intercepting call to ${toolName}`, request);
            try {
                // Send request to Guard Server
                const response = await self.sendToGuard(request);
                self.log(`Guard response for ${toolName}:`, response);
                // Handle the decision
                switch (response.decision) {
                    case types_1.GuardDecision.DENY:
                        throw new types_1.SecurityException(`Access denied: ${response.moderationNotes}`, response.decision, response.decisionId, response.moderationNotes, toolName);
                    case types_1.GuardDecision.FLAG:
                        // Allow but log for review
                        self.logAudit(request, response, Date.now() - startTime);
                        console.warn(`[MOLT-GUARD] Flagged operation: ${toolName} - ${response.moderationNotes}`);
                        break;
                    case types_1.GuardDecision.ALLOW:
                        // Continue with execution
                        break;
                }
                // Inject JIT token if provided
                const modifiedArgs = self.injectJitToken(args, response.jitToken);
                // Execute the original function
                const result = await originalFn(...modifiedArgs);
                // Update budget tracking
                if (self.context && request.metadata.cost) {
                    self.context.budgetUsed += request.metadata.cost;
                }
                return result;
            }
            catch (error) {
                if (error instanceof types_1.SecurityException) {
                    throw error;
                }
                // Handle Guard Server unreachable
                if (self.config?.failOpen) {
                    console.warn(`[MOLT-GUARD] Guard unreachable, failing open for ${toolName}`);
                    return await originalFn(...args);
                }
                throw new types_1.SecurityException(`Guard check failed: ${error.message}`, types_1.GuardDecision.DENY, 'guard-unreachable', 'Guard server unreachable and failOpen is disabled', toolName);
            }
        };
    }
    /**
     * Build a GuardRequest from function call details
     */
    static buildGuardRequest(toolName, args, policyName) {
        // Convert args array to named parameters if possible
        const parameters = {};
        args.forEach((arg, index) => {
            if (typeof arg === 'object' && arg !== null && !Array.isArray(arg)) {
                Object.assign(parameters, arg);
            }
            else {
                parameters[`arg${index}`] = arg;
            }
        });
        // Infer intent from tool name
        const intent = this.inferIntent(toolName, parameters);
        // Detect target service
        const targetService = this.inferService(toolName);
        // Build metadata
        const metadata = {
            userId: this.context?.userId || 'unknown',
            sessionId: this.context?.sessionId,
            budgetUsed: this.context?.budgetUsed || 0,
            cost: this.estimateCost(toolName, parameters),
            userRole: this.context?.userRole,
            timestamp: Date.now(),
            traceId: this.generateTraceId(),
            custom: { policyName },
        };
        return {
            intent,
            toolName,
            parameters,
            metadata,
            targetService,
            content: this.extractContent(parameters),
        };
    }
    /**
     * Send request to Guard Server
     */
    static async sendToGuard(request) {
        const config = this.config;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.timeout);
        try {
            const response = await fetch(`${config.serverUrl}/evaluate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${config.apiKey}`,
                    'X-Trace-Id': request.metadata.traceId || '',
                },
                body: JSON.stringify(request),
                signal: controller.signal,
            });
            clearTimeout(timeoutId);
            if (!response.ok) {
                throw new Error(`Guard server returned ${response.status}`);
            }
            return await response.json();
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    /**
     * Inject JIT token into function arguments
     * Looks for null/undefined placeholders or specific token fields
     */
    static injectJitToken(args, jitToken) {
        if (!jitToken) {
            return args;
        }
        return args.map((arg) => {
            if (typeof arg !== 'object' || arg === null) {
                return arg;
            }
            const modified = { ...arg };
            // Common token field names to inject
            const tokenFields = [
                'apiKey',
                'api_key',
                'token',
                'accessToken',
                'access_token',
                'secretKey',
                'secret_key',
                'credentials',
                'auth',
            ];
            for (const field of tokenFields) {
                if (field in modified && (modified[field] === null || modified[field] === undefined)) {
                    // Inject the appropriate credential
                    if (jitToken.type === types_1.ServiceType.AWS) {
                        modified[field] = {
                            accessKeyId: jitToken.accessKeyId,
                            secretAccessKey: jitToken.secretAccessKey,
                            sessionToken: jitToken.sessionToken,
                        };
                    }
                    else {
                        modified[field] = jitToken.token;
                    }
                }
            }
            // Also check for explicit __jitToken__ placeholder
            if ('__jitToken__' in modified) {
                delete modified.__jitToken__;
                Object.assign(modified, {
                    _injectedCredentials: jitToken,
                });
            }
            return modified;
        });
    }
    /**
     * Infer intent from tool name and parameters
     */
    static inferIntent(toolName, parameters) {
        const action = toolName.split('_')[0] || toolName;
        const target = Object.keys(parameters)[0] || 'resource';
        return `${action} ${target}`;
    }
    /**
     * Infer target service from tool name
     */
    static inferService(toolName) {
        const lowerName = toolName.toLowerCase();
        if (lowerName.includes('stripe') || lowerName.includes('payment')) {
            return types_1.ServiceType.STRIPE;
        }
        if (lowerName.includes('aws') || lowerName.includes('s3') || lowerName.includes('lambda')) {
            return types_1.ServiceType.AWS;
        }
        if (lowerName.includes('moltbook') || lowerName.includes('social')) {
            return types_1.ServiceType.MOLTBOOK;
        }
        return types_1.ServiceType.GENERIC;
    }
    /**
     * Estimate cost of an operation (mock implementation)
     */
    static estimateCost(toolName, parameters) {
        // Look for explicit amount/cost fields
        const costFields = ['amount', 'cost', 'price', 'value'];
        for (const field of costFields) {
            if (typeof parameters[field] === 'number') {
                return parameters[field];
            }
        }
        // Default cost based on tool type
        if (toolName.includes('charge') || toolName.includes('payment')) {
            return 1.0;
        }
        return 0.01; // Minimal cost for most operations
    }
    /**
     * Extract content for moderation from parameters
     */
    static extractContent(parameters) {
        const contentFields = ['content', 'message', 'text', 'body', 'post', 'comment'];
        for (const field of contentFields) {
            if (typeof parameters[field] === 'string') {
                return parameters[field];
            }
        }
        return undefined;
    }
    /**
     * Ensure SDK is initialized
     */
    static ensureInitialized() {
        if (!this.initialized) {
            // Auto-initialize with defaults
            this.init();
        }
    }
    /**
     * Generate a unique session ID
     */
    static generateSessionId() {
        return `sess_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }
    /**
     * Generate a trace ID for request correlation
     */
    static generateTraceId() {
        return `trace_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
    }
    /**
     * Debug logging
     */
    static log(message, data) {
        if (this.config?.debug) {
            console.log(`[MOLT-GUARD] ${message}`, data || '');
        }
    }
    /**
     * Audit logging for compliance
     */
    static logAudit(request, response, executionTimeMs) {
        const entry = {
            timestamp: Date.now(),
            requestId: request.metadata.traceId,
            decisionId: response.decisionId,
            toolName: request.toolName,
            intent: request.intent,
            userId: request.metadata.userId,
            decision: response.decision,
            moderationNotes: response.moderationNotes,
            executionTimeMs,
            jitTokenIssued: !!response.jitToken,
        };
        // In production, send to audit log service
        console.log('[MOLT-GUARD-AUDIT]', JSON.stringify(entry));
    }
    /**
     * Get current configuration (for testing)
     */
    static getConfig() {
        return this.config;
    }
    /**
     * Reset SDK state (for testing)
     */
    static reset() {
        this.config = null;
        this.context = null;
        this.initialized = false;
    }
}
exports.MoltGuardProxy = MoltGuardProxy;
/**
 * Alias for backwards compatibility
 */
exports.MoltGuard = MoltGuardProxy;
//# sourceMappingURL=proxy.js.map