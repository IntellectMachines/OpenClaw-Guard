"use strict";
/**
 * Molt Guard - Main Entry Point
 * "One Command" integration for AI Agent security
 *
 * @packageDocumentation
 * @module molt-guard
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.guard = exports.TokenVendingMachine = exports.createDecisionEngine = exports.DecisionEngine = exports.MoltGuard = exports.MoltGuardProxy = void 0;
exports.createProtectedTool = createProtectedTool;
exports.Protected = Protected;
const proxy_1 = require("./proxy");
const decision_engine_1 = require("./decision-engine");
const token_vendor_1 = require("./token-vendor");
const types_1 = require("./types");
// Re-export all types
__exportStar(require("./types"), exports);
var proxy_2 = require("./proxy");
Object.defineProperty(exports, "MoltGuardProxy", { enumerable: true, get: function () { return proxy_2.MoltGuardProxy; } });
Object.defineProperty(exports, "MoltGuard", { enumerable: true, get: function () { return proxy_2.MoltGuard; } });
var decision_engine_2 = require("./decision-engine");
Object.defineProperty(exports, "DecisionEngine", { enumerable: true, get: function () { return decision_engine_2.DecisionEngine; } });
Object.defineProperty(exports, "createDecisionEngine", { enumerable: true, get: function () { return decision_engine_2.createDecisionEngine; } });
var token_vendor_2 = require("./token-vendor");
Object.defineProperty(exports, "TokenVendingMachine", { enumerable: true, get: function () { return token_vendor_2.TokenVendingMachine; } });
/**
 * Guard Server instance for local evaluation
 */
let guardServer = null;
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
exports.guard = {
    /**
     * Initialize the Molt Guard system
     *
     * @param options - Initialization options
     */
    async init(options = {}) {
        const { policy, sdk, startServer = true, serverPort = 3001, debug = false, } = options;
        // Initialize the SDK
        await proxy_1.MoltGuardProxy.init({
            serverUrl: `http://localhost:${serverPort}`,
            debug,
            ...sdk,
        });
        // Create the decision engine
        const tokenVendor = new token_vendor_1.TokenVendingMachine();
        const engine = (0, decision_engine_1.createDecisionEngine)(policy);
        guardServer = {
            engine,
            tokenVendor,
            running: false,
            port: serverPort,
        };
        // Start embedded server if requested
        if (startServer) {
            await this.startServer(serverPort);
        }
        if (debug) {
            console.log('[MOLT-GUARD] Initialized successfully');
        }
    },
    /**
     * Start the embedded Guard Server
     *
     * @param port - Port to listen on (default: 3001)
     */
    async startServer(port = 3001) {
        if (!guardServer) {
            throw new Error('Guard not initialized. Call guard.init() first.');
        }
        if (guardServer.running) {
            console.log('[MOLT-GUARD] Server already running');
            return;
        }
        try {
            // Dynamic import to avoid requiring http if not needed
            const http = await Promise.resolve().then(() => __importStar(require('http')));
            const server = http.createServer(async (req, res) => {
                // CORS headers
                res.setHeader('Access-Control-Allow-Origin', '*');
                res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
                res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
                if (req.method === 'OPTIONS') {
                    res.writeHead(200);
                    res.end();
                    return;
                }
                if (req.method === 'POST' && req.url === '/evaluate') {
                    let body = '';
                    req.on('data', (chunk) => {
                        body += chunk.toString();
                    });
                    req.on('end', async () => {
                        try {
                            const request = JSON.parse(body);
                            const response = await guardServer.engine.evaluateRequest(request);
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify(response));
                        }
                        catch (error) {
                            res.writeHead(500, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({
                                decision: types_1.GuardDecision.DENY,
                                moderationNotes: `Server error: ${error.message}`,
                                decisionId: 'error',
                                timestamp: Date.now(),
                            }));
                        }
                    });
                }
                else if (req.method === 'GET' && req.url === '/health') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ status: 'healthy', timestamp: Date.now() }));
                }
                else {
                    res.writeHead(404);
                    res.end('Not found');
                }
            });
            await new Promise((resolve, reject) => {
                server.listen(port, () => {
                    guardServer.running = true;
                    guardServer.port = port;
                    console.log(`[MOLT-GUARD] Server running on http://localhost:${port}`);
                    resolve();
                });
                server.on('error', reject);
            });
        }
        catch (error) {
            console.warn('[MOLT-GUARD] Could not start embedded server:', error.message);
            console.warn('[MOLT-GUARD] Using in-process evaluation instead');
        }
    },
    /**
     * Protect a single tool or API
     *
     * @param tool - The tool object to protect
     * @param policyName - Optional policy name to apply
     * @returns Protected tool with security checks
     */
    protect(tool, policyName = 'default') {
        return proxy_1.MoltGuardProxy.wrap(tool, policyName);
    },
    /**
     * Protect multiple tools at once
     *
     * @param tools - Map of tool names to tool objects
     * @param defaultPolicy - Default policy to apply
     * @returns Map of protected tools
     */
    protectAll(tools, defaultPolicy = 'default') {
        return proxy_1.MoltGuardProxy.wrapAll(tools, defaultPolicy);
    },
    /**
     * Set the current user/session context
     *
     * @param context - User context information
     */
    setContext(context) {
        proxy_1.MoltGuardProxy.setContext(context);
    },
    /**
     * Evaluate a request directly (for testing or custom flows)
     *
     * @param request - The guard request to evaluate
     * @returns Guard response with decision
     */
    async evaluate(request) {
        if (!guardServer) {
            await this.init();
        }
        return guardServer.engine.evaluateRequest(request);
    },
    /**
     * Update the policy configuration
     *
     * @param policy - New policy configuration
     */
    updatePolicy(policy) {
        if (!guardServer) {
            throw new Error('Guard not initialized. Call guard.init() first.');
        }
        const currentPolicy = guardServer.engine.getPolicy();
        guardServer.engine.updatePolicy({ ...currentPolicy, ...policy });
    },
    /**
     * Get the current policy configuration
     */
    getPolicy() {
        return guardServer?.engine.getPolicy() || null;
    },
    /**
     * Vend a JIT token directly
     *
     * @param service - Target service type
     * @param context - Token request context
     * @returns JIT token
     */
    async vendToken(service, context) {
        if (!guardServer) {
            await this.init();
        }
        return guardServer.tokenVendor.vendToken(service, context);
    },
    /**
     * Check if the guard is initialized
     */
    isInitialized() {
        return guardServer !== null;
    },
    /**
     * Check if the embedded server is running
     */
    isServerRunning() {
        return guardServer?.running || false;
    },
    /**
     * Get the token vendor instance (for advanced use)
     */
    getTokenVendor() {
        return guardServer?.tokenVendor || null;
    },
    /**
     * Get the decision engine instance (for advanced use)
     */
    getDecisionEngine() {
        return guardServer?.engine || null;
    },
    /**
     * Reset the guard (for testing)
     */
    reset() {
        guardServer = null;
        proxy_1.MoltGuardProxy.reset();
    },
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
async function createProtectedTool(tool, options = {}) {
    if (!exports.guard.isInitialized()) {
        await exports.guard.init();
    }
    if (options.userId) {
        exports.guard.setContext({
            userId: options.userId,
            userRole: options.userRole,
        });
    }
    return exports.guard.protect(tool, options.policy || 'default');
}
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
function Protected(policyName = 'default') {
    return function (_target, propertyKey, descriptor) {
        const originalMethod = descriptor.value;
        descriptor.value = async function (...args) {
            if (!exports.guard.isInitialized()) {
                await exports.guard.init();
            }
            const request = {
                intent: `Execute ${propertyKey}`,
                toolName: propertyKey,
                parameters: args.reduce((acc, arg, i) => {
                    if (typeof arg === 'object' && arg !== null) {
                        return { ...acc, ...arg };
                    }
                    return { ...acc, [`arg${i}`]: arg };
                }, {}),
                metadata: {
                    userId: 'decorator-user',
                    budgetUsed: 0,
                    timestamp: Date.now(),
                    custom: { policyName },
                },
            };
            const response = await exports.guard.evaluate(request);
            if (response.decision === types_1.GuardDecision.DENY) {
                throw new types_1.SecurityException(response.moderationNotes, response.decision, response.decisionId, response.moderationNotes, propertyKey);
            }
            return originalMethod.apply(this, args);
        };
        return descriptor;
    };
}
// Default export for convenience
exports.default = exports.guard;
//# sourceMappingURL=index.js.map