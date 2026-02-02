/**
 * Molt Guard - Main Entry Point
 * "One Command" integration for AI Agent security
 * 
 * @packageDocumentation
 * @module molt-guard
 */

import { MoltGuardProxy } from './proxy';
import { DecisionEngine, createDecisionEngine } from './decision-engine';
import { TokenVendingMachine } from './token-vendor';
import {
  GuardRequest,
  GuardResponse,
  GuardDecision,
  PolicyConfig,
  MoltGuardConfig,
  ServiceType,
  UserRole,
  SecurityException,
  ToolsMap,
} from './types';

// Re-export all types
export * from './types';
export { MoltGuardProxy, MoltGuard } from './proxy';
export { DecisionEngine, createDecisionEngine } from './decision-engine';
export { TokenVendingMachine } from './token-vendor';

/**
 * Guard Server instance for local evaluation
 */
let guardServer: {
  engine: DecisionEngine;
  tokenVendor: TokenVendingMachine;
  running: boolean;
  port: number;
} | null = null;

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
export const guard = {
  /**
   * Initialize the Molt Guard system
   * 
   * @param options - Initialization options
   */
  async init(options: GuardInitOptions = {}): Promise<void> {
    const {
      policy,
      sdk,
      startServer = true,
      serverPort = 3001,
      debug = false,
    } = options;

    // Initialize the SDK
    await MoltGuardProxy.init({
      serverUrl: `http://localhost:${serverPort}`,
      debug,
      ...sdk,
    });

    // Create the decision engine
    const tokenVendor = new TokenVendingMachine();
    const engine = createDecisionEngine(policy);

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
  async startServer(port: number = 3001): Promise<void> {
    if (!guardServer) {
      throw new Error('Guard not initialized. Call guard.init() first.');
    }

    if (guardServer.running) {
      console.log('[MOLT-GUARD] Server already running');
      return;
    }

    try {
      // Dynamic import to avoid requiring http if not needed
      const http = await import('http');

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
              const request: GuardRequest = JSON.parse(body);
              const response = await guardServer!.engine.evaluateRequest(request);
              
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(response));
            } catch (error) {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                decision: GuardDecision.DENY,
                moderationNotes: `Server error: ${(error as Error).message}`,
                decisionId: 'error',
                timestamp: Date.now(),
              }));
            }
          });
        } else if (req.method === 'GET' && req.url === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', timestamp: Date.now() }));
        } else {
          res.writeHead(404);
          res.end('Not found');
        }
      });

      await new Promise<void>((resolve, reject) => {
        server.listen(port, () => {
          guardServer!.running = true;
          guardServer!.port = port;
          console.log(`[MOLT-GUARD] Server running on http://localhost:${port}`);
          resolve();
        });
        server.on('error', reject);
      });
    } catch (error) {
      console.warn('[MOLT-GUARD] Could not start embedded server:', (error as Error).message);
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
  protect<T extends object>(tool: T, policyName: string = 'default'): T {
    return MoltGuardProxy.wrap(tool, policyName);
  },

  /**
   * Protect multiple tools at once
   * 
   * @param tools - Map of tool names to tool objects
   * @param defaultPolicy - Default policy to apply
   * @returns Map of protected tools
   */
  protectAll<T extends ToolsMap>(tools: T, defaultPolicy: string = 'default'): T {
    return MoltGuardProxy.wrapAll(tools, defaultPolicy);
  },

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
  }): void {
    MoltGuardProxy.setContext(context);
  },

  /**
   * Evaluate a request directly (for testing or custom flows)
   * 
   * @param request - The guard request to evaluate
   * @returns Guard response with decision
   */
  async evaluate(request: GuardRequest): Promise<GuardResponse> {
    if (!guardServer) {
      await this.init();
    }
    return guardServer!.engine.evaluateRequest(request);
  },

  /**
   * Update the policy configuration
   * 
   * @param policy - New policy configuration
   */
  updatePolicy(policy: Partial<PolicyConfig>): void {
    if (!guardServer) {
      throw new Error('Guard not initialized. Call guard.init() first.');
    }
    const currentPolicy = guardServer.engine.getPolicy();
    guardServer.engine.updatePolicy({ ...currentPolicy, ...policy });
  },

  /**
   * Get the current policy configuration
   */
  getPolicy(): PolicyConfig | null {
    return guardServer?.engine.getPolicy() || null;
  },

  /**
   * Vend a JIT token directly
   * 
   * @param service - Target service type
   * @param context - Token request context
   * @returns JIT token
   */
  async vendToken(
    service: ServiceType,
    context: { userId: string; toolName: string; intent: string }
  ) {
    if (!guardServer) {
      await this.init();
    }
    return guardServer!.tokenVendor.vendToken(service, context);
  },

  /**
   * Check if the guard is initialized
   */
  isInitialized(): boolean {
    return guardServer !== null;
  },

  /**
   * Check if the embedded server is running
   */
  isServerRunning(): boolean {
    return guardServer?.running || false;
  },

  /**
   * Get the token vendor instance (for advanced use)
   */
  getTokenVendor(): TokenVendingMachine | null {
    return guardServer?.tokenVendor || null;
  },

  /**
   * Get the decision engine instance (for advanced use)
   */
  getDecisionEngine(): DecisionEngine | null {
    return guardServer?.engine || null;
  },

  /**
   * Reset the guard (for testing)
   */
  reset(): void {
    guardServer = null;
    MoltGuardProxy.reset();
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
export async function createProtectedTool<T extends object>(
  tool: T,
  options: {
    policy?: string;
    userId?: string;
    userRole?: UserRole;
  } = {}
): Promise<T> {
  if (!guard.isInitialized()) {
    await guard.init();
  }

  if (options.userId) {
    guard.setContext({
      userId: options.userId,
      userRole: options.userRole,
    });
  }

  return guard.protect(tool, options.policy || 'default');
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
export function Protected(policyName: string = 'default') {
  return function (
    _target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      if (!guard.isInitialized()) {
        await guard.init();
      }

      const request: GuardRequest = {
        intent: `Execute ${propertyKey}`,
        toolName: propertyKey,
        parameters: args.reduce<Record<string, unknown>>((acc, arg, i) => {
          if (typeof arg === 'object' && arg !== null) {
            return { ...acc, ...(arg as Record<string, unknown>) };
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

      const response = await guard.evaluate(request);

      if (response.decision === GuardDecision.DENY) {
        throw new SecurityException(
          response.moderationNotes,
          response.decision,
          response.decisionId,
          response.moderationNotes,
          propertyKey
        );
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

// Default export for convenience
export default guard;
