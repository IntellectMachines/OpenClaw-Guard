/**
 * Molt Guard SDK - Proxy Wrapper
 * Intercepts tool calls and enforces security policies via Guard Server
 */

import {
  GuardRequest,
  GuardResponse,
  GuardDecision,
  JitToken,
  MoltGuardConfig,
  RequestMetadata,
  SecurityException,
  ServiceType,
  UserRole,
  ToolFunction,
  ToolsMap,
} from './types';

/**
 * Default configuration values
 */
const DEFAULT_CONFIG: Partial<MoltGuardConfig> = {
  timeout: 5000,
  failOpen: false,
  debug: false,
  retry: {
    maxAttempts: 3,
    backoffMs: 1000,
  },
};

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
export class MoltGuardProxy {
  private static config: MoltGuardConfig | null = null;
  private static context: RequestContext | null = null;
  private static initialized: boolean = false;
  private static guardServerUrl: string = 'http://localhost:3001';

  /**
   * Initialize the Molt Guard SDK
   */
  public static async init(config?: Partial<MoltGuardConfig>): Promise<void> {
    this.config = {
      serverUrl: config?.serverUrl || this.guardServerUrl,
      apiKey: config?.apiKey || process.env.MOLT_GUARD_API_KEY || '',
      ...DEFAULT_CONFIG,
      ...config,
    } as MoltGuardConfig;

    // Initialize default context
    this.context = {
      userId: 'system',
      sessionId: this.generateSessionId(),
      userRole: UserRole.USER,
      budgetUsed: 0,
    };

    this.initialized = true;
    this.log('Molt Guard SDK initialized');
  }

  /**
   * Set the current request context
   */
  public static setContext(context: Partial<RequestContext>): void {
    if (!this.context) {
      this.context = {
        userId: 'system',
        sessionId: this.generateSessionId(),
        userRole: UserRole.USER,
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
  public static wrap<T extends object>(tool: T, policyName: string): T {
    this.ensureInitialized();

    return new Proxy(tool, {
      get: (target: T, prop: string | symbol, receiver: unknown) => {
        const original = Reflect.get(target, prop, receiver);

        // Only intercept function calls
        if (typeof original !== 'function') {
          return original;
        }

        // Return wrapped function
        return this.createInterceptedFunction(
          original.bind(target),
          prop.toString(),
          policyName
        );
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
  public static wrapAll<T extends ToolsMap>(
    tools: T,
    defaultPolicy: string = 'default'
  ): T {
    this.ensureInitialized();

    const wrapped: ToolsMap = {};
    for (const [name, tool] of Object.entries(tools)) {
      if (typeof tool === 'function') {
        wrapped[name] = this.createInterceptedFunction(tool, name, defaultPolicy);
      } else if (typeof tool === 'object' && tool !== null) {
        wrapped[name] = this.wrap(tool as object, defaultPolicy) as ToolFunction;
      } else {
        wrapped[name] = tool;
      }
    }
    return wrapped as T;
  }

  /**
   * Create an intercepted function that checks with Guard before execution
   */
  private static createInterceptedFunction(
    originalFn: ToolFunction,
    toolName: string,
    policyName: string
  ): ToolFunction {
    const self = this;

    return async function intercepted(...args: unknown[]): Promise<unknown> {
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
          case GuardDecision.DENY:
            throw new SecurityException(
              `Access denied: ${response.moderationNotes}`,
              response.decision,
              response.decisionId,
              response.moderationNotes,
              toolName
            );

          case GuardDecision.FLAG:
            // Allow but log for review
            self.logAudit(request, response, Date.now() - startTime);
            console.warn(
              `[MOLT-GUARD] Flagged operation: ${toolName} - ${response.moderationNotes}`
            );
            break;

          case GuardDecision.ALLOW:
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
      } catch (error) {
        if (error instanceof SecurityException) {
          throw error;
        }

        // Handle Guard Server unreachable
        if (self.config?.failOpen) {
          console.warn(
            `[MOLT-GUARD] Guard unreachable, failing open for ${toolName}`
          );
          return await originalFn(...args);
        }

        throw new SecurityException(
          `Guard check failed: ${(error as Error).message}`,
          GuardDecision.DENY,
          'guard-unreachable',
          'Guard server unreachable and failOpen is disabled',
          toolName
        );
      }
    };
  }

  /**
   * Build a GuardRequest from function call details
   */
  private static buildGuardRequest(
    toolName: string,
    args: unknown[],
    policyName: string
  ): GuardRequest {
    // Convert args array to named parameters if possible
    const parameters: Record<string, unknown> = {};
    args.forEach((arg, index) => {
      if (typeof arg === 'object' && arg !== null && !Array.isArray(arg)) {
        Object.assign(parameters, arg);
      } else {
        parameters[`arg${index}`] = arg;
      }
    });

    // Infer intent from tool name
    const intent = this.inferIntent(toolName, parameters);

    // Detect target service
    const targetService = this.inferService(toolName);

    // Build metadata
    const metadata: RequestMetadata = {
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
  private static async sendToGuard(request: GuardRequest): Promise<GuardResponse> {
    const config = this.config!;
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

      return await response.json() as GuardResponse;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Inject JIT token into function arguments
   * Looks for null/undefined placeholders or specific token fields
   */
  private static injectJitToken(
    args: unknown[],
    jitToken?: JitToken
  ): unknown[] {
    if (!jitToken) {
      return args;
    }

    return args.map((arg) => {
      if (typeof arg !== 'object' || arg === null) {
        return arg;
      }

      const modified = { ...arg } as Record<string, unknown>;

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
          if (jitToken.type === ServiceType.AWS) {
            modified[field] = {
              accessKeyId: jitToken.accessKeyId,
              secretAccessKey: jitToken.secretAccessKey,
              sessionToken: jitToken.sessionToken,
            };
          } else {
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
  private static inferIntent(
    toolName: string,
    parameters: Record<string, unknown>
  ): string {
    const action = toolName.split('_')[0] || toolName;
    const target = Object.keys(parameters)[0] || 'resource';
    return `${action} ${target}`;
  }

  /**
   * Infer target service from tool name
   */
  private static inferService(toolName: string): ServiceType {
    const lowerName = toolName.toLowerCase();
    if (lowerName.includes('stripe') || lowerName.includes('payment')) {
      return ServiceType.STRIPE;
    }
    if (lowerName.includes('aws') || lowerName.includes('s3') || lowerName.includes('lambda')) {
      return ServiceType.AWS;
    }
    if (lowerName.includes('moltbook') || lowerName.includes('social')) {
      return ServiceType.MOLTBOOK;
    }
    return ServiceType.GENERIC;
  }

  /**
   * Estimate cost of an operation (mock implementation)
   */
  private static estimateCost(
    toolName: string,
    parameters: Record<string, unknown>
  ): number {
    // Look for explicit amount/cost fields
    const costFields = ['amount', 'cost', 'price', 'value'];
    for (const field of costFields) {
      if (typeof parameters[field] === 'number') {
        return parameters[field] as number;
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
  private static extractContent(parameters: Record<string, unknown>): string | undefined {
    const contentFields = ['content', 'message', 'text', 'body', 'post', 'comment'];
    for (const field of contentFields) {
      if (typeof parameters[field] === 'string') {
        return parameters[field] as string;
      }
    }
    return undefined;
  }

  /**
   * Ensure SDK is initialized
   */
  private static ensureInitialized(): void {
    if (!this.initialized) {
      // Auto-initialize with defaults
      this.init();
    }
  }

  /**
   * Generate a unique session ID
   */
  private static generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Generate a trace ID for request correlation
   */
  private static generateTraceId(): string {
    return `trace_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Debug logging
   */
  private static log(message: string, data?: unknown): void {
    if (this.config?.debug) {
      console.log(`[MOLT-GUARD] ${message}`, data || '');
    }
  }

  /**
   * Audit logging for compliance
   */
  private static logAudit(
    request: GuardRequest,
    response: GuardResponse,
    executionTimeMs: number
  ): void {
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
  public static getConfig(): MoltGuardConfig | null {
    return this.config;
  }

  /**
   * Reset SDK state (for testing)
   */
  public static reset(): void {
    this.config = null;
    this.context = null;
    this.initialized = false;
  }
}

/**
 * Alias for backwards compatibility
 */
export const MoltGuard = MoltGuardProxy;
