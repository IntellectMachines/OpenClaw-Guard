/**
 * Molt Guard - Token Vending Machine
 * JIT (Just-In-Time) credential issuance for Zero Trust security
 */
import { JitToken, ServiceType } from './types';
/**
 * Token request context for audit and scoping
 */
export interface TokenRequestContext {
    userId: string;
    toolName: string;
    intent: string;
    scopes?: string[];
}
/**
 * Audit entry for token issuance
 */
interface TokenAuditEntry {
    timestamp: number;
    service: ServiceType;
    userId: string;
    toolName: string;
    tokenId: string;
    expiresAt: number;
    scopes: string[];
    requestSignature: string;
}
/**
 * Token Vending Machine
 *
 * Holds master secrets and vends ephemeral credentials to agents.
 * The Agent never sees the real secrets - only temporary tokens that expire.
 *
 * Supported services:
 * - AWS: Uses STS AssumeRole for temporary credentials
 * - Stripe: Returns master key with full audit logging (or restricted keys if available)
 * - Moltbook: Issues signed JWTs verified by the Moltbook API
 */
export declare class TokenVendingMachine {
    private readonly secrets;
    private readonly jwtSecret;
    private readonly auditLog;
    private readonly defaultTtl;
    constructor();
    /**
     * Load master secrets from environment variables
     * In production, these would come from a secrets manager (Vault, AWS Secrets Manager, etc.)
     */
    private loadSecrets;
    /**
     * Vend a temporary token for the specified service
     */
    vendToken(service: ServiceType, context: TokenRequestContext): Promise<JitToken>;
    /**
     * Vend AWS temporary credentials using STS AssumeRole
     */
    private vendAwsToken;
    /**
     * Create mock AWS credentials for development
     */
    private createMockAwsToken;
    /**
     * Vend Stripe token
     *
     * Note: Stripe doesn't support true ephemeral keys for server-side operations.
     * Options:
     * 1. Return the master key but with full audit logging
     * 2. Use Stripe's Restricted Keys feature (if available)
     * 3. Proxy all Stripe calls through the Guard server
     *
     * We implement option 1 with comprehensive auditing.
     */
    private vendStripeToken;
    /**
     * Attempt to create a restricted Stripe key
     * Returns null if not supported, falls back to master key with audit
     */
    private tryCreateRestrictedStripeKey;
    /**
     * Vend Moltbook JWT token
     * The Guard signs JWTs that Moltbook API verifies
     */
    private vendMoltbookToken;
    /**
     * Vend generic token for other services
     */
    private vendGenericToken;
    /**
     * Simple JWT signing implementation
     * In production, use a proper JWT library like 'jsonwebtoken'
     */
    private signJwt;
    /**
     * Verify a JWT token
     */
    verifyJwt(token: string): {
        valid: boolean;
        payload?: Record<string, unknown>;
    };
    /**
     * Create a request signature for audit purposes
     */
    private createRequestSignature;
    /**
     * Log token issuance for audit compliance
     */
    private logTokenIssuance;
    /**
     * Generate unique token ID
     */
    private generateTokenId;
    /**
     * Generate JWT secret for development
     */
    private generateJwtSecret;
    /**
     * Revoke a token (mark as invalid before expiry)
     */
    revokeToken(tokenId: string): Promise<boolean>;
    /**
     * Get audit log entries (for compliance reporting)
     */
    getAuditLog(filter?: {
        userId?: string;
        service?: ServiceType;
        since?: number;
    }): TokenAuditEntry[];
    /**
     * Check if a service is configured
     */
    isServiceConfigured(service: ServiceType): boolean;
    /**
     * Get configured services
     */
    getConfiguredServices(): ServiceType[];
}
export {};
//# sourceMappingURL=token-vendor.d.ts.map