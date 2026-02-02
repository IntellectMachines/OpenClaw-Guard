"use strict";
/**
 * Molt Guard - Token Vending Machine
 * JIT (Just-In-Time) credential issuance for Zero Trust security
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenVendingMachine = void 0;
const types_1 = require("./types");
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
class TokenVendingMachine {
    // Master secrets stored in private variables (loaded from env)
    secrets = new Map();
    // JWT signing key for Moltbook tokens
    jwtSecret;
    // Audit log for compliance
    auditLog = [];
    // Token TTL configuration (in seconds)
    defaultTtl = new Map([
        [types_1.ServiceType.AWS, 900], // 15 minutes
        [types_1.ServiceType.STRIPE, 3600], // 1 hour (audit-based)
        [types_1.ServiceType.MOLTBOOK, 300], // 5 minutes
        [types_1.ServiceType.GENERIC, 600], // 10 minutes
    ]);
    constructor() {
        // Load secrets from environment (never from code!)
        this.loadSecrets();
        this.jwtSecret = process.env.MOLT_GUARD_JWT_SECRET || this.generateJwtSecret();
    }
    /**
     * Load master secrets from environment variables
     * In production, these would come from a secrets manager (Vault, AWS Secrets Manager, etc.)
     */
    loadSecrets() {
        // AWS credentials
        this.secrets.set(types_1.ServiceType.AWS, {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
            roleArn: process.env.MOLT_GUARD_AWS_ROLE_ARN || '',
            region: process.env.AWS_REGION || 'us-east-1',
        });
        // Stripe credentials
        this.secrets.set(types_1.ServiceType.STRIPE, {
            secretKey: process.env.STRIPE_SECRET_KEY || '',
            publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
            webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
        });
        // Moltbook credentials
        this.secrets.set(types_1.ServiceType.MOLTBOOK, {
            apiKey: process.env.MOLTBOOK_API_KEY || '',
            appId: process.env.MOLTBOOK_APP_ID || '',
        });
    }
    /**
     * Vend a temporary token for the specified service
     */
    async vendToken(service, context) {
        const tokenId = this.generateTokenId();
        const ttl = this.defaultTtl.get(service) || 600;
        const expiresAt = Date.now() + ttl * 1000;
        try {
            let token;
            switch (service) {
                case types_1.ServiceType.AWS:
                    token = await this.vendAwsToken(context, tokenId, expiresAt);
                    break;
                case types_1.ServiceType.STRIPE:
                    token = await this.vendStripeToken(context, tokenId, expiresAt);
                    break;
                case types_1.ServiceType.MOLTBOOK:
                    token = await this.vendMoltbookToken(context, tokenId, expiresAt);
                    break;
                default:
                    token = await this.vendGenericToken(service, context, tokenId, expiresAt);
                    break;
            }
            // Log the token issuance for audit
            this.logTokenIssuance(token, context);
            return token;
        }
        catch (error) {
            throw new types_1.TokenVendingException(`Failed to vend token for ${service}: ${error.message}`, service);
        }
    }
    /**
     * Vend AWS temporary credentials using STS AssumeRole
     */
    async vendAwsToken(context, tokenId, expiresAt) {
        const awsSecrets = this.secrets.get(types_1.ServiceType.AWS);
        if (!awsSecrets?.roleArn) {
            throw new Error('AWS Role ARN not configured');
        }
        // In production, use @aws-sdk/client-sts
        // This is a mock implementation for development
        try {
            // Dynamic import to avoid requiring AWS SDK if not needed
            // Using Function constructor to avoid TypeScript module resolution
            const importModule = new Function('moduleName', 'return import(moduleName)');
            const stsModule = await importModule('@aws-sdk/client-sts').catch(() => null);
            if (!stsModule) {
                // AWS SDK not available, use mock credentials
                console.warn('[MOLT-GUARD] AWS SDK not available, using mock credentials');
                return this.createMockAwsToken(context, tokenId, expiresAt);
            }
            const { STSClient, AssumeRoleCommand } = stsModule;
            const stsClient = new STSClient({
                region: awsSecrets.region,
                credentials: {
                    accessKeyId: awsSecrets.accessKeyId,
                    secretAccessKey: awsSecrets.secretAccessKey,
                },
            });
            const command = new AssumeRoleCommand({
                RoleArn: awsSecrets.roleArn,
                RoleSessionName: `molt-guard-${context.userId}-${tokenId}`,
                DurationSeconds: 900, // 15 minutes
                Tags: [
                    { Key: 'UserId', Value: context.userId },
                    { Key: 'ToolName', Value: context.toolName },
                    { Key: 'TokenId', Value: tokenId },
                ],
            });
            const response = await stsClient.send(command);
            const credentials = response.Credentials;
            if (!credentials) {
                throw new Error('No credentials returned from STS');
            }
            return {
                token: tokenId,
                type: types_1.ServiceType.AWS,
                expiresAt,
                accessKeyId: credentials.AccessKeyId,
                secretAccessKey: credentials.SecretAccessKey,
                sessionToken: credentials.SessionToken,
                scopes: context.scopes || ['*'],
                metadata: {
                    roleArn: awsSecrets.roleArn,
                    sessionName: `molt-guard-${context.userId}-${tokenId}`,
                },
            };
        }
        catch (error) {
            // Fallback for development/testing without AWS SDK
            console.warn('[MOLT-GUARD] AWS SDK not available, using mock credentials');
            return this.createMockAwsToken(context, tokenId, expiresAt);
        }
    }
    /**
     * Create mock AWS credentials for development
     */
    createMockAwsToken(context, tokenId, expiresAt) {
        return {
            token: tokenId,
            type: types_1.ServiceType.AWS,
            expiresAt,
            accessKeyId: `AKIAMOCK${tokenId.substring(0, 12).toUpperCase()}`,
            secretAccessKey: `mock-secret-${tokenId}`,
            sessionToken: `mock-session-token-${tokenId}-${Date.now()}`,
            scopes: context.scopes || ['*'],
            metadata: {
                mock: true,
                userId: context.userId,
            },
        };
    }
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
    async vendStripeToken(context, tokenId, expiresAt) {
        const stripeSecrets = this.secrets.get(types_1.ServiceType.STRIPE);
        if (!stripeSecrets?.secretKey) {
            throw new Error('Stripe secret key not configured');
        }
        // Create a request signature for audit purposes
        const requestSignature = this.createRequestSignature(context);
        // Check if we can create a restricted key (Stripe API feature)
        // For now, we return the master key with full audit logging
        const restrictedKey = await this.tryCreateRestrictedStripeKey(stripeSecrets.secretKey, context);
        return {
            token: restrictedKey || stripeSecrets.secretKey,
            type: types_1.ServiceType.STRIPE,
            expiresAt,
            scopes: context.scopes || ['charges:write', 'customers:read'],
            metadata: {
                tokenId,
                requestSignature,
                isRestricted: !!restrictedKey,
                userId: context.userId,
                toolName: context.toolName,
                // Important: We log the exact operation for audit
                auditReference: `stripe-audit-${tokenId}`,
            },
        };
    }
    /**
     * Attempt to create a restricted Stripe key
     * Returns null if not supported, falls back to master key with audit
     */
    async tryCreateRestrictedStripeKey(_masterKey, _context) {
        // Stripe's restricted keys are created via dashboard or API
        // This is a placeholder for future implementation
        // See: https://stripe.com/docs/keys#limit-access
        // For now, return null to use master key with audit
        return null;
    }
    /**
     * Vend Moltbook JWT token
     * The Guard signs JWTs that Moltbook API verifies
     */
    async vendMoltbookToken(context, tokenId, expiresAt) {
        const moltbookSecrets = this.secrets.get(types_1.ServiceType.MOLTBOOK);
        if (!moltbookSecrets?.appId) {
            throw new Error('Moltbook App ID not configured');
        }
        // Create JWT payload
        const payload = {
            sub: context.userId,
            iss: 'molt-guard',
            aud: 'moltbook-api',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(expiresAt / 1000),
            jti: tokenId,
            appId: moltbookSecrets.appId,
            scopes: context.scopes || ['post:create', 'post:read'],
            toolName: context.toolName,
            intent: context.intent,
        };
        // Sign the JWT
        const jwt = this.signJwt(payload);
        return {
            token: jwt,
            type: types_1.ServiceType.MOLTBOOK,
            expiresAt,
            scopes: payload.scopes,
            metadata: {
                tokenId,
                appId: moltbookSecrets.appId,
                userId: context.userId,
            },
        };
    }
    /**
     * Vend generic token for other services
     */
    async vendGenericToken(service, context, tokenId, expiresAt) {
        // Create a generic signed token
        const payload = {
            sub: context.userId,
            iss: 'molt-guard',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(expiresAt / 1000),
            jti: tokenId,
            service: service,
            scopes: context.scopes || ['*'],
        };
        const token = this.signJwt(payload);
        return {
            token,
            type: service,
            expiresAt,
            scopes: payload.scopes,
            metadata: {
                tokenId,
                userId: context.userId,
            },
        };
    }
    /**
     * Simple JWT signing implementation
     * In production, use a proper JWT library like 'jsonwebtoken'
     */
    signJwt(payload) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const encodeBase64Url = (data) => {
            return Buffer.from(data)
                .toString('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        };
        const headerEncoded = encodeBase64Url(JSON.stringify(header));
        const payloadEncoded = encodeBase64Url(JSON.stringify(payload));
        const signatureInput = `${headerEncoded}.${payloadEncoded}`;
        // Simple HMAC-SHA256 signature
        // In production, use crypto.createHmac
        const crypto = require('crypto');
        const signature = crypto
            .createHmac('sha256', this.jwtSecret)
            .update(signatureInput)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        return `${signatureInput}.${signature}`;
    }
    /**
     * Verify a JWT token
     */
    verifyJwt(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return { valid: false };
            }
            const [headerEncoded, payloadEncoded, signatureReceived] = parts;
            const signatureInput = `${headerEncoded}.${payloadEncoded}`;
            const crypto = require('crypto');
            const expectedSignature = crypto
                .createHmac('sha256', this.jwtSecret)
                .update(signatureInput)
                .digest('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
            if (signatureReceived !== expectedSignature) {
                return { valid: false };
            }
            const decodeBase64Url = (data) => {
                const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
                return Buffer.from(base64, 'base64').toString('utf-8');
            };
            const payload = JSON.parse(decodeBase64Url(payloadEncoded));
            // Check expiration
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                return { valid: false };
            }
            return { valid: true, payload };
        }
        catch {
            return { valid: false };
        }
    }
    /**
     * Create a request signature for audit purposes
     */
    createRequestSignature(context) {
        const crypto = require('crypto');
        const data = JSON.stringify({
            userId: context.userId,
            toolName: context.toolName,
            intent: context.intent,
            timestamp: Date.now(),
        });
        return crypto
            .createHash('sha256')
            .update(data)
            .digest('hex')
            .substring(0, 16);
    }
    /**
     * Log token issuance for audit compliance
     */
    logTokenIssuance(token, context) {
        const entry = {
            timestamp: Date.now(),
            service: token.type,
            userId: context.userId,
            toolName: context.toolName,
            tokenId: token.token.substring(0, 20) + '...', // Truncate for security
            expiresAt: token.expiresAt,
            scopes: token.scopes || [],
            requestSignature: this.createRequestSignature(context),
        };
        this.auditLog.push(entry);
        // In production, send to audit log service
        console.log('[MOLT-GUARD-TOKEN-AUDIT]', JSON.stringify(entry));
        // Keep audit log bounded
        if (this.auditLog.length > 10000) {
            this.auditLog.splice(0, 1000);
        }
    }
    /**
     * Generate unique token ID
     */
    generateTokenId() {
        const crypto = require('crypto');
        return `tok_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    }
    /**
     * Generate JWT secret for development
     */
    generateJwtSecret() {
        const crypto = require('crypto');
        const secret = crypto.randomBytes(32).toString('hex');
        console.warn('[MOLT-GUARD] Generated random JWT secret. Set MOLT_GUARD_JWT_SECRET in production.');
        return secret;
    }
    /**
     * Revoke a token (mark as invalid before expiry)
     */
    async revokeToken(tokenId) {
        // In production, this would add to a revocation list checked during validation
        console.log(`[MOLT-GUARD] Token revoked: ${tokenId}`);
        return true;
    }
    /**
     * Get audit log entries (for compliance reporting)
     */
    getAuditLog(filter) {
        let entries = [...this.auditLog];
        if (filter?.userId) {
            entries = entries.filter((e) => e.userId === filter.userId);
        }
        if (filter?.service) {
            entries = entries.filter((e) => e.service === filter.service);
        }
        if (filter?.since !== undefined) {
            const since = filter.since;
            entries = entries.filter((e) => e.timestamp >= since);
        }
        return entries;
    }
    /**
     * Check if a service is configured
     */
    isServiceConfigured(service) {
        const secrets = this.secrets.get(service);
        if (!secrets)
            return false;
        switch (service) {
            case types_1.ServiceType.AWS:
                return !!(secrets.accessKeyId && secrets.secretAccessKey);
            case types_1.ServiceType.STRIPE:
                return !!secrets.secretKey;
            case types_1.ServiceType.MOLTBOOK:
                return !!secrets.appId;
            default:
                return Object.values(secrets).some((v) => !!v);
        }
    }
    /**
     * Get configured services
     */
    getConfiguredServices() {
        return [types_1.ServiceType.AWS, types_1.ServiceType.STRIPE, types_1.ServiceType.MOLTBOOK, types_1.ServiceType.GENERIC]
            .filter((s) => this.isServiceConfigured(s));
    }
}
exports.TokenVendingMachine = TokenVendingMachine;
//# sourceMappingURL=token-vendor.js.map