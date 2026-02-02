# Molt Guard

> Security Middleware for AI Agents - Zero Trust Architecture with JIT Token Vending

Molt Guard is a TypeScript library that acts as a security layer between AI agents and their tools. It implements a Zero Trust architecture where the agent never directly holds sensitive credentials - instead, it requests permission and receives ephemeral tokens just-in-time.

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│                 │      │                 │      │                 │
│    AI Agent     │─────▶│   Molt Guard    │─────▶│  External APIs  │
│   (OpenClaw)    │      │   (Interceptor) │      │ (Stripe, AWS)   │
│                 │◀─────│                 │◀─────│                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘
                                │
                                │
                                ▼
                    ┌───────────────────────┐
                    │                       │
                    │    Guard Server       │
                    │    (The Brain)        │
                    │                       │
                    │  • Policy Engine      │
                    │  • Content Moderation │
                    │  • Token Vending      │
                    │  • Audit Logging      │
                    │                       │
                    └───────────────────────┘
```

## Features

- **🛡️ Zero Trust Architecture**: Agents never hold master secrets
- **⏱️ JIT Token Vending**: Ephemeral credentials that expire in minutes
- **📝 Content Moderation**: PII detection, sentiment analysis, offensive content filtering
- **💰 Budget Controls**: Daily, hourly, and per-request spending limits
- **🔐 Role-Based Access**: Fine-grained authorization for different operations
- **📊 Audit Logging**: Complete trail of all decisions and token issuances
- **🔌 One-Line Integration**: Wrap your tools with a single command

## Installation

```bash
npm install molt-guard
```

## Quick Start

```typescript
import { guard } from 'molt-guard';

// 1. Initialize the guard
await guard.init();

// 2. Protect your tools
const protectedTools = guard.protectAll(myToolsList);

// 3. Use them normally - they're secured!
await protectedTools.stripe.charge({ amount: 1000 });
```

## Core Concepts

### GuardRequest

Every tool call is converted into a `GuardRequest`:

```typescript
interface GuardRequest {
  intent: string;           // Human-readable intent
  toolName: string;         // Name of the tool being called
  parameters: object;       // Arguments to the tool
  metadata: {
    userId: string;
    budgetUsed: number;
    userRole?: UserRole;
    cost?: number;
  };
}
```

### GuardResponse

The Guard Server responds with a decision:

```typescript
interface GuardResponse {
  decision: 'ALLOW' | 'DENY' | 'FLAG';
  jitToken?: JitToken;      // Ephemeral credential if allowed
  moderationNotes: string;  // Explanation of the decision
  decisionId: string;       // For audit trail
}
```

### JIT Tokens

Just-In-Time tokens are ephemeral credentials:

```typescript
interface JitToken {
  token: string;
  type: 'AWS' | 'STRIPE' | 'MOLTBOOK';
  expiresAt: number;
  scopes?: string[];
  // AWS-specific fields
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
}
```

## Usage Examples

### Basic Protection

```typescript
import { guard } from 'molt-guard';

await guard.init();

const stripeApi = {
  charge: async (params) => { /* ... */ },
  refund: async (params) => { /* ... */ },
};

// Wrap with security
const securedStripe = guard.protect(stripeApi, 'financial_policy');

// Set user context
guard.setContext({
  userId: 'user_123',
  userRole: UserRole.ADMIN,
});

// Use normally - Guard intercepts and validates
await securedStripe.charge({ amount: 1000 });
```

### Using Decorators

```typescript
import { Protected } from 'molt-guard';

class PaymentService {
  @Protected('financial_policy')
  async processPayment(amount: number): Promise<void> {
    // Implementation
  }
}
```

### Custom Policy

```typescript
await guard.init({
  policy: {
    strictMode: true,
    budget: {
      dailyLimit: 500,
      perRequestLimit: 50,
    },
    moderation: {
      detectPii: true,
      analyzeSentiment: true,
      minSentimentScore: 0, // Only positive content
    },
  },
});
```

### Direct Token Vending

```typescript
const awsToken = await guard.vendToken(ServiceType.AWS, {
  userId: 'user_123',
  toolName: 'deploy_lambda',
  intent: 'Deploy new function',
});

// Use the temporary credentials
const s3Client = new S3Client({
  credentials: {
    accessKeyId: awsToken.accessKeyId!,
    secretAccessKey: awsToken.secretAccessKey!,
    sessionToken: awsToken.sessionToken!,
  },
});
```

## Decision Flow

1. **Agent calls `stripe.charge()`**
2. **SDK Proxy intercepts the call** - "Hold on, I need to check this."
3. **SDK sends payload to Guard Server**
4. **Guard checks:**
   - Budget? ✓ OK
   - Intent? ✓ "Charge User" → Allowed
   - Auth? ✓ User is Admin → Allowed
5. **Guard calls Token Vendor** - "Give me a Stripe key."
6. **Guard replies to SDK** - "ALLOW. Here is the key."
7. **SDK injects key into `stripe.charge()` arguments and executes**
8. **Agent gets the result**, unaware it was moderated

## Policy Configuration

Policies are defined in JSON:

```json
{
  "version": "1.0.0",
  "strictMode": false,
  "budget": {
    "dailyLimit": 1000,
    "perRequestLimit": 100
  },
  "moderation": {
    "detectPii": true,
    "detectOffensive": true,
    "analyzeSentiment": true
  },
  "rules": [
    {
      "id": "rule-001",
      "name": "Block negative posts",
      "targetTools": ["post_to_moltbook"],
      "conditions": [],
      "action": {
        "decision": "ALLOW",
        "requireModeration": true
      }
    }
  ],
  "allowlistedTools": ["read_file", "search_web"],
  "denylistedTools": ["delete_all", "format_disk"]
}
```

## Environment Variables

```bash
# Guard configuration
MOLT_GUARD_JWT_SECRET=your-secure-secret
MOLT_GUARD_API_KEY=your-api-key

# AWS (for JIT token vending)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
MOLT_GUARD_AWS_ROLE_ARN=arn:aws:iam::123456789012:role/AgentRole

# Stripe
STRIPE_SECRET_KEY=sk_live_...

# Moltbook
MOLTBOOK_API_KEY=...
MOLTBOOK_APP_ID=...
```

## API Reference

### `guard.init(options?)`
Initialize the Molt Guard system.

### `guard.protect(tool, policyName?)`
Wrap a single tool with security checks.

### `guard.protectAll(tools, policyName?)`
Wrap multiple tools at once.

### `guard.setContext(context)`
Set the current user/session context.

### `guard.evaluate(request)`
Directly evaluate a GuardRequest.

### `guard.vendToken(service, context)`
Vend a JIT token for a service.

### `guard.updatePolicy(policy)`
Dynamically update the policy.

## License

MIT
