/**
 * Molt Guard - Usage Examples
 * 
 * This file demonstrates how to integrate Molt Guard into your AI agent.
 */

import { guard, createProtectedTool, Protected, UserRole, ServiceType } from './src';

// =============================================================================
// EXAMPLE 1: Basic Integration
// =============================================================================

async function basicExample() {
  // Initialize the guard
  await guard.init({
    debug: true,
    startServer: true,
    serverPort: 3001,
  });

  // Define your tools
  const stripeApi = {
    async charge(params: { amount: number; currency: string; apiKey?: string }) {
      console.log(`Charging ${params.amount} ${params.currency}`);
      // Actual Stripe API call would go here
      return { success: true, chargeId: 'ch_123' };
    },
    async refund(params: { chargeId: string; amount?: number }) {
      console.log(`Refunding charge ${params.chargeId}`);
      return { success: true, refundId: 're_123' };
    },
  };

  const moltbookApi = {
    async post(params: { content: string; apiKey?: string }) {
      console.log(`Posting to Moltbook: ${params.content}`);
      return { success: true, postId: 'post_123' };
    },
  };

  // Protect the tools
  const securedStripe = guard.protect(stripeApi, 'financial_policy');
  const securedMoltbook = guard.protect(moltbookApi, 'social_policy');

  // Set user context
  guard.setContext({
    userId: 'user_123',
    userRole: UserRole.ADMIN,
    budgetUsed: 0,
  });

  // Use the tools - they're now secured!
  try {
    // This will be intercepted, checked, and allowed (user is ADMIN)
    const result = await securedStripe.charge({
      amount: 1000,
      currency: 'usd',
      apiKey: null, // Will be injected by Guard
    });
    console.log('Charge result:', result);
  } catch (error) {
    console.error('Charge failed:', error);
  }

  try {
    // This will be moderated for content before allowing
    await securedMoltbook.post({
      content: 'Hello, this is a great product!', // Positive sentiment - will pass
    });
  } catch (error) {
    console.error('Post failed:', error);
  }
}

// =============================================================================
// EXAMPLE 2: Bulk Tool Protection
// =============================================================================

async function bulkProtectionExample() {
  await guard.init();

  // Define all your tools
  const myToolsList = {
    stripe: {
      charge: async (amount: number) => ({ chargeId: 'ch_123' }),
      refund: async (chargeId: string) => ({ refundId: 're_123' }),
    },
    aws: {
      deploy: async (config: object) => ({ deploymentId: 'dep_123' }),
      uploadS3: async (bucket: string, key: string, data: Buffer) => ({ url: 's3://...' }),
    },
    moltbook: {
      post: async (content: string) => ({ postId: 'post_123' }),
      comment: async (postId: string, content: string) => ({ commentId: 'com_123' }),
    },
  };

  // Protect all tools at once
  const protectedTools = guard.protectAll(myToolsList);

  // Use them normally - all calls are secured
  await protectedTools.stripe.charge(1000);
}

// =============================================================================
// EXAMPLE 3: Using Decorators (Class-based)
// =============================================================================

class PaymentService {
  @Protected('financial_policy')
  async processPayment(amount: number, currency: string): Promise<{ success: boolean }> {
    console.log(`Processing payment: ${amount} ${currency}`);
    return { success: true };
  }

  @Protected('financial_policy')
  async issueRefund(transactionId: string): Promise<{ success: boolean }> {
    console.log(`Issuing refund for: ${transactionId}`);
    return { success: true };
  }
}

async function decoratorExample() {
  await guard.init();

  const paymentService = new PaymentService();
  
  // These calls are automatically protected by the decorator
  await paymentService.processPayment(100, 'usd');
  await paymentService.issueRefund('txn_123');
}

// =============================================================================
// EXAMPLE 4: One-liner with createProtectedTool
// =============================================================================

async function oneLineExample() {
  const stripeApi = {
    charge: async (amount: number) => ({ chargeId: 'ch_123' }),
  };

  // Create protected tool in one line
  const securedStripe = await createProtectedTool(stripeApi, {
    policy: 'financial',
    userId: 'user_123',
    userRole: UserRole.ADMIN,
  });

  await securedStripe.charge(1000);
}

// =============================================================================
// EXAMPLE 5: Direct Token Vending
// =============================================================================

async function tokenVendingExample() {
  await guard.init();

  // Vend a token directly for custom integrations
  const awsToken = await guard.vendToken(ServiceType.AWS, {
    userId: 'user_123',
    toolName: 'custom_aws_operation',
    intent: 'Deploy Lambda function',
  });

  console.log('AWS Token:', {
    accessKeyId: awsToken.accessKeyId,
    expiresAt: new Date(awsToken.expiresAt),
    scopes: awsToken.scopes,
  });

  // Use the temporary credentials
  // const s3Client = new S3Client({ credentials: awsToken });
}

// =============================================================================
// EXAMPLE 6: Custom Policy Configuration
// =============================================================================

async function customPolicyExample() {
  await guard.init({
    policy: {
      strictMode: true,
      budget: {
        dailyLimit: 500,
        perRequestLimit: 50,
        hourlyLimit: 100,
        alertThreshold: 70,
      },
      moderation: {
        detectPii: true,
        detectOffensive: true,
        analyzeSentiment: true,
        minSentimentScore: 0, // Only allow neutral or positive content
        blockedTerms: ['spam', 'scam', 'fake'],
      },
      allowlistedTools: ['get_time', 'get_weather'],
      denylistedTools: ['delete_all', 'format_disk'],
    },
  });

  // Later, update the policy dynamically
  guard.updatePolicy({
    budget: {
      dailyLimit: 1000, // Increased limit
      perRequestLimit: 100,
      hourlyLimit: 200,
        alertThreshold: 80,
    },
  });
}

// =============================================================================
// EXAMPLE 7: OpenClaw Bot Integration
// =============================================================================

async function openClawBotExample() {
  // This is how you'd integrate with an OpenClaw bot

  // 1. Initialize guard
  await guard.init();

  // 2. Define your AI agent's tools
  const agentTools = {
    search_web: async (query: string) => {
      // Web search implementation
      return { results: [] };
    },
    read_file: async (path: string) => {
      // File reading implementation
      return { content: '' };
    },
    post_to_moltbook: async (content: string) => {
      // Moltbook posting implementation
      return { postId: 'post_123' };
    },
    stripe_charge: async (amount: number, customerId: string) => {
      // Stripe charge implementation
      return { chargeId: 'ch_123' };
    },
    aws_deploy: async (functionName: string, code: string) => {
      // AWS Lambda deployment
      return { functionArn: 'arn:aws:lambda:...' };
    },
  };

  // 3. Protect all tools
  const protectedTools = guard.protectAll(agentTools);

  // 4. Set context for current user/session
  guard.setContext({
    userId: 'agent_user_123',
    sessionId: 'session_abc',
    userRole: UserRole.USER,
    budgetUsed: 0,
  });

  // 5. Use tools in your agent - they're all secured!
  // The agent can call these normally, but every call is:
  // - Checked against budget limits
  // - Content moderated (for social posts)
  // - Authorized based on user role
  // - Injected with JIT tokens when needed

  // Example agent execution:
  const searchResults = await protectedTools.search_web('TypeScript tutorials');
  
  // This will be moderated for content
  await protectedTools.post_to_moltbook('Found great TypeScript resources!');
  
  // This requires ADMIN role and will get JIT credentials
  // await protectedTools.stripe_charge(1000, 'cus_123');
}

// =============================================================================
// RUN EXAMPLES
// =============================================================================

async function runExamples() {
  console.log('=== Molt Guard Examples ===\n');

  console.log('Running basic example...');
  await basicExample();
  guard.reset();

  console.log('\nAll examples completed!');
}

// Uncomment to run:
// runExamples().catch(console.error);

export {
  basicExample,
  bulkProtectionExample,
  decoratorExample,
  oneLineExample,
  tokenVendingExample,
  customPolicyExample,
  openClawBotExample,
};
