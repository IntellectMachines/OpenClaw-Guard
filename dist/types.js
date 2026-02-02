"use strict";
/**
 * Molt Guard - Type Definitions
 * Communication protocol for Zero Trust AI Agent Security Middleware
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenVendingException = exports.ConfigurationException = exports.SecurityException = exports.ConditionOperator = exports.ModerationSeverity = exports.UserRole = exports.ServiceType = exports.GuardDecision = void 0;
// ============================================================================
// ENUMS & CONSTANTS
// ============================================================================
/**
 * Decision outcomes from the Guard Server
 */
var GuardDecision;
(function (GuardDecision) {
    GuardDecision["ALLOW"] = "ALLOW";
    GuardDecision["DENY"] = "DENY";
    GuardDecision["FLAG"] = "FLAG";
})(GuardDecision || (exports.GuardDecision = GuardDecision = {}));
/**
 * Supported service types for JIT token vending
 */
var ServiceType;
(function (ServiceType) {
    ServiceType["AWS"] = "AWS";
    ServiceType["STRIPE"] = "STRIPE";
    ServiceType["MOLTBOOK"] = "MOLTBOOK";
    ServiceType["GENERIC"] = "GENERIC";
})(ServiceType || (exports.ServiceType = ServiceType = {}));
/**
 * User roles for authorization checks
 */
var UserRole;
(function (UserRole) {
    UserRole["ADMIN"] = "ADMIN";
    UserRole["USER"] = "USER";
    UserRole["SERVICE"] = "SERVICE";
    UserRole["READONLY"] = "READONLY";
})(UserRole || (exports.UserRole = UserRole = {}));
/**
 * Severity levels for moderation
 */
var ModerationSeverity;
(function (ModerationSeverity) {
    ModerationSeverity["NONE"] = "NONE";
    ModerationSeverity["LOW"] = "LOW";
    ModerationSeverity["MEDIUM"] = "MEDIUM";
    ModerationSeverity["HIGH"] = "HIGH";
    ModerationSeverity["CRITICAL"] = "CRITICAL";
})(ModerationSeverity || (exports.ModerationSeverity = ModerationSeverity = {}));
// ============================================================================
// POLICY CONFIGURATION
// ============================================================================
/**
 * Condition operators for policy rules
 */
var ConditionOperator;
(function (ConditionOperator) {
    ConditionOperator["EQUALS"] = "EQUALS";
    ConditionOperator["NOT_EQUALS"] = "NOT_EQUALS";
    ConditionOperator["CONTAINS"] = "CONTAINS";
    ConditionOperator["NOT_CONTAINS"] = "NOT_CONTAINS";
    ConditionOperator["GREATER_THAN"] = "GREATER_THAN";
    ConditionOperator["LESS_THAN"] = "LESS_THAN";
    ConditionOperator["MATCHES_REGEX"] = "MATCHES_REGEX";
    ConditionOperator["IN_LIST"] = "IN_LIST";
    ConditionOperator["NOT_IN_LIST"] = "NOT_IN_LIST";
})(ConditionOperator || (exports.ConditionOperator = ConditionOperator = {}));
// ============================================================================
// EXCEPTIONS
// ============================================================================
/**
 * Security exception thrown when a request is denied
 */
class SecurityException extends Error {
    decision;
    decisionId;
    moderationNotes;
    toolName;
    timestamp;
    constructor(message, decision, decisionId, moderationNotes, toolName) {
        super(message);
        this.name = 'SecurityException';
        this.decision = decision;
        this.decisionId = decisionId;
        this.moderationNotes = moderationNotes;
        this.toolName = toolName;
        this.timestamp = Date.now();
        // Maintains proper stack trace for where error was thrown
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, SecurityException);
        }
    }
}
exports.SecurityException = SecurityException;
/**
 * Configuration exception for invalid setup
 */
class ConfigurationException extends Error {
    constructor(message) {
        super(message);
        this.name = 'ConfigurationException';
    }
}
exports.ConfigurationException = ConfigurationException;
/**
 * Token vending exception
 */
class TokenVendingException extends Error {
    service;
    constructor(message, service) {
        super(message);
        this.name = 'TokenVendingException';
        this.service = service;
    }
}
exports.TokenVendingException = TokenVendingException;
//# sourceMappingURL=types.js.map