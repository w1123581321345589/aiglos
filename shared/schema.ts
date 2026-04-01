import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, real, boolean, jsonb, integer, serial } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const organizations = pgTable("organizations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  slug: text("slug").notNull().unique(),
  plan: text("plan").notNull().default("enterprise"),
  maxUsers: integer("max_users").notNull().default(50),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertOrganizationSchema = createInsertSchema(organizations).omit({ id: true });
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;
export type Organization = typeof organizations.$inferSelect;

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  role: text("role").notNull().default("viewer"),
  organizationId: varchar("organization_id"),
  displayName: text("display_name"),
  email: text("email"),
  lastLogin: timestamp("last_login"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  role: true,
  organizationId: true,
  displayName: true,
  email: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export const ROLES = ["admin", "analyst", "viewer"] as const;

export const sessions = pgTable("sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  modelId: text("model_id").notNull(),
  modelVersion: text("model_version").notNull(),
  initiatedBy: text("initiated_by").notNull(),
  authorizedGoal: text("authorized_goal").notNull(),
  goalIntegrityScore: real("goal_integrity_score").notNull().default(1.0),
  anomalyScore: real("anomaly_score").notNull().default(0.0),
  isActive: boolean("is_active").notNull().default(true),
  toolPermissions: text("tool_permissions").array().default(sql`'{}'::text[]`),
  systemPromptHash: text("system_prompt_hash"),
  startTime: timestamp("start_time").notNull().defaultNow(),
  endTime: timestamp("end_time"),
});

export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true });
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type Session = typeof sessions.$inferSelect;

export const securityEvents = pgTable("security_events", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  sessionId: varchar("session_id").notNull(),
  eventType: text("event_type").notNull(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  details: jsonb("details").default({}),
  cmmcControls: text("cmmc_controls").array().default(sql`'{}'::text[]`),
  nistControls: text("nist_controls").array().default(sql`'{}'::text[]`),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertSecurityEventSchema = createInsertSchema(securityEvents).omit({ id: true });
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;

export const toolCalls = pgTable("tool_calls", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  sessionId: varchar("session_id").notNull(),
  serverId: text("server_id").notNull(),
  toolName: text("tool_name").notNull(),
  arguments: jsonb("arguments").default({}),
  allowed: boolean("allowed").notNull().default(true),
  blockedReason: text("blocked_reason"),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertToolCallSchema = createInsertSchema(toolCalls).omit({ id: true });
export type InsertToolCall = z.infer<typeof insertToolCallSchema>;
export type ToolCall = typeof toolCalls.$inferSelect;

export const trustedServers = pgTable("trusted_servers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  host: text("host").notNull(),
  port: integer("port").notNull(),
  alias: text("alias"),
  status: text("status").notNull().default("allowed"),
  reason: text("reason"),
  toolManifestHash: text("tool_manifest_hash"),
  lastSeen: timestamp("last_seen").defaultNow(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertTrustedServerSchema = createInsertSchema(trustedServers).omit({ id: true });
export type InsertTrustedServer = z.infer<typeof insertTrustedServerSchema>;
export type TrustedServer = typeof trustedServers.$inferSelect;

export const policyRules = pgTable("policy_rules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  name: text("name").notNull(),
  description: text("description").notNull(),
  pattern: text("pattern").notNull(),
  action: text("action").notNull().default("block"),
  severity: text("severity").notNull().default("high"),
  enabled: boolean("enabled").notNull().default(true),
  category: text("category").notNull().default("general"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertPolicyRuleSchema = createInsertSchema(policyRules).omit({ id: true });
export type InsertPolicyRule = z.infer<typeof insertPolicyRuleSchema>;
export type PolicyRule = typeof policyRules.$inferSelect;

export const auditLogs = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  userId: varchar("user_id"),
  username: text("username").notNull(),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id"),
  details: jsonb("details").default({}),
  ipAddress: text("ip_address"),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
});

export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({ id: true });
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;

export const dataRetentionPolicies = pgTable("data_retention_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  resourceType: text("resource_type").notNull(),
  retentionDays: integer("retention_days").notNull().default(90),
  enabled: boolean("enabled").notNull().default(true),
  lastPurgedAt: timestamp("last_purged_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertDataRetentionPolicySchema = createInsertSchema(dataRetentionPolicies).omit({ id: true });
export type InsertDataRetentionPolicy = z.infer<typeof insertDataRetentionPolicySchema>;
export type DataRetentionPolicy = typeof dataRetentionPolicies.$inferSelect;

export const alertDestinations = pgTable("alert_destinations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id"),
  name: text("name").notNull(),
  type: text("type").notNull(),
  config: jsonb("config").notNull().default({}),
  severityFilter: text("severity_filter").array().default(sql`'{}'::text[]`),
  eventTypeFilter: text("event_type_filter").array().default(sql`'{}'::text[]`),
  enabled: boolean("enabled").notNull().default(true),
  lastTriggeredAt: timestamp("last_triggered_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertAlertDestinationSchema = createInsertSchema(alertDestinations).omit({ id: true });
export type InsertAlertDestination = z.infer<typeof insertAlertDestinationSchema>;
export type AlertDestination = typeof alertDestinations.$inferSelect;

export const apiKeys = pgTable("api_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  organizationId: varchar("organization_id").notNull(),
  name: text("name").notNull(),
  keyHash: text("key_hash").notNull(),
  keyPrefix: text("key_prefix").notNull(),
  lastUsedAt: timestamp("last_used_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertApiKeySchema = createInsertSchema(apiKeys).omit({ id: true });
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type ApiKey = typeof apiKeys.$inferSelect;

export const ALERT_TYPES = ["slack", "webhook", "splunk", "siem", "email", "pagerduty"] as const;

export const EVENT_TYPES = [
  "tool_call", "tool_response", "goal_drift", "credential_detected",
  "policy_violation", "anomaly_detected", "session_start", "session_end",
  "server_untrusted", "behavioral_anomaly", "trust_violation",
  "tool_redefinition", "agent_attested", "command_injection", "path_traversal"
] as const;

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const POLICY_ACTIONS = ["allow", "block", "log", "alert", "require_approval"] as const;

export const RETENTION_RESOURCE_TYPES = ["security_events", "sessions", "tool_calls", "audit_logs"] as const;
