import {
  type User, type InsertUser,
  type Organization, type InsertOrganization,
  type Session, type InsertSession,
  type SecurityEvent, type InsertSecurityEvent,
  type ToolCall, type InsertToolCall,
  type TrustedServer, type InsertTrustedServer,
  type PolicyRule, type InsertPolicyRule,
  type AuditLog, type InsertAuditLog,
  type DataRetentionPolicy, type InsertDataRetentionPolicy,
  type AlertDestination, type InsertAlertDestination,
  type ApiKey, type InsertApiKey,
  users, organizations, sessions, securityEvents, toolCalls,
  trustedServers, policyRules, auditLogs, dataRetentionPolicies, alertDestinations, apiKeys,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, sql, count, lt, inArray } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getUsers(orgId?: string): Promise<User[]>;
  updateUser(id: string, data: Partial<User>): Promise<User | undefined>;
  deleteUser(id: string): Promise<boolean>;

  getOrganization(id: string): Promise<Organization | undefined>;
  getOrganizationBySlug(slug: string): Promise<Organization | undefined>;
  createOrganization(org: InsertOrganization): Promise<Organization>;
  getOrganizations(): Promise<Organization[]>;

  getSessions(orgId?: string, activeOnly?: boolean): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  createSession(session: InsertSession): Promise<Session>;
  deleteSessionsBefore(date: Date, orgId?: string): Promise<number>;

  getSecurityEvents(filters?: { severity?: string; type?: string; limit?: number; orgId?: string }): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;
  deleteEventsBefore(date: Date, orgId?: string): Promise<number>;

  getToolCalls(sessionId?: string, orgId?: string): Promise<ToolCall[]>;
  createToolCall(call: InsertToolCall): Promise<ToolCall>;
  deleteToolCallsBefore(date: Date, orgId?: string): Promise<number>;

  getTrustedServers(orgId?: string): Promise<TrustedServer[]>;
  createTrustedServer(server: InsertTrustedServer): Promise<TrustedServer>;
  updateTrustedServer(id: string, data: Partial<TrustedServer>): Promise<TrustedServer | undefined>;

  getPolicyRules(orgId?: string): Promise<PolicyRule[]>;
  createPolicyRule(rule: InsertPolicyRule): Promise<PolicyRule>;
  updatePolicyRule(id: string, data: Partial<PolicyRule>): Promise<PolicyRule | undefined>;

  createAuditLog(entry: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(filters?: { orgId?: string; userId?: string; resourceType?: string; limit?: number }): Promise<AuditLog[]>;
  deleteAuditLogsBefore(date: Date, orgId?: string): Promise<number>;

  getDataRetentionPolicies(orgId?: string): Promise<DataRetentionPolicy[]>;
  createDataRetentionPolicy(policy: InsertDataRetentionPolicy): Promise<DataRetentionPolicy>;
  updateDataRetentionPolicy(id: string, data: Partial<DataRetentionPolicy>): Promise<DataRetentionPolicy | undefined>;
  deleteDataRetentionPolicy(id: string): Promise<boolean>;

  getAlertDestinations(orgId?: string): Promise<AlertDestination[]>;
  getAlertDestination(id: string): Promise<AlertDestination | undefined>;
  createAlertDestination(dest: InsertAlertDestination): Promise<AlertDestination>;
  updateAlertDestination(id: string, data: Partial<AlertDestination>): Promise<AlertDestination | undefined>;
  deleteAlertDestination(id: string): Promise<boolean>;

  createApiKey(key: InsertApiKey): Promise<ApiKey>;
  getApiKeyByHash(keyHash: string): Promise<ApiKey | undefined>;
  getApiKeys(orgId: string): Promise<ApiKey[]>;
  deleteApiKey(id: string): Promise<boolean>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  getDashboardStats(orgId?: string): Promise<{
    activeSessions: number;
    totalEvents: number;
    criticalEvents: number;
    blockedCalls: number;
    avgIntegrity: number;
    trustedServers: number;
  }>;

  getComplianceData(orgId?: string): Promise<{
    overallScore: number;
    controlFamilies: { id: string; name: string; controls: number; covered: number; score: number }[];
    recentControls: { id: string; name: string; status: string; eventsCount: number }[];
  }>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async getUsers(orgId?: string): Promise<User[]> {
    if (orgId) {
      return db.select().from(users).where(eq(users.organizationId, orgId)).orderBy(desc(users.createdAt));
    }
    return db.select().from(users).orderBy(desc(users.createdAt));
  }

  async updateUser(id: string, data: Partial<User>): Promise<User | undefined> {
    const [updated] = await db.update(users).set(data).where(eq(users.id, id)).returning();
    return updated;
  }

  async deleteUser(id: string): Promise<boolean> {
    const result = await db.delete(users).where(eq(users.id, id)).returning();
    return result.length > 0;
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
    return org;
  }

  async getOrganizationBySlug(slug: string): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.slug, slug));
    return org;
  }

  async createOrganization(org: InsertOrganization): Promise<Organization> {
    const [created] = await db.insert(organizations).values(org).returning();
    return created;
  }

  async getOrganizations(): Promise<Organization[]> {
    return db.select().from(organizations).orderBy(desc(organizations.createdAt));
  }

  async getSessions(orgId?: string, activeOnly?: boolean): Promise<Session[]> {
    const conditions = [];
    if (orgId) conditions.push(eq(sessions.organizationId, orgId));
    if (activeOnly) conditions.push(eq(sessions.isActive, true));
    if (conditions.length > 0) {
      return db.select().from(sessions).where(and(...conditions)).orderBy(desc(sessions.startTime));
    }
    return db.select().from(sessions).orderBy(desc(sessions.startTime));
  }

  async getSession(id: string): Promise<Session | undefined> {
    const [session] = await db.select().from(sessions).where(eq(sessions.id, id));
    return session;
  }

  async createSession(session: InsertSession): Promise<Session> {
    const [created] = await db.insert(sessions).values(session).returning();
    return created;
  }

  async deleteSessionsBefore(date: Date, orgId?: string): Promise<number> {
    const conditions = [lt(sessions.startTime, date)];
    if (orgId) conditions.push(eq(sessions.organizationId, orgId));
    const result = await db.delete(sessions).where(and(...conditions)).returning();
    return result.length;
  }

  async getSecurityEvents(filters?: { severity?: string; type?: string; limit?: number; orgId?: string }): Promise<SecurityEvent[]> {
    const conditions = [];
    if (filters?.severity) conditions.push(eq(securityEvents.severity, filters.severity));
    if (filters?.type) conditions.push(eq(securityEvents.eventType, filters.type));
    if (filters?.orgId) conditions.push(eq(securityEvents.organizationId, filters.orgId));

    const query = db.select().from(securityEvents);
    if (conditions.length > 0) {
      return query.where(and(...conditions)).orderBy(desc(securityEvents.timestamp)).limit(filters?.limit || 100);
    }
    return query.orderBy(desc(securityEvents.timestamp)).limit(filters?.limit || 100);
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent> {
    const [created] = await db.insert(securityEvents).values(event).returning();
    return created;
  }

  async deleteEventsBefore(date: Date, orgId?: string): Promise<number> {
    const conditions = [lt(securityEvents.timestamp, date)];
    if (orgId) conditions.push(eq(securityEvents.organizationId, orgId));
    const result = await db.delete(securityEvents).where(and(...conditions)).returning();
    return result.length;
  }

  async getToolCalls(sessionId?: string, orgId?: string): Promise<ToolCall[]> {
    const conditions = [];
    if (sessionId) conditions.push(eq(toolCalls.sessionId, sessionId));
    if (orgId) conditions.push(eq(toolCalls.organizationId, orgId));
    if (conditions.length > 0) {
      return db.select().from(toolCalls).where(and(...conditions)).orderBy(desc(toolCalls.timestamp));
    }
    return db.select().from(toolCalls).orderBy(desc(toolCalls.timestamp)).limit(100);
  }

  async createToolCall(call: InsertToolCall): Promise<ToolCall> {
    const [created] = await db.insert(toolCalls).values(call).returning();
    return created;
  }

  async deleteToolCallsBefore(date: Date, orgId?: string): Promise<number> {
    const conditions = [lt(toolCalls.timestamp, date)];
    if (orgId) conditions.push(eq(toolCalls.organizationId, orgId));
    const result = await db.delete(toolCalls).where(and(...conditions)).returning();
    return result.length;
  }

  async getTrustedServers(orgId?: string): Promise<TrustedServer[]> {
    if (orgId) {
      return db.select().from(trustedServers).where(eq(trustedServers.organizationId, orgId)).orderBy(desc(trustedServers.createdAt));
    }
    return db.select().from(trustedServers).orderBy(desc(trustedServers.createdAt));
  }

  async createTrustedServer(server: InsertTrustedServer): Promise<TrustedServer> {
    const [created] = await db.insert(trustedServers).values(server).returning();
    return created;
  }

  async updateTrustedServer(id: string, data: Partial<TrustedServer>): Promise<TrustedServer | undefined> {
    const [updated] = await db.update(trustedServers).set(data).where(eq(trustedServers.id, id)).returning();
    return updated;
  }

  async getPolicyRules(orgId?: string): Promise<PolicyRule[]> {
    if (orgId) {
      return db.select().from(policyRules).where(eq(policyRules.organizationId, orgId)).orderBy(desc(policyRules.createdAt));
    }
    return db.select().from(policyRules).orderBy(desc(policyRules.createdAt));
  }

  async createPolicyRule(rule: InsertPolicyRule): Promise<PolicyRule> {
    const [created] = await db.insert(policyRules).values(rule).returning();
    return created;
  }

  async updatePolicyRule(id: string, data: Partial<PolicyRule>): Promise<PolicyRule | undefined> {
    const [updated] = await db.update(policyRules).set(data).where(eq(policyRules.id, id)).returning();
    return updated;
  }

  async createAuditLog(entry: InsertAuditLog): Promise<AuditLog> {
    const [created] = await db.insert(auditLogs).values(entry).returning();
    return created;
  }

  async getAuditLogs(filters?: { orgId?: string; userId?: string; resourceType?: string; limit?: number }): Promise<AuditLog[]> {
    const conditions = [];
    if (filters?.orgId) conditions.push(eq(auditLogs.organizationId, filters.orgId));
    if (filters?.userId) conditions.push(eq(auditLogs.userId, filters.userId));
    if (filters?.resourceType) conditions.push(eq(auditLogs.resourceType, filters.resourceType));
    if (conditions.length > 0) {
      return db.select().from(auditLogs).where(and(...conditions)).orderBy(desc(auditLogs.timestamp)).limit(filters?.limit || 200);
    }
    return db.select().from(auditLogs).orderBy(desc(auditLogs.timestamp)).limit(filters?.limit || 200);
  }

  async deleteAuditLogsBefore(date: Date, orgId?: string): Promise<number> {
    const conditions = [lt(auditLogs.timestamp, date)];
    if (orgId) conditions.push(eq(auditLogs.organizationId, orgId));
    const result = await db.delete(auditLogs).where(and(...conditions)).returning();
    return result.length;
  }

  async getDataRetentionPolicies(orgId?: string): Promise<DataRetentionPolicy[]> {
    if (orgId) {
      return db.select().from(dataRetentionPolicies).where(eq(dataRetentionPolicies.organizationId, orgId));
    }
    return db.select().from(dataRetentionPolicies);
  }

  async createDataRetentionPolicy(policy: InsertDataRetentionPolicy): Promise<DataRetentionPolicy> {
    const [created] = await db.insert(dataRetentionPolicies).values(policy).returning();
    return created;
  }

  async updateDataRetentionPolicy(id: string, data: Partial<DataRetentionPolicy>): Promise<DataRetentionPolicy | undefined> {
    const [updated] = await db.update(dataRetentionPolicies).set(data).where(eq(dataRetentionPolicies.id, id)).returning();
    return updated;
  }

  async deleteDataRetentionPolicy(id: string): Promise<boolean> {
    const result = await db.delete(dataRetentionPolicies).where(eq(dataRetentionPolicies.id, id)).returning();
    return result.length > 0;
  }

  async getAlertDestinations(orgId?: string): Promise<AlertDestination[]> {
    if (orgId) {
      return db.select().from(alertDestinations).where(eq(alertDestinations.organizationId, orgId)).orderBy(desc(alertDestinations.createdAt));
    }
    return db.select().from(alertDestinations).orderBy(desc(alertDestinations.createdAt));
  }

  async getAlertDestination(id: string): Promise<AlertDestination | undefined> {
    const [dest] = await db.select().from(alertDestinations).where(eq(alertDestinations.id, id));
    return dest;
  }

  async createAlertDestination(dest: InsertAlertDestination): Promise<AlertDestination> {
    const [created] = await db.insert(alertDestinations).values(dest).returning();
    return created;
  }

  async updateAlertDestination(id: string, data: Partial<AlertDestination>): Promise<AlertDestination | undefined> {
    const [updated] = await db.update(alertDestinations).set(data).where(eq(alertDestinations.id, id)).returning();
    return updated;
  }

  async deleteAlertDestination(id: string): Promise<boolean> {
    const result = await db.delete(alertDestinations).where(eq(alertDestinations.id, id)).returning();
    return result.length > 0;
  }

  async createApiKey(key: InsertApiKey): Promise<ApiKey> {
    const [created] = await db.insert(apiKeys).values(key).returning();
    return created;
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKey | undefined> {
    const [key] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
    return key;
  }

  async getApiKeys(orgId: string): Promise<ApiKey[]> {
    return db.select().from(apiKeys).where(eq(apiKeys.organizationId, orgId)).orderBy(desc(apiKeys.createdAt));
  }

  async deleteApiKey(id: string): Promise<boolean> {
    const result = await db.delete(apiKeys).where(eq(apiKeys.id, id)).returning();
    return result.length > 0;
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, id));
  }

  async getDashboardStats(orgId?: string) {
    const orgFilter = orgId ? eq(sessions.organizationId, orgId) : undefined;
    const eventOrgFilter = orgId ? eq(securityEvents.organizationId, orgId) : undefined;
    const callOrgFilter = orgId ? eq(toolCalls.organizationId, orgId) : undefined;
    const serverOrgFilter = orgId ? eq(trustedServers.organizationId, orgId) : undefined;

    const activeConditions = orgFilter ? and(eq(sessions.isActive, true), orgFilter) : eq(sessions.isActive, true);
    const [activeCount] = await db.select({ count: count() }).from(sessions).where(activeConditions);

    const [totalEventsCount] = await db.select({ count: count() }).from(securityEvents).where(eventOrgFilter);
    const criticalConditions = eventOrgFilter ? and(eq(securityEvents.severity, "critical"), eventOrgFilter) : eq(securityEvents.severity, "critical");
    const [criticalCount] = await db.select({ count: count() }).from(securityEvents).where(criticalConditions);

    const blockedConditions = callOrgFilter ? and(eq(toolCalls.allowed, false), callOrgFilter) : eq(toolCalls.allowed, false);
    const [blockedCount] = await db.select({ count: count() }).from(toolCalls).where(blockedConditions);

    const [avgResult] = await db.select({ avg: sql<number>`coalesce(avg(${sessions.goalIntegrityScore}), 1.0)` }).from(sessions).where(orgFilter);

    const serverConditions = serverOrgFilter ? and(eq(trustedServers.status, "allowed"), serverOrgFilter) : eq(trustedServers.status, "allowed");
    const [serverCount] = await db.select({ count: count() }).from(trustedServers).where(serverConditions);

    return {
      activeSessions: activeCount.count,
      totalEvents: totalEventsCount.count,
      criticalEvents: criticalCount.count,
      blockedCalls: blockedCount.count,
      avgIntegrity: Number(avgResult.avg),
      trustedServers: serverCount.count,
    };
  }

  async getComplianceData(orgId?: string) {
    const orgFilter = orgId ? eq(securityEvents.organizationId, orgId) : undefined;
    const allEvents = orgFilter
      ? await db.select().from(securityEvents).where(orgFilter)
      : await db.select().from(securityEvents);

    const controlMap = new Map<string, Set<string>>();
    for (const event of allEvents) {
      if (event.cmmcControls) {
        for (const ctrl of event.cmmcControls) {
          if (!controlMap.has(ctrl)) controlMap.set(ctrl, new Set());
          controlMap.get(ctrl)!.add(event.id);
        }
      }
    }

    const families = [
      { id: "AC", name: "Access Control", controls: 22 },
      { id: "AU", name: "Audit & Accountability", controls: 9 },
      { id: "CM", name: "Configuration Management", controls: 9 },
      { id: "IA", name: "Identification & Authentication", controls: 11 },
      { id: "SC", name: "System & Communications Protection", controls: 16 },
    ];

    const controlFamilies = families.map((f) => {
      const coveredControls = Array.from(controlMap.keys()).filter(k => k.startsWith(f.id)).length;
      const score = Math.round((coveredControls / f.controls) * 100);
      return { ...f, covered: coveredControls, score: Math.min(score, 100) };
    });

    const overallTotal = families.reduce((s, f) => s + f.controls, 0);
    const overallCovered = controlFamilies.reduce((s, f) => s + f.covered, 0);
    const overallScore = Math.round((overallCovered / overallTotal) * 100);

    const nistControls = [
      { id: "AC-3.1", name: "Account Management" },
      { id: "AC-3.2", name: "Access Enforcement" },
      { id: "AC-17.1", name: "Remote Access" },
      { id: "AU-2.1", name: "Event Logging" },
      { id: "AU-3.1", name: "Content of Audit Records" },
      { id: "AU-6.1", name: "Audit Review, Analysis, Reporting" },
      { id: "CM-2.1", name: "Baseline Configuration" },
      { id: "CM-6.1", name: "Configuration Settings" },
      { id: "CM-7.1", name: "Least Functionality" },
      { id: "IA-2.1", name: "Identification and Authentication" },
      { id: "IA-5.1", name: "Authenticator Management" },
      { id: "SC-7.1", name: "Boundary Protection" },
      { id: "SC-8.1", name: "Transmission Confidentiality" },
      { id: "SC-13.1", name: "Cryptographic Protection" },
      { id: "SC-28.1", name: "Protection of Information at Rest" },
    ];

    const recentControls = nistControls.map(c => {
      const eventCount = controlMap.get(c.id)?.size || 0;
      return {
        id: c.id,
        name: c.name,
        status: eventCount > 2 ? "covered" : eventCount > 0 ? "partial" : "not_covered",
        eventsCount: eventCount,
      };
    });

    return { overallScore, controlFamilies, recentControls };
  }
}

export const storage = new DatabaseStorage();
