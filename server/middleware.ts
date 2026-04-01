import type { Request, Response, NextFunction } from "express";
import { storage } from "./storage";
import type { User } from "@shared/schema";

declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

declare module "express-session" {
  interface SessionData {
    userId?: string;
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session?.userId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required" });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}

export async function loadUser(req: Request, _res: Response, next: NextFunction) {
  if (req.session?.userId) {
    const user = await storage.getUser(req.session.userId);
    if (user) {
      req.user = user;
    }
  }
  next();
}

export async function auditLog(
  req: Request,
  action: string,
  resourceType: string,
  resourceId?: string,
  details?: Record<string, any>
) {
  try {
    await storage.createAuditLog({
      organizationId: req.user?.organizationId || null,
      userId: req.user?.id || null,
      username: req.user?.username || "system",
      action,
      resourceType,
      resourceId: resourceId || null,
      details: details || {},
      ipAddress: req.ip || req.socket.remoteAddress || null,
    });
  } catch (e) {
    console.error("Failed to write audit log:", e);
  }
}
