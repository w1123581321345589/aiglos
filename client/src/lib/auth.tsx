import { createContext, useContext, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "./queryClient";
import type { User } from "@shared/schema";

type AuthUser = Omit<User, "password">;

interface AuthContextType {
  user: AuthUser | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
  isAnalyst: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  isLoading: true,
  login: async () => {},
  logout: async () => {},
  isAdmin: false,
  isAnalyst: false,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { data: user, isLoading } = useQuery<AuthUser | null>({
    queryKey: ["/api/auth/me"],
    queryFn: async () => {
      try {
        const res = await fetch("/api/auth/me", { credentials: "include" });
        if (res.status === 401) return null;
        if (!res.ok) return null;
        return await res.json();
      } catch {
        return null;
      }
    },
    retry: false,
    staleTime: Infinity,
  });

  const login = async (username: string, password: string) => {
    const res = await apiRequest("POST", "/api/auth/login", { username, password });
    const userData = await res.json();
    queryClient.setQueryData(["/api/auth/me"], userData);
  };

  const logout = async () => {
    await apiRequest("POST", "/api/auth/logout");
    queryClient.setQueryData(["/api/auth/me"], null);
    queryClient.clear();
  };

  const isAdmin = user?.role === "admin";
  const isAnalyst = user?.role === "analyst" || user?.role === "admin";

  return (
    <AuthContext.Provider value={{ user: user ?? null, isLoading, login, logout, isAdmin, isAnalyst }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
