"use client";
/**
 * AI Sentinel — Demo Authentication Dialog.
 * Client-side authentication for SOC Analyst / Evaluator access.
 * Validates password criteria (min 6 chars, >= 1 uppercase) and persists locally.
 */
import { useState } from "react";
import { Shield, Lock, Mail, User as UserIcon, CheckCircle2, AlertCircle, KeyRound, Sparkles } from "lucide-react";
import { useSentinelStore } from "@/lib/sentinel/store";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function AuthModal() {
  const authModalOpen = useSentinelStore((s) => s.authModalOpen);
  const setAuthModalOpen = useSentinelStore((s) => s.setAuthModalOpen);
  const login = useSentinelStore((s) => s.login);
  const signup = useSentinelStore((s) => s.signup);

  const [mode, setMode] = useState<"login" | "signup">("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<"SOC Analyst" | "Lead Responder" | "Guest Evaluator">("SOC Analyst");
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await login(email, password);
      if (!res.success) {
        setError(res.error || "Login failed");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const res = await signup(email, name, password, role);
      if (!res.success) {
        setError(res.error || "Signup failed");
      } else {
        setSuccessMsg(`Account created for ${name}! Please sign in with your credentials to access the SOC Dashboard.`);
        setMode("login");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemo = async () => {
    setEmail("analyst@sentinel.soc");
    setPassword("Sentinel@2026");
    setError(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      await login("analyst@sentinel.soc", "Sentinel@2026");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={authModalOpen} onOpenChange={setAuthModalOpen}>
      <DialogContent className="border-zinc-800 bg-zinc-950 text-zinc-100 sm:max-w-md shadow-2xl">
        <DialogHeader className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mb-2">
            <Shield className="h-6 w-6" aria-hidden />
          </div>
          <DialogTitle className="text-xl font-bold tracking-tight">AI Sentinel SOC Console</DialogTitle>
          <DialogDescription className="text-zinc-400 text-xs">
            Authenticate to access live intrusion detection, security simulations, and incident controls.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={mode} onValueChange={(v) => { setMode(v as "login" | "signup"); setError(null); }} className="w-full mt-2">
          <TabsList className="grid w-full grid-cols-2 bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="signup" className="data-[state=active]:bg-zinc-800 text-xs font-semibold">
              1. Create Account
            </TabsTrigger>
            <TabsTrigger value="login" className="data-[state=active]:bg-zinc-800 text-xs font-semibold">
              2. Sign In
            </TabsTrigger>
          </TabsList>

          {successMsg && (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-300">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
              <span>{successMsg}</span>
            </div>
          )}

          {error && (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300">
              <AlertCircle className="h-4 w-4 shrink-0" aria-hidden />
              <span>{error}</span>
            </div>
          )}

          <TabsContent value="login">
            <form onSubmit={handleLogin} className="space-y-3.5 mt-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">SOC Email Address</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
                  <Input
                    type="email"
                    placeholder="analyst@sentinel.soc"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="border-zinc-800 bg-zinc-900/80 pl-9 text-sm text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">Access Key / Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
                  <Input
                    type="password"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="border-zinc-800 bg-zinc-900/80 pl-9 text-sm text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                  />
                </div>
              </div>

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-emerald-600 font-semibold text-white hover:bg-emerald-500 mt-2"
              >
                {loading ? "Authenticating…" : "Sign In to SOC"}
              </Button>

              <div className="pt-2 border-t border-zinc-900">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleQuickDemo}
                  className="w-full border-zinc-800 bg-zinc-900/50 text-xs text-amber-300 hover:bg-zinc-800 hover:text-amber-200"
                >
                  <Sparkles className="mr-1.5 h-3.5 w-3.5 text-amber-400" /> Quick Hackathon Demo Login
                </Button>
              </div>
            </form>
          </TabsContent>

          <TabsContent value="signup">
            <form onSubmit={handleSignup} className="space-y-3 mt-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">Full Name</Label>
                <div className="relative">
                  <UserIcon className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
                  <Input
                    type="text"
                    placeholder="Alex Chen"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    className="border-zinc-800 bg-zinc-900/80 pl-9 text-sm text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">Work Email</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
                  <Input
                    type="email"
                    placeholder="alex.chen@cyber.org"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="border-zinc-800 bg-zinc-900/80 pl-9 text-sm text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">SOC Role</Label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as User["role"])}
                  className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <option value="SOC Analyst">SOC Analyst</option>
                  <option value="Lead Responder">Lead Responder</option>
                  <option value="Security Lead">Security Lead</option>
                  <option value="Guest Evaluator">Guest Evaluator (Judge)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-zinc-400 font-medium">
                  Password <span className="text-[10px] text-zinc-500">(min 6 chars, 1 uppercase)</span>
                </Label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
                  <Input
                    type="password"
                    placeholder="At least 6 chars + 1 capital"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="border-zinc-800 bg-zinc-900/80 pl-9 text-sm text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-emerald-500"
                  />
                </div>
              </div>

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-emerald-600 font-semibold text-white hover:bg-emerald-500 mt-2"
              >
                {loading ? "Creating Account…" : "Register Analyst"}
              </Button>
            </form>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
