import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AI Sentinel — AI-Powered Network Intrusion Detection System",
  description:
    "Educational NIDS prototype: RandomForest + IsolationForest threat classification, safe attack simulation, offline PCAP analysis, and a real-time SOC dashboard. All demo traffic is synthetic.",
  keywords: [
    "intrusion detection",
    "machine learning",
    "RandomForest",
    "IsolationForest",
    "network security",
    "SOC dashboard",
    "PCAP analysis",
  ],
  authors: [{ name: "AI Sentinel Hackathon Team" }],
  openGraph: {
    title: "AI Sentinel — AI-Powered NIDS",
    description:
      "ML-based network intrusion detection with live SOC dashboard, safe simulations and PCAP analysis.",
    siteName: "AI Sentinel",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
