import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ClawScan — Security Scanner for OpenClaw",
  description:
    "The first security skill built for OpenClaw AI agents. Find vulnerabilities, misconfigs, and exposed secrets. Install with: openclaw skill install clawscan",
  openGraph: {
    title: "ClawScan — Security Scanner for OpenClaw",
    description:
      "OpenClaw skill for security scanning. 24 checks, A-F grading, pure bash, zero dependencies. Install: openclaw skill install clawscan",
    images: ["/og-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "ClawScan — Security Scanner for OpenClaw",
    description:
      "OpenClaw security skill. Install: openclaw skill install clawscan",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}