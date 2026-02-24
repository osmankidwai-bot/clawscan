export default function Home() {
  return (
    <main className="min-h-screen bg-bg overflow-hidden">
      {/* Ambient glow */}
      <div className="fixed inset-0 bg-gradient-radial pointer-events-none" />

      {/* ── Hero ── */}
      <section className="relative px-6 pt-32 pb-24 max-w-4xl mx-auto text-center">
        <div className="animate-fade-in-up">
          <div className="inline-block mb-6 px-4 py-1.5 rounded-full border border-accent/30 text-accent text-sm font-mono tracking-wide">
            OpenClaw Skill &mdash; Install with one command
          </div>
          <h1 className="text-4xl md:text-6xl font-bold text-white leading-tight mb-6">
            Security Scanner
            <br />
            <span className="text-accent glow">for OpenClaw</span>
          </h1>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto mb-10">
            The first security skill built for OpenClaw. Find vulnerabilities, misconfigs, and exposed secrets in your AI agent setup. Pure bash, zero dependencies.
          </p>
          
          {/* Install command prominently displayed */}
          <div className="mb-8 max-w-2xl mx-auto glow-box rounded-xl overflow-hidden">
            <div className="bg-[#1a1a1a] px-4 py-3 flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
              <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
              <div className="w-3 h-3 rounded-full bg-[#28c840]" />
              <span className="ml-3 text-gray-500 text-sm font-mono">terminal</span>
            </div>
            <div className="bg-black/80 p-6 font-mono text-sm text-center">
              <span className="text-gray-500">$ </span>
              <span className="text-accent font-semibold">openclaw skill install clawscan</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="#install"
              className="inline-flex items-center justify-center px-8 py-3.5 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-dim transition-colors text-lg"
            >
              Install in One Command
            </a>
            <a
              href="#pricing"
              className="inline-flex items-center justify-center px-8 py-3.5 border border-accent/40 text-accent font-semibold rounded-lg hover:bg-accent/10 transition-colors text-lg"
            >
              View Pricing
            </a>
          </div>
        </div>
      </section>

      {/* ── Expert Validation ── */}
      <section className="px-6 py-16 max-w-4xl mx-auto">
        <div className="border border-accent/30 rounded-xl p-8 bg-accent/[0.03] glow-box text-center">
          <div className="text-accent text-sm font-mono uppercase tracking-wider mb-4">
            VALIDATED BY AI EXPERTS
          </div>
          <blockquote className="text-xl md:text-2xl font-bold text-white mb-4 italic leading-relaxed">
            &ldquo;AI agent networks [are becoming a] computer security nightmare at scale&rdquo;
          </blockquote>
          <cite className="text-gray-400 text-sm">
            — Andrej Karpathy, OpenAI Co-founder, Former Tesla AI Director
          </cite>
          <div className="mt-6 text-accent font-semibold">
            ClawScan was built to prevent exactly this nightmare.
          </div>
        </div>
      </section>

      {/* ── The Problem ── */}
      <section className="px-6 py-20 max-w-3xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-12">
          Why ClawScan Exists
        </h2>
        <div className="space-y-6 text-center">
          <div className="flex items-center justify-center gap-4">
            <span className="text-accent font-mono text-3xl font-bold">100K+</span>
            <span className="text-gray-400 text-lg">OpenClaw users running AI agents with system access.</span>
          </div>
          <div className="flex items-center justify-center gap-4">
            <span className="text-red-400 font-mono text-3xl font-bold">0</span>
            <span className="text-gray-400 text-lg">Security tools built specifically for OpenClaw. Until now.</span>
          </div>
          <div className="flex items-center justify-center gap-4">
            <span className="text-yellow-400 font-mono text-3xl font-bold">24</span>
            <span className="text-gray-400 text-lg">OpenClaw-specific security checks. Free tier included.</span>
          </div>
        </div>
      </section>

      {/* ── How It Works ── */}
      <section id="install" className="px-6 py-20 max-w-4xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-16">
          How It Works
        </h2>

        {/* Steps */}
        <div className="grid md:grid-cols-3 gap-8 mb-16">
          {[
            {
              step: "01",
              title: "Install Skill",
              desc: "One command installs ClawScan as an OpenClaw skill. Pure bash, zero dependencies.",
              code: "openclaw skill install clawscan",
            },
            {
              step: "02",
              title: "Run Security Scan",
              desc: "24 checks across config, files, skills, and network exposure. A-F grading system.",
              code: "openclaw run clawscan",
            },
            {
              step: "03",
              title: "Fix Issues",
              desc: "Get actionable findings with fix recommendations. Secure your setup before exploits.",
              code: "Grade: B+ (87/100) ✅",
            },
          ].map((item) => (
            <div
              key={item.step}
              className="border-glow rounded-xl p-6 bg-white/[0.02] hover:bg-white/[0.04] transition-colors"
            >
              <div className="text-accent font-mono text-sm mb-2">{item.step}</div>
              <h3 className="text-xl font-bold text-white mb-2">{item.title}</h3>
              <p className="text-gray-400 text-sm mb-4">{item.desc}</p>
              <div className="bg-black/60 rounded-lg p-3 font-mono text-sm text-accent/80">
                <span className="text-gray-500">$ </span>
                {item.code}
              </div>
            </div>
          ))}
        </div>

        {/* Terminal mockup */}
        <div className="max-w-2xl mx-auto glow-box rounded-xl overflow-hidden">
          <div className="bg-[#1a1a1a] px-4 py-3 flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
            <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
            <div className="w-3 h-3 rounded-full bg-[#28c840]" />
            <span className="ml-3 text-gray-500 text-sm font-mono">openclaw run clawscan</span>
          </div>
          <div className="bg-black/80 p-6 font-mono text-sm leading-relaxed">
            <pre className="text-gray-300 whitespace-pre overflow-x-auto">{`╔════════════════════════════════════════════╗
║        ClawScan Security Report            ║
╠════════════════════════════════════════════╣
║  Grade: B+ (87/100)                        ║
╠════════════════════════════════════════════╣
║  [OpenClaw Config Security]                ║
║  `}<span className="text-green-400">{"✅ Gateway auth properly configured"}</span>{`
║  `}<span className="text-green-400">{"✅ Model allowlist restrictive"}</span>{`
║  `}<span className="text-red-400">{"❌ API keys found in gateway config"}</span>{`
║  [Workspace Security]                      ║
║  `}<span className="text-green-400">{"✅ Memory files have proper perms"}</span>{`
║  `}<span className="text-yellow-400">{"⚠️  Passwords found in MEMORY.md"}</span>{`
║  [Skill Security]                          ║
║  `}<span className="text-green-400">{"✅ All skills from trusted sources"}</span>{`
║  `}<span className="text-yellow-400">{"⚠️  2 skills have broad file access"}</span>{`
║  [Network & Webhook Security]              ║
║  `}<span className="text-green-400">{"✅ HTTPS enforced for webhooks"}</span>{`
║  `}<span className="text-red-400">{"❌ Gateway accessible from internet"}</span>{`
╠════════════════════════════════════════════╣
║  Pro upgrade: 16 additional checks         ║
║  → openclaw skill upgrade clawscan         ║
╚════════════════════════════════════════════╝`}</pre>
          </div>
        </div>
      </section>

      {/* ── Security Check Categories ── */}
      <section className="px-6 py-20 max-w-4xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-16">
          5 Categories of Security Checks
        </h2>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            {
              category: "OpenClaw Config",
              icon: "⚙️",
              checks: ["Gateway authentication", "Model restrictions", "API key exposure", "Webhook validation", "Skill permissions"],
              highlight: true,
            },
            {
              category: "Workspace Security",
              icon: "📁",
              checks: ["File permissions", "Memory data exposure", "Credential scanning", "Backup security", "Temp file cleanup"],
            },
            {
              category: "Skill Audit",
              icon: "🔌",
              checks: ["Source verification", "Permission analysis", "Dependency security", "Code execution risks", "Update validation"],
              highlight: true,
            },
            {
              category: "Network Exposure",
              icon: "🌐",
              checks: ["Port scanning", "Service discovery", "HTTPS enforcement", "Firewall validation", "Remote access audit"],
            },
            {
              category: "Secrets & Keys",
              icon: "🔑",
              checks: ["API key detection", "Token scanning", "Credential storage", "Environment leaks", "Browser session data"],
            },
          ].map((cat) => (
            <div
              key={cat.category}
              className={`rounded-xl p-6 transition-colors ${
                cat.highlight 
                  ? "border border-accent/60 bg-accent/[0.03] glow-box" 
                  : "border-glow bg-white/[0.02] hover:bg-white/[0.04]"
              }`}
            >
              <div className="flex items-center gap-3 mb-4">
                <span className="text-2xl">{cat.icon}</span>
                <h3 className="text-lg font-bold text-white">{cat.category}</h3>
                {cat.highlight && (
                  <span className="text-xs bg-accent/20 text-accent px-2 py-0.5 rounded-full font-mono">
                    OPENCLAW SPECIFIC
                  </span>
                )}
              </div>
              <ul className="space-y-2 text-sm text-gray-400">
                {cat.checks.map((check) => (
                  <li key={check} className="flex items-start gap-2">
                    <span className="text-accent mt-0.5 text-xs">▸</span>
                    {check}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* ── Pricing ── */}
      <section id="pricing" className="px-6 py-20 max-w-4xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-16">
          Pricing
        </h2>
        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          {/* Free */}
          <div className="border-glow rounded-xl p-8 bg-white/[0.02]">
            <div className="text-gray-400 text-sm font-mono uppercase tracking-wider mb-2">
              Free
            </div>
            <div className="text-4xl font-bold text-white mb-1">$0</div>
            <div className="text-gray-500 text-sm mb-6">forever</div>
            <ul className="space-y-3 text-gray-300 text-sm mb-8">
              {[
                "24 security checks",
                "A-F grading system",
                "OpenClaw-specific audits",
                "Pure bash, zero deps",
                "CLI & JSON output",
                "Community support",
              ].map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <span className="text-accent mt-0.5">✓</span>
                  {f}
                </li>
              ))}
            </ul>
            <div className="space-y-3">
              <div className="bg-black/60 rounded-lg p-3 font-mono text-sm text-accent/80 text-center">
                <span className="text-gray-500">$ </span>
                openclaw skill install clawscan
              </div>
            </div>
          </div>

          {/* Pro */}
          <div className="border border-accent/60 rounded-xl p-8 bg-accent/[0.03] glow-box relative">
            <div className="absolute -top-3 right-6 px-3 py-0.5 bg-accent text-bg text-xs font-bold rounded-full">
              COMING SOON
            </div>
            <div className="text-accent text-sm font-mono uppercase tracking-wider mb-2">
              Pro
            </div>
            <div className="text-4xl font-bold text-white mb-1">
              $19<span className="text-lg text-gray-400 font-normal">/mo</span>
            </div>
            <div className="text-gray-500 text-sm mb-6">cancel anytime</div>
            <ul className="space-y-3 text-gray-300 text-sm mb-8">
              {[
                "Everything in Free",
                "40+ total security checks",
                "Trend tracking over time",
                "Severity scoring system",
                "Custom check configuration",
                "Priority support",
              ].map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <span className="text-accent mt-0.5">✓</span>
                  {f}
                </li>
              ))}
            </ul>
            <a
              href="https://buy.stripe.com/test_3cIaEX4fI8MO2kC9uWcQU00"
              className="block w-full text-center py-3 bg-accent text-bg rounded-lg hover:bg-accent-dim transition-colors font-semibold"
            >
              Get Pro
            </a>
          </div>

          {/* Managed */}
          <div className="border-glow rounded-xl p-8 bg-white/[0.02]">
            <div className="text-gray-400 text-sm font-mono uppercase tracking-wider mb-2">
              Managed
            </div>
            <div className="text-4xl font-bold text-white mb-1">
              $49<span className="text-lg text-gray-400 font-normal">/mo</span>
            </div>
            <div className="text-gray-500 text-sm mb-6">coming soon</div>
            <ul className="space-y-3 text-gray-300 text-sm mb-8">
              {[
                "Everything in Pro",
                "Continuous monitoring",
                "Auto-remediation scripts",
                "Real-time alerting",
                "Incident response",
                "White-glove setup",
              ].map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <span className="text-accent mt-0.5">✓</span>
                  {f}
                </li>
              ))}
            </ul>
            <a
              href="https://buy.stripe.com/test_7sYbJ1cMe9QS1gy6iKcQU01"
              className="block w-full text-center py-3 border border-accent/40 text-accent rounded-lg hover:bg-accent/10 transition-colors font-medium"
            >
              Get Managed
            </a>
          </div>
        </div>

        {/* Enterprise */}
        <div className="max-w-2xl mx-auto mt-12">
          <div className="border-glow rounded-xl p-8 bg-white/[0.02] text-center">
            <div className="text-gray-400 text-sm font-mono uppercase tracking-wider mb-2">Enterprise Audit</div>
            <div className="text-4xl font-bold text-white mb-2">$500</div>
            <p className="text-gray-400 text-sm mb-6">One-time comprehensive security review, custom playbook, and 30-day follow-up support.</p>
            <a href="https://buy.stripe.com/test_9B69AT6nQ1km0cubD4cQU02" className="inline-flex items-center justify-center px-6 py-3 border border-accent/40 text-accent rounded-lg hover:bg-accent/10 transition-colors font-medium">Book Enterprise Audit</a>
          </div>
        </div>
      </section>

      {/* ── Why Choose ClawScan ── */}
      <section className="px-6 py-20 max-w-3xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-12">
          Why Choose ClawScan?
        </h2>
        <div className="space-y-8">
          {[
            {
              title: "Built for OpenClaw",
              desc: "The first and only security tool designed specifically for OpenClaw environments. We understand your AI agent's attack surface.",
              icon: "🎯",
            },
            {
              title: "Zero Dependencies",
              desc: "Pure bash implementation. No Python, Node.js, or external libraries. Runs on any system with a shell and OpenClaw.",
              icon: "⚡",
            },
            {
              title: "OpenClaw-Native",
              desc: "Installs as an OpenClaw skill. No separate installation, configuration, or maintenance. Just `openclaw skill install clawscan`.",
              icon: "🔌",
            },
            {
              title: "Privacy-First",
              desc: "All scanning happens locally. No data leaves your machine. No telemetry, tracking, or cloud dependencies.",
              icon: "🔒",
            },
          ].map((item) => (
            <div key={item.title} className="flex items-start gap-4">
              <span className="text-2xl mt-1">{item.icon}</span>
              <div>
                <h3 className="text-xl font-bold text-white mb-2">{item.title}</h3>
                <p className="text-gray-400">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Social Proof ── */}
      <section className="px-6 py-20 max-w-3xl mx-auto text-center">
        <div className="border-glow rounded-xl p-10 bg-white/[0.02]">
          <p className="text-lg text-gray-300 mb-4 italic">
            &ldquo;Built by an OpenClaw power user running AI agents 24/7 on production infrastructure.&rdquo;
          </p>
          <a
            href="https://twitter.com/UngratefulAI"
            className="text-accent hover:text-accent-dim transition-colors font-mono"
          >
            @UngratefulAI
          </a>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="px-6 py-12 border-t border-white/5">
        <div className="max-w-4xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="font-mono text-accent font-bold text-lg">
            CLAWSCAN
          </div>
          <div className="flex items-center gap-8 text-sm text-gray-500">
            <a href="#install" className="hover:text-gray-300 transition-colors">
              Install
            </a>
            <a href="#pricing" className="hover:text-gray-300 transition-colors">
              Pricing
            </a>
            <a
              href="https://twitter.com/UngratefulAI"
              className="hover:text-gray-300 transition-colors"
            >
              @UngratefulAI
            </a>
          </div>
          <div className="text-gray-600 text-xs">
            &copy; 2026 CLAWSCAN. MIT Licensed.
          </div>
        </div>
      </footer>
    </main>
  );
}