# Agent Jail

### Don't kill the agent. Jail the threat.

Agent Jail is a runtime security and containment layer for AI agents that detects and contains indirect prompt injection attacks before untrusted content can influence sensitive agent actions.

External content such as emails, documents, webpages, and retrieved data is treated as untrusted by default. Agent Jail combines taint tracking, provenance, Moss semantic threat intelligence, Gemini intent analysis, and a deterministic policy engine to decide whether content should be allowed, quarantined, or blocked.

## Architecture

```text
External / Untrusted Content
            |
            v
    Taint + Provenance
            |
       +----+----+
       |         |
       v         v
     Moss      Gemini
   Semantic     Intent &
   Threat       Context
   Retrieval    Analysis
       |         |
       +----+----+
            |
            v
   Deterministic Policy
        Engine
            |
     +------+------+ 
     |      |      |
     v      v      v
  ALLOW  QUARANTINE BLOCK
     |      |      |
     v      v      v
   Agent  Vault   Tool
                  Execution
                  Prevented
Observability & Dashboard
Agent Jail
    |
    +---- OpenTelemetry → Traces & Security Telemetry
    |
    +---- LiveKit → Real-time Security Events
                    |
                    v
              Next.js Dashboard
How It Works
Taint & Provenance
External content is marked untrusted and associated with its source and provenance.
Moss Semantic Threat Detection
Moss performs semantic similarity search against the agent-jail-threats-v2 threat intelligence index and returns relevant threat patterns.
Gemini Intent Analysis
Gemini analyzes whether the content is attempting to address or manipulate an AI agent, request privileged actions, access sensitive data, or override instructions.
Deterministic Policy Engine
Moss and Gemini provide security evidence. The final decision is made by a deterministic policy engine rather than by an LLM.
Containment
ALLOW: content can proceed to the agent.
QUARANTINE: suspicious content is isolated in the Quarantine Vault.
BLOCK: the requested action is prevented and the content is isolated.

Observability
OpenTelemetry provides correlated traces across email ingestion, Moss scanning, Gemini analysis, policy evaluation, and quarantine operations.

Key Features
Indirect prompt injection detection
Taint and provenance tracking
Semantic threat intelligence with Moss
LLM-based intent and context analysis
Deterministic security policy enforcement
Quarantine Vault for isolated content
Tool/action interception
Gmail integration
LiveKit real-time security events
Next.js security dashboard
OpenTelemetry tracing
Local Gemini result caching for reliable demo replay

Technology Stack
Component	Technology
Threat Intelligence	:Moss
Intent Analysis	:Gemini
Agent / LLM	Groq
Agent Framework	:LangChain
Email Source	:Gmail API
Real-time Events	:LiveKit
Dashboard	:Next.js, TypeScript, Tailwind CSS
Observability	:OpenTelemetry
Language	:Python

Demo
Agent Jail was tested against a controlled set of five Gmail messages containing benign, ambiguous, and indirect prompt-injection scenarios.

Scenario	Decision	Risk
PO Reconciliation	BLOCK	CRITICAL
Security Awareness	QUARANTINE	HIGH
Q3 Vendor Reconciliation	BLOCK	CRITICAL
Invoice Verification	BLOCK	CRITICAL
September Invoice	ALLOW	LOW

The benign invoice was allowed through to the agent while the other four messages were contained.

Moss semantic retrieval produced low-latency results, with approximately 11 ms observed in a standalone security scan.

Testing

The project includes unit tests covering:

Policy decisions
Taint tracking
Security context
Threat parsing
Quarantine behavior
Security pipeline
Intent analysis

Current test status:

21 passed
Project Structure
agent-jail/
├── agent.py
├── security_scan.py
├── intent_analysis.py
├── policy.py
├── taint.py
├── quarantine.py
├── email_tools.py
├── telemetry.py
├── threat_patterns.json
├── threat_patterns_v2.json
├── tests/
└── dashboard/
    └── app/
Production Hardening

The current implementation focuses on the core runtime security pipeline. For production deployment, additional infrastructure would include:

API Gateway
JWT/OAuth2 authentication
Rate limiting
TLS 1.3
AES-256 encryption
Structured prompt templates
Formal functional/non-functional requirements and traceability
Production telemetry backend

These are deployment hardening requirements rather than claims about the current prototype.

Security Principle

External content is data, not instructions.

Agent Jail creates a security boundary between what an agent reads and what an agent is allowed to do.

Detect. Contain. Continue.

AI-Assisted Development

AI tools were used throughout the development process as development and research assistants.

They were used for:
- Exploring and validating security architecture ideas
- Researching prompt injection and agent security concepts
- Generating and refining implementation approaches
- Debugging Python, LangChain, Gmail, LiveKit, and Next.js integration issues
- Writing and improving unit tests
- Reviewing code and identifying potential edge cases
- Refining documentation, architecture diagrams, and the demo presentation

The system architecture, security model, threat corpus, policy logic, integrations, testing, and final implementation were reviewed, adapted, and validated as part of the development process.

AI was used as a development aid; security decisions at runtime are enforced by Agent Jail's deterministic policy engine rather than delegated to an LLM.
