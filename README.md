# Agent Jail

### Runtime Security and Containment Layer for AI Agents

Agent Jail is a runtime security layer for AI agents designed to detect and contain indirect prompt injection attacks before untrusted content can influence sensitive agent actions.

The system treats external content such as emails, webpages, documents, and retrieved data as untrusted by default. It tracks taint and provenance, uses Moss for semantic threat intelligence retrieval, evaluates security policies, and quarantines malicious content before it reaches the agent.

## Core Idea

AI agents increasingly interact with external data that cannot be fully trusted.

A malicious instruction hidden inside an email or webpage can attempt to manipulate an agent into performing actions such as sending emails, forwarding information, modifying files, or calling external APIs.

Agent Jail introduces a security boundary between external content and agent actions.

```text
External Content
       |
       v
Taint and Provenance
       |
       v
Moss Semantic Threat Intelligence
       |
       v
Threat Evidence
       |
       v
Risk and Policy Engine
       |
       +------> ALLOW ------> Agent
       |
       +------> QUARANTINE -> Quarantine Vault
       |
       +------> BLOCK ------> Tool Execution Prevented
