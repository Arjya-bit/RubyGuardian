-- =============================================================================
-- RubyGuardian - SQLite Schema for Simulated C2 Server
-- =============================================================================
--
-- EDUCATIONAL DISCLAIMER:
--   This schema defines the database structure for the simulated C2 server.
--   It stores metadata about simulated agent connections and exfiltration
--   attempts for research analysis. NO actual stolen data is stored.
--
-- MITRE ATT&CK References:
--   - T1041     : Exfiltration Over C2 Channel (exfil_records table)
--   - T1071.001 : Application Layer Protocol: Web Protocols (agents table)
--   - T1082     : System Information Discovery (agent system info)
--
-- Usage:
--   sqlite3 c2_simulation.db < schema.sql
-- =============================================================================

-- Enable WAL mode for better concurrent read performance during simulations
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- =============================================================================
-- Table: agents
-- =============================================================================
-- Tracks simulated compromised CI runners that register with the C2 server.
-- Each row represents a unique agent session. In real CI/CD attacks, these
-- would be build workers compromised through supply chain vectors.
CREATE TABLE IF NOT EXISTS agents (
    -- Primary key: internal auto-incrementing ID
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Unique agent identifier assigned at registration (UUID format)
    agent_id    TEXT    NOT NULL UNIQUE,

    -- Hostname reported by the agent during registration
    -- In CI/CD attacks, this reveals the runner's identity (e.g., "runner-abc123")
    hostname    TEXT    NOT NULL DEFAULT 'unknown',

    -- Source IP address from the registration request
    ip          TEXT    NOT NULL DEFAULT '0.0.0.0',

    -- Operating system and platform info reported by the agent
    os_info     TEXT    DEFAULT NULL,

    -- CI platform identifier (github_actions, gitlab_ci, jenkins, etc.)
    ci_platform TEXT    DEFAULT NULL,

    -- Timestamp of initial agent registration
    first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Timestamp of most recent heartbeat
    last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Agent connection status: 'active', 'stale', 'disconnected'
    status      TEXT    NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'stale', 'disconnected')),

    -- Simulation metadata
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Index for fast lookup by agent_id (used in heartbeat and command routes)
CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);

-- Index for filtering by status (used in dashboard queries)
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

-- Index for time-based queries (session analysis)
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

-- =============================================================================
-- Table: exfil_records
-- =============================================================================
-- Logs metadata about simulated exfiltration attempts. The actual payload
-- content is NEVER stored; only metadata is retained for analysis.
-- This mirrors how defenders analyze C2 traffic patterns.
CREATE TABLE IF NOT EXISTS exfil_records (
    -- Primary key: internal auto-incrementing ID
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Unique record identifier (UUID format)
    record_id   TEXT    NOT NULL UNIQUE,

    -- Foreign key reference to the agent that sent the data
    agent_id    TEXT    NOT NULL,

    -- Category of exfiltrated data:
    --   env_vars, ssh_keys, api_tokens, cloud_credentials,
    --   source_code, build_artifacts, docker_config, kubeconfig,
    --   npm_tokens, gem_credentials, unknown
    data_type   TEXT    NOT NULL DEFAULT 'unknown',

    -- Origin within the CI environment:
    --   ci_pipeline, build_environment, artifact_store,
    --   secret_manager, config_files, container_runtime, unknown
    source      TEXT    NOT NULL DEFAULT 'unknown',

    -- Size of the exfiltration payload in bytes
    -- NOTE: This is the reported size; no payload data is actually stored
    size        INTEGER NOT NULL DEFAULT 0,

    -- Assessed severity level: critical, high, medium, low
    severity    TEXT    DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low')),

    -- Comma-separated MITRE ATT&CK technique IDs
    mitre_refs  TEXT    DEFAULT NULL,

    -- Timestamp when the exfiltration was received
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Simulation metadata
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Foreign key constraint linking to agents table
    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        ON DELETE CASCADE
);

-- Index for filtering by agent (show all exfil from a specific runner)
CREATE INDEX IF NOT EXISTS idx_exfil_agent_id ON exfil_records(agent_id);

-- Index for filtering by data type (analyze what types of data are targeted)
CREATE INDEX IF NOT EXISTS idx_exfil_data_type ON exfil_records(data_type);

-- Index for severity-based queries (prioritize critical findings)
CREATE INDEX IF NOT EXISTS idx_exfil_severity ON exfil_records(severity);

-- Index for time-range queries (timeline analysis)
CREATE INDEX IF NOT EXISTS idx_exfil_timestamp ON exfil_records(timestamp);

-- =============================================================================
-- Table: command_log
-- =============================================================================
-- Records all commands queued for agents. In a real C2, these would be
-- shell commands or directives. Here they are logged for research analysis.
CREATE TABLE IF NOT EXISTS command_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id  TEXT    NOT NULL UNIQUE,
    agent_id    TEXT    NOT NULL,
    command     TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'delivered', 'acknowledged', 'expired')),
    queued_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    delivered_at TEXT   DEFAULT NULL,

    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cmdlog_agent_id ON command_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_cmdlog_status ON command_log(status);

-- =============================================================================
-- View: simulation_summary
-- =============================================================================
-- Convenience view for the research dashboard showing a quick overview
-- of the simulation state.
CREATE VIEW IF NOT EXISTS simulation_summary AS
SELECT
    (SELECT COUNT(*) FROM agents) AS total_agents,
    (SELECT COUNT(*) FROM agents WHERE status = 'active') AS active_agents,
    (SELECT COUNT(*) FROM exfil_records) AS total_exfil_records,
    (SELECT COALESCE(SUM(size), 0) FROM exfil_records) AS total_exfil_bytes,
    (SELECT COUNT(*) FROM exfil_records WHERE severity = 'critical') AS critical_findings,
    (SELECT COUNT(*) FROM command_log) AS total_commands;
