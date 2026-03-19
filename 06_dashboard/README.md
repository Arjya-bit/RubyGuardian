# RubyGuardian Phase 6 - Dashboard & Visualization

## Overview

Phase 6 provides comprehensive monitoring, visualization, and management capabilities for the RubyGuardian security platform. It integrates an ELK Stack for log aggregation and search, Grafana for metrics visualization, and a React-based web UI for real-time threat management.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      React Web UI (Vite + Tailwind)             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │ Dashboard │ │Classifier│ │Forensics │ │ Honeypot Intel     │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘ │
└──────────────────────┬──────────────────────────────────────────┘
                       │ REST / WebSocket
┌──────────────────────▼──────────────────────────────────────────┐
│                    Backend API (Phase 1-5)                       │
└──────────┬───────────────────────┬──────────────────────────────┘
           │                       │
┌──────────▼──────────┐ ┌─────────▼─────────┐
│     ELK Stack       │ │     Grafana        │
│ ┌─────────────────┐ │ │ ┌───────────────┐  │
│ │  Elasticsearch   │ │ │ │  Dashboards   │  │
│ │  (Data Store)    │◄├─┤ │  (Metrics)    │  │
│ ├─────────────────┤ │ │ └───────────────┘  │
│ │  Logstash        │ │ └───────────────────┘
│ │  (Ingestion)     │ │
│ ├─────────────────┤ │
│ │  Kibana          │ │
│ │  (Exploration)   │ │
│ └─────────────────┘ │
└─────────────────────┘
```

## Components

### ELK Stack (`elk_stack/`)

- **Elasticsearch**: Stores and indexes all RubyGuardian events, honeypot captures, forensic reports, and ML classifications. Configured with custom index templates and mappings optimized for security event data.
- **Logstash**: Ingests data from multiple sources (agents, honeypots, forensic collectors) with enrichment and normalization pipelines.
- **Kibana**: Pre-built dashboards for threat overview, process hollowing detection, CI/CD poisoning, LOLRuby activity, ObjectSpace anomalies, honeypot intelligence, ML classifications, and forensic timelines.

### Grafana (`grafana/`)

- System health monitoring
- Agent performance metrics
- Attack metrics and trends
- Auto-provisioned datasources connected to Elasticsearch

### React Web UI (`web_ui/`)

A modern single-page application built with:
- **Vite** for fast development and optimized builds
- **React 18** with functional components and hooks
- **Tailwind CSS** for utility-first styling
- **Recharts** for interactive charts
- **WebSocket** support for real-time event streaming

#### Features
- **Threat Overview Dashboard**: Live threat scores, attack timelines, geographic threat maps
- **Live Process Table**: Real-time view of monitored Ruby processes
- **ML Classifier Interface**: Upload and classify suspicious code samples
- **Forensic Analysis**: Memory dump viewer, ObjectSpace inspector, forensic reports
- **Honeypot Intelligence**: Captured samples, attack patterns, source IP analysis

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for local web UI development)

### Running with Docker Compose

```bash
# From the project root
docker-compose -f 06_dashboard/docker-compose.yml up -d

# Access services:
# - Kibana:        http://localhost:5601
# - Grafana:       http://localhost:3000  (admin/RubyGuardian2024!)
# - React Web UI:  http://localhost:5173
# - Elasticsearch: http://localhost:9200
```

### Local Web UI Development

```bash
cd 06_dashboard/web_ui
npm install
npm run dev
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_HOST` | `elasticsearch` | Elasticsearch hostname |
| `ELASTICSEARCH_PORT` | `9200` | Elasticsearch port |
| `KIBANA_HOST` | `kibana` | Kibana hostname |
| `KIBANA_PORT` | `5601` | Kibana port |
| `GRAFANA_ADMIN_PASSWORD` | `RubyGuardian2024!` | Grafana admin password |
| `VITE_API_BASE_URL` | `http://localhost:4000/api` | Backend API URL |
| `VITE_WS_URL` | `ws://localhost:4000/ws` | WebSocket URL |
| `VITE_ES_URL` | `http://localhost:9200` | Elasticsearch URL |

## Index Templates

| Template | Pattern | Description |
|----------|---------|-------------|
| `ruby_guardian_events` | `rg-events-*` | Agent-reported security events |
| `honeypot_captures` | `rg-honeypot-*` | Honeypot interaction captures |
| `forensic_reports` | `rg-forensic-*` | Memory and ObjectSpace forensic reports |
| `ml_classifications` | `rg-ml-*` | ML model classification results |

## License

Part of the RubyGuardian security platform.
