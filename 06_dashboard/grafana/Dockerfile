FROM grafana/grafana:10.2.3

LABEL maintainer="RubyGuardian Team"
LABEL description="RubyGuardian Grafana with pre-provisioned dashboards and datasources"

# Copy configuration
COPY grafana.ini /etc/grafana/grafana.ini

# Copy provisioning files
COPY provisioning/datasources/ /etc/grafana/provisioning/datasources/
COPY provisioning/dashboards/ /etc/grafana/provisioning/dashboards/

# Install useful plugins
USER root
RUN grafana cli plugins install grafana-clock-panel && \
    grafana cli plugins install grafana-piechart-panel && \
    grafana cli plugins install grafana-worldmap-panel && \
    grafana cli plugins install marcusolsson-treemap-panel

# Create necessary directories
RUN mkdir -p /var/lib/grafana/dashboards && \
    chown -R grafana:root /var/lib/grafana && \
    chown -R grafana:root /etc/grafana

USER grafana

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=30s \
  CMD wget -qO- http://localhost:3000/api/health | grep -q '"database": "ok"' || exit 1

EXPOSE 3000
