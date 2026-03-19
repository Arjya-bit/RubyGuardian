FROM docker.elastic.co/kibana/kibana:8.12.0

LABEL maintainer="RubyGuardian Team"
LABEL description="RubyGuardian Kibana with pre-built security dashboards"

# Copy configuration
COPY kibana.yml /usr/share/kibana/config/kibana.yml

# Copy dashboard exports for import on startup
COPY dashboards/ /usr/share/kibana/dashboards/

# Create log directory
USER root
RUN mkdir -p /usr/share/kibana/logs && \
    chown -R kibana:kibana /usr/share/kibana/logs

# Copy import script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Waiting for Kibana to be ready..."\n\
until curl -sf http://localhost:5601/api/status | grep -q "available"; do\n\
  sleep 5\n\
done\n\
echo "Kibana is ready. Importing dashboards..."\n\
for f in /usr/share/kibana/dashboards/*.ndjson; do\n\
  if [ -f "$f" ]; then\n\
    echo "Importing $(basename $f)..."\n\
    curl -sf -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \\\n\
      -H "kbn-xsrf: true" \\\n\
      --form file=@"$f" || echo "Warning: Failed to import $f"\n\
  fi\n\
done\n\
echo "Dashboard import complete."\n\
' > /usr/local/bin/import-dashboards.sh && \
    chmod +x /usr/local/bin/import-dashboards.sh

USER kibana

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=120s \
  CMD curl -sf http://localhost:5601/api/status | grep -q "available" || exit 1

EXPOSE 5601
