FROM docker.elastic.co/elasticsearch/elasticsearch:8.12.0

LABEL maintainer="RubyGuardian Team"
LABEL description="RubyGuardian Elasticsearch node with custom index templates"

# Copy configuration
COPY elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml

# Copy index templates
COPY index_templates/ /usr/share/elasticsearch/config/index_templates/

# Install analysis plugins
RUN elasticsearch-plugin install --batch analysis-icu

# Create data and log directories with correct permissions
USER root
RUN mkdir -p /usr/share/elasticsearch/data /usr/share/elasticsearch/logs && \
    chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/data /usr/share/elasticsearch/logs
USER elasticsearch

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=60s \
  CMD curl -sf http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=10s || exit 1

# Expose ports
EXPOSE 9200 9300

# Set JVM options for container environment
ENV ES_JAVA_OPTS="-Xms1g -Xmx1g"
ENV ELASTIC_PASSWORD="changeme"
