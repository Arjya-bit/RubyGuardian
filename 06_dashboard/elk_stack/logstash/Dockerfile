FROM docker.elastic.co/logstash/logstash:8.12.0

LABEL maintainer="RubyGuardian Team"
LABEL description="RubyGuardian Logstash pipeline for ingesting detection events, forensic reports, and honeypot captures"

# Remove default pipeline configuration
RUN rm -f /usr/share/logstash/pipeline/logstash.conf

# Copy custom pipeline configurations
COPY pipeline/ /usr/share/logstash/pipeline/
COPY pipelines.yml /usr/share/logstash/config/pipelines.yml
COPY logstash.yml /usr/share/logstash/config/logstash.yml

# Install required plugins for enrichment and GeoIP
RUN logstash-plugin install logstash-filter-translate && \
    logstash-plugin install logstash-filter-fingerprint && \
    logstash-plugin install logstash-filter-threats_classifier && \
    logstash-plugin install logstash-output-elasticsearch

# Copy GeoIP database for threat geolocation
COPY --chown=logstash:logstash geoip/ /usr/share/logstash/geoip/

# Copy lookup tables for MITRE ATT&CK enrichment
COPY --chown=logstash:logstash lookups/ /usr/share/logstash/lookups/

# Create persistent queue directory for reliability
USER root
RUN mkdir -p /usr/share/logstash/data/queue \
             /usr/share/logstash/data/dead_letter_queue \
             /usr/share/logstash/logs && \
    chown -R logstash:logstash /usr/share/logstash/data /usr/share/logstash/logs
USER logstash

# Health check - verify Logstash API is responding
HEALTHCHECK --interval=30s --timeout=15s --retries=5 --start-period=90s \
  CMD curl -sf http://localhost:9600/_node/stats/pipelines || exit 1

# Expose Logstash API and Beats input ports
EXPOSE 9600 5044 5045 5046

# JVM tuning for container environment
ENV LS_JAVA_OPTS="-Xms512m -Xmx512m"
ENV PIPELINE_WORKERS="2"
ENV PIPELINE_BATCH_SIZE="250"
ENV PIPELINE_BATCH_DELAY="50"

# Enable persistent queues for at-least-once delivery
ENV QUEUE_TYPE="persisted"
ENV QUEUE_MAX_BYTES="1gb"
ENV QUEUE_CHECKPOINT_WRITES="1024"
