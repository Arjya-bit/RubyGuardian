FROM ruby:3.2-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test

COPY . .

RUN cd agent/native_extensions/ebpf_bridge && ruby extconf.rb && make
RUN cd agent/native_extensions/ptrace_helper && ruby extconf.rb && make

USER nobody
ENTRYPOINT ["ruby", "agent/ruby_guardian_agent.rb"]
CMD ["--config", "config/detection_config.yml"]
