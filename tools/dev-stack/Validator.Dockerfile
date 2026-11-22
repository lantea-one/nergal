# Independent, check-only native validation in a container network namespace.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables python3 \
    && rm -rf /var/lib/apt/lists/*
COPY validate-source.py /usr/local/bin/validate-source.py
ENTRYPOINT ["python3", "/usr/local/bin/validate-source.py"]
