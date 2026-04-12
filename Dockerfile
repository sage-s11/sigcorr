# SigCorr - Multi-Architecture Dockerfile
# Supports: linux/amd64, linux/arm64
#
# Single-arch (as before):
#   docker build -t sigcorr .
#
# Multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/sage-s11/sigcorr:latest --push .

# --- Build (runs on host arch for speed via BUILDPLATFORM) ---
FROM --platform=$BUILDPLATFORM eclipse-temurin:21-jdk AS builder

RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src/ src/
RUN mvn clean package -DskipTests -q

# --- Runtime (built for each TARGETPLATFORM) ---
FROM eclipse-temurin:21-jre

LABEL org.opencontainers.image.source="https://github.com/sage-s11/sigcorr"
LABEL org.opencontainers.image.description="Passive Cross-Protocol Attack Detection for Mobile Core Networks"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark python3 python3-scapy && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /sigcorr
COPY --from=builder /build/target/sigcorr-0.1.0-all.jar sigcorr.jar
COPY sigcorr-config.yaml .
COPY test-pcaps/ test-pcaps/
COPY test.sh .
RUN mkdir -p /data /sigcorr/evidence

ENTRYPOINT ["java", "-jar", "sigcorr.jar"]
CMD ["--help"]
