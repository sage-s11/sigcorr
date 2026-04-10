FROM eclipse-temurin:21-jdk AS builder

RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q

COPY src/ src/
RUN mvn clean package -DskipTests -q

# --- Runtime ---
FROM eclipse-temurin:21-jre

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
