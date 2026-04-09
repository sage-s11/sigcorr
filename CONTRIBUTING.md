# Contributing to SigCorr

Thanks for considering contributing to SigCorr! This project aims to make telecom signaling security accessible to researchers, operators, and security professionals.

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/sage-s11/sigcorr/issues) with:

- SigCorr version (`java -jar target/sigcorr-0.1.0.jar --version`)
- Java version (`java --version`)
- tshark version (`tshark --version`)
- Steps to reproduce
- Expected vs actual behavior
- If possible, a (sanitized) pcap that triggers the bug

**Important:** Never include real subscriber data (IMSI, MSISDN) in bug reports. Use the test pcap generators to create synthetic samples.

### Suggesting New Attack Patterns

If you've identified a signaling attack chain not covered by SigCorr's current 22 patterns, open an issue tagged `new-pattern` with:

- A description of the attack sequence
- Which protocols are involved (SS7/MAP, Diameter S6a, GTPv2-C)
- Reference (3GPP spec, GSMA guideline, research paper, or CVE)
- If possible, a pcap generator script

### Code Contributions

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/sigcorr.git`
3. **Create a branch**: `git checkout -b feature/your-feature`
4. **Make your changes**
5. **Run tests**: `./test.sh` — all tests must pass
6. **Commit** with a clear message: `git commit -m 'Add ATK-022: GTP tunnel hijack pattern'`
7. **Push**: `git push origin feature/your-feature`
8. **Open a Pull Request** against `main`

### What We're Looking For

- New attack pattern detections (especially cross-protocol chains)
- Support for additional protocols (SIP, SCTP, GTP-U)
- Performance improvements for large pcap analysis
- Documentation improvements
- Test coverage for edge cases and encoding variations

### Code Style

- Java 17+ features are welcome
- Follow the existing package structure (`core/`, `ingest/`, `correlation/`, `detection/`)
- New attack patterns should include a corresponding test pcap generator in `test-pcaps/`
- Keep detection logic in `detection/` — don't mix it into parsers

## Development Setup

```bash
# Prerequisites
java --version   # 17+
mvn --version    # 3.8+
tshark --version # 3.6+

# Build
mvn clean package -DskipTests

# Run tests
./test.sh

# Run a single analysis
java -jar target/sigcorr-0.1.0.jar analyze test-pcaps/attack-samples/your_test.pcap
```

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license, consistent with the rest of the project.

## Questions?

Open an issue or reach out to [@sage-s11](https://github.com/sage-s11).
