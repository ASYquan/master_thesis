FROM kalilinux/kali-rolling

# Install only required tools
RUN apt update && apt install -y --no-install-recommends \
    nmap \
    metasploit-framework \
    python3 python3-pip python3-pymodbus \
    mosquitto-clients \
    binwalk \
    impacket-scripts \
    curl wget \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Non-root user for execution
RUN useradd -m -s /bin/bash executor
USER executor
WORKDIR /workspace

# Default: drop to shell
CMD ["/bin/bash"]
