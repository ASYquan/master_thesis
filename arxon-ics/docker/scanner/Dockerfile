FROM python:3.12-slim

RUN pip install --no-cache-dir pymodbus paho-mqtt aiocoap requests
RUN apt update && apt install -y --no-install-recommends \
    nmap mosquitto-clients \
    && apt clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m scanner
USER scanner
WORKDIR /scan

COPY scanner.py /scan/scanner.py
CMD ["python3", "/scan/scanner.py"]
