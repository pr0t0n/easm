FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx

COPY socks5_stub.py stub_agent.py ./

CMD ["python3", "stub_agent.py"]
