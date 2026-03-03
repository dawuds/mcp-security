FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV MCP_DB_PATH=/data/db.sqlite
RUN mkdir -p /data

# Run as non-root user
RUN useradd --no-create-home --shell /bin/false mcpuser
RUN chown mcpuser:mcpuser /data
USER mcpuser

VOLUME ["/data"]

# MCP servers communicate over stdio — no ports to expose
CMD ["python", "server.py"]
