FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV MCP_WORKSPACE_DIR=/workspace
RUN mkdir -p /workspace

# Run as non-root user
RUN useradd --no-create-home --shell /bin/false mcpuser
RUN chown mcpuser:mcpuser /workspace
USER mcpuser

VOLUME ["/workspace"]

# MCP servers communicate over stdio — no ports to expose
CMD ["python", "server.py"]
