FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# MCP_ALLOWED_DOMAINS should be set at runtime via environment variable,
# e.g.: docker run -e MCP_ALLOWED_DOMAINS=api.example.com ...

# Run as non-root user
RUN useradd --no-create-home --shell /bin/false mcpuser
USER mcpuser

# MCP servers communicate over stdio — no ports to expose
CMD ["python", "server.py"]
