# SASTify Docker Image
# Multi-stage build for optimal image size

# ============ Build Stage ============
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY Backend/Requirements.txt .
RUN pip install --no-cache-dir --user -r Requirements.txt

# ============ Production Stage ============
FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd --create-home --shell /bin/bash sastify

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/sastify/.local

# Copy application code
COPY Backend/ /app/Backend/
COPY Frontend/ /app/Frontend/
COPY action.yml /app/

# Set environment variables
ENV PATH=/home/sastify/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Create data directory for SQLite
RUN mkdir -p /app/data && chown -R sastify:sastify /app

# Switch to non-root user
USER sastify

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command - API server
CMD ["python", "-m", "uvicorn", "Backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Alternative: CLI mode
# docker run sastify python -m Backend.cli scan /code --format sarif
