# Dockerfile with security issues
FROM python:3.7-slim  # Outdated Python version

# Security issue: running as root
USER root

# Security issue: installing packages without pinned versions
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Security issue: copying all files (including secrets)
COPY . /app

WORKDIR /app

# Security issue: installing as root and not pinning versions
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Security issue: exposing on all interfaces
EXPOSE 5000

# Security issue: hardcoded environment variables
ENV FLASK_APP=src/webapp/app.py
ENV FLASK_ENV=development
ENV SECRET_KEY=hardcoded-docker-secret
ENV DATABASE_URL=sqlite:///app.db

# Security issue: running as root user
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]