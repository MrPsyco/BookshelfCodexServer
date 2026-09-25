FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# rclone for cloud storage backends; curl + ca-certs for build-time fetch;
# fuse3 for in-container FUSE mounts.
RUN apt-get update && apt-get install -y --no-install-recommends \
        rclone \
        curl \
        ca-certificates \
        fuse3 \
        fuse \
    && rm -rf /var/lib/apt/lists/*

# Tailwind standalone CLI (offline-friendly, no Node, no CDN at runtime).
# Downloaded at build time so we don't bloat the repo with a 42 MB binary.
ARG TAILWIND_VERSION=3.4.17
RUN curl -fsSL -o /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-x64" \
    && chmod +x /usr/local/bin/tailwindcss

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Build minified Tailwind CSS from static/index.html into static/dist/tailwind.css
RUN mkdir -p static/dist \
    && echo '@tailwind base;\n@tailwind components;\n@tailwind utilities;' \
       | tailwindcss \
           -c tailwind.config.js \
           -i - \
           -o static/dist/tailwind.css \
           --minify \
    && ls -la static/dist/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
