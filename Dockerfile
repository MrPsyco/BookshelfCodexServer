FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# rclone for cloud storage backends; curl + ca-certs for build-time fetch
RUN apt-get update && apt-get install -y --no-install-recommends \
        rclone \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Tailwind standalone CLI (offline-friendly, no Node, no CDN at runtime)
# Build the CSS once during image build so the browser never hits a CDN.
COPY tailwindcss /usr/local/bin/tailwindcss
RUN chmod +x /usr/local/bin/tailwindcss

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
