FROM python:3.11-slim

WORKDIR /app

# Install deps first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY templates/ ./templates/
COPY static/ ./static/
COPY workers/ ./workers/

# Default data directory — Railway should mount a Volume here
RUN mkdir -p /data
ENV DB_PATH=/data/settlements.db

# Honor Railway's $PORT; default 8080 for local docker run
ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 60 --access-logfile - --error-logfile -"]
