FROM python:3.9-slim

RUN apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Update virus definitions
RUN mkdir -p /var/lib/clamav && \
    freshclam --quiet || true

EXPOSE 8080

CMD ["python", "clamav_service.py"]
