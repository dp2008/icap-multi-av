FROM python:3.9-slim

RUN apt-get update && apt-get install -y git build-essential

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone Neo23x0 rules
RUN git clone https://github.com/Neo23x0/signature-base.git /rules

COPY . .

EXPOSE 8080

CMD ["python", "yara_service.py"]
