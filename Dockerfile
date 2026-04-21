FROM golang:1.23-bookworm AS vbuilder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
ENV GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py db.py vulnx_scanner.py app.py ./
COPY templates ./templates
COPY static ./static

COPY --from=vbuilder /go/bin/vulnx /usr/local/bin/vulnx

ENV DATA_DIR=/data
VOLUME /data
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
