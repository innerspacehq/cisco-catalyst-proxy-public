FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --shell /usr/sbin/nologin proxyuser

COPY proto/ proto/
COPY proxy/ proxy/
COPY proxy_main.py .
COPY configs/ configs/

# WLC-facing gRPC port
EXPOSE 57000

USER proxyuser

ENTRYPOINT ["python", "proxy_main.py"]
CMD ["--config", "configs/production.yml"]
