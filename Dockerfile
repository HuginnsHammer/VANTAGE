FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 vantage \
    && useradd --system --uid 10001 --gid vantage --home-dir /nonexistent vantage

COPY . .

RUN pip install --no-cache-dir ".[api,auth,postgres]" \
    && chown -R vantage:vantage /app

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "vantage.api.hosted:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
