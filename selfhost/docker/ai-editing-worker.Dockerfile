# The AI editing worker for the self-host `ai` profile: docker/ai-editing-worker.Dockerfile
# with the sources baked in instead of bind-mounted from a checkout.
FROM node:22-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g bun
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile
WORKDIR /app/services/ai-editing-worker
RUN bun scripts/generate-sandbox.ts
EXPOSE 8933
CMD ["sh", "-c", "\
  printf 'OPENAI_API_KEY=%s\\nANTHROPIC_API_KEY=%s\\nCEREBRAS_API_KEY=%s\\n' \
    \"${OPENAI_API_KEY:-}\" \"${ANTHROPIC_API_KEY:-}\" \"${CEREBRAS_API_KEY:-}\" > .dev.vars \
  && exec npx wrangler dev --env local --ip 0.0.0.0 \
    --var SYNC_WS_BASE:ws://sync-service:8787 \
    --var CANVAS_RENDER_URL:${MACRO_PUBLIC_URL}/app/canvas-render.html \
    --var OTEL_EXPORTER_OTLP_ENDPOINT:${MACRO_OTEL_HTTP_ENDPOINT:+${MACRO_OTEL_HTTP_ENDPOINT}/v1/traces}"]
