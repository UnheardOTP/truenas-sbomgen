# TrueNAS SBOM Generator
# Build args pin tool versions; leave empty to take the latest releases at build time.
FROM debian:bookworm-slim AS tools
ARG SYFT_VERSION=""
ARG GRYPE_VERSION=""
# Changes on each CI build so "latest" is re-resolved instead of served from the layer cache
ARG TOOLS_DATE=""
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY fetch-tools.sh /fetch-tools.sh
RUN echo "tools build $TOOLS_DATE" && sh /fetch-tools.sh

FROM python:3.13-slim
LABEL org.opencontainers.image.title="truenas-sbomgen" \
      org.opencontainers.image.description="Scheduled SBOMs and vulnerability reports for TrueNAS hosts and apps"
COPY --from=tools /out/syft /out/grype /usr/local/bin/
COPY --from=tools /out/VERSIONS /etc/sbomgen-tool-versions
COPY app/ /app/
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app \
    SYFT_CHECK_FOR_APP_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false \
    DATA_DIR=/data HOST_ROOT=/host PORT=8099 \
    XDG_CACHE_HOME=/data/.cache HOME=/data
EXPOSE 8099
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz',timeout=4)"
CMD ["python", "-m", "sbomgen"]
