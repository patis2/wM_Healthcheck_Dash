FROM python:3.12-slim
RUN useradd --system --create-home --uid 10001 wmhub && mkdir -p /data && chown wmhub /data
WORKDIR /opt/wm-hub
COPY run_collector.py rules.json ./
COPY hub ./hub
COPY web ./web
USER wmhub
EXPOSE 8443
VOLUME /data
# Mount your collector.json (db_path: /data/hub.db) and certificates; secrets come in as environment variables.
# Inside a container set listen.host to 0.0.0.0 AND ui_auth.mode to basic: the collector refuses an anonymous
# dashboard on a non-loopback address. This image has not been built or run in the prototype environment.
CMD ["python", "run_collector.py", "--config", "/etc/wm-hub/collector.json"]
