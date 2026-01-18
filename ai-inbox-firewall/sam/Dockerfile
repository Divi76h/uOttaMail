FROM solace/solace-agent-mesh:latest

# Ensure the SAM CLI is always discoverable
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh

# No chmod needed, we run it with sh
ENTRYPOINT ["/bin/sh", "-c", "sh /app/entrypoint.sh"]

