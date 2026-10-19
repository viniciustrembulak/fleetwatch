FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -m -u 1000 fleetwatch

USER fleetwatch
ENTRYPOINT ["fleetwatch"]
CMD ["--help"]
