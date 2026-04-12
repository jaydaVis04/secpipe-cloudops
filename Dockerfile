FROM python:3.11-slim

WORKDIR /app

# Keep the container setup simple and aligned with the local package install flow.
COPY pyproject.toml README.md ./
COPY secpipe ./secpipe
COPY cloud ./cloud
COPY docs ./docs
COPY samples ./samples
COPY config.yaml.example ./

RUN pip install --no-cache-dir .
RUN mkdir -p output

ENTRYPOINT ["python", "-m", "secpipe.cli"]
CMD ["--help"]
