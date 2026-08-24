FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/fieldora-bastion
RUN apt-get update \
 && apt-get install -y --no-install-recommends clamav \
 && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml /opt/fieldora-bastion/
COPY src /opt/fieldora-bastion/src
RUN python -m pip install --no-cache-dir . \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin fieldora-bastion
USER 10001:10001
ENTRYPOINT ["fieldora-bastion"]
CMD ["--help"]
