# One image recipe for all six services: docker compose passes SERVICE=auth|ballot|...
FROM python:3.12-slim

ARG SERVICE
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY shared /tmp/shared
RUN pip install /tmp/shared && rm -rf /tmp/shared

WORKDIR /srv
COPY services/${SERVICE}/app /srv/app

USER app
CMD ["python", "-m", "common.run"]
