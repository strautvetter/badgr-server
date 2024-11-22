# Best practies taken from here: https://snyk.io/blog/best-practices-containerizing-python-docker/

# ------------------------------> Build image
FROM python:3.8.14-slim-buster as build
RUN apt-get clean all && apt-get update
RUN apt-get install -y default-libmysqlclient-dev \
                       python3-dev \
                       python3-cairo \
                       build-essential \
                       xmlsec1 \
                       libxmlsec1-dev \
                       pkg-config \
                       curl

RUN mkdir /badgr_server
WORKDIR /badgr_server
RUN python -m venv /badgr_server/venv
ENV PATH="/badgr_server/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

# ------------------------------> Final image
FROM python:3.8.14-slim-buster
RUN apt-get update
RUN apt-get install -y default-libmysqlclient-dev \
                       python3-cairo \
                       libxml2 \
                       git \
                       curl

RUN groupadd -g 999 python && \
    useradd -r -u 999 -g python python

RUN mkdir /badgr_server && chown python:python /badgr_server
RUN touch /badgr_server/user_emails.csv && chown python:python /badgr_server/user_emails.csv
RUN touch /badgr_server/esco_issuers.txt && chown python:python /badgr_server/esco_issuers.txt  

WORKDIR /badgr_server

# Copy installed dependencies
COPY --chown=python:python --from=build /badgr_server/venv /badgr_server/venv

# Copy everything related Django stuff
COPY --chown=python:python  manage.py                          .
COPY --chown=python:python  .docker/etc/uwsgi.ini              .
COPY --chown=python:python  .docker/etc/wsgi.py                .
COPY --chown=python:python  apps                               ./apps
COPY --chown=python:python  .git                               ./.git
COPY --chown=python:python  .docker/etc/settings_local.py      ./apps/mainsite/settings_local.py
COPY --chown=python:python  entrypoint.sh                      .
COPY --chown=python:python  crontab                             /etc/cron.d/crontab

RUN chmod +x entrypoint.sh

RUN touch /var/log/cron_cleartokens.log && \
    chown python:python /var/log/cron_cleartokens.log && \
    chmod 644 /var/log/cron_cleartokens.log


# Latest releases available at https://github.com/aptible/supercronic/releases
ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.30/supercronic-linux-amd64 \
    SUPERCRONIC=supercronic-linux-amd64 \
    SUPERCRONIC_SHA1SUM=9f27ad28c5c57cd133325b2a66bba69ba2235799

RUN curl -fsSLO "$SUPERCRONIC_URL" \
 && echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - \
 && chmod +x "$SUPERCRONIC" \
 && mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" \
 && ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic

USER 999

ENV PATH="/badgr_server/venv/bin:$PATH"
ENTRYPOINT ["./entrypoint.sh"]
