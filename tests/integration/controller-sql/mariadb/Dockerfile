# MariaDB 13.1.2 GA is available as a binary tarball while the official image still ships 13.0.2.
FROM mariadb:13.0.2-resolute@sha256:54f493ea0d60b621a5bff84e5b20100f8b86b6efa6b79158e04756c5194a5e4d AS binaries
ADD --checksum=sha256:649ae1ea36f381cdcb8e11694637eca3106ec81ac4cd7e3c813d6192b2d6de38 https://archive.mariadb.org/mariadb-13.1.2/bintar-linux-systemd-x86_64/mariadb-13.1.2-linux-systemd-x86_64.tar.gz /tmp/mariadb.tar.gz
RUN mkdir /opt/mariadb && tar -xzf /tmp/mariadb.tar.gz -C /opt/mariadb --strip-components=1

FROM mariadb:13.0.2-resolute@sha256:54f493ea0d60b621a5bff84e5b20100f8b86b6efa6b79158e04756c5194a5e4d
COPY --from=binaries /opt/mariadb /opt/mariadb
ENV PATH="/opt/mariadb/bin:/opt/mariadb/scripts:${PATH}" MARIADB_VERSION="13.1.2"
RUN printf '[mariadbd]\nbasedir=/opt/mariadb\n' > /etc/mysql/mariadb.conf.d/99-fixture-basedir.cnf && \
    mariadbd --version && mariadb-dump --version
