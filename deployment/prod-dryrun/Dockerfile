# Dry-run image for docs/L2-PRODUCTION-DEPLOY.md (agent 385, round 18). Rehearsal only: it stands in for a fresh
# Ubuntu 24.04 host (A = 136.244.93.186 roles, B = the second follower / replica RPC host). Containers run with
# systemd as PID 1 and `--network none`: nothing in them can reach a public network or another host.
# The base is the local ubuntu:24.04 image; harness.sh records its image ID and `dpkg -l` with every run.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus python3 sudo openssh-server openssh-client \
      curl ca-certificates nginx libnginx-mod-http-js openssl gnupg iproute2 ufw xz-utils less \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system docker \
 && ssh-keygen -A \
 && systemctl mask getty@tty1.service console-getty.service systemd-logind.service || true
# The prover installer runs `docker image inspect <pinned gnark image>`. There is no Docker daemon in a
# dry-run container: this shim answers that one call for the pinned digest only and refuses everything else.
COPY docker-shim-inspect.sh /usr/local/bin/docker
RUN chmod 0755 /usr/local/bin/docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
