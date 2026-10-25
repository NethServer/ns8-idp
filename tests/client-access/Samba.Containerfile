FROM docker.io/library/debian:13-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba-ad-provision samba-ad-dc samba-dsdb-modules samba-vfs-modules winbind ldap-utils python3 && rm -rf /var/lib/apt/lists/*
COPY samba-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["bash", "/entrypoint.sh"]
