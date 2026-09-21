#!/bin/sh
# Authoritative BIND for the devcontainer sidecar. Mirrors examples/docker-compose.yaml
# so Start All Tasks can AXFR the demo pack from hostname "bind".
set -e
mkdir -p /var/lib/bind/keys
cp /etc/bind/zones-source/* /var/lib/bind/
chmod 664 /var/lib/bind/db.*
echo 'also-notify { };' > /var/lib/bind/also-notify.conf

cat > /var/lib/bind/rndc-internal.conf <<'EOF'
key "rndc-key" {
    algorithm hmac-sha256;
    secret "xT7J2kLpN9qRvW4mY8sF1gH5bC3dE6aZ0iO7uP2wX4c=";
};
options {
    default-key "rndc-key";
    default-server 127.0.0.1;
    default-port 953;
};
EOF

chown -R bind:bind /var/lib/bind

(
  api_host=dev
  i=0
  while [ "$i" -lt 60 ]; do
    set -- $(getent hosts "$api_host" 2>/dev/null || true)
    if [ -n "$1" ]; then
      echo "also-notify { $1 port 5354; };" > /var/lib/bind/also-notify.conf
      chown bind:bind /var/lib/bind/also-notify.conf
      rndc -c /var/lib/bind/rndc-internal.conf reconfig 2>/dev/null || true
      echo "[entrypoint] NOTIFY target set to $1"
      break
    fi
    i=$((i + 1))
    sleep 2
  done
) &

exec /usr/sbin/named -g -c /etc/bind/named.conf -u bind
