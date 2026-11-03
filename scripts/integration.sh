#!/bin/sh
# Starts throwaway PostgreSQL, MySQL, Redis and OpenBao containers on loopback
# ports and runs the integration tests against them.
#
#   scripts/integration.sh          start containers, run tests, remove containers
#   KEEP=1 scripts/integration.sh   leave the containers running afterwards
#
# The containers use fixed, well-known bootstrap passwords and listen on
# 127.0.0.1 only. Never point these tests at a real server: they create
# and alter roles and users.
set -eu

PG_PORT=55432
MY_PORT=53306
RD1_PORT=56379
RD2_PORT=56380
BAO_PORT=58200

cleanup() {
	if [ "${KEEP:-0}" != 1 ]; then
		docker rm -f tp-it-pg tp-it-my tp-it-rd1 tp-it-rd2 tp-it-bao >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

docker rm -f tp-it-pg tp-it-my tp-it-rd1 tp-it-rd2 tp-it-bao >/dev/null 2>&1 || true
docker run -d --name tp-it-bao --cap-add IPC_LOCK -p 127.0.0.1:$BAO_PORT:8200 -e BAO_DEV_ROOT_TOKEN_ID=root openbao/openbao:2 server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
docker run -d --name tp-it-pg -p 127.0.0.1:$PG_PORT:5432 -e POSTGRES_PASSWORD=postgres postgres:18 >/dev/null
docker run -d --name tp-it-my -p 127.0.0.1:$MY_PORT:3306 -e MYSQL_ROOT_PASSWORD=rootpw mysql:8.4 >/dev/null
docker run -d --name tp-it-rd1 -p 127.0.0.1:$RD1_PORT:6379 redis:8 >/dev/null
docker run -d --name tp-it-rd2 -p 127.0.0.1:$RD2_PORT:6379 redis:8 >/dev/null

echo "waiting for servers..."
for _ in $(seq 90); do
	if docker exec tp-it-pg pg_isready -U postgres >/dev/null 2>&1 &&
		docker exec tp-it-my mysql -uroot -prootpw -h127.0.0.1 -e 'SELECT 1' >/dev/null 2>&1; then
		break
	fi
	sleep 2
done

# Let the test's root@'%' grant PROXY (used to test that proxy users are refused).
docker exec tp-it-my mysql -uroot -prootpw -e "GRANT PROXY ON ''@'' TO 'root'@'%' WITH GRANT OPTION" 2>/dev/null

export TENANT_PASS_TEST_PG=127.0.0.1:$PG_PORT
export TENANT_PASS_TEST_MYSQL=127.0.0.1:$MY_PORT
export TENANT_PASS_TEST_REDIS=127.0.0.1:$RD1_PORT,127.0.0.1:$RD2_PORT
export TENANT_PASS_TEST_VAULT=http://127.0.0.1:$BAO_PORT

go test -count=1 -race "$@" ./internal/store/... ./internal/directory/... ./internal/kms/...
