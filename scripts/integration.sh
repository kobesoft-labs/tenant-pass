#!/bin/sh
# Starts throwaway PostgreSQL, MySQL and Redis containers on loopback
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

cleanup() {
	if [ "${KEEP:-0}" != 1 ]; then
		docker rm -f tp-it-pg tp-it-my tp-it-rd1 tp-it-rd2 >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

docker rm -f tp-it-pg tp-it-my tp-it-rd1 tp-it-rd2 >/dev/null 2>&1 || true
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

go test -count=1 -race "$@" ./internal/store/... ./internal/directory/...
