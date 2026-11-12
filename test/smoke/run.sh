#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, run as the unprivileged user, and serve signed requests:
# create a user and an access key as the root user, kept in the store on its
# volume, and sign a request with that key.
set -eu

image=${1:?usage: run.sh IMAGE}
name=identity-smoke-$$
root_key=AKIAIOSFODNN7EXAMPLE
root_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::9030 \
	-e TULE_Auth_AccessKeyID=$root_key -e TULE_Auth_SecretAccessKey=$root_secret \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

# The image must not run as root: it holds the store in its volume.
ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9030/tcp | head -n 1)

# Every call is a signed, form-encoded POST / naming the operation in Action,
# which is what the AWS Query protocol the SDKs speak looks like on the wire.
# call SERVICE KEY SECRET FORM
call() {
	curl -fsS --aws-sigv4 "aws:amz:us-east-1:$1" --user "$2:$3" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		--data-binary "$4" "http://$addr/"
}

user=$(call iam $root_key $root_secret 'Action=CreateUser&Version=2010-05-08&UserName=smoke')
case $user in
*'<Arn>arn:aws:iam::000000000000:user/smoke</Arn>'*) ;;
*)
	echo "created user $user, want it in the default account" >&2
	exit 1
	;;
esac

key=$(call iam $root_key $root_secret \
	'Action=CreateAccessKey&Version=2010-05-08&UserName=smoke')
key_id=$(printf '%s' "$key" | sed -n 's|.*<AccessKeyId>\([^<]*\)</AccessKeyId>.*|\1|p')
key_secret=$(printf '%s' "$key" | sed -n 's|.*<SecretAccessKey>\([^<]*\)</SecretAccessKey>.*|\1|p')
if [ -z "$key_id" ] || [ -z "$key_secret" ]; then
	echo "created access key $key, want an ID and a secret" >&2
	exit 1
fi

me=$(call sts "$key_id" "$key_secret" 'Action=GetCallerIdentity&Version=2011-06-15')
case $me in
*'<Arn>arn:aws:iam::000000000000:user/smoke</Arn>'*) ;;
*)
	echo "caller identity $me, want the smoke user" >&2
	exit 1
	;;
esac

if ! docker exec "$name" test -s /data/identity.db; then
	echo "no store at /data/identity.db" >&2
	exit 1
fi

echo "smoke test passed: $image"
