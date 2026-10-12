#!/bin/sh

# The proof is deliberately synthetic. These tests check HTTP ownership and
# credential lifetimes, not the cryptography implemented by an external helper.

printf "%s %s %s\n" "$REQUEST_METHOD" "$REQUEST_URI" \
	"${HTTP_DPOP-none}" >>"$DPOP_TEST_DIR/requests"

read mode <"$DPOP_TEST_DIR/mode"
case "$mode" in
ordinary-basic | ordinary-bearer)
	if test "$mode" = ordinary-basic
	then
		expected="Basic YWxpY2U6c2VjcmV0"
		challenge="Basic realm=\"ordinary\""
	else
		expected="Bearer ordinary-token"
		challenge="Bearer realm=\"ordinary\""
	fi
	if test "$HTTP_AUTHORIZATION" != "$expected"
	then
		printf "HTTP/1.1 401 Unauthorized\r\n"
		printf "WWW-Authenticate: %s\r\n\r\n" "$challenge"
		exit
	fi
	test -z "$HTTP_DPOP" || exit 1
	printf "%s authenticated\n" "$REQUEST_METHOD" >>"$DPOP_TEST_DIR/ordinary-requests"
	printf "HTTP/1.1 200 OK\r\n"
	GIT_PROJECT_ROOT="$DPOP_TEST_DIR/httpd/www"
	export GIT_PROJECT_ROOT
	exec "$GIT_EXEC_PATH/git-http-backend"
	;;
esac
if test "$mode" = public-discovery && test "$REQUEST_METHOD" = GET
then
	printf "HTTP/1.1 200 OK\r\n"
	GIT_PROJECT_ROOT="$DPOP_TEST_DIR/httpd/www"
	export GIT_PROJECT_ROOT
	exec "$GIT_EXEC_PATH/git-http-backend"
fi

challenge () {
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\n"
	printf "dPoP-nOnCe: nonce-one\r\n\r\n"
}

if test -z "$HTTP_AUTHORIZATION"
then
	test -z "$HTTP_DPOP" || exit 1
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: DPoP realm=\"test\"\r\n\r\n"
	exit
fi

case "$HTTP_DPOP" in
e30."$REQUEST_METHOD".*)
	;;
*)
	printf "HTTP/1.1 500 Wrong method in proof\r\n\r\n"
	exit
	;;
esac

if test "$HTTP_AUTHORIZATION" != "DPoP test-token" ||
   test -n "$HTTP_EXPECT" ||
   ! mkdir "$DPOP_TEST_DIR/seen/$HTTP_DPOP"
then
	printf "HTTP/1.1 500 Invalid or reused credential\r\n\r\n"
	exit
fi

count=${HTTP_DPOP##*.}
count=${count%%-*}
target=${REQUEST_URI%%\?*}
if test -n "$QUERY_STRING"
then
	target="$target?$QUERY_STRING"
fi
if ! grep -Fqx "http-url=https://$HTTP_HOST$target" \
	"$DPOP_TEST_DIR/get-$count.input"
then
	printf "HTTP/1.1 500 Wrong URL in proof request\r\n\r\n"
	exit
fi

case "$mode" in
drop)
	exit
	;;
nonce | escaped-nonce)
	case "$HTTP_DPOP" in
	*-nonce-one | *-nonce-two)
		;;
	*)
		if test "$mode" = escaped-nonce
		then
			printf "HTTP/1.1 401 Unauthorized\r\n"
			printf "%s\r\n" "WWW-Authenticate: Bearer realm=\"other\\\\realm\", DPoP realm=\"git\\\\realm\", error=\"use_dpop_nonce\""
			printf "DPoP-Nonce: nonce-one\r\n\r\n"
		else
			challenge
		fi
		exit
		;;
	esac
	;;
always-nonce)
	challenge
	exit
	;;
bad-nonce)
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\n"
	printf "DPoP-Nonce: bad\001nonce\r\n\r\n"
	exit
	;;
duplicate-nonce)
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\n"
	printf "DPoP-Nonce: nonce-one\r\nDPoP-Nonce: nonce-two\r\n\r\n"
	exit
	;;
folded-nonce)
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"\r\n"
	printf "DPoP-Nonce: nonce-one\r\n nonce-two\r\n\r\n"
	exit
	;;
not-a-nonce-challenge)
	printf "HTTP/1.1 401 Unauthorized\r\n"
	printf "WWW-Authenticate: Bearer error=\"use_dpop_nonce\"\r\n"
	printf "WWW-Authenticate: DPoP realm=\"test\"\r\n"
	printf "DPoP-Nonce: nonce-one\r\n\r\n"
	exit
	;;
redirect)
	printf "HTTP/1.1 307 Temporary Redirect\r\n"
	printf "Location: https://other.invalid/repo.git\r\n\r\n"
	exit
	;;
forbidden)
	printf "HTTP/1.1 403 Forbidden\r\n\r\n"
	exit
	;;
post-expectation-failed)
	if test "$REQUEST_METHOD" = POST
	then
		cat >/dev/null
		printf "HTTP/1.1 417 Expectation Failed\r\n\r\n"
		exit
	fi
	;;
post-nonce | post-always-nonce | gzip-nonce)
	if test "$REQUEST_METHOD" = POST && test "$CONTENT_LENGTH" != 4
	then
		if test "$mode" != gzip-nonce || test "$HTTP_CONTENT_ENCODING" = gzip
		then
			if test "$mode" = post-always-nonce ||
			   mkdir "$DPOP_TEST_DIR/post-challenged" 2>/dev/null
			then
				# Exercise a late challenge, after the complete upload.
				cat >/dev/null
				challenge
				exit
			fi
		fi
	fi
	;;
esac

printf "HTTP/1.1 200 OK\r\n"
printf "DPoP-Nonce: nonce-two\r\n"
printf "dpop: %s\r\n" "$HTTP_DPOP"
GIT_PROJECT_ROOT="$DPOP_TEST_DIR/httpd/www"
export GIT_PROJECT_ROOT
exec "$GIT_EXEC_PATH/git-http-backend"
