#!/bin/sh

test_description='request-local DPoP over verified HTTPS'
GIT_TEST_DEFAULT_INITIAL_BRANCH_NAME=main
export GIT_TEST_DEFAULT_INITIAL_BRANCH_NAME

. ./test-lib.sh

LIB_HTTPD_SSL=1
DPOP_TEST_DIR=$TRASH_DIRECTORY
export DPOP_TEST_DIR
. "$TEST_DIRECTORY"/lib-httpd.sh

enable_cgipassauth
if ! test_have_prereq CGIPASSAUTH
then
	skip_all="no CGIPassAuth support"
	test_done
fi
HTTPD_PARA="$HTTPD_PARA -DDPOP"
start_httpd

# lib-httpd defaults to disabling verification for its other HTTPS tests.
# This test instead trusts only its generated certificate.
unset GIT_SSL_NO_VERIFY

reset_dpop () {
	rm -f nonce counter observe-fails &&
	rm -rf seen post-challenged &&
	mkdir seen &&
	>events &&
	>requests &&
	echo "$1" >mode
}

check_observations () {
	sed -n "s/^get //p" events | sort >prepared &&
	sed -n "s/^observe \([^ ]*\) .*/\1/p" events | sort >observed &&
	test_cmp prepared observed &&
	test_grep ! "^unexpected " events
}

test_expect_success 'set up helper and repository' '
	git config --global http.sslCAInfo "$HTTPD_ROOT_PATH/httpd.pem" &&
	git config --global http.sslVerify true &&
	write_script helper <<-\EOF &&
	op=$1
	input="$DPOP_TEST_DIR/helper-input"
	cat >"$input"
	case "$op" in
	get)
		count=0
		test ! -f "$DPOP_TEST_DIR/counter" ||
			read count <"$DPOP_TEST_DIR/counter"
		count=$((count + 1))
		echo "$count" >"$DPOP_TEST_DIR/counter"
		method=$(sed -n "s/^http-method=//p" "$input")
		target=$(sed -n "s/^http-url=//p" "$input")
		test -n "$method" && test -n "$target" || exit 1
		nonce=none
		test ! -f "$DPOP_TEST_DIR/nonce" ||
			read nonce <"$DPOP_TEST_DIR/nonce"
		printf "get %s\n" "$count" >>"$DPOP_TEST_DIR/events"
		cp "$input" "$DPOP_TEST_DIR/get-$count.input"
		printf "capability[]=authtype\ncapability[]=state\ncapability[]=dpop\n"
		printf "authtype=DPoP\ncredential=test-token\nephemeral=1\n"
		printf "dpop=e30.%s.%s-%s\nstate[]=test:%s\n" \
			"$method" "$count" "$nonce" "$count"
		;;
	observe)
		if grep -E "^(credential|password|dpop|oauth_refresh_token)=" "$input"
		then
			exit 1
		fi
		count=$(sed -n "s/^state\[\]=test://p" "$input")
		status=$(sed -n "s/^http-status=//p" "$input")
		test -n "$count" && test -n "$status" || exit 1
		sed -n "/^http-method=/p; /^http-url=/p" "$input" \
			>"$DPOP_TEST_DIR/observed-context"
		sed -n "/^http-method=/p; /^http-url=/p" \
			"$DPOP_TEST_DIR/get-$count.input" >"$DPOP_TEST_DIR/prepared-context"
		cmp "$DPOP_TEST_DIR/observed-context" "$DPOP_TEST_DIR/prepared-context" ||
			exit 1
		printf "observe %s %s\n" "$count" "$status" >>"$DPOP_TEST_DIR/events"
		nonce=$(sed -n "s/^dpop-nonce=//p" "$input")
		test -z "$nonce" || echo "$nonce" >"$DPOP_TEST_DIR/nonce"
		cp "$input" "$DPOP_TEST_DIR/observe-$count.input"
		test ! -f "$DPOP_TEST_DIR/observe-fails"
		;;
	*)
		printf "unexpected %s\n" "$op" >>"$DPOP_TEST_DIR/events"
		exit 1
		;;
	esac
	EOF
	git config --global credential.helper "!\"$PWD/helper\"" &&
	git config --global credential.interactive false &&
	git config --global "http.$HTTPD_URL/dpop_auth/repo.git.dpop" true &&
	test_commit initial &&
	git init --bare "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" config http.receivepack true &&
	git push "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" main &&
	git clone --bare "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" \
		"$HTTPD_DOCUMENT_ROOT_PATH/other.git" &&
	write_script capture-helper <<-\EOF
	cat >"$DPOP_TEST_DIR/ordinary.input"
	printf "quit=1\n"
	EOF
'

test_expect_success 'default-off HTTPS lookup does not disclose request context' '
	reset_dpop normal &&
	test_must_fail git -c credential.helper= \
		-c credential.helper="!\"$PWD/capture-helper\"" \
		ls-remote "$HTTPD_URL/dpop_auth/other.git" >out 2>err &&
	test_grep ! "^capability\[\]=dpop$" ordinary.input &&
	test_grep ! "^http-method=" ordinary.input &&
	test_grep ! "^http-url=" ordinary.input &&
	test_grep ! "^path=" ordinary.input &&
	test_grep "^capability\[\]=authtype$" ordinary.input &&
	test_grep "^capability\[\]=state$" ordinary.input
'

test_expect_success 'ordinary RPC reauthentication preserves all_capabilities=0' '
	reset_dpop public-discovery &&
	test_must_fail git -c credential.helper= \
		-c credential.helper="!\"$PWD/capture-helper\"" \
		-c protocol.version=2 ls-remote "$HTTPD_URL/dpop_auth/other.git" >out 2>err &&
	test_grep "^POST " requests &&
	test_grep ! "^capability\[\]=" ordinary.input &&
	test_grep ! "^http-url=" ordinary.input
'

test_expect_success 'URL-specific opt-out suppresses the new helper fields' '
	reset_dpop normal &&
	test_must_fail git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=false" \
		-c credential.helper= \
		-c credential.helper="!\"$PWD/capture-helper\"" \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	test_grep ! "^capability\[\]=dpop$" ordinary.input &&
	test_grep ! "^http-url=" ordinary.input
'

test_expect_success 'ordinary opaque DPoP authtype does not activate request-bound mode' '
	reset_dpop normal &&
	write_script opaque-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/ordinary.input"
	printf "%s\n" "$1" >>"$DPOP_TEST_DIR/opaque.calls"
	if test "$1" = get
	then
		printf "capability[]=authtype\nauthtype=DPoP\ncredential=test-token\n"
	fi
	EOF
	>opaque.calls &&
	test_must_fail env GIT_TRACE_CURL="$PWD/opaque.trace" GIT_TRACE_CURL_NO_DATA=1 \
		git -c credential.helper= \
		-c credential.helper="!\"$PWD/opaque-helper\"" \
		ls-remote "$HTTPD_URL/dpop_auth/other.git" >out 2>err &&
	test_grep "Authorization: DPoP <redacted>" opaque.trace &&
	test_grep ! "Send header: DPoP:" opaque.trace &&
	test_grep ! "^capability\[\]=dpop$" ordinary.input &&
	test_grep ! "^http-url=" ordinary.input &&
	test_grep ! "^observe$" opaque.calls
'

test_expect_success 'GET gets a proof for the full URL and observes success' '
	reset_dpop normal &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	test_grep "refs/heads/main" refs &&
	test_grep -F "http-url=$HTTPD_URL/dpop_auth/repo.git/info/refs?service=git-upload-pack" get-1.input &&
	test_grep ! "^path=" get-1.input &&
	test_grep "^http-method=GET$" get-1.input &&
	test_grep "^http-status=200$" observe-1.input &&
	test_grep "^dpop-nonce=nonce-two$" observe-1.input &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'opt-in permits anonymous discovery of a public resource' '
	reset_dpop public-discovery &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	test_grep "refs/heads/main" refs &&
	test_must_be_empty events &&
	test_line_count = 1 requests &&
	test_grep "^GET .* none$" requests
'

test_expect_success 'userinfo is removed from the proof target, not the username hint' '
	reset_dpop normal &&
	git -c protocol.version=0 ls-remote \
		"https://hint%40example.com@$HTTPD_DEST/dpop_auth/repo.git" >refs &&
	test_grep "^username=hint@example.com$" get-1.input &&
	test_grep -F "http-url=$HTTPD_URL/dpop_auth/repo.git/info/refs?service=git-upload-pack" get-1.input &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'URL-supplied complete credentials are not replaced by DPoP' '
	reset_dpop normal &&
	test_must_fail git -c protocol.version=0 ls-remote \
		"https://hint:caller-password@$HTTPD_DEST/dpop_auth/repo.git" >refs 2>err &&
	test_grep "Authentication failed" err &&
	test_grep ! "^get " events
'

test_expect_success 'userinfo-free targets and username hint survive discovery into RPCs' '
	reset_dpop normal &&
	git clone "https://hint@$HTTPD_DEST/dpop_auth/repo.git" \
		userinfo-client &&
	test_commit -C userinfo-client userinfo &&
	git -C userinfo-client push origin HEAD:refs/heads/userinfo-test &&
	git -C userinfo-client rev-parse HEAD >expect &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse refs/heads/userinfo-test >actual &&
	test_cmp expect actual &&
	check_observations &&
	for attempt in $(cat prepared)
	do
		test_grep "^username=hint$" "get-$attempt.input" &&
		test_grep ! "^http-url=.*@" "get-$attempt.input" ||
		return 1
	done &&
	test_grep "^POST " requests
'

test_expect_success 'earlier partial helper secrets are not part of the winning credential' '
	reset_dpop normal &&
	write_script partial-helper <<-\EOF &&
	cat >/dev/null
	printf "password=earlier-secret\n"
	printf "oauth_refresh_token=earlier-refresh\n"
	printf "partial\n" >>"$DPOP_TEST_DIR/partial.calls"
	EOF
	>partial.calls &&
	git -c credential.helper= \
		-c credential.helper="!\"$PWD/partial-helper\"" \
		-c credential.helper="!\"$PWD/helper\"" \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	test_grep "^password=earlier-secret$" get-1.input &&
	test_grep "^oauth_refresh_token=earlier-refresh$" get-1.input &&
	test_line_count = 1 partial.calls &&
	check_observations
'

test_expect_success 'nonce challenge obtains a fresh proof without erase' '
	reset_dpop nonce &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	check_observations &&
	test_line_count = 2 prepared &&
	test_line_count = 3 requests &&
	test_grep "^GET .* none$" requests &&
	test_grep "^http-status=401$" observe-1.input &&
	test_grep "^http-status=200$" observe-2.input &&
	test_grep "e30.GET.2-nonce-one$" requests
'

test_expect_success 'nongit protocol v2 ls-remote can spool a large request and retry it' '
	reset_dpop post-nonce &&
	mkdir nongit-spool &&
	chmod 700 nongit-spool &&
	write_script spool-helper <<-\EOF &&
	if test "$1" = get
	then
		find "$DPOP_TEST_DIR/nongit-spool" -type f \
			-name "git-dpop-rpc-*" >>"$DPOP_TEST_DIR/spool-files-seen"
	fi
	exec "$DPOP_TEST_DIR/helper" "$@"
	EOF
	>spool-files-seen &&
	# Request payload, not response refs: 32 * 4096 bytes exceeds postBuffer.
	option=$(printf "%04096d" 0) &&
	set -- &&
	for i in $(test_seq 1 32)
	do
		set -- "$@" "--server-option=$option" ||
		return 1
	done &&
	nongit env TMPDIR="$TRASH_DIRECTORY/nongit-spool" \
		GIT_TRACE_CURL="$TRASH_DIRECTORY/nongit.trace" \
		GIT_TRACE_CURL_NO_DATA=1 \
		git -c protocol.version=2 -c http.postBuffer=70000 \
		-c credential.helper= \
		-c credential.helper="!\"$TRASH_DIRECTORY/spool-helper\"" \
		ls-remote "$@" "$HTTPD_URL/dpop_auth/repo.git" >refs 2>nongit-err &&
	test_grep "refs/heads/main" refs &&
	test_grep -i "Transfer-Encoding: chunked" nongit.trace &&
	test_grep "^observe .* 401$" events &&
	sort -u spool-files-seen >spool-paths &&
	test_line_count = 1 spool-paths &&
	test -z "$(find nongit-spool -type f)" &&
	check_observations
'

test_expect_success 'nongit spool creation failure sends no oversized RPC' '
	reset_dpop normal &&
	option=$(printf "%04096d" 0) &&
	set -- &&
	for i in $(test_seq 1 32)
	do
		set -- "$@" "--server-option=$option" ||
		return 1
	done &&
	# The helper can close its input while ls-remote is still writing options.
	nongit test_must_fail ok=sigpipe env TMPDIR="$TRASH_DIRECTORY/missing-spool-directory" \
		git -c protocol.version=2 -c http.postBuffer=70000 \
		ls-remote "$@" "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	test_grep "unable to spool DPoP request" err &&
	# Only the authentication probe was sent, not the oversized request.
	sed -n "/^POST /p" requests >posts &&
	test_line_count = 1 posts &&
	check_observations
'

test_expect_success 'find a nonce challenge after quoted pairs and another scheme' '
	reset_dpop escaped-nonce &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	check_observations &&
	test_line_count = 2 prepared &&
	test_grep "e30.GET.2-nonce-one$" requests
'

test_expect_success 'preserve percent escapes in the signed request URL' '
	reset_dpop normal &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo%2egit" >refs &&
	test_grep -F "http-url=$HTTPD_URL/dpop_auth/repo%2egit/info/refs?service=git-upload-pack" get-1.input &&
	check_observations
'

test_expect_success 'nonce retries are bounded' '
	reset_dpop always-nonce &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 2 prepared
'

test_expect_success 'a different scheme cannot request a nonce retry' '
	reset_dpop not-a-nonce-challenge &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'reject control characters in a nonce' '
	reset_dpop bad-nonce &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 1 prepared &&
	test_grep ! "^dpop-nonce=" observe-1.input
'

for mode in duplicate-nonce folded-nonce
do
	test_expect_success "reject ambiguous nonce headers without caching them: $mode" '
		reset_dpop "$mode" &&
		test_must_fail git -c protocol.version=0 \
			ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
		check_observations &&
		test_line_count = 1 prepared &&
		test_grep ! "^dpop-nonce=" observe-1.input
	'
done

test_expect_success 'refuse redirects even when always-follow is configured' '
	reset_dpop redirect &&
	test_must_fail git -c protocol.version=0 -c http.followRedirects=true \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	test_grep "refusing to follow a redirect" err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'do not retry or erase after an authorization failure' '
	reset_dpop forbidden &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'a dropped connection consumes the attempt without replay' '
	reset_dpop drop &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 1 prepared &&
	test_grep "^http-status=0$" observe-1.input
'

test_expect_success 'an observation failure prevents a nonce retry' '
	reset_dpop nonce &&
	>observe-fails &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'successful HTTP result survives observation failure with a warning' '
	reset_dpop normal &&
	>observe-fails &&
	git -c protocol.version=0 ls-remote "$HTTPD_URL/dpop_auth/repo.git" \
		>refs 2>err &&
	test_grep "refs/heads/main" refs &&
	test_grep "DPoP response bookkeeping failed" err &&
	test_grep ! -F "test-token" err &&
	test_grep ! "e30\." err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'observation failure does not replace the original transport error' '
	reset_dpop drop &&
	>observe-fails &&
	test_must_fail git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	test_grep "DPoP response bookkeeping failed" err &&
	test_grep "Empty reply from server" err &&
	check_observations &&
	test_line_count = 1 prepared
'

test_expect_success 'accepted push is not reported failed or retried for bookkeeping' '
	reset_dpop normal &&
	test_commit -C userinfo-client bookkeeping-success &&
	>observe-fails &&
	git -C userinfo-client push origin HEAD:refs/heads/bookkeeping-success \
		>out 2>err &&
	git -C userinfo-client rev-parse HEAD >expect &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse \
		refs/heads/bookkeeping-success >actual &&
	test_cmp expect actual &&
	test_grep "DPoP response bookkeeping failed" err &&
	sed -n "/^POST /p" requests >posts &&
	test_line_count = 1 posts &&
	check_observations
'

test_expect_success 'bookkeeping warning does not hide a Git pack-protocol rejection' '
	reset_dpop normal &&
	test_when_finished "rm -f \"$HTTPD_DOCUMENT_ROOT_PATH/repo.git/hooks/pre-receive\"" &&
	write_script "$HTTPD_DOCUMENT_ROOT_PATH/repo.git/hooks/pre-receive" <<-\EOF &&
	cat >/dev/null
	echo "deliberate push rejection" >&2
	exit 1
	EOF
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse \
		refs/heads/bookkeeping-success >expect &&
	test_commit -C userinfo-client bookkeeping-rejection &&
	>observe-fails &&
	test_must_fail git -C userinfo-client push origin \
		HEAD:refs/heads/bookkeeping-success >out 2>err &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse \
		refs/heads/bookkeeping-success >actual &&
	test_cmp expect actual &&
	test_grep "DPoP response bookkeeping failed" err &&
	test_grep "pre-receive hook declined" err &&
	sed -n "/^POST /p" requests >posts &&
	test_line_count = 1 posts &&
	check_observations
'

for header in 'Authorization: Basic other' 'dpop: stale.proof.here' \
	'Host: other.invalid' 'Expect: 100-continue'
do
	test_expect_success "conflicting header fails before sending a proof: $header" '
		reset_dpop normal &&
		test_must_fail git -c http.proactiveAuth=auto \
			-c http.extraHeader="$header" \
			ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
		test_must_be_empty requests &&
		check_observations &&
		test_line_count = 1 prepared &&
		test_grep "^http-status=0$" observe-1.input
	'
done

test_expect_success 'control characters cannot be injected through a signed header list' '
	reset_dpop normal &&
	header=$(printf "X-Test: one\\001two") &&
	test_must_fail git -c http.proactiveAuth=auto \
		-c http.extraHeader="$header" \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >out 2>err &&
	test_must_be_empty requests &&
	check_observations &&
	test_grep "^http-status=0$" observe-1.input
'

test_expect_success 'curl trace redacts proofs including lowercase response fields' '
	reset_dpop normal &&
	GIT_TRACE_CURL="$PWD/curl.trace" GIT_TRACE_CURL_NO_DATA=1 \
		GIT_TRACE_REDACT=0 git -c protocol.version=0 \
		ls-remote "$HTTPD_URL/dpop_auth/repo.git" >refs &&
	test_grep "DPoP: <redacted>" curl.trace &&
	test_grep "dpop: <redacted>" curl.trace &&
	test_grep ! "e30\." curl.trace &&
	check_observations
'

test_expect_success 'clone and fetch use distinct GET and POST proofs' '
	reset_dpop normal &&
	git clone "$HTTPD_URL/dpop_auth/repo.git" client &&
	test_commit next &&
	git push "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" main &&
	git -C client fetch origin &&
	git rev-parse HEAD >expect &&
	git -C client rev-parse origin/main >actual &&
	test_cmp expect actual &&
	git -C client merge --ff-only origin/main &&
	test_grep "^GET .* e30.GET." requests &&
	test_grep "^POST .* e30.POST." requests &&
	check_observations
'

test_expect_success 'push replays a buffered POST only after an explicit nonce challenge' '
	reset_dpop post-nonce &&
	test_commit -C client pushed &&
	git -C client push origin main &&
	git -C client rev-parse HEAD >expect &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse HEAD >actual &&
	test_cmp expect actual &&
	test_grep "^observe .* 401$" events &&
	check_observations
'

test_expect_success 'chunked push, its probe and its nonce retry have fresh proofs' '
	reset_dpop post-nonce &&
	test-tool genrandom dpop 262144 >client/large &&
	git -C client add large &&
	git -C client commit -m large &&
	GIT_TRACE_CURL="$PWD/chunked.trace" GIT_TRACE_CURL_NO_DATA=1 \
		git -C client -c http.postBuffer=65520 push origin main &&
	git -C client rev-parse HEAD >expect &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse HEAD >actual &&
	test_cmp expect actual &&
	test_grep -i "Transfer-Encoding: chunked" chunked.trace &&
	test_grep "^observe .* 401$" events &&
	check_observations &&
	test -z "$(find client/.git -name "dpop-rpc-*")"
'

test_expect_success 'a nonce retry preserves a gzip request body and its encoding' '
	parent=$(git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse HEAD) &&
	tree=$(git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse HEAD^{tree}) &&
	for i in $(test_seq 1 64)
	do
		commit=$(echo "branch $i" |
			git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" commit-tree "$tree" -p "$parent") &&
		git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" update-ref "refs/heads/dpop-$i" "$commit" ||
		return 1
	done &&
	reset_dpop gzip-nonce &&
	GIT_TRACE_CURL="$PWD/gzip.trace" GIT_TRACE_CURL_NO_DATA=1 \
		git -c protocol.version=0 clone --no-checkout \
		"$HTTPD_URL/dpop_auth/repo.git" gzip-client &&
	test_grep "Content-Encoding: gzip" gzip.trace &&
	test_grep "^observe .* 401$" events &&
	check_observations
'

test_expect_success 'parallel dumb object requests have isolated proofs and observations' '
	reset_dpop normal &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" update-server-info &&
	GIT_SMART_HTTP=0 GIT_HTTP_MAX_REQUESTS=4 git clone \
		"$HTTPD_URL/dpop_auth/repo.git" dumb-client &&
	git -C "$HTTPD_DOCUMENT_ROOT_PATH/repo.git" rev-parse HEAD >expect &&
	git -C dumb-client rev-parse HEAD >actual &&
	test_cmp expect actual &&
	check_observations
'

test_expect_success 'a repeated POST nonce challenge is not an unbounded push retry' '
	reset_dpop post-always-nonce &&
	test_commit -C client rejected &&
	test_must_fail git -C client push origin main >out 2>err &&
	test_grep "DPoP nonce retry exhausted" err &&
	sed -n "/^POST /p" requests >posts &&
	test_line_count = 2 posts &&
	check_observations
'

test_expect_success 'libcurl does not transparently resend a proof after HTTP 417' '
	reset_dpop post-expectation-failed &&
	test_must_fail git -C client push origin main >out 2>err &&
	test_grep "HTTP 417" err &&
	sed -n "/^POST /p" requests >posts &&
	test_line_count = 1 posts &&
	check_observations
'

test_expect_success 'set up ordinary helpers which decline DPoP' '
	write_script ordinary-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/ordinary-input"
	printf "%s\n" "$1" >>"$DPOP_TEST_DIR/ordinary-calls"
	if test "$1" = get
	then
		read mode <"$DPOP_TEST_DIR/mode"
		if test "$mode" = ordinary-basic
		then
			printf "username=alice\npassword=secret\n"
		else
			printf "capability[]=authtype\nauthtype=Bearer\ncredential=ordinary-token\n"
		fi
	fi
	EOF
	write_script ordinary-name-helper <<-\EOF &&
	cat >/dev/null
	printf "name %s\n" "$1" >>"$DPOP_TEST_DIR/partial-ordinary-calls"
	test "$1" != get || printf "username=alice\n"
	EOF
	write_script ordinary-password-helper <<-\EOF
	cat >"$DPOP_TEST_DIR/partial-ordinary-input"
	printf "password %s\n" "$1" >>"$DPOP_TEST_DIR/partial-ordinary-calls"
	if test "$1" = get
	then
		grep -q "^username=alice$" "$DPOP_TEST_DIR/partial-ordinary-input" || exit 1
		printf "password=secret\n"
	fi
	EOF
'

for scheme in basic bearer
do
	for proactive in none auto
	do
		test_expect_success "opt-in preserves cached $scheme credentials with proactiveAuth=$proactive" '
			for enabled in false true
			do
				reset_dpop "ordinary-$scheme" &&
				>ordinary-calls &&
				>ordinary-requests &&
				git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
					-c "http.proactiveAuth=$proactive" \
					-c credential.helper= \
					-c credential.helper="!\"$PWD/ordinary-helper\"" \
					-c protocol.version=2 clone --no-checkout \
					"$HTTPD_URL/dpop_auth/repo.git" \
					"ordinary-$scheme-$proactive-$enabled" &&
				printf "get\nstore\n" >expect &&
				test_cmp expect ordinary-calls &&
				test_grep "^GET authenticated$" ordinary-requests &&
				test_grep "^POST authenticated$" ordinary-requests &&
				cp requests "ordinary-$enabled.requests" &&
				cp ordinary-requests "ordinary-$enabled.authenticated" ||
				return 1
			done &&
			test_cmp ordinary-false.requests ordinary-true.requests &&
			test_cmp ordinary-false.authenticated ordinary-true.authenticated
		'
	done
done

test_expect_success 'opted-in Basic server works with an ordinary partial helper chain' '
	reset_dpop ordinary-basic &&
	>partial-ordinary-calls &&
	>ordinary-requests &&
	git -c credential.helper= \
		-c credential.helper="!\"$PWD/ordinary-name-helper\"" \
		-c credential.helper="!\"$PWD/ordinary-password-helper\"" \
		-c protocol.version=2 clone --no-checkout \
		"$HTTPD_URL/dpop_auth/repo.git" ordinary-partial &&
	printf "name get\npassword get\nname store\npassword store\n" >expect &&
	test_cmp expect partial-ordinary-calls &&
	test_grep "^GET authenticated$" ordinary-requests &&
	test_grep "^POST authenticated$" ordinary-requests
'

test_expect_success 'ordinary refresh-token chain matches the opt-out flow over TLS' '
	write_script refresh-cache-helper <<-\EOF &&
	op=$1
	read profile <"$DPOP_TEST_DIR/refresh-profile"
	cat >"$DPOP_TEST_DIR/refresh-$profile-cache-$op"
	printf "cache %s\n" "$op" >>"$DPOP_TEST_DIR/refresh-$profile.calls"
	if test "$op" = get
	then
		printf "username=alice\npassword=expired-secret\n"
		printf "oauth_refresh_token=rt-123\npassword_expiry_utc=1\n"
	fi
	EOF
	write_script refresh-token-helper <<-\EOF &&
	op=$1
	read profile <"$DPOP_TEST_DIR/refresh-profile"
	input="$DPOP_TEST_DIR/refresh-$profile-refresh-$op"
	cat >"$input"
	printf "refresh %s\n" "$op" >>"$DPOP_TEST_DIR/refresh-$profile.calls"
	if test "$op" = get
	then
		grep -q "^oauth_refresh_token=rt-123$" "$input" || exit 1
		printf "password=secret\noauth_refresh_token=rt-456\n"
	fi
	EOF
	for enabled in false true
	do
		reset_dpop ordinary-basic &&
		echo "$enabled" >refresh-profile &&
		>"refresh-$enabled.calls" &&
		>ordinary-requests &&
		git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
			-c credential.helper= \
			-c credential.helper="!\"$PWD/refresh-cache-helper\"" \
			-c credential.helper="!\"$PWD/refresh-token-helper\"" \
			-c protocol.version=2 clone --no-checkout \
			"$HTTPD_URL/dpop_auth/repo.git" "refresh-clone-$enabled" &&
		printf "cache get\nrefresh get\ncache store\nrefresh store\n" >expect &&
		test_cmp expect "refresh-$enabled.calls" &&
		test_grep "^GET authenticated$" ordinary-requests &&
		test_grep "^POST authenticated$" ordinary-requests &&
		test_grep "^oauth_refresh_token=rt-123$" "refresh-$enabled-refresh-get" &&
		test_grep ! "^password=" "refresh-$enabled-refresh-get" &&
		test_grep "^password=secret$" "refresh-$enabled-refresh-store" &&
		test_grep "^oauth_refresh_token=rt-456$" "refresh-$enabled-refresh-store" &&
		cp requests "refresh-$enabled.requests" ||
		return 1
	done &&
	test_cmp refresh-false.requests refresh-true.requests &&
	for request in cache-get refresh-get cache-store refresh-store
	do
		sed -e "/^capability\[\]=dpop$/d" \
			-e "/^http-method=/d" -e "/^http-url=/d" \
			"refresh-true-$request" >normalized &&
		test_cmp "refresh-false-$request" normalized ||
		return 1
	done
'

test_expect_success 'set up a helper which records URL credential lookups' '
	write_script url-credential-helper <<-\EOF
	op=$1
	read profile <"$DPOP_TEST_DIR/url-profile"
	cat >"$DPOP_TEST_DIR/url-$profile-$op"
	printf "%s\n" "$op" >>"$DPOP_TEST_DIR/url-$profile.calls"
	test "$op" != get || cat "$DPOP_TEST_DIR/url-reply"
	EOF
'

for proactive in none basic auto
do
	test_expect_success "opt-in does not look up URL-supplied complete credentials with proactiveAuth=$proactive" '
		# A lookup would replace the URL credentials with the wrong secret.
		printf "username=alice\npassword=helper-secret\n" >url-reply &&
		for enabled in false true
		do
			reset_dpop ordinary-basic &&
			echo "$enabled" >url-profile &&
			>"url-$enabled.calls" &&
			>ordinary-requests &&
			git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
				-c "http.proactiveAuth=$proactive" \
				-c credential.helper= \
				-c credential.helper="!\"$PWD/url-credential-helper\"" \
				-c protocol.version=2 clone \
				"https://alice:secret@$HTTPD_DEST/dpop_auth/repo.git" \
				"url-complete-$proactive-$enabled" &&
			test-tool genrandom seed 40000 \
				>"url-complete-$proactive-$enabled/payload" &&
			git -C "url-complete-$proactive-$enabled" add payload &&
			git -C "url-complete-$proactive-$enabled" commit -m payload &&
			git -C "url-complete-$proactive-$enabled" \
				-c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
				-c "http.proactiveAuth=$proactive" \
				-c http.postBuffer=4096 \
				-c credential.helper= \
				-c credential.helper="!\"$PWD/url-credential-helper\"" \
				push origin "HEAD:refs/heads/url-complete-$proactive-$enabled" &&
			printf "store\nstore\n" >expect &&
			test_cmp expect "url-$enabled.calls" &&
			cp requests "url-$enabled.requests" &&
			cp ordinary-requests "url-$enabled.authenticated" ||
			return 1
		done &&
		test_cmp url-false.requests url-true.requests &&
		test_cmp url-false.authenticated url-true.authenticated &&
		test_cmp url-false-store url-true-store
	'
done

for proactive in none basic auto
do
	test_expect_success "opt-in preserves the rejection of URL-supplied complete credentials with proactiveAuth=$proactive" '
		# A lookup would supply the right secret and hide the rejection.
		printf "username=alice\npassword=secret\n" >url-reply &&
		for enabled in false true
		do
			reset_dpop ordinary-basic &&
			echo "$enabled" >url-profile &&
			>"url-$enabled.calls" &&
			test_must_fail git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
				-c "http.proactiveAuth=$proactive" \
				-c credential.helper= \
				-c credential.helper="!\"$PWD/url-credential-helper\"" \
				-c protocol.version=2 clone --no-checkout \
				"https://alice:wrong@$HTTPD_DEST/dpop_auth/repo.git" \
				"url-rejected-$proactive-$enabled" 2>"url-$enabled.err" &&
			test_grep "Authentication failed" "url-$enabled.err" &&
			echo erase >expect &&
			test_cmp expect "url-$enabled.calls" &&
			cp requests "url-$enabled.requests" ||
			return 1
		done &&
		test_cmp url-false.requests url-true.requests &&
		test_cmp url-false-erase url-true-erase
	'
done

for proactive in none basic auto
do
	test_expect_success "opt-in still consults helpers for a URL-supplied username alone with proactiveAuth=$proactive" '
		printf "password=secret\n" >url-reply &&
		for enabled in false true
		do
			reset_dpop ordinary-basic &&
			echo "$enabled" >url-profile &&
			>"url-$enabled.calls" &&
			>ordinary-requests &&
			git -c "http.$HTTPD_URL/dpop_auth/repo.git.dpop=$enabled" \
				-c "http.proactiveAuth=$proactive" \
				-c credential.helper= \
				-c credential.helper="!\"$PWD/url-credential-helper\"" \
				-c protocol.version=2 clone --no-checkout \
				"https://alice@$HTTPD_DEST/dpop_auth/repo.git" \
				"url-partial-$proactive-$enabled" &&
			printf "get\nstore\n" >expect &&
			test_cmp expect "url-$enabled.calls" &&
			test_grep "^username=alice$" "url-$enabled-get" &&
			cp requests "url-$enabled.requests" &&
			cp ordinary-requests "url-$enabled.authenticated" ||
			return 1
		done &&
		test_cmp url-false.requests url-true.requests &&
		test_cmp url-false.authenticated url-true.authenticated &&
		sed -e "/^capability\[\]=dpop$/d" \
			-e "/^http-method=/d" -e "/^http-url=/d" \
			url-true-get >normalized &&
		test_cmp url-false-get normalized &&
		test_cmp url-false-store url-true-store
	'
done

test_expect_success 'ordinary multistage state and flags match the opt-out flow over TLS' '
	# Use the same CGI and token/state progression as t5563, with ephemeral
	# declared only on the first leg so continuity is actually exercised.
	cat >"$HTTPD_ROOT_PATH/custom-auth.valid" <<-\EOF &&
	id=1 creds=Multistage YS1naXQtdG9rZW4=
	id=2 creds=Multistage YW5vdGhlci10b2tlbg==
	EOF
	cat >"$HTTPD_ROOT_PATH/custom-auth.challenge" <<-\EOF &&
	id=1 status=401 response=WWW-Authenticate: Multistage challenge="456"
	id=2 status=200
	id=default response=WWW-Authenticate: Multistage challenge="123"
	EOF
	write_script multistage-helper <<-\EOF &&
	op=$1
	read profile <"$DPOP_TEST_DIR/multistage-profile"
	input="$DPOP_TEST_DIR/multistage-input"
	cat >"$input"
	state=$(sed -n "s/^state\[\]=helper://p" "$input")
	state=${state:-initial}
	cp "$input" "$DPOP_TEST_DIR/multistage-$profile-$op-$state"
	printf "%s %s\n" "$op" "$state" >>"$DPOP_TEST_DIR/multistage-$profile.calls"
	if test "$op" = get
	then
		printf "capability[]=authtype\ncapability[]=state\nauthtype=Multistage\n"
		case "$state" in
		initial)
			printf "credential=YS1naXQtdG9rZW4=\nephemeral=1\n"
			printf "state[]=helper:foobar\ncontinue=1\n"
			;;
		foobar)
			grep -q "^authtype=Multistage$" "$input" || exit 1
			grep -q "^ephemeral=1$" "$input" || exit 1
			printf "credential=YW5vdGhlci10b2tlbg==\nstate[]=helper:bazquux\n"
			;;
		*)
			exit 1
			;;
		esac
	fi
	EOF
	for enabled in false true
	do
		echo "$enabled" >multistage-profile &&
		>"multistage-$enabled.calls" &&
		git -c "http.$HTTPD_URL/custom_auth/repo.git.dpop=$enabled" \
			-c credential.helper= \
			-c credential.helper="!\"$PWD/multistage-helper\"" \
			-c protocol.version=0 ls-remote "$HTTPD_URL/custom_auth/repo.git" \
			>refs &&
		test_grep "refs/heads/main" refs &&
		printf "get initial\nget foobar\nstore bazquux\n" >expect &&
		test_cmp expect "multistage-$enabled.calls" &&
		test_grep "^state\[\]=helper:foobar$" "multistage-$enabled-get-foobar" &&
		test_grep ! "^continue=" "multistage-$enabled-get-foobar" &&
		test_grep ! "^credential=" "multistage-$enabled-get-foobar" &&
		test_grep "^ephemeral=1$" "multistage-$enabled-store-bazquux" &&
		test_grep ! "^continue=" "multistage-$enabled-store-bazquux" ||
		return 1
	done &&
	for request in get-initial get-foobar store-bazquux
	do
		sed -e "/^capability\[\]=dpop$/d" \
			-e "/^http-method=/d" -e "/^http-url=/d" \
			"multistage-true-$request" >normalized &&
		test_cmp "multistage-false-$request" normalized ||
		return 1
	done
'

test_done
