#!/bin/sh

test_description='HTTP-only request-bound credential exchange'

. ./test-lib.sh

# Remove only the explicitly negotiated request-bound fields, so that an
# opted-in helper query can be compared with the generic credential flow.
strip_request_fields () {
	sed -e "/^capability\[\]=dpop$/d" -e "/^http-method=/d" \
		-e "/^http-url=/d" "$@"
}

test_expect_success 'set up a request-aware credential helper' '
	DPOP_TEST_DIR=$TRASH_DIRECTORY &&
	export DPOP_TEST_DIR &&
	write_script helper <<-\EOF &&
	printf "%s\n" "$1" >>"$DPOP_TEST_DIR/commands"
	cat >"$DPOP_TEST_DIR/$1.input"
	case "$1" in
	get)
		cat "$DPOP_TEST_DIR/reply"
		test ! -f "$DPOP_TEST_DIR/helper-fails"
		;;
	esac
	EOF
	git config --global credential.helper "!\"$PWD/helper\"" &&
	cat >request <<-\EOF &&
	capability[]=authtype
	capability[]=state
	capability[]=dpop
	protocol=https
	host=example.com
	path=repo.git
	http-method=GET
	http-url=https://example.com/repo.git/info/refs?service=git-upload-pack
	EOF
	cat >legacy-request <<-\EOF &&
	capability[]=authtype
	protocol=https
	host=example.com
	EOF
	cat >generic-request <<-\EOF &&
	capability[]=authtype
	capability[]=state
	protocol=https
	host=example.com
	path=repo.git
	EOF
	write_script fragment-helper <<-\EOF &&
	cat >/dev/null
	printf "capability[]=authtype\ncapability[]=state\n"
	printf "password=earlier-secret\noauth_refresh_token=earlier-refresh\n"
	printf "ephemeral=1\ncontinue=1\nstate[]=prefix:unused\n"
	EOF
	cat >good-reply <<-\EOF
	capability[]=authtype
	capability[]=state
	capability[]=dpop
	authtype=DPoP
	credential=test-token
	dpop=e30.e30.c2ln
	ephemeral=1
	state[]=test:attempt-1
	EOF
'

test_expect_success 'generic CLI does not advertise HTTP-only capability' '
	git credential capability >actual &&
	test_grep "^capability authtype$" actual &&
	test_grep "^capability state$" actual &&
	test_grep ! "^capability dpop$" actual
'

for operation in fill approve reject
do
	test_expect_success "generic CLI cannot accept request-bound $operation" '
		>commands &&
		test_must_fail git credential "$operation" <request >actual 2>err &&
		test_grep "supported only by the HTTP transport" err &&
		test_must_be_empty commands
	'
done

test_expect_success 'a legacy arbitrary DPoP scheme remains an opaque credential' '
	cat >reply <<-\EOF &&
	capability[]=authtype
	authtype=DPoP
	credential=legacy-token
	EOF
	git credential fill <legacy-request >actual &&
	test_grep "^authtype=DPoP$" actual &&
	test_grep "^credential=legacy-token$" actual &&
	test_grep ! "^capability\[\]=dpop$" get.input &&
	test_grep ! "^http-url=" get.input &&
	>commands &&
	git credential approve <actual &&
	echo store >expect &&
	test_cmp expect commands
'

test_expect_success 'internal HTTP caller preserves full URL without useHttpPath' '
	cp good-reply reply &&
	test-tool credential-http fill <request >actual &&
	test_grep "^dpop=e30.e30.c2ln$" actual &&
	test_grep "^http-method=GET$" get.input &&
	test_grep -F "http-url=https://example.com/repo.git/info/refs?service=git-upload-pack" get.input &&
	test_grep ! "^path=" get.input &&
	test_grep ! "^dpop=" get.input &&
	test_grep ! "^credential=" get.input
'

test_expect_success 'useHttpPath does not replace the request URL' '
	cp good-reply reply &&
	test-tool credential-http -c credential.useHttpPath=true fill <request >actual &&
	test_grep "^path=repo.git$" get.input &&
	test_grep -F "http-url=https://example.com/repo.git/info/refs?service=git-upload-pack" get.input
'

test_expect_success 'legacy username/password output remains usable' '
	printf "username=alice\npassword=secret\n" >reply &&
	test-tool credential-http fill <request >actual &&
	test_grep "^username=alice$" actual &&
	test_grep "^password=secret$" actual &&
	test_grep ! "^capability\[\]=dpop$" actual
'

for scheme in Basic Bearer DPoP
do
	test_expect_success "scheme $scheme alone does not select the new protocol" '
		printf "capability[]=authtype\nauthtype=%s\ncredential=test-token\n" "$scheme" >reply &&
		test-tool credential-http fill <request >actual &&
		test_grep "^authtype=$scheme$" actual &&
		test_grep ! "^capability\[\]=dpop$" actual &&
		test_grep ! "^dpop=" actual
	'
done

for field in 'capability\[\]=dpop' 'capability\[\]=state' \
	'capability\[\]=authtype' 'dpop=' 'state\[\]=' 'ephemeral=' \
	'credential=' 'authtype='
do
	test_expect_success "reject a negotiated DPoP response missing $field" '
		sed "/^$field/d" good-reply >reply &&
		test_must_fail test-tool credential-http fill <request >actual 2>err &&
		test_grep "invalid DPoP credential response" err
	'
done

for extra in \
	'dpop=e30.e30.c2ln' \
	'credential=another-token' \
	'state[]=other:attempt' \
	'ephemeral=0' \
	'continue=1' \
	'password=secret' \
	'oauth_refresh_token=refresh' \
	'http-url=https://other.example.com/repo.git' \
	'http-method=POST' \
	'http-status=200' \
	'dpop-nonce=from-helper'
do
	test_expect_success "reject a malformed negotiated combination: $extra" '
		cat good-reply >reply &&
		echo "$extra" >>reply &&
		test_must_fail test-tool credential-http fill <request >actual 2>err &&
		test_grep "invalid DPoP credential response" err
	'
done

test_expect_success 'reject a proof with the wrong authorization scheme' '
	sed "s/authtype=DPoP/authtype=Bearer/" good-reply >reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid DPoP credential response" err
'

for proof in '' a.b a..b a.b.c.d 'a.b.c injected' 'a.b.c:injected'
do
	test_expect_success "reject invalid compact proof: $proof" '
		sed "s/^dpop=.*/dpop=$proof/" good-reply >reply &&
		test_must_fail test-tool credential-http fill <request >actual 2>err &&
		test_grep "invalid DPoP credential response" err
	'
done

test_expect_success 'request-bound response rejects control characters' '
	sed "/^credential=/d" good-reply >reply &&
	printf "credential=token\\rInjected: bad\n" >>reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid DPoP credential response" err
'

test_expect_success 'request-bound response rejects embedded NUL' '
	sed "/^credential=/d" good-reply >reply &&
	printf "credential=one\\000two\n" >>reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid credential line length" err
'

test_expect_success 'request-bound response rejects oversized token' '
	sed "/^credential=/d" good-reply >reply &&
	printf "credential=%016385d\n" 0 >>reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid DPoP credential response" err
'

test_expect_success 'reject helper failure after a complete response' '
	test_when_finished "rm -f helper-fails" &&
	>helper-fails &&
	cp good-reply reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid DPoP credential response" err
'

test_expect_success 'reject insecure target before asking helper to sign' '
	cp good-reply reply &&
	>commands &&
	sed "s,https,http,g" request >insecure &&
	test_must_fail test-tool credential-http fill <insecure >actual 2>err &&
	test_grep "HTTPS credential scope" err &&
	test_must_be_empty commands
'

test_expect_success 'reject another origin before asking helper to sign' '
	cp good-reply reply &&
	>commands &&
	sed "s,http-url=https://example.com/,http-url=https://other.example.com/," \
		request >other-origin &&
	test_must_fail test-tool credential-http fill <other-origin >actual 2>err &&
	test_grep "HTTPS credential scope" err &&
	test_must_be_empty commands
'

test_expect_success 'a prepared proof cannot be reused' '
	cp good-reply reply &&
	test_must_fail test-tool credential-http reuse <request >actual 2>err &&
	test_grep "refusing to reuse a DPoP proof" err
'

for operation in approve reject
do
	test_expect_success "internal $operation never broadcasts a DPoP credential" '
		cp good-reply reply &&
		>commands &&
		test-tool credential-http "$operation" <request &&
		echo get >expect &&
		test_cmp expect commands
	'
done

test_expect_success 'earlier ordinary fragments reach the winner but not its response' '
	cp good-reply reply &&
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/fragment-helper\"" \
		-c credential.helper="!\"$PWD/helper\"" fill <request >actual &&
	test_grep "^password=earlier-secret$" get.input &&
	test_grep "^oauth_refresh_token=earlier-refresh$" get.input &&
	test_grep "^ephemeral=1$" get.input &&
	test_grep "^continue=1$" get.input &&
	test_grep ! "^state\[\]=" get.input &&
	test_grep "^dpop=e30.e30.c2ln$" actual &&
	test_grep ! "^password=" actual &&
	test_grep ! "^oauth_refresh_token=" actual &&
	test_grep ! "^continue=" actual &&
	sed -n "/^state\[\]=/p" actual >states &&
	echo "state[]=test:attempt-1" >expect &&
	test_cmp expect states
'

test_expect_success 'a caller password fragment is not a winning response field' '
	cp good-reply reply &&
	cat request >with-password &&
	printf "password=caller-secret\n" >>with-password &&
	test-tool credential-http fill <with-password >actual &&
	test_grep "^dpop=e30.e30.c2ln$" actual &&
	test_grep ! "^password=" actual
'

test_expect_success 'another helper cannot supply missing capability or ephemeral' '
	write_script prefix-helper <<-\EOF &&
	cat >/dev/null
	printf "capability[]=authtype\ncapability[]=state\ncapability[]=dpop\nephemeral=1\n"
	EOF
	for field in "capability\[\]=dpop" "ephemeral="
	do
		sed "/^$field/d" good-reply >reply &&
		test_must_fail test-tool credential-http -c credential.helper= \
			-c credential.helper="!\"$PWD/prefix-helper\"" \
			-c credential.helper="!\"$PWD/helper\"" fill <request >actual 2>err &&
		test_grep "invalid DPoP credential response" err ||
		return 1
	done
'

test_expect_success 'do not send the selected proof to a later helper' '
	cp good-reply reply &&
	>commands &&
	test-tool credential-http \
		-c credential.helper="!echo later >>\"$PWD/commands\"" fill <request >actual &&
	echo get >expect &&
	test_cmp expect commands
'

test_expect_success 'request-bound mode requires protected helper protocol' '
	cp good-reply reply &&
	>commands &&
	test_must_fail test-tool credential-http -c credential.protectProtocol=false \
		fill <request >actual 2>err &&
	test_grep "requires credential.protectProtocol" err &&
	test_must_be_empty commands
'

test_expect_success 'helper URL output cannot erase the negotiated caller context' '
	{
		echo "url=https://example.com/repo.git" &&
		cat good-reply
	} >reply &&
	test_must_fail test-tool credential-http fill <request >actual 2>err &&
	test_grep "invalid DPoP credential response" err
'

test_expect_success 'HTTP observation preserves response metadata but never secrets' '
	cp good-reply reply &&
	>commands &&
	test-tool credential-http observe <request &&
	printf "get\nobserve\n" >expect &&
	test_cmp expect commands &&
	test_grep "^http-status=200$" observe.input &&
	test_grep "^dpop-nonce=response-nonce$" observe.input &&
	test_grep "^wwwauth\[\]=DPoP realm=" observe.input &&
	test_grep "^state\[\]=test:attempt-1$" observe.input &&
	test_grep ! "^credential=" observe.input &&
	test_grep ! "^dpop=" observe.input &&
	test_grep ! "^password=" observe.input
'

test_expect_success 'abandonment strips partial response metadata before helper notification' '
	cp good-reply reply &&
	>commands &&
	test-tool credential-http abandon <request &&
	printf "get\nobserve\n" >expect &&
	test_cmp expect commands &&
	test_grep "^http-status=0$" observe.input &&
	test_grep "^state\[\]=test:attempt-1$" observe.input &&
	test_grep "^http-method=GET$" observe.input &&
	test_grep ! "^dpop-nonce=" observe.input &&
	test_grep ! "^wwwauth\[\]=" observe.input &&
	test_grep ! "^credential=" observe.input &&
	test_grep ! "^dpop=" observe.input &&
	test_grep ! "^password=" observe.input
'

test_expect_success 'completing a winning attempt omits earlier ordinary fragments' '
	cp good-reply reply &&
	>commands &&
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/fragment-helper\"" \
		-c credential.helper="!\"$PWD/helper\"" observe <request &&
	printf "get\nobserve\n" >expect &&
	test_cmp expect commands &&
	test_grep "^http-status=200$" observe.input &&
	test_grep ! "^password=" observe.input &&
	test_grep ! "^oauth_refresh_token=" observe.input &&
	test_grep ! "^continue=" observe.input &&
	sed -n "/^state\[\]=/p" observe.input >states &&
	echo "state[]=test:attempt-1" >expect &&
	test_cmp expect states
'

test_expect_success 'ordinary username-only helper feeds the next password helper' '
	write_script username-helper <<-\EOF &&
	cat >/dev/null
	printf "username=alice\npassword_expiry_utc=4102444800\n"
	EOF
	write_script password-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/password-query"
	grep -q "^username=alice$" "$DPOP_TEST_DIR/password-query" || exit 1
	printf "password=ordinary-secret\n"
	EOF
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/username-helper\"" \
		-c credential.helper="!\"$PWD/password-helper\"" fill <request >actual &&
	test_grep "^username=alice$" actual &&
	test_grep "^password=ordinary-secret$" actual &&
	test_grep "^password_expiry_utc=4102444800$" actual &&
	test_grep "^username=alice$" password-query &&
	test_grep ! "^capability\[\]=dpop$" actual
'

test_expect_success 'ordinary password-only fragment is supplied to the next helper' '
	write_script secret-helper <<-\EOF &&
	cat >/dev/null
	printf "password=ordinary-secret\n"
	EOF
	write_script name-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/name-query"
	printf "username=alice\n"
	EOF
	git -c credential.helper= \
		-c credential.helper="!\"$PWD/secret-helper\"" \
		-c credential.helper="!\"$PWD/name-helper\"" \
		credential fill <generic-request >generic &&
	cp name-query generic-name-query &&
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/secret-helper\"" \
		-c credential.helper="!\"$PWD/name-helper\"" fill <request >actual &&
	test_grep "^username=alice$" actual &&
	test_grep "^password=ordinary-secret$" actual &&
	test_grep "^password=ordinary-secret$" name-query &&
	test_cmp generic actual &&
	strip_request_fields name-query >normalized &&
	test_cmp generic-name-query normalized
'

test_expect_success 'expired cached password still feeds its refresh token to the next helper' '
	write_script cache-helper <<-\EOF &&
	cat >/dev/null
	printf "username=alice\npassword=expired-pw\n"
	printf "oauth_refresh_token=rt-123\npassword_expiry_utc=1\n"
	EOF
	write_script refresh-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/refresh-query"
	grep -q "^oauth_refresh_token=rt-123$" "$DPOP_TEST_DIR/refresh-query" || exit 1
	printf "password=fresh-pw\noauth_refresh_token=rt-456\n"
	printf "password_expiry_utc=4102444800\n"
	EOF
	git -c credential.helper= \
		-c credential.helper="!\"$PWD/cache-helper\"" \
		-c credential.helper="!\"$PWD/refresh-helper\"" \
		credential fill <generic-request >generic &&
	cp refresh-query generic-refresh-query &&
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/cache-helper\"" \
		-c credential.helper="!\"$PWD/refresh-helper\"" fill <request >actual &&
	test_grep "^username=alice$" actual &&
	test_grep "^password=fresh-pw$" actual &&
	test_grep "^oauth_refresh_token=rt-456$" actual &&
	test_grep "^password_expiry_utc=4102444800$" actual &&
	test_grep "^oauth_refresh_token=rt-123$" refresh-query &&
	test_grep ! "^password=" refresh-query &&
	test_grep ! "^password_expiry_utc=" refresh-query &&
	test_cmp generic actual &&
	strip_request_fields refresh-query >normalized &&
	test_cmp generic-refresh-query normalized
'

test_expect_success 'ordinary helper query retains scheme and stage hints' '
	write_script scheme-helper <<-\EOF &&
	cat >/dev/null
	printf "capability[]=authtype\ncapability[]=state\n"
	printf "authtype=Multistage\nephemeral=1\ncontinue=1\nstate[]=scheme:one\n"
	EOF
	write_script token-helper <<-\EOF &&
	cat >"$DPOP_TEST_DIR/token-query"
	grep -q "^authtype=Multistage$" "$DPOP_TEST_DIR/token-query" || exit 1
	grep -q "^ephemeral=1$" "$DPOP_TEST_DIR/token-query" || exit 1
	grep -q "^continue=1$" "$DPOP_TEST_DIR/token-query" || exit 1
	printf "capability[]=authtype\ncapability[]=state\ncredential=ordinary-token\n"
	EOF
	git -c credential.helper= \
		-c credential.helper="!\"$PWD/scheme-helper\"" \
		-c credential.helper="!\"$PWD/token-helper\"" \
		credential fill <generic-request >generic &&
	cp token-query generic-token-query &&
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/scheme-helper\"" \
		-c credential.helper="!\"$PWD/token-helper\"" fill <request >actual &&
	test_grep "^authtype=Multistage$" actual &&
	test_grep "^ephemeral=1$" actual &&
	test_grep "^continue=1$" actual &&
	test_grep "^state\[\]=scheme:one$" actual &&
	test_cmp generic actual &&
	strip_request_fields token-query >normalized &&
	test_cmp generic-token-query normalized
'

test_expect_success 'ordinary helper can explicitly reset ephemeral and continue hints' '
	write_script reset-helper <<-\EOF &&
	cat >/dev/null
	printf "capability[]=authtype\ncapability[]=state\n"
	printf "credential=ordinary-token\nephemeral=0\ncontinue=0\n"
	EOF
	test-tool credential-http -c credential.helper= \
		-c credential.helper="!\"$PWD/scheme-helper\"" \
		-c credential.helper="!\"$PWD/reset-helper\"" fill <request >actual &&
	test_grep "^authtype=Multistage$" actual &&
	test_grep ! "^ephemeral=" actual &&
	test_grep ! "^continue=" actual
'

test_done
