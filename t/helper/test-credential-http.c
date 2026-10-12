#define USE_THE_REPOSITORY_VARIABLE

#include "test-tool.h"
#include "config.h"
#include "credential.h"
#include "repository.h"
#include "setup.h"

int cmd__credential_http(int argc, const char **argv)
{
	struct credential c = CREDENTIAL_INIT;
	const char *operation;
	int i = 1;

	while (i + 1 < argc && !strcmp(argv[i], "-c")) {
		git_config_push_parameter(argv[i + 1]);
		i += 2;
	}
	if (i + 1 != argc)
		die("usage: test-tool credential-http [-c key=value] (fill|approve|reject|reuse|observe|abandon)");
	operation = argv[i];
	setup_git_directory(the_repository);
	repo_config(the_repository, git_default_config, NULL);

	/* An internal HTTP caller enables this before reading test context. */
	credential_set_http_request(&c, "GET", "https://example.com/");
	if (credential_read(&c, stdin, CREDENTIAL_OP_INITIAL))
		die("unable to read HTTP credential test context");
	credential_fill(the_repository, &c, 1);
	if (!strcmp(operation, "fill")) {
		credential_next_state(&c);
		credential_write(&c, stdout, CREDENTIAL_OP_RESPONSE);
	} else if (!strcmp(operation, "approve")) {
		credential_approve(the_repository, &c);
	} else if (!strcmp(operation, "reject")) {
		credential_reject(the_repository, &c);
	} else if (!strcmp(operation, "reuse")) {
		credential_fill(the_repository, &c, 1);
	} else if (!strcmp(operation, "observe") || !strcmp(operation, "abandon")) {
		c.dpop_nonce = xstrdup("response-nonce");
		strvec_push(&c.wwwauth_headers, "DPoP realm=\"test\"");
		if (credential_dpop_observe(&c, !strcmp(operation, "observe") ? 200 : 0)) {
			credential_clear(&c);
			return 1;
		}
	} else {
		die("unknown HTTP credential test operation");
	}
	credential_clear(&c);
	return 0;
}
