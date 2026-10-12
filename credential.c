#define DISABLE_SIGN_COMPARE_WARNINGS

#include "git-compat-util.h"
#include "abspath.h"
#include "config.h"
#include "credential.h"
#include "gettext.h"
#include "string-list.h"
#include "run-command.h"
#include "url.h"
#include "prompt.h"
#include "sigchain.h"
#include "strbuf.h"
#include "urlmatch.h"
#include "environment.h"
#include "trace2.h"
#include "repository.h"

void credential_init(struct credential *c)
{
	struct credential blank = CREDENTIAL_INIT;
	memcpy(c, &blank, sizeof(*c));
}

void credential_clear(struct credential *c)
{
	credential_clear_secrets(c);
	free(c->protocol);
	free(c->host);
	free(c->path);
	free(c->username);
	free(c->oauth_refresh_token);
	free(c->authtype);
	free(c->http_method);
	free(c->http_url);
	free(c->dpop_nonce);
	free(c->dpop_helper);
	string_list_clear(&c->helpers, 0);
	strvec_clear(&c->wwwauth_headers);
	strvec_clear(&c->state_headers);
	strvec_clear(&c->state_headers_to_send);

	credential_init(c);
}

void credential_next_state(struct credential *c)
{
	strvec_clear(&c->state_headers_to_send);
	SWAP(c->state_headers, c->state_headers_to_send);
}

void credential_clear_secrets(struct credential *c)
{
	FREE_AND_NULL(c->password);
	FREE_AND_NULL(c->credential);
	FREE_AND_NULL(c->dpop);
}

int credential_is_dpop(const struct credential *c)
{
	return credential_has_capability(&c->capa_dpop, CREDENTIAL_OP_RESPONSE) &&
		(c->dpop || (c->authtype && !strcasecmp(c->authtype, "DPoP")));
}

void credential_set_http_request(struct credential *c, const char *method,
				 const char *url)
{
	free(c->http_method);
	free(c->http_url);
	c->http_method = xstrdup(method);
	c->http_url = xstrdup(url);
	c->capa_authtype.request_initial = 1;
	c->capa_state.request_initial = 1;
	c->capa_dpop.request_initial = 1;
}

static int dpop_value_valid(const char *value, const char *extra)
{
	size_t len;

	if (!value || !(len = strlen(value)) || len > CREDENTIAL_DPOP_MAX_VALUE)
		return 0;
	for (; *value; value++)
		if (!isalnum((unsigned char)*value) && !strchr(extra, *value))
			return 0;
	return 1;
}

static int dpop_request_valid(const struct credential *c)
{
	const char *authority, *p;
	size_t len;

	if (!c->protocol || strcmp(c->protocol, "https") ||
	    !c->host || !c->http_url ||
	    !skip_prefix(c->http_url, "https://", &authority) ||
	    !dpop_value_valid(c->http_method, "-"))
		return 0;
	len = strlen(c->http_url);
	if (len > CREDENTIAL_DPOP_MAX_VALUE || strchr(authority, '#'))
		return 0;
	for (p = c->http_url; *p; p++)
		if ((unsigned char)*p <= ' ' || (unsigned char)*p >= 127)
			return 0;
	len = strcspn(authority, "/?");
	return len == strlen(c->host) &&
		!strncasecmp(authority, c->host, len);
}

static int dpop_credential_valid(const struct credential *c)
{
	const char *p;
	int dots = 0;

	if (c->dpop_invalid ||
	    !credential_has_capability(&c->capa_dpop, CREDENTIAL_OP_RESPONSE) ||
	    !credential_has_capability(&c->capa_authtype, CREDENTIAL_OP_RESPONSE) ||
	    !credential_has_capability(&c->capa_state, CREDENTIAL_OP_RESPONSE) ||
	    !c->authtype || strcasecmp(c->authtype, "DPoP") ||
	    !c->ephemeral || c->multistage || c->password ||
	    c->oauth_refresh_token || c->state_headers.nr != 1 ||
	    !dpop_request_valid(c) ||
	    !dpop_value_valid(c->credential, "-._~+/=") ||
	    !dpop_value_valid(c->dpop, "-_.") ||
	    !dpop_value_valid(c->state_headers.v[0], "-._~+/:=") ||
	    c->password_expiry_utc < time(NULL))
		return 0;

	for (p = c->dpop; *p; p++)
		if (*p == '.') {
			if (p == c->dpop || !p[1] || p[1] == '.')
				return 0;
			dots++;
		}
	return dots == 2;
}

static void credential_set_capability(struct credential_capability *capa,
				      enum credential_op_type op_type)
{
	switch (op_type) {
	case CREDENTIAL_OP_INITIAL:
		capa->request_initial = 1;
		break;
	case CREDENTIAL_OP_HELPER:
		capa->request_helper = 1;
		break;
	case CREDENTIAL_OP_RESPONSE:
		capa->response = 1;
		break;
	}
}


void credential_set_all_capabilities(struct credential *c,
				     enum credential_op_type op_type)
{
	credential_set_capability(&c->capa_authtype, op_type);
	credential_set_capability(&c->capa_state, op_type);
}

static void announce_one(struct credential_capability *cc, const char *name, FILE *fp) {
	if (cc->request_initial)
		fprintf(fp, "capability %s\n", name);
}

void credential_announce_capabilities(struct credential *c, FILE *fp) {
	fprintf(fp, "version 0\n");
	announce_one(&c->capa_authtype, "authtype", fp);
	announce_one(&c->capa_state, "state", fp);
}

int credential_match(const struct credential *want,
		     const struct credential *have, int match_password)
{
#define CHECK(x) (!want->x || (have->x && !strcmp(want->x, have->x)))
	return CHECK(protocol) &&
	       CHECK(host) &&
	       CHECK(path) &&
	       CHECK(username) &&
	       (!match_password || CHECK(password)) &&
	       (!match_password || CHECK(credential));
#undef CHECK
}


static int credential_from_potentially_partial_url(struct credential *c,
						   const char *url);

static int credential_config_callback(const char *var, const char *value,
				      const struct config_context *ctx UNUSED,
				      void *data)
{
	struct credential *c = data;
	const char *key;

	if (!skip_prefix(var, "credential.", &key))
		return 0;

	if (!value)
		return config_error_nonbool(var);

	if (!strcmp(key, "helper")) {
		if (*value)
			string_list_append(&c->helpers, value);
		else
			string_list_clear(&c->helpers, 0);
	} else if (!strcmp(key, "username")) {
		if (!c->username_from_proto) {
			free(c->username);
			c->username = xstrdup(value);
		}
	}
	else if (!strcmp(key, "usehttppath"))
		c->use_http_path = git_config_bool(var, value);
	else if (!strcmp(key, "sanitizeprompt"))
		c->sanitize_prompt = git_config_bool(var, value);
	else if (!strcmp(key, "protectprotocol"))
		c->protect_protocol = git_config_bool(var, value);

	return 0;
}

static int proto_is_http(const char *s)
{
	if (!s)
		return 0;
	return !strcmp(s, "https") || !strcmp(s, "http");
}

static void credential_describe(struct credential *c, struct strbuf *out);
static void credential_format(struct credential *c, struct strbuf *out);

static int select_all(const struct urlmatch_item *a UNUSED,
		      const struct urlmatch_item *b UNUSED)
{
	return 0;
}

static int match_partial_url(const char *url, void *cb)
{
	struct credential *c = cb;
	struct credential want = CREDENTIAL_INIT;
	int matches = 0;

	if (credential_from_potentially_partial_url(&want, url) < 0)
		warning(_("skipping credential lookup for key: credential.%s"),
			url);
	else
		matches = credential_match(&want, c, 0);
	credential_clear(&want);

	return matches;
}

static void credential_apply_config(struct repository *r, struct credential *c)
{
	char *normalized_url;
	struct urlmatch_config config = URLMATCH_CONFIG_INIT;
	struct strbuf url = STRBUF_INIT;

	if (!c->host)
		die(_("refusing to work with credential missing host field"));
	if (!c->protocol)
		die(_("refusing to work with credential missing protocol field"));

	if (c->configured)
		return;

	config.section = "credential";
	config.key = NULL;
	config.collect_fn = credential_config_callback;
	config.cascade_fn = NULL;
	config.select_fn = select_all;
	config.fallback_match_fn = match_partial_url;
	config.cb = c;

	credential_format(c, &url);
	normalized_url = url_normalize(url.buf, &config.url);

	repo_config(r, urlmatch_config_entry, &config);
	string_list_clear(&config.vars, 1);
	free(normalized_url);
	urlmatch_config_release(&config);
	strbuf_release(&url);

	c->configured = 1;

	if (!c->use_http_path && proto_is_http(c->protocol)) {
		FREE_AND_NULL(c->path);
	}
}

static void credential_describe(struct credential *c, struct strbuf *out)
{
	if (!c->protocol)
		return;
	strbuf_addf(out, "%s://", c->protocol);
	if (c->username && *c->username)
		strbuf_addf(out, "%s@", c->username);
	if (c->host)
		strbuf_addstr(out, c->host);
	if (c->path)
		strbuf_addf(out, "/%s", c->path);
}

static void credential_format(struct credential *c, struct strbuf *out)
{
	if (!c->protocol)
		return;
	strbuf_addf(out, "%s://", c->protocol);
	if (c->username && *c->username) {
		strbuf_add_percentencode(out, c->username, STRBUF_ENCODE_SLASH);
		strbuf_addch(out, '@');
	}
	if (c->host)
		strbuf_add_percentencode(out, c->host,
					 STRBUF_ENCODE_HOST_AND_PORT);
	if (c->path) {
		strbuf_addch(out, '/');
		strbuf_add_percentencode(out, c->path, 0);
	}
}

static char *credential_ask_one(const char *what, struct credential *c,
				int flags)
{
	struct strbuf desc = STRBUF_INIT;
	struct strbuf prompt = STRBUF_INIT;
	char *r;

	if (c->sanitize_prompt)
		credential_format(c, &desc);
	else
		credential_describe(c, &desc);
	if (desc.len)
		strbuf_addf(&prompt, "%s for '%s': ", what, desc.buf);
	else
		strbuf_addf(&prompt, "%s: ", what);

	r = git_prompt(prompt.buf, flags);

	strbuf_release(&desc);
	strbuf_release(&prompt);
	return xstrdup(r);
}

static int credential_getpass(struct repository *r, struct credential *c)
{
	int interactive;
	char *value;
	if (!repo_config_get_maybe_bool(r, "credential.interactive", &interactive) &&
	    !interactive) {
		trace2_data_intmax("credential", r,
				   "interactive/skipped", 1);
		return -1;
	}
	if (!repo_config_get_string(r, "credential.interactive", &value)) {
		int same = !strcmp(value, "never");
		free(value);
		if (same) {
			trace2_data_intmax("credential", r,
					   "interactive/skipped", 1);
			return -1;
		}
	}

	trace2_region_enter("credential", "interactive", r);
	if (!c->username)
		c->username = credential_ask_one("Username", c,
						 PROMPT_ASKPASS|PROMPT_ECHO);
	if (!c->password)
		c->password = credential_ask_one("Password", c,
						 PROMPT_ASKPASS);
	trace2_region_leave("credential", "interactive", r);

	return 0;
}

int credential_has_capability(const struct credential_capability *capa,
			      enum credential_op_type op_type)
{
	/*
	 * We're checking here if each previous step indicated that we had the
	 * capability.  If it did, then we want to pass it along; conversely, if
	 * it did not, we don't want to report that to our caller.
	 */
	switch (op_type) {
	case CREDENTIAL_OP_HELPER:
		return capa->request_initial;
	case CREDENTIAL_OP_RESPONSE:
		return capa->request_initial && capa->request_helper;
	default:
		return 0;
	}
}

int credential_read(struct credential *c, FILE *fp,
		    enum credential_op_type op_type)
{
	struct strbuf line = STRBUF_INIT;
	int authtype_seen = 0, credential_seen = 0, dpop_seen = 0;
	int ephemeral_seen = 0;
	int authtype_cap = 0, state_cap = 0, dpop_cap = 0;
	int invalid = 0, selected = 0;
	int request_dpop = c->capa_dpop.request_initial;
	size_t state_start = c->state_headers.nr;

	while (strbuf_getline(&line, fp) != EOF) {
		char *key = line.buf;
		char *value = strchr(key, '=');

		if (!line.len)
			break;
		if (request_dpop &&
		    (line.len > 65534 || strlen(line.buf) != line.len)) {
			warning("invalid credential line length");
			strbuf_release(&line);
			return -1;
		}

		if (!value) {
			warning("invalid credential line: %s", key);
			strbuf_release(&line);
			return -1;
		}
		*value++ = '\0';

		if (!strcmp(key, "username")) {
			free(c->username);
			c->username = xstrdup(value);
			c->username_from_proto = 1;
		} else if (!strcmp(key, "password")) {
			free(c->password);
			c->password = xstrdup(value);
		} else if (!strcmp(key, "credential")) {
			credential_seen++;
			if (!authtype_cap)
				invalid = 1;
			free(c->credential);
			c->credential = xstrdup(value);
		} else if (!strcmp(key, "protocol")) {
			free(c->protocol);
			c->protocol = xstrdup(value);
		} else if (!strcmp(key, "host")) {
			free(c->host);
			c->host = xstrdup(value);
		} else if (!strcmp(key, "path")) {
			free(c->path);
			c->path = xstrdup(value);
		} else if (!strcmp(key, "ephemeral")) {
			ephemeral_seen++;
			c->ephemeral_received = 1;
			if (!authtype_cap)
				invalid = 1;
			c->ephemeral = !!git_config_bool("ephemeral", value);
		} else if (!strcmp(key, "wwwauth[]")) {
			strvec_push(&c->wwwauth_headers, value);
		} else if (!strcmp(key, "state[]")) {
			if (!state_cap)
				invalid = 1;
			strvec_push(&c->state_headers, value);
		} else if (!strcmp(key, "capability[]")) {
			if (!strcmp(value, "authtype")) {
				authtype_cap = 1;
				credential_set_capability(&c->capa_authtype, op_type);
			} else if (!strcmp(value, "state")) {
				state_cap = 1;
				credential_set_capability(&c->capa_state, op_type);
			} else if (!strcmp(value, "dpop")) {
				if (op_type == CREDENTIAL_OP_INITIAL && !request_dpop)
					goto unsupported;
				if (!request_dpop)
					continue;
				dpop_cap = 1;
				credential_set_capability(&c->capa_dpop, op_type);
			}
		} else if (!strcmp(key, "continue")) {
			c->multistage_received = 1;
			c->multistage = !!git_config_bool("continue", value);
		} else if (!strcmp(key, "password_expiry_utc")) {
			c->expiry_received = 1;
			errno = 0;
			c->password_expiry_utc = parse_timestamp(value, NULL, 10);
			if (c->password_expiry_utc == 0 || errno == ERANGE)
				c->password_expiry_utc = TIME_MAX;
		} else if (!strcmp(key, "oauth_refresh_token")) {
			free(c->oauth_refresh_token);
			c->oauth_refresh_token = xstrdup(value);
		} else if (!strcmp(key, "authtype")) {
			authtype_seen++;
			if (request_dpop && !strcasecmp(value, "DPoP"))
				selected = 1;
			if (!authtype_cap)
				invalid = 1;
			free(c->authtype);
			c->authtype = xstrdup(value);
		} else if (!strcmp(key, "dpop")) {
			if (op_type == CREDENTIAL_OP_INITIAL && !request_dpop)
				goto unsupported;
			if (!request_dpop)
				continue;
			selected = 1;
			dpop_seen++;
			if (!dpop_cap)
				invalid = 1;
			free(c->dpop);
			c->dpop = xstrdup(value);
		} else if (!strcmp(key, "http-method") ||
			   !strcmp(key, "http-url")) {
			if (op_type == CREDENTIAL_OP_INITIAL && !request_dpop)
				goto unsupported;
			if (!request_dpop)
				continue;
			if (op_type != CREDENTIAL_OP_INITIAL) {
				invalid = 1;
			} else if (!strcmp(key, "http-method")) {
				free(c->http_method);
				c->http_method = xstrdup(value);
			} else {
				free(c->http_url);
				c->http_url = xstrdup(value);
			}
		} else if (!strcmp(key, "http-status") ||
			   !strcmp(key, "dpop-nonce")) {
			if (op_type == CREDENTIAL_OP_INITIAL && !request_dpop)
				goto unsupported;
			/* These are one-way response observations, not credentials. */
			if (request_dpop && op_type == CREDENTIAL_OP_HELPER)
				invalid = 1;
		} else if (!strcmp(key, "url")) {
			credential_from_url(c, value);
		} else if (!strcmp(key, "quit")) {
			c->quit = !!git_config_bool("quit", value);
		}
		/*
		 * Ignore other lines; we don't know what they mean, but
		 * this future-proofs us when later versions of git do
		 * learn new lines, and the helpers are updated to match.
		 */
	}

	if (request_dpop && op_type == CREDENTIAL_OP_HELPER &&
	    (dpop_seen || (dpop_cap && selected))) {
		char *state = NULL;

		if (c->state_headers.nr == state_start + 1)
			state = xstrdup(c->state_headers.v[state_start]);
		strvec_clear(&c->state_headers);
		if (state)
			strvec_push_nodup(&c->state_headers, state);
		c->dpop_invalid = invalid || !authtype_cap || !state_cap ||
			!credential_has_capability(&c->capa_dpop, CREDENTIAL_OP_RESPONSE) ||
			!dpop_cap || authtype_seen != 1 || credential_seen != 1 ||
			dpop_seen != 1 || ephemeral_seen != 1 || !state;
	}
	strbuf_release(&line);
	return 0;

unsupported:
	warning("request-bound DPoP is supported only by the HTTP transport");
	strbuf_release(&line);
	return -1;
}

static void credential_write_item(const struct credential *c,
				  FILE *fp, const char *key, const char *value,
				  int required)
{
	if (!value && required)
		BUG("credential value for %s is missing", key);
	if (!value)
		return;
	if (strchr(value, '\n'))
		die("credential value for %s contains newline", key);
	if (c->protect_protocol && strchr(value, '\r'))
		die("credential value for %s contains carriage return\n"
		    "If this is intended, set `credential.protectProtocol=false`",
		    key);
	fprintf(fp, "%s=%s\n", key, value);
}

void credential_write(const struct credential *c, FILE *fp,
		      enum credential_op_type op_type)
{
	if (credential_has_capability(&c->capa_authtype, op_type))
		credential_write_item(c, fp, "capability[]", "authtype", 0);
	if (credential_has_capability(&c->capa_state, op_type))
		credential_write_item(c, fp, "capability[]", "state", 0);
	if (credential_has_capability(&c->capa_dpop, op_type))
		credential_write_item(c, fp, "capability[]", "dpop", 0);

	if (credential_has_capability(&c->capa_authtype, op_type)) {
		credential_write_item(c, fp, "authtype", c->authtype, 0);
		credential_write_item(c, fp, "credential", c->credential, 0);
		if (c->ephemeral)
			credential_write_item(c, fp, "ephemeral", "1", 0);
	}
	credential_write_item(c, fp, "protocol", c->protocol, 1);
	credential_write_item(c, fp, "host", c->host, 1);
	credential_write_item(c, fp, "path", c->path, 0);
	credential_write_item(c, fp, "username", c->username, 0);
	credential_write_item(c, fp, "password", c->password, 0);
	credential_write_item(c, fp, "oauth_refresh_token", c->oauth_refresh_token, 0);
	if (credential_has_capability(&c->capa_dpop, op_type)) {
		credential_write_item(c, fp, "http-method", c->http_method, 0);
		credential_write_item(c, fp, "http-url", c->http_url, 0);
		credential_write_item(c, fp, "dpop", c->dpop, 0);
		credential_write_item(c, fp, "dpop-nonce", c->dpop_nonce, 0);
		if (c->http_status >= 0)
			fprintf(fp, "http-status=%ld\n", c->http_status);
	}
	if (c->password_expiry_utc != TIME_MAX) {
		char *s = xstrfmt("%"PRItime, c->password_expiry_utc);
		credential_write_item(c, fp, "password_expiry_utc", s, 0);
		free(s);
	}
	for (size_t i = 0; i < c->wwwauth_headers.nr; i++)
		credential_write_item(c, fp, "wwwauth[]", c->wwwauth_headers.v[i], 0);
	if (credential_has_capability(&c->capa_state, op_type)) {
		if (c->multistage)
			credential_write_item(c, fp, "continue", "1", 0);
		for (size_t i = 0; i < c->state_headers_to_send.nr; i++)
			credential_write_item(c, fp, "state[]", c->state_headers_to_send.v[i], 0);
	}
}

static int run_credential_helper(const struct credential *c,
				 struct credential *response,
				 const char *cmd,
				 int want_output)
{
	struct child_process helper = CHILD_PROCESS_INIT;
	FILE *fp;

	strvec_push(&helper.args, cmd);
	helper.use_shell = 1;
	helper.in = -1;
	if (want_output)
		helper.out = -1;
	else
		helper.no_stdout = 1;

	if (start_command(&helper) < 0)
		return -1;

	fp = xfdopen(helper.in, "w");
	sigchain_push(SIGPIPE, SIG_IGN);
	credential_write(c, fp, want_output ? CREDENTIAL_OP_HELPER : CREDENTIAL_OP_RESPONSE);
	fclose(fp);
	sigchain_pop(SIGPIPE);

	if (want_output) {
		int r;
		fp = xfdopen(helper.out, "r");
		r = credential_read(response, fp, CREDENTIAL_OP_HELPER);
		fclose(fp);
		if (r < 0) {
			finish_command(&helper);
			return -1;
		}
	}

	if (finish_command(&helper))
		return -1;
	return 0;
}

static int credential_do(struct credential *c, const char *helper,
			 const char *operation, struct credential *response)
{
	struct strbuf cmd = STRBUF_INIT;
	int r;

	if (helper[0] == '!')
		strbuf_addstr(&cmd, helper + 1);
	else if (is_absolute_path(helper))
		strbuf_addstr(&cmd, helper);
	else
		strbuf_addf(&cmd, "git credential-%s", helper);

	strbuf_addf(&cmd, " %s", operation);
	r = run_credential_helper(c, response, cmd.buf, !strcmp(operation, "get"));

	strbuf_release(&cmd);
	return r;
}

/*
 * Copy only lookup/request context. Helper output is always read into a
 * separate instance, so an earlier password, capability or ephemeral flag
 * cannot complete or invalidate a later DPoP response. The query sent to a
 * helper is built separately; see credential_fill_http().
 */
static void copy_http_credential_context(struct credential *dst,
					 const struct credential *src)
{
	dst->protocol = xstrdup_or_null(src->protocol);
	dst->host = xstrdup_or_null(src->host);
	dst->path = xstrdup_or_null(src->path);
	dst->username = xstrdup_or_null(src->username);
	dst->username_from_proto = src->username_from_proto;
	dst->configured = src->configured;
	dst->use_http_path = src->use_http_path;
	dst->sanitize_prompt = src->sanitize_prompt;
	dst->protect_protocol = src->protect_protocol;
	credential_set_http_request(dst, src->http_method, src->http_url);
	for (size_t i = 0; i < src->helpers.nr; i++)
		string_list_append(&dst->helpers, src->helpers.items[i].string);
}

static void merge_credential_string(char **dst, char **src)
{
	if (*src) {
		free(*dst);
		*dst = *src;
		*src = NULL;
	}
}

/*
 * Ordinary helpers may contribute partial credentials. Merge only after
 * excluding a DPoP response, which must remain entirely self-contained.
 */
static void merge_ordinary_response(struct credential *c,
				    struct credential *response)
{
	if (response->username)
		c->username_from_proto = response->username_from_proto;
	merge_credential_string(&c->username, &response->username);
	merge_credential_string(&c->password, &response->password);
	merge_credential_string(&c->credential, &response->credential);
	merge_credential_string(&c->authtype, &response->authtype);
	merge_credential_string(&c->protocol, &response->protocol);
	merge_credential_string(&c->host, &response->host);
	merge_credential_string(&c->path, &response->path);
	merge_credential_string(&c->oauth_refresh_token, &response->oauth_refresh_token);
	if (response->ephemeral_received)
		c->ephemeral = response->ephemeral;
	if (response->multistage_received)
		c->multistage = response->multistage;
	if (response->expiry_received)
		c->password_expiry_utc = response->password_expiry_utc;
	c->quit = response->quit;
	c->capa_authtype.request_helper |= response->capa_authtype.request_helper;
	c->capa_state.request_helper |= response->capa_state.request_helper;
	strvec_pushv(&c->state_headers, response->state_headers.v);
	strvec_pushv(&c->wwwauth_headers, response->wwwauth_headers.v);
}

static void credential_fill_http(struct repository *r, struct credential *c)
{
	credential_apply_config(r, c);
	if (!c->protect_protocol)
		die("request-bound authentication requires credential.protectProtocol");
	if (!dpop_request_valid(c))
		die("DPoP request URL does not match the HTTPS credential scope");

	credential_next_state(c);
	c->multistage = 0;
	for (size_t i = 0; i < c->helpers.nr; i++) {
		const char *helper = c->helpers.items[i].string;
		struct credential query = CREDENTIAL_INIT;
		struct credential response = CREDENTIAL_INIT;
		int ret;

		if (c->dpop_helper && strcmp(c->dpop_helper, helper))
			continue;
		copy_http_credential_context(&query, c);
		/*
		 * Query every candidate as a lookup without negotiation would.
		 * The ordinary partial credential gathered so far, such as a
		 * refresh token returned with an expired password, is input to
		 * trusted helpers. Only the response, read below into its own
		 * instance, is isolated from it.
		 */
		query.password = xstrdup_or_null(c->password);
		query.credential = xstrdup_or_null(c->credential);
		query.oauth_refresh_token = xstrdup_or_null(c->oauth_refresh_token);
		query.authtype = xstrdup_or_null(c->authtype);
		query.ephemeral = c->ephemeral;
		query.multistage = c->multistage;
		query.password_expiry_utc = c->password_expiry_utc;
		strvec_pushv(&query.wwwauth_headers, c->wwwauth_headers.v);
		strvec_pushv(&query.state_headers_to_send, c->state_headers_to_send.v);
		copy_http_credential_context(&response, &query);
		ret = credential_do(&query, helper, "get", &response);
		credential_clear(&query);
		if (credential_is_dpop(&response) || response.dpop_invalid ||
		    c->dpop_helper) {
			if (ret || !dpop_credential_valid(&response)) {
				credential_clear(&response);
				die("invalid DPoP credential response");
			}
			response.dpop_helper = xstrdup(helper);
			strvec_clear(&response.wwwauth_headers);
			credential_clear(c);
			*c = response;
			return;
		}
		merge_ordinary_response(c, &response);
		credential_clear(&response);
		if (c->password_expiry_utc < time(NULL)) {
			credential_clear_secrets(c);
			c->password_expiry_utc = TIME_MAX;
		}
		if ((c->username && c->password) || c->credential) {
			strvec_clear(&c->wwwauth_headers);
			goto ordinary;
		}
		if (c->quit)
			die("credential helper '%s' told us to quit", helper);
	}
	if (c->dpop_helper)
		die("DPoP credential helper is no longer configured");
	if (credential_getpass(r, c) ||
	    (!c->username && !c->password && !c->credential))
		die("unable to get password from user");

ordinary:
	memset(&c->capa_dpop, 0, sizeof(c->capa_dpop));
	FREE_AND_NULL(c->http_method);
	FREE_AND_NULL(c->http_url);
}

void credential_fill(struct repository *r,
		     struct credential *c, int all_capabilities)
{
	int i;

	if (credential_is_dpop(c))
		die("refusing to reuse a DPoP proof");
	if (c->capa_dpop.request_initial) {
		if (c->dpop)
			die("refusing to reuse a DPoP proof");
		credential_fill_http(r, c);
		return;
	}
	if ((c->username && c->password) || c->credential)
		return;

	credential_next_state(c);
	c->multistage = 0;

	credential_apply_config(r, c);
	if (all_capabilities)
		credential_set_all_capabilities(c, CREDENTIAL_OP_INITIAL);

	for (i = 0; i < c->helpers.nr; i++) {
		credential_do(c, c->helpers.items[i].string, "get", c);

		if (c->password_expiry_utc < time(NULL)) {
			/*
			 * Don't use credential_clear() here: callers such as
			 * cmd_credential() expect to still be able to call
			 * credential_write() on a struct credential whose
			 * secrets have expired.
			 */
			credential_clear_secrets(c);
			/* Reset expiry to maintain consistency */
			c->password_expiry_utc = TIME_MAX;
		}
		if ((c->username && c->password) || c->credential) {
			strvec_clear(&c->wwwauth_headers);
			return;
		}
		if (c->quit)
			die("credential helper '%s' told us to quit",
			    c->helpers.items[i].string);
	}

	if (credential_getpass(r, c) ||
	    (!c->username && !c->password && !c->credential))
		die("unable to get password from user");
}

void credential_approve(struct repository *r, struct credential *c)
{
	int i;

	if (credential_is_dpop(c) || c->dpop_helper || c->dpop_invalid) {
		credential_clear_secrets(c);
		return;
	}
	if (c->approved)
		return;
	if (((!c->username || !c->password) && !c->credential) || c->password_expiry_utc < time(NULL))
		return;

	credential_next_state(c);

	credential_apply_config(r, c);

	for (i = 0; i < c->helpers.nr; i++)
		credential_do(c, c->helpers.items[i].string, "store", NULL);
	c->approved = 1;
}

void credential_reject(struct repository *r, struct credential *c)
{
	int i;

	if (credential_is_dpop(c) || c->dpop_helper || c->dpop_invalid) {
		credential_clear_secrets(c);
		return;
	}
	credential_next_state(c);

	credential_apply_config(r, c);

	for (i = 0; i < c->helpers.nr; i++)
		credential_do(c, c->helpers.items[i].string, "erase", NULL);

	credential_clear_secrets(c);
	FREE_AND_NULL(c->username);
	FREE_AND_NULL(c->oauth_refresh_token);
	c->password_expiry_utc = TIME_MAX;
	c->approved = 0;
}

int credential_dpop_observe(struct credential *c, long status)
{
	int ret;

	if (!c->dpop_helper)
		return 0;
	credential_clear_secrets(c);
	if (!status) {
		FREE_AND_NULL(c->dpop_nonce);
		strvec_clear(&c->wwwauth_headers);
	}
	c->http_status = status;
	credential_next_state(c);
	ret = credential_do(c, c->dpop_helper, "observe", NULL);
	if (ret)
		warning(_("DPoP response bookkeeping failed"));
	return ret;
}

static int check_url_component(const char *url, int quiet,
			       const char *name, const char *value)
{
	if (!value)
		return 0;
	if (!strchr(value, '\n'))
		return 0;

	if (!quiet)
		warning(_("url contains a newline in its %s component: %s"),
			name, url);
	return -1;
}

/*
 * Potentially-partial URLs can, but do not have to, contain
 *
 * - a protocol (or scheme) of the form "<protocol>://"
 *
 * - a host name (the part after the protocol and before the first slash after
 *   that, if any)
 *
 * - a user name and potentially a password (as "<user>[:<password>]@" part of
 *   the host name)
 *
 * - a path (the part after the host name, if any, starting with the slash)
 *
 * Missing parts will be left unset in `struct credential`. Thus, `https://`
 * will have only the `protocol` set, `example.com` only the host name, and
 * `/git` only the path.
 *
 * Note that an empty host name in an otherwise fully-qualified URL (e.g.
 * `cert:///path/to/cert.pem`) will be treated as unset if we expect the URL to
 * be potentially partial, and only then (otherwise, the empty string is used).
 *
 * The credential_from_url() function does not allow partial URLs.
 */
static int credential_from_url_1(struct credential *c, const char *url,
				 int allow_partial_url, int quiet)
{
	const char *at, *colon, *cp, *slash, *host, *proto_end;

	credential_clear(c);

	/*
	 * Match one of:
	 *   (1) proto://<host>/...
	 *   (2) proto://<user>@<host>/...
	 *   (3) proto://<user>:<pass>@<host>/...
	 */
	proto_end = strstr(url, "://");
	if (!allow_partial_url && (!proto_end || proto_end == url)) {
		if (!quiet)
			warning(_("url has no scheme: %s"), url);
		return -1;
	}
	cp = proto_end ? proto_end + 3 : url;
	at = strchr(cp, '@');
	colon = strchr(cp, ':');

	/*
	 * A query or fragment marker before the slash ends the host portion.
	 * We'll just continue to call this "slash" for simplicity. Notably our
	 * "trim leading slashes" part won't skip over this part of the path,
	 * but that's what we'd want.
	 */
	slash = cp + strcspn(cp, "/?#");

	if (!at || slash <= at) {
		/* Case (1) */
		host = cp;
	}
	else if (!colon || at <= colon) {
		/* Case (2) */
		c->username = url_decode_mem(cp, at - cp);
		if (c->username && *c->username)
			c->username_from_proto = 1;
		host = at + 1;
	} else {
		/* Case (3) */
		c->username = url_decode_mem(cp, colon - cp);
		if (c->username && *c->username)
			c->username_from_proto = 1;
		c->password = url_decode_mem(colon + 1, at - (colon + 1));
		host = at + 1;
	}

	if (proto_end && proto_end - url > 0)
		c->protocol = xmemdupz(url, proto_end - url);
	if (!allow_partial_url || slash - host > 0)
		c->host = url_decode_mem(host, slash - host);
	/* Trim leading and trailing slashes from path */
	while (*slash == '/')
		slash++;
	if (*slash) {
		char *p;
		c->path = url_decode(slash);
		p = c->path + strlen(c->path) - 1;
		while (p > c->path && *p == '/')
			*p-- = '\0';
	}

	if (check_url_component(url, quiet, "username", c->username) < 0 ||
	    check_url_component(url, quiet, "password", c->password) < 0 ||
	    check_url_component(url, quiet, "protocol", c->protocol) < 0 ||
	    check_url_component(url, quiet, "host", c->host) < 0 ||
	    check_url_component(url, quiet, "path", c->path) < 0)
		return -1;

	return 0;
}

static int credential_from_potentially_partial_url(struct credential *c,
						   const char *url)
{
	return credential_from_url_1(c, url, 1, 0);
}

int credential_from_url_gently(struct credential *c, const char *url, int quiet)
{
	return credential_from_url_1(c, url, 0, quiet);
}

void credential_from_url(struct credential *c, const char *url)
{
	if (credential_from_url_gently(c, url, 0) < 0)
		die(_("credential url cannot be parsed: %s"), url);
}
