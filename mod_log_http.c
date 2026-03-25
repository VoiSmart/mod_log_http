/*
 * mod_log_http for FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * mod_log_http.c -- HTTP JSON logger
 *
 * Sends FreeSWITCH logs as JSON via HTTP(S) POST.
 * Designed for FluentBit/FluentD HTTP input, but works with any
 * HTTP endpoint that accepts JSON POST requests.
 *
 */
#include <switch.h>
#include <switch_curl.h>

#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_log_http_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_log_http_shutdown);
SWITCH_MODULE_DEFINITION(mod_log_http, mod_log_http_load, mod_log_http_shutdown, NULL);
static switch_status_t mod_log_http_logger(const switch_log_node_t *node, switch_log_level_t level);

#define MAX_URLS 20
#define MAX_BATCH_SIZE 200
#define LOG_QUEUE_SIZE 25000
#define MAX_BACKOFF_SECS 60
#define MAX_DELAY_SECS 300
#define MAX_TIMEOUT_SECS 300
#define WORKER_STARTUP_TIMEOUT_USEC 5000000
#define DROP_WARN_INTERVAL 60000000 /* 60 seconds in microseconds */
#define MY_SOURCE_FILE "mod_log_http.c"

typedef enum {
	WORKER_STARTUP_PENDING = 0,
	WORKER_STARTUP_RUNNING,
	WORKER_STARTUP_FAILED
} worker_startup_state_t;

static struct {
	switch_memory_pool_t *pool;
	char *urls[MAX_URLS];
	int url_count;
	int url_index;
	switch_log_level_t log_level;
	int shutdown;
	switch_thread_t *worker_thread;
	int worker_started;
	int logger_bound;
	switch_queue_t *log_queue;
	switch_event_t *session_fields;
	cJSON *static_properties;
	switch_log_json_format_t json_format;
	switch_mutex_t *startup_mutex;
	switch_thread_cond_t *startup_cond;
	worker_startup_state_t startup_state;
	switch_status_t startup_status;
	/* HTTP options */
	int timeout;
	uint32_t retries;
	uint32_t delay;
	int disable100continue;
	/* SSL options */
	char *ssl_cert_file;
	char *ssl_key_file;
	char *ssl_key_password;
	char *ssl_cacert_file;
	uint32_t enable_cacert_check;
	uint32_t enable_ssl_verifyhost;
	/* Batching */
	int batch_size;
	int batch_timeout_ms;
} globals;

static switch_time_t last_drop_warning = 0;

static switch_bool_t generated_field_name_matches(const char *name, const char *generated_name)
{
	return (!zstr(name) && !zstr(generated_name) && !strcmp(name, generated_name)) ? SWITCH_TRUE : SWITCH_FALSE;
}

static switch_bool_t static_property_conflicts_with_generated_field(const char *name)
{
	if (zstr(name)) {
		return SWITCH_FALSE;
	}

	if (generated_field_name_matches(name, globals.json_format.version.name) ||
		generated_field_name_matches(name, globals.json_format.host.name) ||
		generated_field_name_matches(name, globals.json_format.timestamp.name) ||
		generated_field_name_matches(name, globals.json_format.level.name) ||
		generated_field_name_matches(name, globals.json_format.ident.name) ||
		generated_field_name_matches(name, globals.json_format.pid.name) ||
		generated_field_name_matches(name, globals.json_format.uuid.name) ||
		generated_field_name_matches(name, globals.json_format.file.name) ||
		generated_field_name_matches(name, globals.json_format.line.name) ||
		generated_field_name_matches(name, globals.json_format.function.name) ||
		generated_field_name_matches(name, globals.json_format.full_message.name) ||
		generated_field_name_matches(name, globals.json_format.short_message.name) ||
		generated_field_name_matches(name, globals.json_format.sequence.name) ||
		generated_field_name_matches(name, "level_name")) {
		return SWITCH_TRUE;
	}

	return SWITCH_FALSE;
}

static char *property_path_join(const char *parent_path, const char *name)
{
	if (zstr(name)) {
		return switch_mprintf("%s", zstr(parent_path) ? "<unnamed>" : parent_path);
	}

	if (zstr(parent_path)) {
		return switch_mprintf("%s", name);
	}

	return switch_mprintf("%s.%s", parent_path, name);
}

static switch_status_t parse_static_property_children(switch_xml_t parent, cJSON *target, const char *parent_path, switch_bool_t top_level);

static cJSON *parse_static_property_item(switch_xml_t prop, const char *property_path, switch_status_t *status)
{
	const char *ptype = switch_xml_attr(prop, "type");
	const char *pvalue = switch_xml_attr(prop, "value");
	switch_xml_t child = switch_xml_child(prop, "property");
	switch_bool_t has_object_children = child ? SWITCH_TRUE : SWITCH_FALSE;
	switch_bool_t explicit_object = (!zstr(ptype) && !strcasecmp(ptype, "object")) ? SWITCH_TRUE : SWITCH_FALSE;
	cJSON *item = NULL;

	*status = SWITCH_STATUS_FALSE;

	if (has_object_children) {
		if (!zstr(ptype) && !explicit_object) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": object property cannot use type \"%s\"\n",
							  property_path, ptype);
			return NULL;
		}

		if (pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring value attribute for object property \"%s\"\n",
							  property_path);
		}

		item = cJSON_CreateObject();
		if (!item) {
			*status = SWITCH_STATUS_MEMERR;
			return NULL;
		}

		*status = parse_static_property_children(prop, item, property_path, SWITCH_FALSE);
		if (*status != SWITCH_STATUS_SUCCESS) {
			cJSON_Delete(item);
			return NULL;
		}

		return item;
	}

	if (explicit_object) {
		if (pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring value attribute for object property \"%s\"\n",
							  property_path);
		}

		item = cJSON_CreateObject();
		if (!item) {
			*status = SWITCH_STATUS_MEMERR;
			return NULL;
		}

		*status = SWITCH_STATUS_SUCCESS;
		return item;
	}

	if (zstr(ptype) || !strcasecmp(ptype, "string")) {
		if (!pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": missing value attribute\n",
							  property_path);
			return NULL;
		}

		item = cJSON_CreateString(pvalue);
	} else if (!strcasecmp(ptype, "bool")) {
		if (!pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": missing value attribute\n",
							  property_path);
			return NULL;
		}

		if (switch_true(pvalue)) {
			item = cJSON_CreateTrue();
		} else if (switch_false(pvalue)) {
			item = cJSON_CreateFalse();
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": invalid bool value \"%s\"\n",
							  property_path, pvalue);
			return NULL;
		}
	} else if (!strcasecmp(ptype, "int")) {
		char *end = NULL;
		long value;

		if (!pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": missing value attribute\n",
							  property_path);
			return NULL;
		}

		errno = 0;
		value = strtol(pvalue, &end, 10);
		if (end == pvalue || *end != '\0' || errno == ERANGE || value < INT_MIN || value > INT_MAX) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": invalid int value \"%s\"\n",
							  property_path, pvalue);
			return NULL;
		}

		item = cJSON_CreateNumber((double)value);
	} else if (!strcasecmp(ptype, "number")) {
		char *end = NULL;
		double value;

		if (!pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": missing value attribute\n",
							  property_path);
			return NULL;
		}

		errno = 0;
		value = strtod(pvalue, &end);
		if (end == pvalue || *end != '\0' || errno == ERANGE) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring property \"%s\": invalid number value \"%s\"\n",
							  property_path, pvalue);
			return NULL;
		}

		item = cJSON_CreateNumber(value);
	} else if (!strcasecmp(ptype, "null")) {
		if (pvalue) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring value attribute for null property \"%s\"\n",
							  property_path);
		}

		item = cJSON_CreateNull();
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
						  "Ignoring property \"%s\": unsupported type \"%s\"\n",
						  property_path, ptype);
		return NULL;
	}

	if (!item) {
		*status = SWITCH_STATUS_MEMERR;
		return NULL;
	}

	*status = SWITCH_STATUS_SUCCESS;
	return item;
}

static switch_status_t parse_static_property_children(switch_xml_t parent, cJSON *target, const char *parent_path, switch_bool_t top_level)
{
	switch_xml_t prop;

	for (prop = switch_xml_child(parent, "property"); prop; prop = prop->next) {
		const char *pname = switch_xml_attr(prop, "name");
		char *property_path = NULL;
		cJSON *item = NULL;
		switch_status_t status = SWITCH_STATUS_SUCCESS;

		if (zstr(pname)) {
			if (zstr(parent_path)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
								  "Ignoring unnamed property\n");
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
								  "Ignoring unnamed property under \"%s\"\n",
								  parent_path);
			}
			continue;
		}

		property_path = property_path_join(parent_path, pname);
		if (!property_path) {
			return SWITCH_STATUS_MEMERR;
		}

		if (top_level && static_property_conflicts_with_generated_field(pname)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring static property \"%s\": conflicts with generated log field\n",
							  property_path);
			free(property_path);
			continue;
		}

		if (cJSON_GetObjectItemCaseSensitive(target, pname)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Ignoring duplicate property \"%s\"\n",
							  property_path);
			free(property_path);
			continue;
		}

		item = parse_static_property_item(prop, property_path, &status);
		if (status == SWITCH_STATUS_MEMERR) {
			free(property_path);
			return status;
		}

		if (status == SWITCH_STATUS_SUCCESS && item) {
			cJSON_AddItemToObject(target, pname, item);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
							  "Added static property \"%s\"\n",
							  property_path);
		}

		free(property_path);
	}

	return SWITCH_STATUS_SUCCESS;
}

static void merge_static_properties(cJSON *json)
{
	cJSON *dup;
	cJSON *child;
	cJSON *next;

	if (!json || !globals.static_properties || !globals.static_properties->child) {
		return;
	}

	dup = cJSON_Duplicate(globals.static_properties, cJSON_True);
	if (!dup) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
						  "mod_log_http: failed to duplicate static properties, continuing without them\n");
		return;
	}

	for (child = dup->child; child; child = next) {
		next = child->next;

		if (cJSON_GetObjectItemCaseSensitive(json, child->string)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
							  "Skipping static property \"%s\": log entry already contains that field\n",
							  switch_str_nil(child->string));
			cJSON_Delete(cJSON_DetachItemViaPointer(dup, child));
			continue;
		}

		cJSON_AddItemToObject(json, child->string, cJSON_DetachItemViaPointer(dup, child));
	}

	cJSON_Delete(dup);
}

static void signal_worker_startup(worker_startup_state_t state, switch_status_t status)
{
	if (!globals.startup_mutex || !globals.startup_cond) {
		return;
	}

	switch_mutex_lock(globals.startup_mutex);
	globals.startup_state = state;
	globals.startup_status = status;
	switch_thread_cond_signal(globals.startup_cond);
	switch_mutex_unlock(globals.startup_mutex);
}

static switch_status_t append_header(switch_curl_slist_t **headers, const char *value)
{
	switch_curl_slist_t *new_headers = switch_curl_slist_append(*headers, value);

	if (!new_headers) {
		return SWITCH_STATUS_MEMERR;
	}

	*headers = new_headers;
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Convert log node to JSON string.
 * Called from the worker thread (not under BINDLOCK).
 */
static char *to_json(const switch_log_node_t *node, switch_log_level_t log_level)
{
	char *json_text = NULL;
	cJSON *json = switch_log_node_to_json(node, (int)log_level, &globals.json_format, NULL);

	if (!json) {
		return NULL;
	}

	cJSON_AddItemToObject(json, "level_name", cJSON_CreateString(switch_log_level2str(log_level)));
	merge_static_properties(json);
	json_text = cJSON_PrintUnformatted(json);
	cJSON_Delete(json);
	return json_text;
}

/**
 * CURL response callback - discard response body
 */
static size_t http_callback(char *buffer, size_t size, size_t nitems, void *outstream)
{
	(void)buffer;
	(void)outstream;
	return size * nitems;
}

/**
 * Snapshot configured session fields at log time so queued entries do not
 * depend on later session state.
 */
static void snapshot_session_fields(switch_log_node_t *node)
{
	switch_core_session_t *session;
	switch_channel_t *channel;
	switch_event_header_t *hp;

	if (!node || zstr(node->userdata) || !globals.session_fields || !globals.session_fields->headers) {
		return;
	}

	session = switch_core_session_locate(node->userdata);
	if (!session) {
		return;
	}

	channel = switch_core_session_get_channel(session);

	for (hp = globals.session_fields->headers; hp; hp = hp->next) {
		const char *val;

		if (zstr(hp->name) || zstr(hp->value)) {
			continue;
		}

		val = switch_channel_get_variable(channel, hp->value);
		if (zstr(val)) {
			continue;
		}

		if (!node->tags) {
			if (switch_event_create_plain(&node->tags, SWITCH_EVENT_CHANNEL_DATA) != SWITCH_STATUS_SUCCESS) {
				break;
			}
		}

		switch_event_add_header_string(node->tags, SWITCH_STACK_BOTTOM, hp->name, val);
	}

	switch_core_session_rwunlock(session);
}

/**
 * Configure CURL handle with current global settings.
 * The headers list must remain valid for the lifetime of the CURL handle.
 */
static void configure_curl_handle(switch_CURL *curl_handle, switch_curl_slist_t *headers)
{
	switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	switch_curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "freeswitch-mod_log_http/1.0");
	switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, http_callback);
	switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, (long)globals.timeout);

	if (!zstr(globals.ssl_cert_file)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, globals.ssl_cert_file);
	}
	if (!zstr(globals.ssl_key_file)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSLKEY, globals.ssl_key_file);
	}
	if (!zstr(globals.ssl_key_password)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSLKEYPASSWD, globals.ssl_key_password);
	}
	if (!zstr(globals.ssl_cacert_file)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_CAINFO, globals.ssl_cacert_file);
	}
}

/**
 * Set SSL verification options based on destination URL
 */
static void configure_ssl_for_url(switch_CURL *curl_handle, const char *url)
{
	if (!strncasecmp(url, "https", 5)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, globals.enable_cacert_check ? 1L : 0L);
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, globals.enable_ssl_verifyhost ? 2L : 0L);
	}
}

/**
 * Check if a CURL error code indicates a connection-level failure
 */
static int is_connection_error(switch_CURLcode code)
{
	return (code == CURLE_COULDNT_CONNECT ||
			code == CURLE_COULDNT_RESOLVE_HOST ||
			code == CURLE_COULDNT_RESOLVE_PROXY ||
			code == CURLE_SEND_ERROR ||
			code == CURLE_RECV_ERROR ||
			code == CURLE_OPERATION_TIMEDOUT);
}

/**
 * Check if an HTTP status code is retryable
 */
static int is_retryable_http_code(long code)
{
	return (code >= 500 || code == 408 || code == 429);
}

/**
 * Build HTTP POST body from batch entries.
 * Returns allocated string that must be freed by caller.
 * For single entry, returns the entry directly (caller must not double-free).
 */
static char *build_batch_body(char **entries, int count, int *must_free)
{
	if (count == 1) {
		*must_free = 0;
		return entries[0];
	} else {
		switch_stream_handle_t stream = { 0 };
		int i;
		SWITCH_STANDARD_STREAM(stream);
		stream.write_function(&stream, "[");
		for (i = 0; i < count; i++) {
			if (i > 0) {
				stream.write_function(&stream, ",");
			}
			stream.write_function(&stream, "%s", entries[i]);
		}
		stream.write_function(&stream, "]");
		*must_free = 1;
		return (char *)stream.data;
	}
}

/**
 * Sleep in 1-second intervals, checking for shutdown
 */
static void interruptible_sleep(int seconds)
{
	int i;
	for (i = 0; i < seconds && !globals.shutdown; i++) {
		switch_yield(1000000);
	}
}

/**
 * Post a batch of log entries via HTTP.
 * Makes 1 initial attempt + globals.retries retry attempts.
 * Returns SWITCH_STATUS_SUCCESS on 2xx,
 *         SWITCH_STATUS_NOTFOUND on non-retryable 4xx,
 *         SWITCH_STATUS_FALSE on exhausted retries.
 */
static switch_status_t post_batch(switch_CURL *curl_handle, switch_curl_slist_t *headers, char **entries, int count)
{
	char *body;
	int body_must_free = 0;
	switch_CURLcode curl_code;
	long http_code = 0;
	uint32_t attempt;
	uint32_t max_attempts = 1 + globals.retries;

	body = build_batch_body(entries, count, &body_must_free);

	for (attempt = 0; attempt < max_attempts && !globals.shutdown; attempt++) {
		const char *url = globals.urls[globals.url_index];

		if (attempt > 0) {
			interruptible_sleep((int)globals.delay);
			if (globals.shutdown) break;
		}

		switch_curl_easy_setopt(curl_handle, CURLOPT_URL, url);
		switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, body);
		configure_ssl_for_url(curl_handle, url);

		curl_code = switch_curl_easy_perform(curl_handle);

		if (curl_code != CURLE_OK) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: CURL error posting to [%s]: %s\n",
							  url, switch_curl_easy_strerror(curl_code));

			if (is_connection_error(curl_code)) {
				curl_easy_reset((CURL *)curl_handle);
				configure_curl_handle(curl_handle, headers);
			}

			if (globals.url_count > 1) {
				globals.url_index = (globals.url_index + 1) % globals.url_count;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
								  "mod_log_http: Failing over to [%s]\n", globals.urls[globals.url_index]);
			}
			continue;
		}

		switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

		if (http_code >= 200 && http_code < 300) {
			if (body_must_free) switch_safe_free(body);
			return SWITCH_STATUS_SUCCESS;
		}

		if (is_retryable_http_code(http_code)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: HTTP %ld from [%s], retrying\n", http_code, url);
			if (globals.url_count > 1) {
				globals.url_index = (globals.url_index + 1) % globals.url_count;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
								  "mod_log_http: Failing over to [%s]\n", globals.urls[globals.url_index]);
			}
			continue;
		}

		/* Non-retryable client error (4xx except 408/429) */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
						  "mod_log_http: HTTP %ld client error from [%s], not retrying\n", http_code, url);
		if (body_must_free) switch_safe_free(body);
		return SWITCH_STATUS_NOTFOUND;
	}

	if (body_must_free) switch_safe_free(body);
	return SWITCH_STATUS_FALSE;
}

/**
 * Worker thread that delivers logs via HTTP.
 * JSON serialization happens here, outside the core BINDLOCK.
 */
static void *SWITCH_THREAD_FUNC deliver_http_thread(switch_thread_t *thread, void *obj)
{
	switch_CURL *curl_handle = NULL;
	switch_curl_slist_t *headers = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	int fail_count = 0;
	char *batch[MAX_BATCH_SIZE];
	int batch_count;
	int i;

	(void)thread;
	(void)obj;

	if (globals.url_count == 0) {
		signal_worker_startup(WORKER_STARTUP_FAILED, SWITCH_STATUS_FALSE);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: no URLs configured, exiting\n");
		return NULL;
	}

	curl_handle = switch_curl_easy_init();
	if (!curl_handle) {
		signal_worker_startup(WORKER_STARTUP_FAILED, SWITCH_STATUS_MEMERR);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: failed to initialize CURL handle\n");
		return NULL;
	}

	if ((status = append_header(&headers, "Content-Type: application/json")) != SWITCH_STATUS_SUCCESS) {
		signal_worker_startup(WORKER_STARTUP_FAILED, status);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: failed to allocate HTTP headers\n");
		goto done;
	}

	if (globals.disable100continue && (status = append_header(&headers, "Expect:")) != SWITCH_STATUS_SUCCESS) {
		signal_worker_startup(WORKER_STARTUP_FAILED, status);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: failed to allocate HTTP headers\n");
		goto done;
	}
	configure_curl_handle(curl_handle, headers);
	signal_worker_startup(WORKER_STARTUP_RUNNING, SWITCH_STATUS_SUCCESS);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: delivery thread started\n");

	while (!globals.shutdown) {
		switch_log_node_t *entry = NULL;
		char *json;
		switch_status_t result;

		/* Exponential backoff between batches on consecutive failures */
		if (fail_count > 0) {
			int shift = fail_count > 6 ? 6 : fail_count;
			int backoff = (int)globals.delay << shift;
			if (backoff > MAX_BACKOFF_SECS || backoff < 0) backoff = MAX_BACKOFF_SECS;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: backing off %d seconds before next attempt\n", backoff);
			interruptible_sleep(backoff);
			if (globals.shutdown) break;
		}

		/* Block on first entry (a switch_log_node_t*) */
		if (switch_queue_pop(globals.log_queue, (void *)&entry) != SWITCH_STATUS_SUCCESS) {
			break;
		}

		/* Serialize to JSON in this thread (not under BINDLOCK) */
		json = to_json(entry, entry->level);
		switch_log_node_free(&entry);
		if (!json) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: failed to serialize log entry, dropping\n");
			continue;
		}

		batch[0] = json;
		batch_count = 1;

		/* Collect more entries for the batch with a total deadline */
		if (globals.batch_size > 1 && batch_count < globals.batch_size) {
			switch_time_t deadline = switch_micro_time_now() +
				(switch_interval_time_t)globals.batch_timeout_ms * 1000;

			/* First drain whatever is immediately available */
			while (batch_count < globals.batch_size) {
				if (switch_queue_trypop(globals.log_queue, (void *)&entry) != SWITCH_STATUS_SUCCESS) {
					break;
				}
				json = to_json(entry, entry->level);
				switch_log_node_free(&entry);
				if (!json) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
									  "mod_log_http: failed to serialize log entry, dropping\n");
					continue;
				}
				batch[batch_count++] = json;
			}

			/* If still room, wait up to remaining deadline */
			while (batch_count < globals.batch_size && globals.batch_timeout_ms > 0) {
				switch_interval_time_t remaining = deadline - switch_micro_time_now();
				if (remaining <= 0) break;
				if (switch_queue_pop_timeout(globals.log_queue, (void *)&entry, remaining) != SWITCH_STATUS_SUCCESS) {
					break;
				}
				json = to_json(entry, entry->level);
				switch_log_node_free(&entry);
				if (!json) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
									  "mod_log_http: failed to serialize log entry, dropping\n");
					continue;
				}
				batch[batch_count++] = json;
				/* Drain any further immediately available entries */
				while (batch_count < globals.batch_size) {
					if (switch_queue_trypop(globals.log_queue, (void *)&entry) != SWITCH_STATUS_SUCCESS) {
						break;
					}
					json = to_json(entry, entry->level);
					switch_log_node_free(&entry);
					if (!json) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
										  "mod_log_http: failed to serialize log entry, dropping\n");
						continue;
					}
					batch[batch_count++] = json;
				}
			}
		}

		/* Post the batch */
		result = post_batch(curl_handle, headers, batch, batch_count);

		if (result == SWITCH_STATUS_SUCCESS) {
			fail_count = 0;
		} else {
			fail_count++;
			if (fail_count > 10) fail_count = 10;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: failed to deliver %d log entries (consecutive failures: %d)\n",
							  batch_count, fail_count);
		}

		/* Free batch entries */
		for (i = 0; i < batch_count; i++) {
			switch_safe_free(batch[i]);
		}
	}

done:
	/* Drain remaining queue entries */
	{
		switch_log_node_t *entry;
		while (switch_queue_trypop(globals.log_queue, (void *)&entry) == SWITCH_STATUS_SUCCESS) {
			switch_log_node_free(&entry);
		}
	}

	if (curl_handle) {
		switch_curl_easy_cleanup(curl_handle);
	}
	if (headers) {
		switch_curl_slist_free_all(headers);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: delivery thread finished\n");
	return NULL;
}

/**
 * Start the delivery thread (non-detached, handle stored for join).
 * Wait until the worker reports startup success or failure.
 */
static void start_deliver_thread(switch_memory_pool_t *pool)
{
	switch_threadattr_t *thd_attr = NULL;
	switch_status_t status;

	if ((status = switch_threadattr_create(&thd_attr, pool)) != SWITCH_STATUS_SUCCESS) {
		globals.startup_status = status;
		return;
	}

	if ((status = switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE)) != SWITCH_STATUS_SUCCESS) {
		globals.startup_status = status;
		return;
	}

	globals.startup_state = WORKER_STARTUP_PENDING;
	globals.startup_status = SWITCH_STATUS_SUCCESS;
	globals.worker_thread = NULL;
	globals.worker_started = 0;

	switch_mutex_lock(globals.startup_mutex);
	status = switch_thread_create(&globals.worker_thread, thd_attr, deliver_http_thread, NULL, pool);
	if (status == SWITCH_STATUS_SUCCESS) {
		while (globals.startup_state == WORKER_STARTUP_PENDING) {
			status = switch_thread_cond_timedwait(globals.startup_cond, globals.startup_mutex, WORKER_STARTUP_TIMEOUT_USEC);
			if (status != SWITCH_STATUS_SUCCESS) {
				break;
			}
		}
	}
	switch_mutex_unlock(globals.startup_mutex);

	if (status == SWITCH_STATUS_SUCCESS && globals.startup_state == WORKER_STARTUP_RUNNING) {
		globals.worker_started = 1;
		globals.startup_status = SWITCH_STATUS_SUCCESS;
		return;
	}

	if (status != SWITCH_STATUS_SUCCESS) {
		globals.startup_status = status;
	} else if (globals.startup_state == WORKER_STARTUP_FAILED) {
		if (globals.startup_status == SWITCH_STATUS_SUCCESS) {
			globals.startup_status = SWITCH_STATUS_FALSE;
		}
	} else {
		globals.startup_status = SWITCH_STATUS_TIMEOUT;
	}
}

/**
 * Stop the delivery thread via join
 */
static void stop_deliver_thread(void)
{
	switch_status_t st;

	if (!globals.worker_thread) {
		globals.worker_started = 0;
		return;
	}

	globals.shutdown = 1;
	if (globals.log_queue) {
		switch_queue_interrupt_all(globals.log_queue);
	}
	switch_thread_join(&st, globals.worker_thread);
	globals.worker_thread = NULL;
	globals.worker_started = 0;
}

static void cleanup_module_state(void)
{
	if (globals.logger_bound) {
		switch_log_unbind_logger(mod_log_http_logger);
		globals.logger_bound = 0;
	}

	stop_deliver_thread();

	if (globals.session_fields) {
		switch_event_destroy(&globals.session_fields);
	}
	if (globals.static_properties) {
		cJSON_Delete(globals.static_properties);
		globals.static_properties = NULL;
	}

	globals.log_queue = NULL;
}

/**
 * Logger callback from FreeSWITCH core.
 * Runs under BINDLOCK — must be fast.
 * Queues a lightweight node copy; JSON serialization deferred to worker.
 */
static switch_status_t mod_log_http_logger(const switch_log_node_t *node, switch_log_level_t level)
{
	if (globals.log_queue && !globals.shutdown && level <= globals.log_level && level != SWITCH_LOG_CONSOLE) {
		/* Skip our own log messages to prevent feedback loops */
		if (!strncmp(node->file, MY_SOURCE_FILE, sizeof(MY_SOURCE_FILE) - 1)) {
			return SWITCH_STATUS_SUCCESS;
		}

		if (!zstr(node->content) && !zstr(node->content + 1)) {
			switch_log_node_t *dup = switch_log_node_dup(node);
			if (dup) {
				snapshot_session_fields(dup);
				if (switch_queue_trypush(globals.log_queue, dup) != SWITCH_STATUS_SUCCESS) {
					switch_log_node_free(&dup);
					{
						switch_time_t now = switch_micro_time_now();
						if (now - last_drop_warning > DROP_WARN_INTERVAL) {
							last_drop_warning = now;
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
											  "mod_log_http: queue full, dropping entries. "
											  "Is the HTTP endpoint reachable?\n");
						}
					}
				}
			}
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Parse module configuration
 */
static switch_status_t do_config(void)
{
	switch_xml_t cfg, xml, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (!(xml = switch_xml_open_cfg("log_http.conf", &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of log_http.conf failed\n");
		return SWITCH_STATUS_TERM;
	}

	/* Defaults */
	globals.log_level = SWITCH_LOG_WARNING;
	globals.timeout = 5;
	globals.retries = 3;
	globals.delay = 1;
	globals.batch_size = 10;
	globals.batch_timeout_ms = 500;
	globals.url_count = 0;

	if ((settings = switch_xml_child(cfg, "settings"))) {
		switch_xml_t param;
		switch_xml_t fields;

		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *name = (char *)switch_xml_attr_soft(param, "name");
			char *value = (char *)switch_xml_attr_soft(param, "value");

			if (zstr(name)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Ignoring empty param\n");
				continue;
			}
			if (zstr(value)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
								  "Ignoring empty value for param \"%s\"\n", name);
				continue;
			}

			if (!strcasecmp(name, "url")) {
				if (globals.url_count < MAX_URLS) {
					globals.urls[globals.url_count++] = switch_core_strdup(globals.pool, value);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
									  "Added URL [%d]: %s\n", globals.url_count - 1, value);
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Maximum URLs (%d) reached, ignoring: %s\n", MAX_URLS, value);
				}
			} else if (!strcasecmp(name, "loglevel")) {
				switch_log_level_t log_level = switch_log_str2level(value);
				if (log_level == SWITCH_LOG_INVALID) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Ignoring invalid log level: \"%s\"\n", value);
				} else {
					globals.log_level = log_level;
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "\"%s\" = \"%s\"\n", name, value);
				}
			} else if (!strcasecmp(name, "timeout")) {
				int val = atoi(value);
				if (val > 0 && val <= MAX_TIMEOUT_SECS) {
					globals.timeout = val;
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Invalid timeout \"%s\" (must be 1-%d)\n", value, MAX_TIMEOUT_SECS);
				}
			} else if (!strcasecmp(name, "retries")) {
				int val = atoi(value);
				if (val >= 0) {
					globals.retries = (uint32_t)val;
				}
			} else if (!strcasecmp(name, "delay")) {
				int val = atoi(value);
				if (val > 0 && val <= MAX_DELAY_SECS) {
					globals.delay = (uint32_t)val;
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Invalid delay \"%s\" (must be 1-%d)\n", value, MAX_DELAY_SECS);
				}
			} else if (!strcasecmp(name, "batch-size")) {
				int val = atoi(value);
				if (val > 0 && val <= MAX_BATCH_SIZE) {
					globals.batch_size = val;
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Invalid batch-size \"%s\" (must be 1-%d)\n", value, MAX_BATCH_SIZE);
				}
			} else if (!strcasecmp(name, "batch-timeout-ms")) {
				int val = atoi(value);
				if (val >= 0) {
					globals.batch_timeout_ms = val;
				}
			} else if (!strcasecmp(name, "disable-100-continue")) {
				globals.disable100continue = switch_true(value);
			} else if (!strcasecmp(name, "ssl-cert-file")) {
				globals.ssl_cert_file = switch_core_strdup(globals.pool, value);
			} else if (!strcasecmp(name, "ssl-key-file")) {
				globals.ssl_key_file = switch_core_strdup(globals.pool, value);
			} else if (!strcasecmp(name, "ssl-key-password")) {
				globals.ssl_key_password = switch_core_strdup(globals.pool, value);
			} else if (!strcasecmp(name, "ssl-cacert-file")) {
				globals.ssl_cacert_file = switch_core_strdup(globals.pool, value);
			} else if (!strcasecmp(name, "enable-cacert-check")) {
				globals.enable_cacert_check = switch_true(value);
			} else if (!strcasecmp(name, "enable-ssl-verifyhost")) {
				globals.enable_ssl_verifyhost = switch_true(value);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
								  "Ignoring unknown param: \"%s\"\n", name);
			}
		}

		/* Map session fields to channel variables */
		if ((fields = switch_xml_child(settings, "fields"))) {
			switch_xml_t field;
			for (field = switch_xml_child(fields, "field"); field; field = field->next) {
				char *fname = (char *)switch_xml_attr_soft(field, "name");
				char *variable = (char *)switch_xml_attr_soft(field, "variable");
				if (zstr(fname)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Ignoring unnamed session field\n");
					continue;
				}
				if (zstr(variable)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
									  "Ignoring empty channel variable for session field \"%s\"\n", fname);
					continue;
				}
				switch_event_add_header_string(globals.session_fields, SWITCH_STACK_BOTTOM, fname, variable);
			}
		}

		/* Parse static properties to add to every log entry */
		{
			switch_xml_t properties = switch_xml_child(settings, "properties");
			if (properties) {
				status = parse_static_property_children(properties, globals.static_properties, NULL, SWITCH_TRUE);
				if (status != SWITCH_STATUS_SUCCESS) {
					switch_xml_free(xml);
					return status;
				}
			}
		}
	}

	if (globals.log_level != SWITCH_LOG_DISABLE && globals.url_count == 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "No URL configured. At least one url param is required.\n");
		switch_xml_free(xml);
		return SWITCH_STATUS_TERM;
	}

	switch_xml_free(xml);
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_log_http_load)
{
	switch_status_t status;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;

	/* JSON format field mappings - clean names, no GELF conventions */
	globals.json_format.host.name = "host";
	globals.json_format.timestamp.name = "timestamp";
	globals.json_format.timestamp_divisor = 1000000; /* microseconds to seconds */
	globals.json_format.level.name = "level";
	globals.json_format.pid.name = "pid";
	globals.json_format.pid.value = switch_core_sprintf(pool, "%d", (int)getpid());
	globals.json_format.uuid.name = "uuid";
	globals.json_format.file.name = "file";
	globals.json_format.line.name = "line";
	globals.json_format.function.name = "function";
	globals.json_format.full_message.name = "message";
	globals.json_format.short_message.name = "short_message";
	globals.json_format.sequence.name = "sequence";

	if ((status = switch_event_create_plain(&globals.session_fields, SWITCH_EVENT_CHANNEL_DATA)) != SWITCH_STATUS_SUCCESS) {
		return status;
	}

	globals.static_properties = cJSON_CreateObject();
	if (!globals.static_properties) {
		cleanup_module_state();
		return SWITCH_STATUS_MEMERR;
	}

	if ((status = do_config()) != SWITCH_STATUS_SUCCESS) {
		cleanup_module_state();
		return status;
	}

	if (globals.log_level == SWITCH_LOG_DISABLE) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
						  "mod_log_http: loglevel=disable, module loaded without binding logger\n");
		return SWITCH_STATUS_SUCCESS;
	}

	if ((status = switch_mutex_init(&globals.startup_mutex, SWITCH_MUTEX_NESTED, pool)) != SWITCH_STATUS_SUCCESS) {
		cleanup_module_state();
		return status;
	}

	if ((status = switch_thread_cond_create(&globals.startup_cond, pool)) != SWITCH_STATUS_SUCCESS) {
		cleanup_module_state();
		return status;
	}

	if ((status = switch_queue_create(&globals.log_queue, LOG_QUEUE_SIZE, pool)) != SWITCH_STATUS_SUCCESS) {
		cleanup_module_state();
		return status;
	}

	start_deliver_thread(globals.pool);
	if (!globals.worker_started) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "mod_log_http: failed to start delivery thread (status=%d)\n", globals.startup_status);
		cleanup_module_state();
		return SWITCH_STATUS_TERM;
	}

	if ((status = switch_log_bind_logger(mod_log_http_logger, globals.log_level, SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
						  "mod_log_http: failed to bind logger (status=%d)\n", status);
		cleanup_module_state();
		return status;
	}

	globals.logger_bound = 1;

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_log_http_shutdown)
{
	cleanup_module_state();
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
