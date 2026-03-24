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

#include <sys/types.h>
#include <unistd.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_log_http_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_log_http_shutdown);
SWITCH_MODULE_DEFINITION(mod_log_http, mod_log_http_load, mod_log_http_shutdown, NULL);

#define MAX_URLS 20
#define MAX_BATCH_SIZE 200
#define LOG_QUEUE_SIZE 25000
#define MAX_BACKOFF_SECS 60
#define DROP_WARN_INTERVAL 60000000 /* 60 seconds in microseconds */
#define MY_SOURCE_FILE "mod_log_http.c"

static struct {
	switch_memory_pool_t *pool;
	char *urls[MAX_URLS];
	int url_count;
	int url_index;
	switch_log_level_t log_level;
	int shutdown;
	switch_thread_rwlock_t *shutdown_rwlock;
	switch_queue_t *log_queue;
	switch_event_t *session_fields;
	switch_event_t *properties;
	switch_log_json_format_t json_format;
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

/**
 * Convert log node to JSON string
 */
static char *to_json(const switch_log_node_t *node, switch_log_level_t log_level)
{
	char *json_text = NULL;
	cJSON *json = switch_log_node_to_json(node, (int)log_level, &globals.json_format, globals.session_fields);
	cJSON_AddItemToObject(json, "level_name", cJSON_CreateString(switch_log_level2str(log_level)));
	if (globals.properties) {
		switch_event_header_t *hp;
		for (hp = globals.properties->headers; hp; hp = hp->next) {
			cJSON_AddItemToObject(json, hp->name, cJSON_CreateString(hp->value));
		}
	}
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
			switch_yield(globals.delay * 1000000);
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
				/* Destroy and recreate handle to force fresh connection */
				curl_easy_reset((CURL *)curl_handle);
				configure_curl_handle(curl_handle, headers);
			}

			/* Rotate to next URL */
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
 * Worker thread that delivers logs via HTTP
 */
static void *SWITCH_THREAD_FUNC deliver_http_thread(switch_thread_t *thread, void *obj)
{
	switch_CURL *curl_handle = NULL;
	switch_curl_slist_t *headers = NULL;
	int fail_count = 0;
	char *batch[MAX_BATCH_SIZE];
	int batch_count;
	int i;

	(void)thread;
	(void)obj;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: delivery thread started\n");
	switch_thread_rwlock_rdlock(globals.shutdown_rwlock);

	if (globals.url_count == 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: no URLs configured, exiting\n");
		goto done;
	}

	curl_handle = switch_curl_easy_init();
	headers = switch_curl_slist_append(NULL, "Content-Type: application/json");
	if (globals.disable100continue) {
		headers = switch_curl_slist_append(headers, "Expect:");
	}
	configure_curl_handle(curl_handle, headers);

	while (!globals.shutdown) {
		char *log;
		switch_status_t result;

		/* Exponential backoff between batches on consecutive failures */
		if (fail_count > 0) {
			int backoff = globals.delay * (1 << (fail_count > 6 ? 6 : fail_count));
			if (backoff > MAX_BACKOFF_SECS) backoff = MAX_BACKOFF_SECS;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: backing off %d seconds before next attempt\n", backoff);
			interruptible_sleep(backoff);
			if (globals.shutdown) break;
		}

		/* Block on first entry */
		if (switch_queue_pop(globals.log_queue, (void *)&log) != SWITCH_STATUS_SUCCESS) {
			break;
		}

		batch[0] = log;
		batch_count = 1;

		/* Collect more entries for the batch with a total deadline */
		if (globals.batch_size > 1 && batch_count < globals.batch_size) {
			switch_time_t deadline = switch_micro_time_now() +
				(switch_interval_time_t)globals.batch_timeout_ms * 1000;

			/* First drain whatever is immediately available */
			while (batch_count < globals.batch_size) {
				if (switch_queue_trypop(globals.log_queue, (void *)&log) != SWITCH_STATUS_SUCCESS) {
					break;
				}
				batch[batch_count++] = log;
			}

			/* If still room, wait up to remaining deadline */
			while (batch_count < globals.batch_size && globals.batch_timeout_ms > 0) {
				switch_interval_time_t remaining = deadline - switch_micro_time_now();
				if (remaining <= 0) break;
				if (switch_queue_pop_timeout(globals.log_queue, (void *)&log, remaining) != SWITCH_STATUS_SUCCESS) {
					break;
				}
				batch[batch_count++] = log;
				/* Drain any further immediately available entries */
				while (batch_count < globals.batch_size) {
					if (switch_queue_trypop(globals.log_queue, (void *)&log) != SWITCH_STATUS_SUCCESS) {
						break;
					}
					batch[batch_count++] = log;
				}
			}
		}

		/* Post the batch */
		result = post_batch(curl_handle, headers, batch, batch_count);

		if (result == SWITCH_STATUS_SUCCESS) {
			fail_count = 0;
		} else {
			fail_count++;
			if (fail_count > 10) fail_count = 10; /* cap the exponent */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE,
							  "mod_log_http: failed to deliver %d log entries (consecutive failures: %d)\n",
							  batch_count, fail_count);
		}

		/* Free batch entries */
		for (i = 0; i < batch_count; i++) {
			switch_safe_free(batch[i]);
		}
	}

	/* Drain remaining queue entries */
	{
		char *log;
		while (switch_queue_trypop(globals.log_queue, (void *)&log) == SWITCH_STATUS_SUCCESS) {
			switch_safe_free(log);
		}
	}

	if (curl_handle) {
		switch_curl_easy_cleanup(curl_handle);
	}
	if (headers) {
		switch_curl_slist_free_all(headers);
	}

done:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CONSOLE, "mod_log_http: delivery thread finished\n");
	switch_thread_rwlock_unlock(globals.shutdown_rwlock);
	return NULL;
}

/**
 * Start the delivery thread
 */
static void start_deliver_thread(switch_memory_pool_t *pool)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	switch_threadattr_create(&thd_attr, pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, deliver_http_thread, NULL, pool);
}

/**
 * Stop the delivery thread
 */
static void stop_deliver_thread(void)
{
	globals.shutdown = 1;
	switch_queue_interrupt_all(globals.log_queue);
	switch_thread_rwlock_wrlock(globals.shutdown_rwlock);
}

/**
 * Logger callback from FreeSWITCH core.
 * Filters out logs originating from this module to prevent feedback loops.
 */
static switch_status_t mod_log_http_logger(const switch_log_node_t *node, switch_log_level_t level)
{
	if (!globals.shutdown && level <= globals.log_level && level != SWITCH_LOG_CONSOLE) {
		/* Skip our own log messages to prevent feedback loops when the endpoint is down */
		if (!strncmp(node->file, MY_SOURCE_FILE, sizeof(MY_SOURCE_FILE) - 1)) {
			return SWITCH_STATUS_SUCCESS;
		}
		if (!zstr(node->content) && !zstr(node->content + 1)) {
			char *log = to_json(node, level);
			if (switch_queue_trypush(globals.log_queue, log) != SWITCH_STATUS_SUCCESS) {
				free(log);
				/* Rate-limited warning about dropped logs */
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
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Parse module configuration
 */
static switch_status_t do_config(void)
{
	switch_xml_t cfg, xml, settings;

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
				if (val > 0) {
					globals.timeout = val;
				}
			} else if (!strcasecmp(name, "retries")) {
				int val = atoi(value);
				if (val >= 0) {
					globals.retries = (uint32_t)val;
				}
			} else if (!strcasecmp(name, "delay")) {
				int val = atoi(value);
				if (val > 0) {
					globals.delay = (uint32_t)val;
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
				switch_event_add_header_string(globals.session_fields, SWITCH_STACK_BOTTOM,
											   switch_core_strdup(globals.pool, fname),
											   switch_core_strdup(globals.pool, variable));
			}
		}

		/* Parse static properties to add to every log entry */
		{
			switch_xml_t properties = switch_xml_child(settings, "properties");
			if (properties) {
				switch_xml_t prop;
				for (prop = switch_xml_child(properties, "property"); prop; prop = prop->next) {
					char *pname = (char *)switch_xml_attr_soft(prop, "name");
					char *pvalue = (char *)switch_xml_attr_soft(prop, "value");
					if (zstr(pname)) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
										  "Ignoring unnamed property\n");
						continue;
					}
					if (zstr(pvalue)) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
										  "Ignoring empty value for property \"%s\"\n", pname);
						continue;
					}
					switch_event_add_header_string(globals.properties, SWITCH_STACK_BOTTOM,
												   switch_core_strdup(globals.pool, pname),
												   switch_core_strdup(globals.pool, pvalue));
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
									  "Added property: \"%s\" = \"%s\"\n", pname, pvalue);
				}
			}
		}
	}

	if (globals.url_count == 0) {
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

	switch_event_create_plain(&globals.session_fields, SWITCH_EVENT_CHANNEL_DATA);
	switch_event_create_plain(&globals.properties, SWITCH_EVENT_CLONE);

	if (do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_TERM;
	}

	switch_thread_rwlock_create(&globals.shutdown_rwlock, pool);
	switch_queue_create(&globals.log_queue, LOG_QUEUE_SIZE, pool);

	start_deliver_thread(globals.pool);
	switch_log_bind_logger(mod_log_http_logger, SWITCH_LOG_DEBUG, SWITCH_FALSE);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_log_http_shutdown)
{
	switch_log_unbind_logger(mod_log_http_logger);
	stop_deliver_thread();
	if (globals.session_fields) {
		switch_event_destroy(&globals.session_fields);
	}
	if (globals.properties) {
		switch_event_destroy(&globals.properties);
	}
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
