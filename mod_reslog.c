/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 *
 * Apache resource logging module.  Provides logging for CPU times and memory
 * usage on 'heavy' requests.
 *
 * May log resource usage (cpu and/or memory) on either:
 *
 *   o apache ErrorLog (fixed format).
 *   o apache CustomLog (format tags 'M' and 'c', see below).
 *   o syslog (may set facility & level).
 *
 * When using CustomLog, these two tags are provided:
 *
 *  %{...}M: for logging memory usage
 *
 *       These format chars may be used:
 *
 *       o 't' ('total'): logs total memory increase.
 *       o 'r' ('rss'): logs rss memory increase.
 *       o 'd' ('drss'): logs drss memory increase.
 *
 *       (See getrusage(2) for rss & drss meaning).
 *
 *  %{...}c: for logging cpu usage
 *
 *       When logging cpu usage, these format chars may be used:
 *
 *       o 's' ('system'): logs cpu usage in 'kernel mode'.
 *       o 'u' ('user'): logs cpu usage in 'user mode'.
 *       o 't' ('total'): logs cpu usage 'user mode' + 'kernel mode'
 *
 *
 * Both tags ('M' & 'c') support these characters in their format:
 *
 *  o 'S' ('self'): logs resource usage by the apache process per-se.
 *  o 'C' ('child'): logs resource usage by the apache's child process.
 *                   Child processes are seen on SSI's exec, and CGIs.
 *  o 'T' ('total'): logs resource usage by apache process per-se and all child
 *                   processes it may have created.
 *
 * Q&A:
 *
 * 1) Why not using apache request notes for letting mod_log_config get cpu &
 *    memory usage information?
 *
 *   Apache notes are store in a linear search table.  Saving all these 15 combinations:
 *
 *   {cpu.{user,sys,total},mem.{rss,drss}}.{self,child,total}
 *
 *   will make apache notes table larger and therefore slower.
 *
 *   Since this module attempts to find cpu bottleneks / memory starvers, this
 *   module should be as light as possible.
 *
 *   If you think there is a better way of doing this, please report it.
 * 
 * Gonzalo A. Arana <gonzalo.arana@gmail.com>
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_strings.h"
#include "apr_optional.h"

#include "mod_log_config.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

module AP_MODULE_DECLARE_DATA reslog_module;

#define RES_CPU 1
#define RES_MEM 2

#ifdef MOD_RESLOG_DEBUG
#define res_log_debug(p, ...) ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "%s:%d %s.", __FUNCTION__, __LINE__, ## __VA_ARGS__);
#else
#define res_log_debug(p, ...) 
#endif

/*
 * Resource usage values.
 *
 * Keeps user/kernel/total mode cpu usage, as well as current RSS & DRSS memory.
 */
typedef struct rusage_rec {
	struct timeval cpu[3];
#define RES_USER  0
#define RES_SYS   1
#define RES_TOTAL 2

	long mem[3];
#define RES_RSS  0
#define RES_DRSS 1
//#define RES_TOTAL 2
} rusage_rec;

static int fill_rusage_rec(rusage_rec* rec, int flag) {
	struct rusage ru;
	if (getrusage(flag, &ru) < 0)
		return -1;

	rec->cpu[RES_USER] = ru.ru_utime;
	rec->cpu[RES_SYS] = ru.ru_stime;
	timeradd(&ru.ru_utime, &ru.ru_stime, &rec->cpu[RES_TOTAL]);

	rec->mem[RES_RSS] = ru.ru_maxrss;
	rec->mem[RES_DRSS] = ru.ru_idrss;
	rec->mem[RES_TOTAL] = ru.ru_maxrss + ru.ru_idrss;

	return 0;
}

static int xtimercmp(struct timeval* a, struct timeval* b) {
	if (a->tv_sec == 0 && a->tv_usec == 0)
		return 1;
	return timercmp(a,b,<);
}

// returns a < b ? 1 : -1
static int rusage_rec_cmp(rusage_rec* a, rusage_rec* b) {
	int dev = -1;
	if (xtimercmp(&a->cpu[RES_USER], &b->cpu[RES_USER]) ||
	    xtimercmp(&a->cpu[RES_SYS], &b->cpu[RES_SYS]) ||
	    xtimercmp(&a->cpu[RES_TOTAL], &b->cpu[RES_TOTAL]) ||
	    a->mem[RES_RSS] < b->mem[RES_RSS] ||
	    a->mem[RES_DRSS] < b->mem[RES_DRSS] ||
	    a->mem[RES_TOTAL] < b->mem[RES_TOTAL])
		dev = 1;
	return dev;
}

/*
 * Configuration record.  Used for per-directory, per-server and per-request
 * configuration data.
 */
typedef struct res_cfg {
	int flags;
#define RES_ENABLE    0x01
#define RES_SYSLOG    0x02
#define RES_ERRLOG    0x04
#define RES_DONE      0x80
	int log_facility; // used only when logging to syslog
	int log_level;
	char* id;

	rusage_rec res_min[3];
#define RES_SELF  0
#define RES_CHILD 1
//#define RES_TOTAL 2

	rusage_rec res_stt[3];
	rusage_rec res_used[3];
} res_cfg;

#define cpu_add(i) \
	timeradd(&r[RES_SELF].cpu[i]  , &r[RES_CHILD].cpu[i]  , &r[RES_TOTAL].cpu[i]);
static int getresusage(rusage_rec* r) {

	if (fill_rusage_rec(&r[RES_SELF], RUSAGE_SELF) < 0 ||
	    fill_rusage_rec(&r[RES_CHILD], RUSAGE_CHILDREN) < 0)
		return -1;

	cpu_add(RES_USER);
	cpu_add(RES_SYS);
	cpu_add(RES_TOTAL);

	r[RES_TOTAL].mem[RES_RSS] = r[RES_SELF].mem[RES_RSS] + r[RES_CHILD].mem[RES_RSS];
	r[RES_TOTAL].mem[RES_DRSS] = r[RES_SELF].mem[RES_DRSS] + r[RES_CHILD].mem[RES_DRSS];
	r[RES_TOTAL].mem[RES_TOTAL] = r[RES_SELF].mem[RES_TOTAL] + r[RES_CHILD].mem[RES_TOTAL];
	// this is useless, I think

	return 0;
}

// a -= b;
static void rusage_rec_diff(rusage_rec* a, rusage_rec* b) {
	int i = 3;
	while (i--) {
 	 	timersub(&a[i].cpu[RES_USER], &b[i].cpu[RES_USER], &a[i].cpu[RES_USER]);
 	 	timersub(&a[i].cpu[RES_SYS], &b[i].cpu[RES_SYS], &a[i].cpu[RES_SYS]);
 	 	timersub(&a[i].cpu[RES_TOTAL], &b[i].cpu[RES_TOTAL], &a[i].cpu[RES_TOTAL]);

 	 	a[i].mem[RES_RSS] -= b[i].mem[RES_RSS];
 	 	a[i].mem[RES_DRSS] -= b[i].mem[RES_DRSS];
 	 	a[i].mem[RES_TOTAL] -= b[i].mem[RES_TOTAL];
	}
}

static int syslog2apache_loglevel(int level) {
	switch (level) {
		case APLOG_EMERG: return LOG_EMERG;
		case APLOG_ALERT: return LOG_ALERT;
		case APLOG_CRIT: return LOG_CRIT;
		case APLOG_ERR: return LOG_ERR;
		case APLOG_WARNING: return LOG_WARNING;
		case APLOG_NOTICE: return LOG_NOTICE;
		case APLOG_INFO: return LOG_INFO;
		case APLOG_DEBUG: return LOG_DEBUG;
	}
	assert(0 && "What are you trying to do!?");
	return -1; // to avoid compiler warnings.
}

#if 0
static int apache2syslog_loglevel(int level) { //TODO: unused??
	switch (level) {
	case LOG_EMERG: return APLOG_EMERG;
	case LOG_ALERT: return APLOG_ALERT;
	case LOG_CRIT: return APLOG_CRIT;
	case LOG_ERR: return APLOG_ERR;
	case LOG_WARNING: return APLOG_WARNING;
	case LOG_NOTICE: return APLOG_NOTICE;
	case LOG_INFO: return APLOG_INFO;
	case LOG_DEBUG: return APLOG_DEBUG;
	}
	assert(0 && "What are you trying to do!?");
	return -1; // to avoid compiler warnings.
}
#endif

const char* _facilityv[] = {
	[LOG_AUTH] = "AUTH",
	[LOG_AUTHPRIV] = "AUTHPRIV",
	[LOG_CRON] = "CRON",
	[LOG_DAEMON] = "DAEMON",
	[LOG_FTP] = "FTP",
	[LOG_KERN] = "KERN",
	[LOG_LOCAL0] = "LOCAL0",
	[LOG_LOCAL1] = "LOCAL1",
	[LOG_LOCAL2] = "LOCAL2",
	[LOG_LOCAL3] = "LOCAL3",
	[LOG_LOCAL4] = "LOCAL4",
	[LOG_LOCAL5] = "LOCAL5",
	[LOG_LOCAL6] = "LOCAL6",
	[LOG_LOCAL7] = "LOCAL7",
	[LOG_LPR] = "LPR",
	[LOG_MAIL] = "MAIL",
	[LOG_NEWS] = "NEWS",
	[LOG_SYSLOG] = "SYSLOG",
	[LOG_USER] = "USER",
	[LOG_UUCP] = "UUCP"
};

const char* _levelv[] = {
	[LOG_EMERG] = "EMERG",
	[LOG_ALERT] = "ALERT",
	[LOG_CRIT] = "CRIT",
	[LOG_ERR] = "ERR",
	[LOG_WARNING] = "WARNING",
	[LOG_NOTICE] = "NOTICE",
	[LOG_INFO] = "INFO",
	[LOG_DEBUG] = "DEBUG"
};

static int res_log_lookup(const char* _haystack[], size_t n, const char* needle) {
	int i = 0;
	for (; i < n; ++i)
		if (_haystack[i] != NULL && !strcasecmp(_haystack[i], needle))
			return i;
	return -1;
}

static int logprio_aton(const char* s, int* facility, int* level) {
	char slevel[8];
	char sfacil[9];

	if (sscanf(s, "%7[a-zA-Z0-9].%8[a-zA-Z]", sfacil, slevel) != 2 &&
	    (sscanf(s, "%7[a-zA-Z]", slevel) != 1 || NULL == strcpy(sfacil, "user")))
		return -1;

	int ifac = res_log_lookup(_facilityv, sizeof(_facilityv)/sizeof(_facilityv[0]), sfacil);
	int ilev = res_log_lookup(_levelv, sizeof(_levelv)/sizeof(_levelv[0]), slevel);

	if (ifac < 0 || ilev < 0)
		return -1;

	*facility = ifac;
	*level = ilev;

	return 0;
}

#define expand_tv(t) (t).tv_sec, (t).tv_usec

static void res_log(res_cfg* cfg, request_rec* r) {

	if (0 == (cfg->flags & (RES_SYSLOG | RES_ERRLOG)))
		return;

	rusage_rec* res = cfg->res_used;

	char* msg = apr_psprintf(r->pool, 
		"[%s] %s%s %s self %lu.%06luu %lu.%06lus %lu.%06lut total %lu.%06luu %lu.%06lus %lu.%06lut mem %ldrss %lddrss %ldt",
		cfg->id, r->server->server_hostname, r->uri, r->filename,
		expand_tv(res[RES_SELF].cpu[RES_USER]),
		expand_tv(res[RES_SELF].cpu[RES_SYS]),
		expand_tv(res[RES_SELF].cpu[RES_TOTAL]),
		expand_tv(res[RES_TOTAL].cpu[RES_USER]),
		expand_tv(res[RES_TOTAL].cpu[RES_SYS]),
		expand_tv(res[RES_TOTAL].cpu[RES_TOTAL]),
		res->mem[RES_RSS], res->mem[RES_DRSS], res->mem[RES_TOTAL]);

	if (cfg->flags & RES_SYSLOG)
		syslog(cfg->log_facility | cfg->log_level, "%s", msg);

	if (cfg->flags & RES_ERRLOG)
		ap_log_error(APLOG_MARK, syslog2apache_loglevel(cfg->log_level), 0, r->server, "%s", msg);
}

static const char *handle_enable(cmd_parms *cmd, void *mconfig, int on) {
	res_cfg *cfg = (res_cfg *) mconfig;
	if (on) cfg->flags |= RES_ENABLE;
	else cfg->flags &= ~RES_ENABLE;
	return NULL;
}

static const char *handle_reslog(cmd_parms *cmd, void *mconfig, const char* via) {
	res_cfg *cfg = (res_cfg *) mconfig;

	if (!strcmp(via, "error_log"))
		cfg->flags |= RES_ERRLOG;

	else if (!strcmp(via, "syslog"))
		cfg->flags |= RES_SYSLOG;

	else
		return "Unknown ResourceLog value (must be error_log or syslog).";

	return NULL;
}

static const char *handle_string(cmd_parms *cmd, void *mconfig, const char* word1) {
	res_cfg *cfg = (res_cfg *) mconfig;
	//TODO: IS THIS POOL ok??
	cfg->id = apr_pstrdup(cmd->server->process->pconf, word1);
	return NULL;
}

static const char *handle_level(cmd_parms *cmd, void *mconfig, const char* word1) {
	res_cfg *cfg = (res_cfg *) mconfig;
	if (logprio_aton(word1, &cfg->log_facility, &cfg->log_level) < 0)
		return "Invalid logging level.";
	return NULL;
}

static const char* timeval_aton(const char* s, struct timeval* tv) {
	char* end = (char*)s; // to assure that end != NULL
	double d = strtod(s, &end);
	if (*end == '\0' && *s != '\0' && d >= 0.0) {
		tv->tv_sec = (int)d;
		tv->tv_usec = 1000000 * (d - tv->tv_sec);
		return NULL;
	}
	return "Invalid value";
}

static const char* long_aton(const char* s, long* l) {
	char* end = (char*)s;
	*l = strtol(s, &end, 10);
	if (*end == '\0' && *s != '\0' && *l >= 0);
		return NULL;
	return "Invalid value";
}

static const char* _selfv[] = {
	[RES_SELF]  = "self",
	[RES_CHILD] = "child",
	[RES_TOTAL] = "total",
	NULL
};

static const char* _userv[] = {
	[RES_USER]  = "user",
	[RES_SYS]   = "system",
	[RES_TOTAL] = "total",
	NULL
};

static const char* _rssv[] = {
	[RES_USER]  = "rss",
	[RES_SYS]   = "data",
	[RES_TOTAL] = "total",
	NULL
};

static int _lookup(const char* s, const char** v) {
	int i = 0;
	for (; v[i] != NULL; ++i)
		if (!strcmp(s, v[i]))
			return i;
	return -1;
}

static int self_aton(const char* s) { return _lookup(s, _selfv); }
static int user_aton(const char* s) { return _lookup(s, _userv); }
static int rss_aton(const char* s) { return _lookup(s, _rssv); }

/*
 * Declared in the command_rec list with
 *   AP_INIT_TAKE3("directive", function, mconfig, where, help)
 *
 * static const char *handle_TAKE3(cmd_parms *cmd, void *mconfig,
 *                                 char *word1, char *word2, char *word3);
 */
static const char* handle_cpu_thresold(cmd_parms *cmd, void *mconfig,
                                       const char *word1, const char *word2, const char *word3) {
	res_cfg *cfg = (res_cfg *) mconfig;
	int self = self_aton(word1);
	int user = user_aton(word2);
	if (self < 0 || user < 0) {
		return "syntax error: must be LogCPUThresold (self|child|total) (user|system|total) value";
	}
	return timeval_aton(word3, &cfg->res_min[self].cpu[user]);
}

static const char* handle_mem_thresold(cmd_parms *cmd, void *mconfig,
                                       const char *word1, const char *word2, const char *word3) {
	res_cfg *cfg = (res_cfg *) mconfig;
	int self = self_aton(word1);
	int rss = rss_aton(word2);
	if (self < 0 || rss < 0) {
		return "syntax error: must be LogMEMThresold (self|child|total) (rss|data|total) value";
	}
	return long_aton(word3, &cfg->res_min[self].mem[rss]);
}

/*
 * Our configuration record for the directory
 */
static res_cfg* our_dconfig(const request_rec* r) {
	return (res_cfg *) ap_get_module_config(r->per_dir_config, &reslog_module);
}

/*
 * Our configuration record for the server
 */
static res_cfg *our_sconfig(const server_rec *s) {
    return (res_cfg *) ap_get_module_config(s->module_config, &reslog_module);
}

/*
 * Our configuration record for the specified request.
 */
static res_cfg *our_rconfig(const request_rec *r) {
	return (res_cfg *) ap_get_module_config(r->request_config, &reslog_module);
}

static void *res_create_config (apr_pool_t *p) {
    res_cfg *cfg;
    cfg = (res_cfg *) apr_pcalloc(p, sizeof(res_cfg));
	cfg->flags = RES_ERRLOG;
	cfg->id = "RESOURCE_USAGE";
	cfg->log_facility = LOG_USER;
	cfg->log_level = LOG_INFO;
    return (void *) cfg;
}

static res_cfg *res_clone_config(apr_pool_t *p, res_cfg* cfg) {
	return (res_cfg*)memcpy(res_create_config(p), cfg, sizeof(res_cfg));
}

static void *res_create_dir_config(apr_pool_t *p, char *dirspec)    { return res_create_config(p); }
static void *res_create_server_config(apr_pool_t *p, server_rec *s) { return res_create_config(p); }
static int min(int x, int y) { return x < y ? x : y; }

static void *res_merge_config(apr_pool_t *p, res_cfg* pconf, res_cfg* nconf) {
	int self, i;

	if (!nconf)
		return (void*) res_clone_config(p, pconf);

	if (!pconf)
		return (void*) res_clone_config(p, nconf);

	res_cfg *merged_config = res_create_config(p);

	merged_config->flags = pconf->flags | nconf->flags;
	for (self = 0; self <= RES_TOTAL; ++self)
		for (i = 0; i <= RES_TOTAL; ++i) {

			/* We use the parent limit, unless specifically set in more specific context. */
			struct timeval *tm = &merged_config->res_min[self].cpu[i];
			struct timeval *tp = &pconf->res_min[self].cpu[i];
			struct timeval *tn = &nconf->res_min[self].cpu[i];
			memcpy(tm, tn->tv_sec == 0 && tn->tv_usec == 0 ? tp : tn, sizeof(*tm));

			long n = nconf->res_min[self].mem[i];
			long p = pconf->res_min[self].mem[i];
			merged_config->res_min[self].mem[i] = n ? n : p;
		}

	merged_config->log_facility = min(pconf->log_facility, nconf->log_facility);
	merged_config->log_level = min(pconf->log_level, nconf->log_level);
	merged_config->id = apr_pstrdup(p, nconf->id);

	return (void *) merged_config;
}

static void *res_merge_dir_config(apr_pool_t *p, void *parent_conf, void *newloc_conf) {
	return res_merge_config(p, parent_conf, newloc_conf);
}

static void *res_merge_server_config(apr_pool_t *p, void *server1_conf, void *server2_conf) {
	return res_merge_config(p, server1_conf, server2_conf);
}

/*
 * Here, we take getrusage samples.
 */
static int res_post_read_request(request_rec *r) {
	// Ignore this for subrequests.

	if (r->main != NULL)
		return DECLINED;

	res_cfg *scfg = our_sconfig(r->server);
	res_cfg *dcfg = our_dconfig(r);

	if ((scfg == NULL) && (dcfg == NULL))
		return DECLINED;

	res_cfg* rcfg = res_merge_config(r->pool, scfg, dcfg);

	if (0 == (rcfg->flags & RES_ENABLE))
		return DECLINED;

	ap_set_module_config(r->request_config, &reslog_module, rcfg);

	if (getresusage(rcfg->res_stt) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "getrusage error: %s", strerror(errno));
		rcfg->flags &= ~RES_ENABLE;
	}

	return DECLINED;
}

static void res_request_done(res_cfg* cfg, int cgi) {
	/*
	 * FIXME: this may not catch every SIGCHLD.
	 */
	int status;
	struct rusage r;
	wait3(&status, cgi ? 0 : WNOHANG, &r);

	getresusage(cfg->res_used);

	rusage_rec_diff(cfg->res_used, cfg->res_stt);

	cfg->flags |= RES_DONE;
}

/*
 * Here we log resources used.
 */
static int res_logger(request_rec *r) {
	res_cfg *cfg = our_rconfig(r);

	if (cfg == NULL || 0 == (cfg->flags & ( RES_SYSLOG | RES_ERRLOG ) ))
		return DECLINED;

	if (0 == (cfg->flags & RES_DONE))
		res_request_done(cfg, r->handler && !strcmp(r->handler, "cgi-script"));

	/* If any thresold is exceeded, we log CPU & memory used. */
	if (rusage_rec_cmp(&cfg->res_min[RES_SELF], &cfg->res_used[RES_SELF]) >= 0 ||
	    rusage_rec_cmp(&cfg->res_min[RES_CHILD], &cfg->res_used[RES_CHILD]) >= 0 ||
		rusage_rec_cmp(&cfg->res_min[RES_TOTAL], &cfg->res_used[RES_TOTAL]) >= 0)

		res_log(cfg, r);

	return DECLINED;
}

static char* res_parse_log_arg(request_rec* r, int what, char* arg, int* i1, int* i2) {
	int valid = 1;
	while (*arg) {
		switch (*arg) {
			case 'S': valid = 1; *i1 = RES_SELF; break;
			case 'C': valid = 1; *i1 = RES_CHILD; break;
			case 'T': valid = 1; *i1 = RES_TOTAL; break;
			case 's': valid = what == RES_CPU; *i2 = RES_SYS; break;
			case 'u': valid = what == RES_CPU; *i2 = RES_USER; break;
			case 'r': valid = what == RES_MEM; *i2 = RES_RSS; break;
			case 'd': valid = what == RES_MEM; *i2 = RES_DRSS; break;
			case 't': valid = 1; *i2 = RES_TOTAL; break;
			default:
				valid = 0;
		}
		if (!valid)
			break;
		++arg;
	}
	return valid ?  NULL : apr_psprintf(r->pool, "Invalid char arg %c", *arg);
}

static const char* res_get_cpu(request_rec* r, char* arg) {
	int i1 = RES_TOTAL, i2 = RES_TOTAL;
	res_cfg* cfg = our_rconfig(r);

	if (!cfg)
		return NULL;

	if (0 == (cfg->flags & RES_DONE))
		res_request_done(cfg, r->handler && !strcmp(r->handler, "cgi-script"));
	
	const char* dev = res_parse_log_arg(r, RES_CPU, arg, &i1, &i2);
	if (dev != NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "%s", dev);
		dev = NULL;
	} else {
		struct timeval* tv = &cfg->res_used[i1].cpu[i2];
		dev = apr_psprintf(r->pool, "%lu.%06lu", tv->tv_sec, tv->tv_usec);
	}
	return dev;
}

static const char* res_get_mem(request_rec* r, char* arg) {
	int i1 = RES_SELF, i2 = RES_RSS;
	res_cfg* cfg = our_rconfig(r);

	if (!cfg)
		return NULL;

	if (0 == (cfg->flags & RES_DONE))
		res_request_done(cfg, r->handler && !strcmp(r->handler, "cgi-script"));
	const char* dev = res_parse_log_arg(r, RES_MEM, arg, &i1, &i2);
	if (dev != NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "%s", dev);
		dev = NULL;
	} else {
		dev = apr_psprintf(r->pool, "%ld", cfg->res_used[i1].mem[i2]);
	}
	return dev ;
}

static int res_pre_config(apr_pool_t* p, apr_pool_t* plog, apr_pool_t* ptmp) {
	APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;
	log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

	if (log_pfn_register) {
		log_pfn_register(p, "M", res_get_mem, 1);
		log_pfn_register(p, "c", res_get_cpu, 1);
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p,
			"register ap_register_log_handler not found by mod_reslog.");
	}

	return OK;
}

static void res_register_hooks(apr_pool_t *p) {
    /* [1] post read_request handling */
    ap_hook_post_read_request(res_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(res_logger, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(res_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

/* 
 * List of directives.
 */
static const command_rec res_cmds[] = {
	AP_INIT_FLAG("ResourceLogEnable", handle_enable, NULL, RSRC_CONF, ""),
	AP_INIT_TAKE1("ResourceLog", handle_reslog, NULL, RSRC_CONF, ""),
	AP_INIT_TAKE1("ResourceLogLevel", handle_level, NULL, RSRC_CONF, ""),
	AP_INIT_TAKE1("ResourceLogString", handle_string, NULL, RSRC_CONF, ""),
	AP_INIT_TAKE3("LogCPUThresold", handle_cpu_thresold, NULL, RSRC_CONF, ""),
	AP_INIT_TAKE3("LogMEMThresold", handle_mem_thresold, NULL, RSRC_CONF, ""),
    {NULL}
};

/* 
 * Module definition for configuration.  If a particular callback is not
 * needed, replace its routine name below with the word NULL.
 */
module AP_MODULE_DECLARE_DATA reslog_module = {
    STANDARD20_MODULE_STUFF,
    res_create_dir_config,    /* per-directory config creator */
    res_merge_dir_config,     /* dir config merger */
    res_create_server_config, /* server config creator */
    res_merge_server_config,  /* server config merger */
    res_cmds,                 /* command table */
    res_register_hooks,       /* set up other request processing hooks */
};

