mod_reslog
==========

Apache httpd resource logging module

This module is written to aid in finding cpu / memory starvers.   It basically calls getrusage(2) ('get resource usage' system call) at the very beggining of the request and at the very end of it.

This module may log cpu / memory usage to either/any of:
 * apache ErrorLog (non-customizable format, only a string identifier can be set).
 * syslog (may set facility & level, same format as ErrorLog).
 * apache CustomLog (fully customizable format with tags 'M' and 'c', see below).

Logging through CustomLog:
-------------------------

When using CustomLog, these two tags are provided for LogFormat:

 * %{...}M: for logging memory usage
   These format chars may be used:
   * 't' ('total'): logs total memory increase.
   * 'r' ('rss'): logs rss memory increase.
   * 'd' ('drss'): logs drss memory increase.

 * %{...}c: for logging cpu usage
   When logging cpu usage, these format chars may be used:
   * 's' ('system'): logs cpu usage in 'kernel mode'.
   * 'u' ('user'): logs cpu usage in 'user mode'.
   * 't' ('total'): logs cpu usage 'user mode' + 'kernel mode'

Both tags ('M' & 'c') also support these characters in their format:

 * 'S' ('self'): logs resource usage by the apache process per-se.
 * 'C' ('child'): logs resource usage by the apache's child process.  Child processes are seen on SSI's exec, and CGIs.
 * 'T' ('total'): logs resource usage by apache process per-se and all child processes it may have created.

Example:
```
  LogFormat "%a %u %v %{Host}i %U%q %f %>s %D %{Su}c %{St}c %ct %{S}M" resource
  CustomLog "/var/log/apache2/resource.log" resource
```

 Will log:
   * self-usermode cpu usage ("%{Su}c").
   * self user + kernel mode cpu usage ("%{St}c".
   * self memory increase ("%{S}M").

Logging to Apache error log and/or syslog:
-----------------------------------------

To use only the CustomLog tags:

```
    ResourceLogEnable on
```

To enable apache's error log:

```
    ResourceLogEnable on
    ResourceLog error_log
```

To enable logging via syslog:

```
    ResourceLogEnable on
    ResourceLog syslog
```

To use both syslog and apache's error_log, and possibly the CustomLog tags:

```
    ResourceLogEnable on
    ResourceLog syslog
    ResourceLog error_log
```

Don't log light requests:
------------------------

When logging to ErrorLog or to syslog, cpu usage thresolds may be specified to
avoid log entries of light requests:

    LogCPUThresold (self|child|total) (user|sys|total) 0.01
    # values are in seconds

    LogMEMThresold (self|child|total) (rss|data|total) 1000000
    # valures are in bytes

Add a visible mark in the messages:
----------------------------------

With the line below "easy_to_grep_string" will be included on every line.

    ResourceLogString easy_to_grep_string

Notes:
  * If logging to syslog, LOG_USER|LOG_INFO will be used as a priority.
  * If logging to apache error log, APLOG_INFO will be used as the logging level.

Apache configuration reference:
------------------------------

### ResourceLogEnable
Enable or disable mod_reslog.
If the module is disabled, none of the CustomLog tags, apache's error log and syslog
will work.
This has to be enabled if you plan to use this module at all.
```
  ResourceLogEnable (on|off)
```

### ResourceLog

 Specify mod_reslog specific logging: either apache's error log or syslog.
 Can be specified more than once
```
  ResourceLog (syslog|error_log)
```

### ReourceLogLevel

Sets the logging level used for both apache error log and syslog.

* **'facility'** Is optional and if specified, may be any of:
auth, authpriv, cron, daemon, ftp, kern, local0 .. local7, lpr, mail, news, syslog, user, uucp.

* **'level'** Is mandatory, and may be any of:
emerg, alert, crit, err, warning, notice, info or debug.

When logging into:
* Apache error log: APLOG_level is used (emerg => APLOG_EMERG).
* syslog: LOG_facility|LOG_level is used (local4.info => LOG_LOCAL4|LOG_INFO).

## Note:
If apache's LogLevel is set to notice, and ResourceLogLevel is set to info, mod_reslog's error logging will get filtered out by apache.
So, ResourceLogLevel should be higher than LogLevel (by "higher" I mean more "critical").
 
  ResourceLogLevel [facility.]level

Examples:
```
  ResourceLogLevel notice
  ResourceLogLevel local4.notice
  LogLevel notice  # can also use info or debug, or the messages will get filtered out by apache.
```

### ResourceLogString
Let you specify a string that will be included in every line.  This is to ease Apache error log/syslog grepping.
  ResourceLogString some_custom_string

### Loggin thresholds:
Let you specify minimum values a request must exceed in order to get logged on Apache error log or syslog. Has no efect on CustomLog logging.

```
LogCPUThresold (self|child|total) (user|system|total) seconds
LogMEMThresold (self|child|total) (rss|data|total) bytes
```

Where:
 * 'seconds' may have fractional (you may log requests that took over 1ms of cpu time).
 * 'bytes' minimum number of bytes a request must allocate in order to get logged.

A request will be logged if it satisfies any of the conditions imposed by these directives.

Apache configuration example:
-----------------------------

```
<IfModule mod_reslog.c>
     # Enable the resource usage collection, and CustomLog tags.
     ResourceLogEnable on

     # If we are going to log to apache's error log, set the level to warning for profiling messages.
     ResourceLogLevel warning

     # Use the apache error log and syslog as well
     ResourceLog syslog

     # Set syslog: LOG_LOCAL4 | LOG_INFO
     # Set apache: APLOG_INFO
     ResourceLogLevel local4.info

     # We want to filter the results with: "grep REQUEST_RESOURCE_USAGE /path/of/the*logs"
     ResourceLogString REQUEST_RESOURCE_USAGE

     # Don't log light requests
     LogCPUThresold self user 0.01
     LogCPUThresold self system 0.001
     LogMEMThresold self total 1000000
</IfModule>
```

Brief:
 * Module is enabled, and
 * It will log to syslog with facility 'local4' and priority 'info'.
 * Will log only requests that consumed more than 10ms of usermode cpu, or 1ms of kermode cpu, or if process size increased by 1 million bytes.
 * Resource usage will sill be calculcated and will be available to mod_log_config (and reported via syslog as well).
 * Lines like this would appear in apache ErrorLog (line is wrapped for readability):

```
[Fri Apr 28 11:48:09 2006] [info] [REQUEST_RESOURCE_USAGE]
	your-host/apache2-default/index.html.en 
	/var/www/apache2-default/index.html.en
	self 0.004999u 0.001999s 0.006998t
	total 0.004999u 0.001999s 0.006998t
```

Guide
-----

Here are some guidelines for choosing the right configuration variables for your setup:
 
What to log?
===========

  * If you are running "heavy" **in-process** (like using libphp5.so, mod_python, etc), you will want to log self.user CPU.
  * If you are using some soft of "fast-cgi" (fcgid, or any of it's variants), this module will not work for you.
  * If you are running "heavy" **cgis**, you will want to log child.user and/or child.total CPU.
  * If you are running scripts that you are not in control (say, shared hosting), you will certainly want total.total CPU.

The distinction of self|child|total:
  * total = child + self
  * self: CPU used by httpd process itself.
  * child: CPU used by child processes
    * in PHP: when you use system(), shell_exec(), etc.
    * in PERL: when you use the backtick operator, popen, etc.

Also, you will want to avoid flooding your logs with extremely light requests, so I recommend having:

```
     LogCPUThresold self user 0.01
     LogCPUThresold self system 0.001
     LogMEMThresold self total 1000000
```

You will want to tune the values above to match your requirements.

Where to log?
============

* If you and some trusted team have access to upload scripts, choose whatever you like (CustomLog tags, ErrorLog, syslog, etc).
* If you are not in full control of what gets executed (someone you don't trust can upload scripts), you should be careful enough to log the profiling information to some place where the user cannot access, or he may fake log lines. Example: if you set mod_reslog to report to syslog, someone could call the syslog() function from PHP/PERL and your log-file-processing-script will tell you that someone else is responsible for the CPU usage.

