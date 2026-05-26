"""Gunicorn config for ScanForge production deployment."""

bind = '0.0.0.0:5000'
workers = 4
worker_class = 'sync'
timeout = 120
keepalive = 5
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'
