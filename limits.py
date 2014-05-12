import resource

def set_limits():
    (soft, hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY,
        resource.RLIM_INFINITY))
