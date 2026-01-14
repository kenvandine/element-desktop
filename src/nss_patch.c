#define _GNU_SOURCE
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

typedef int (*getpwuid_r_t)(uid_t, struct passwd *, char *, size_t, struct passwd **);

static int copy_str(char **dest_ptr, const char *src, char **buf_ptr, size_t *len_ptr) {
    size_t slen = strlen(src) + 1;
    if (*len_ptr < slen) return -1;
    
    memcpy(*buf_ptr, src, slen);
    *dest_ptr = *buf_ptr;
    
    *buf_ptr += slen;
    *len_ptr -= slen;
    return 0;
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
    
    // Only intercept if looking up "myself"
    if (uid == getuid()) {
        char *env_user = getenv("USER");
        char *env_home = getenv("HOME");
        char *env_shell = getenv("SHELL");

        if (!env_user) env_user = "user";
        if (!env_home) env_home = "/tmp";
        if (!env_shell) env_shell = "/bin/bash";

        char *cursor = buf;
        size_t remaining = buflen;

        pwd->pw_uid = uid;
        pwd->pw_gid = getgid();
        
        if (copy_str(&pwd->pw_name, env_user, &cursor, &remaining) < 0 ||
            copy_str(&pwd->pw_passwd, "x", &cursor, &remaining) < 0 ||
            copy_str(&pwd->pw_gecos, "Element User", &cursor, &remaining) < 0 ||
            copy_str(&pwd->pw_dir, env_home, &cursor, &remaining) < 0 ||
            copy_str(&pwd->pw_shell, env_shell, &cursor, &remaining) < 0) {
            
            return ERANGE;
        }

        *result = pwd;
        return 0;
    }

    static getpwuid_r_t real_func = NULL;
    if (!real_func) {
        real_func = (getpwuid_r_t)dlsym(RTLD_NEXT, "getpwuid_r");
    }

    if (real_func) {
        return real_func(uid, pwd, buf, buflen, result);
    }
    
    *result = NULL;
    return ENOENT; 
}
