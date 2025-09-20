/**
 *  pam_flag - PAM module to flag users recently authenticated
 *  Copyright (C) 2025  Anna-Sophie Kasierocka
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 **/

#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#define UNUSED  __attribute__((unused))

/**
 * Creates a directory or updates permissions if it already exists.
 * Returns true if directory exists after call and false if it is not
 */
static bool ensure_dir(pam_handle_t *pamh, const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) { /* directory exists */
        if (S_ISLNK(st.st_mode)) {
            pam_syslog(pamh, LOG_ERR, "%s is a symlink; refusing", dir);
            return false;
        }
        if (!S_ISDIR(st.st_mode)) {
            pam_syslog(pamh, LOG_ERR, "%s exists and is not a directory", dir);
            return false;
        }
        if(st.st_uid != 0){
            pam_syslog(pamh, LOG_ERR, "%s exists and is not owned by root", dir);
            return false;
        }
        if ((st.st_mode & 0777) != 0700) {
            pam_syslog(pamh, LOG_NOTICE, "%s exists but is not 0700", dir);
            if (chmod(dir, 0700) != 0) {
                pam_syslog(pamh, LOG_ERR, "chmod %s: %s", dir, strerror(errno));
                return false;
            }
        }
        return true;
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        pam_syslog(pamh, LOG_ERR, "mkdir %s: %s", dir, strerror(errno));
        return false;
    }
    return true;
}

/**
 * Safely build a path to a flag file for a given user
 */
static bool flag_path(pam_handle_t *pamh, uid_t uid, char *out, size_t outsz) {
    const char *dir = "/run/pam-flag";
    if (!ensure_dir(pamh, dir)){
        return false;
    }
    if (snprintf(out, outsz, "%s/%u", dir, (unsigned)uid) >= (int)outsz) {
        pam_syslog(pamh, LOG_ERR, "flag path too long");
        return false;
    }
    return true;
}

static bool touch_mtime_now(pam_handle_t *pamh, const char *path) {
    struct timespec ts[2];
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_nsec = UTIME_NOW;
    if (utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW) == -1) {
        pam_syslog(pamh, LOG_ERR, "utimensat %s: %s", path, strerror(errno));
        return false;
    }
    return true;
}

static bool validate_flag(pam_handle_t *pamh, const char *path){
    struct stat st;
    if (lstat(path, &st) != 0) {
        pam_syslog(pamh, LOG_ERR, "lstat %s: %s", path, strerror(errno));
        return false;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0777) != 0600) {
        pam_syslog(pamh, LOG_ERR, "refusing to use pre-existing unsafe flag %s", path);
        return false;
    }
    return true;
}

/**
 * Writes a flag file for a given user
 * Returns true if flag exists with proper permissions after call and false if not
 */
static bool create_flag(pam_handle_t *pamh, uid_t uid) {
    char path[512];
    memset(path, 0, sizeof(path));
    if (!flag_path(pamh, uid, path, sizeof(path))){
        pam_syslog(pamh, LOG_ERR, "can not create flag path");
        return false;
    }

    if(strlen(path) == 0){
        pam_syslog(pamh, LOG_ERR, "can not create flag path, path is empty. If you see this message, please report it to the developers.");
        return false;
    }


    // Create with restrictive perms, fail if races
    mode_t old_umask = umask(0077);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    umask(old_umask);

    if (fd < 0) {
        if (errno == EEXIST) {
            if(!validate_flag(pamh, path)){
                return false;
            }
            return touch_mtime_now(pamh, path);
        }
        pam_syslog(pamh, LOG_ERR, "open %s: %s", path, strerror(errno));
        return false;
    }
    pam_syslog(pamh, LOG_NOTICE, "created flag for uid %u at path %s", (unsigned)uid, path);
    close(fd);
    return true;
}

static bool has_timed_out(pam_handle_t *pamh, const char *path, time_t timeout) {
    if (timeout == 0){
         pam_syslog(pamh, LOG_NOTICE, "Timeouts are disabled by zero value");
         return false;
    }

    if (timeout < 0){
        pam_syslog(pamh, LOG_ERR, "Timeout < 0 after initial check. This is a bug.");
        return true;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        pam_syslog(pamh, LOG_ERR, "stat %s: %s", path, strerror(errno));
        return true;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        pam_syslog(pamh, LOG_ERR, "time() failed: %s", strerror(errno));
        return true;
    }

    time_t mtime = st.st_mtime;

    if (mtime > now) {
        pam_syslog(pamh, LOG_WARNING, "mtime of %s is in the future", path);
        return true;
    }

    pam_syslog(pamh, LOG_DEBUG, "mtime of %s is %ld, now is %ld", path, mtime, now);

    return (now - mtime) >= timeout;
}

/**
 * Checks that there is a valid flag file for a given user
 */
static bool have_valid_flag(pam_handle_t *pamh, uid_t uid, time_t timeout) {
    char path[512];
    memset(path, 0, sizeof(path));
    if (!flag_path(pamh, uid, path, sizeof(path))){
         pam_syslog(pamh, LOG_ERR, "can not create flag path");
         return false;
    }
    struct stat st;

    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        // basic sanity: owner root, 0600
        if (st.st_uid != 0) {
            pam_syslog(pamh, LOG_ERR, "uid %u flag not owned by root", (unsigned)uid);
            return false;
        }
        if ((st.st_mode & 0777) != 0600) {
            pam_syslog(pamh, LOG_ERR, "uid %u flag permissions are not restrictive enough. Refusing to use it.",
                       (unsigned)uid);
            return false;
        }
        return !has_timed_out(pamh, path, timeout);
    }
    return false;
}

static int get_uid(pam_handle_t *pamh, uid_t *uid) {
    const char *user = NULL;
    int rc = pam_get_user(pamh, &user, NULL);
    if (rc != PAM_SUCCESS || !user || !*user) {
        pam_syslog(pamh, LOG_ERR, "cannot determine user");
        return PAM_USER_UNKNOWN;
    }

    struct passwd *pw = pam_modutil_getpwnam(pamh, user);
    if (!pw) {
        pam_syslog(pamh, LOG_ERR, "cannot resolve user '%s' to passwd entry", user);
        return PAM_USER_UNKNOWN;
    }

    *uid = pw->pw_uid;
    return PAM_SUCCESS;
}

static const char* parse_mode(int argc, const char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "mode=", 5) == 0) return argv[i] + 5;
    }
    return "require";
}

static int parse_timeout(pam_handle_t *pamh, int argc, const char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "timeout=", 8) == 0) {
            const char *val = argv[i] + 8;
            char *end = NULL;
            errno = 0;
            long v = strtol(val, &end, 10);
            if (errno != 0 || end == val || *end != '\0' || v < 0 || v > INT_MAX) {
                pam_syslog(pamh, LOG_ERR, "invalid timeout value: %s", val);
                return -1;
            }
            return (int)v;
        }
    }
    return 60;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int UNUSED flags,
                                   int argc, const char **argv) {
    const char *mode = parse_mode(argc, argv);
    time_t timeout = parse_timeout(pamh, argc, argv);
    if(timeout < 0){
        pam_syslog(pamh, LOG_ERROR, "negative timeout is prohibited", (unsigned)timeout);
        return PAM_AUTH_ERR;
    }

    uid_t uid = 0;
    int rc = get_uid(pamh, &uid);
    if (rc != PAM_SUCCESS) return rc;

    pam_syslog(pamh, LOG_DEBUG, "uid=%u, mode=%s, timeout=%ld", (unsigned)uid, mode, timeout);

    if (strcmp(mode, "set") == 0) {
        pam_syslog(pamh, LOG_NOTICE, "setting flag for uid %u", (unsigned)uid);
        // This should be placed AFTER a successful authenticator in the stack.
        if (!create_flag(pamh, uid)) {
            pam_syslog(pamh, LOG_ERR, "failed to set flag for uid %u", (unsigned)uid);
            // Don't lock users out due to transient fs errors; configurable choice:
            return PAM_SUCCESS;
        }
        return PAM_SUCCESS;
    } else {
        // require
        if (have_valid_flag(pamh, uid, timeout)) {
            // Flag present: allow to continue to next module
            return PAM_SUCCESS;
        } else {
            // No flag: deny access at authentication stage
            pam_syslog(pamh, LOG_NOTICE, "denying uid %u: flag missing or invalid", (unsigned)uid);
            return PAM_AUTH_ERR;
        }
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t UNUSED *pamh, int UNUSED flags,
                              int UNUSED argc, const char UNUSED **argv) {
    // No creds management needed
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_flag_modstruct = {
    "pam_flag",
    NULL,
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
};
#endif

