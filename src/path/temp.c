#include <sys/types.h>  /* stat(2), opendir(3), */
#include <sys/stat.h>   /* stat(2), chmod(2), */
#include <unistd.h>     /* stat(2), rmdir(2), unlink(2), readlink(2), */
#include <errno.h>      /* errno(2), */
#include <stdbool.h>    /* bool, true, false, */
#include <dirent.h>     /* readdir(3), opendir(3), */
#include <string.h>     /* strcmp(3), */
#include <stdlib.h>     /* free(3), getenv(3), */
#include <stdio.h>      /* P_tmpdir, */
#include <talloc.h>     /* talloc(3), */

#include "cli/note.h"

/**
 * Create one uniquely-named directory below @parent and remove it
 * right away: a probe that @parent is a writable directory, executed
 * with the very operation the callers of get_temp_directory() will
 * perform.  Returns whether the probe passed; on failure @error, when
 * non-NULL, carries the errno of the failed mkdtemp(3).
 */

/* mkdtemp(3) replacement: musl's implementation issues the legacy
 * mkdir(2) (nr 83, TRAP-class on Android 15 x86_64) internally, and
 * libc-internal calls escape the compile-time *at remap -- the AVD
 * launcher died exactly here, creating the glue root.  Same 6-char
 * suffix dance, over the remapped mkdir (mkdirat). */
static char *temp_mkdtemp(char *tmpl)
{
        static const char alphabet[] =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        size_t len;
        int attempt, i;

        if (tmpl == NULL) {
                errno = EINVAL;
                return NULL;
        }
        len = strlen(tmpl);
        if (len < 6 || strcmp(tmpl + len - 6, "XXXXXX") != 0) {
                errno = EINVAL;
                return NULL;
        }
        for (attempt = 0; attempt < 64; attempt++) {
                for (i = 0; i < 6; i++)
                        tmpl[len - 6 + i] = alphabet[rand() % 62];
                if (mkdir(tmpl, 0700) == 0)
                        return tmpl;
                if (errno != EEXIST)
                        return NULL;
        }
        errno = EEXIST;
        return NULL;
}

static int probe_temp_parent(const char *parent, int *error)
{
        char name[strlen(parent) + sizeof("/nproot-tmp-probe-XXXXXX")];
        char *result;

        snprintf(name, sizeof(name), "%s/nproot-tmp-probe-XXXXXX", parent);
        result = temp_mkdtemp(name);
        if (result == NULL) {
                if (error != NULL)
                        *error = errno;
                return 0;
        }

        rmdir(result);
        return 1;
}

/**
 * Whether @a and @b name the same directory, trailing slashes aside:
 * bionic's P_tmpdir is "/tmp/" while a TMPDIR export usually says
 * "/tmp", and both spellings would be probed -- and reported -- twice.
 */
static bool same_dir(const char *a, const char *b)
{
        size_t length_a = strlen(a);
        size_t length_b = strlen(b);

        while (length_a > 1 && a[length_a - 1] == '/')
                length_a--;
        while (length_b > 1 && b[length_b - 1] == '/')
                length_b--;

        return length_a == length_b && strncmp(a, b, length_a) == 0;
}

/**
 * mkdir(2) that creates missing parents as well.
 *
 * mkdir(2) only ever creates the leaf directory, so a candidate such
 * as "$HOME/.cache/nproot" dies with ENOENT when ~/.cache does not
 * exist yet -- the usual case on a fresh Termux home, and the reason
 * one device saw every candidate rejected.  Walk the path from the
 * root, create whatever is missing with mode 0700, and ignore EEXIST
 * along the way.  Returns whether @path is a directory once we return;
 * the caller probes writability anyway, this is only about giving the
 * probe a chance to succeed.
 */
static bool mkdir_recursively(const char *path)
{
        char copy[PATH_MAX];
        struct stat st;
        size_t i;

        if (strlen(path) >= sizeof(copy))
                return false;
        strcpy(copy, path);

        for (i = 1; copy[i] != '\0'; i++) {
                if (copy[i] != '/')
                        continue;
                copy[i] = '\0';
                (void) mkdir(copy, 0700);
                copy[i] = '/';
        }
        (void) mkdir(copy, 0700);

        return stat(copy, &st) == 0 && S_ISDIR(st.st_mode);
}

/**
 * Return the path to a directory where temporary files should be
 * created.
 *
 * A set PROOT_TMP_DIR is the whole answer: probed with mkdtemp(3),
 * created (best effort) if missing, and reported as-is when unusable
 * so the mkdtemp error downstream stays worded after it, exactly as
 * this function behaved before.  Unset, the first writable candidate
 * wins, probed the same way -- which matters on systems with no
 * canonical temporary directory, Android above all: bionic's P_tmpdir
 * is "/tmp/" but the directory either does not exist there or exists
 * yet rejects the app (devices were seen where it is simply EACCES),
 * the Termux environment provides $PREFIX/tmp (TMPDIR usually points
 * there too), and $HOME/.cache/nproot is created on demand -- parents
 * included -- before $HOME itself is tried as the last resort.  Every
 * rejected candidate is reported, so a device report shows what was
 * tried and why each attempt failed.
 */
const char *get_temp_directory()
{
        static const char *temp_directory = NULL;
        TALLOC_CTX *context = talloc_autofree_context();
        const char *candidates[5];
        char *composed[3];
        size_t nb_composed = 0;
        size_t nb_candidates = 0;
        const char *env;
        char *tmp;
        size_t i = 0;
        int errors[5];

        if (temp_directory != NULL)
                return temp_directory;

        /*
         * A set PROOT_TMP_DIR is authoritative and stays alone in the
         * list: its owner chose the location on purpose, so an unusable
         * one must fail loudly rather than silently send the temporary
         * files elsewhere (see tests/test-tempdire.sh).  It also skips
         * the probe loop entirely, jumping straight to "found" with
         * candidate 0 -- hence i being initialized at declaration.
         */
        env = getenv("PROOT_TMP_DIR");
        if (env != NULL) {
                candidates[nb_candidates++] = env;
                goto found;
        }

        env = getenv("TMPDIR");         /* POSIX override, first pick. */
        if (env != NULL)
                candidates[nb_candidates++] = env;

        candidates[nb_candidates++] = P_tmpdir;

        env = getenv("PREFIX");         /* Termux layout. */
        if (env != NULL && nb_composed < sizeof(composed)/sizeof(*composed)) {
                composed[nb_composed] = talloc_asprintf(context, "%s/tmp", env);
                if (composed[nb_composed] != NULL)
                        candidates[nb_candidates++] = composed[nb_composed++];
        }

        env = getenv("HOME");           /* Created on demand, then raw. */
        if (env != NULL && nb_composed < sizeof(composed)/sizeof(*composed)) {
                composed[nb_composed] = talloc_asprintf(context,
                        "%s/.cache/nproot", env);
                if (composed[nb_composed] != NULL)
                        candidates[nb_candidates++] = composed[nb_composed++];

                if (nb_composed < sizeof(composed)/sizeof(*composed)) {
                        composed[nb_composed] = talloc_strdup(context, env);
                        if (composed[nb_composed] != NULL)
                                candidates[nb_candidates++] = composed[nb_composed++];
                }
        }

        /*
         * Drop candidates naming the same directory as an earlier one:
         * Termux exports TMPDIR=$PREFIX/tmp, and bionic's P_tmpdir is
         * "/tmp/" where the export says "/tmp", so identical
         * directories would otherwise be probed -- and reported --
         * twice.
         */
        {
                size_t kept = 0;
                size_t j;

                for (j = 0; j < nb_candidates; j++) {
                        bool duplicate = false;
                        size_t k;

                        for (k = 0; k < kept; k++) {
                                if (same_dir(candidates[k], candidates[j])) {
                                        duplicate = true;
                                        break;
                                }
                        }
                        if (!duplicate)
                                candidates[kept++] = candidates[j];
                }
                nb_candidates = kept;
        }

        for (i = 0; i < nb_candidates; i++) {
                errors[i] = 0;
                if (probe_temp_parent(candidates[i], &errors[i]))
                        goto found;

                (void) mkdir_recursively(candidates[i]);
                if (probe_temp_parent(candidates[i], &errors[i]))
                        goto found;
        }

        /*
         * Nothing usable: say why each candidate was rejected, then let
         * the caller fail with its own error, which names the actual
         * path -- same behavior as before, but now with the rejected
         * candidates on record for the bug report.
         */
        for (i = 0; i < nb_candidates; i++)
                note(NULL, WARNING, INTERNAL,
                        "temp directory candidate '%s' is unusable: %s",
                        candidates[i], strerror(errors[i]));
        i = 0;                  /* Report candidate 0 and let the caller fail. */

found:
        temp_directory = candidates[i];

        tmp = realpath(temp_directory, NULL);
        if (tmp == NULL) {
                note(NULL, WARNING, SYSTEM,
                        "can't canonicalize %s", temp_directory);
                return temp_directory;
        }

        temp_directory = talloc_strdup(context, tmp);
        if (temp_directory == NULL)
                temp_directory = tmp;
        else
                free(tmp);

        return temp_directory;
}

/**
 * Remove recursively the content of the current working directory.
 * This latter has to lie in temp_directory (ie. "/tmp" on most
 * systems).  This function returns -1 if a fatal error occured
 * (ie. the recursion must be stopped), the number of non-fatal errors
 * otherwise.
 *
 * WARNING: this function changes the current working directory for
 * the calling process.
 */
static int clean_temp_cwd()
{
        const char *temp_directory = get_temp_directory();
        const size_t length_temp_directory = strlen(temp_directory);
        char *prefix = NULL;
        int nb_errors = 0;
        DIR *dir = NULL;
        int status;

        prefix = talloc_size(NULL, length_temp_directory + 1);
        if (prefix == NULL) {
                note(NULL, WARNING, INTERNAL, "can't allocate memory");
                nb_errors++;
                goto end;
        }

        /* Sanity check: ensure the current directory lies in
         * "/tmp".  */
        status = readlink("/proc/self/cwd", prefix, length_temp_directory);
        if (status < 0) {
                note(NULL, WARNING, SYSTEM, "can't readlink '/proc/self/cwd'");
                nb_errors++;
                goto end;
        }
        prefix[status] = '\0';

        if (strncmp(prefix, temp_directory, length_temp_directory) != 0) {
                note(NULL, ERROR, INTERNAL,
                        "trying to remove a directory outside of '%s', "
                        "please report this error.", temp_directory);
                nb_errors++;
                goto end;
        }

        dir = opendir(".");
        if (dir == NULL) {
                note(NULL, WARNING, SYSTEM, "can't open '.'");
                nb_errors++;
                goto end;
        }

        while (1) {
                struct dirent *entry;

                errno = 0;
                entry = readdir(dir);
                if (entry == NULL)
                        break;

                if (   strcmp(entry->d_name, ".")  == 0
                    || strcmp(entry->d_name, "..") == 0)
                        continue;

                /* Skip chmod on symlinks: chmod follows them and would
                 * report spurious errors when the target no longer
                 * exists (common with the /dev/{stdin,fd,...} symlinks
                 * bubblewrap leaves behind in emulated tmpfs dirs).
                 * We only need to unlink the symlink itself.  */
                if (entry->d_type != DT_LNK) {
                        status = chmod(entry->d_name, 0700);
                        if (status < 0) {
                                note(NULL, WARNING, SYSTEM, "cant chmod '%s'", entry->d_name);
                                nb_errors++;
                                continue;
                        }
                }

                if (entry->d_type == DT_DIR) {
                        status = chdir(entry->d_name);
                        if (status < 0) {
                                note(NULL, WARNING, SYSTEM, "can't chdir '%s'", entry->d_name);
                                nb_errors++;
                                continue;
                        }

                        /* Recurse.  */
                        status = clean_temp_cwd();
                        if (status < 0) {
                                nb_errors = -1;
                                goto end;
                        }
                        nb_errors += status;

                        status = chdir("..");
                        if (status < 0) {
                                note(NULL, ERROR, SYSTEM, "can't chdir to '..'");
                                nb_errors = -1;
                                goto end;
                        }

                        status = rmdir(entry->d_name);
                }
                else {
                        status = unlink(entry->d_name);
                }
                if (status < 0) {
                        note(NULL, WARNING, SYSTEM, "can't remove '%s'", entry->d_name);
                        nb_errors++;
                        continue;
                }
        }
        if (errno != 0) {
                note(NULL, WARNING, SYSTEM, "can't readdir '.'");
                nb_errors++;
        }

end:
        TALLOC_FREE(prefix);

        if (dir != NULL)
                (void) closedir(dir);

        return nb_errors;
}

/**
 * Remove recursively @path.  This latter has to be a directory lying
 * in temp_directory (ie. "/tmp" on most systems).  This function
 * returns -1 on error, otherwise 0.
 */
static int remove_temp_directory2(const char *path)
{
        int result;
        int status;
        char *cwd;

#ifdef __ANDROID__
        cwd = malloc(PATH_MAX);
        getcwd(cwd, PATH_MAX);
#else
        cwd = get_current_dir_name();
#endif

        status = chmod(path, 0700);
        if (status < 0) {
                note(NULL, ERROR, SYSTEM, "can't chmod '%s'", path);
                result = -1;
                goto end;
        }

        status = chdir(path);
        if (status < 0) {
                note(NULL, ERROR, SYSTEM, "can't chdir to '%s'", path);
                result = -1;
                goto end;
        }

        status = clean_temp_cwd();
        result = (status == 0 ? 0 : -1);

        /* Try to remove path even if something went wrong.  */
        status = chdir("..");
        if (status < 0) {
                note(NULL, ERROR, SYSTEM, "can't chdir to '..'");
                result = -1;
                goto end;
        }

        status = rmdir(path);
        if (status < 0) {
                note(NULL, ERROR, SYSTEM, "cant remove '%s'", path);
                result = -1;
                goto end;
        }

end:
        if (cwd != NULL) {
                status = chdir(cwd);
                if (status < 0) {
                        result = -1;
                        note(NULL, ERROR, SYSTEM, "can't chdir to '%s'", cwd);
                }
                free(cwd);
        }

        return result;
}

/**
 * Like remove_temp_directory2() but always return 0.
 *
 * Note: this is a talloc destructor.
 */
static int remove_temp_directory(char *path)
{
        (void) remove_temp_directory2(path);
        return 0;
}

/**
 * Remove the file @path.  This function always returns 0.
 *
 * Note: this is a talloc destructor.
 */
static int remove_temp_file(char *path)
{
        int status;

        status = unlink(path);
        if (status < 0)
                note(NULL, ERROR, SYSTEM, "can't remove '%s'", path);

        return 0;
}

/**
 * Create a path name with the following format:
 * "/tmp/@prefix-$PID-XXXXXX".  The returned C string is either
 * auto-freed if @context is NULL.  This function returns NULL if an
 * error occurred.
 */
char *create_temp_name(TALLOC_CTX *context, const char *prefix)
{
        const char *temp_directory = get_temp_directory();
        char *name;

        if (context == NULL)
                context = talloc_autofree_context();

        name = talloc_asprintf(context, "%s/%s-%d-XXXXXX", temp_directory, prefix, getpid());
        if (name == NULL) {
                note(NULL, ERROR, INTERNAL, "can't allocate memory");
                return NULL;
        }

        return name;
}

/**
 * Create a directory that will be automatically removed either on
 * PRoot termination if @context is NULL, or once its path name
 * (attached to @context) is freed.  This function returns NULL on
 * error, otherwise the absolute path name to the created directory
 * (@prefix-ed).
 */
const char *create_temp_directory(TALLOC_CTX *context, const char *prefix)
{
        char *name;
        char *template;

        name = create_temp_name(context, prefix);
        if (name == NULL)
                return NULL;

        template = name;
        name = temp_mkdtemp(name);
        if (name == NULL) {
                note(NULL, ERROR, SYSTEM,
                        "can't create temporary directory '%s'", template);
                note(NULL, INFO, USER, "Please set PROOT_TMP_DIR env. variable "
                        "to an alternate location (with write permission).");
                return NULL;
        }

        talloc_set_destructor(name, remove_temp_directory);

        return name;
}

/**
 * Create a file that will be automatically removed either on PRoot
 * termination if @context is NULL, or once its path name (attached to
 * @context) is freed.  This function returns NULL on error,
 * otherwise the absolute path name to the created file (@prefix-ed).
 */
const char *create_temp_file(TALLOC_CTX *context, const char *prefix)
{
        char *name;
        int fd;

        name = create_temp_name(context, prefix);
        if (name == NULL)
                return NULL;

        fd = mkstemp(name);
        if (fd < 0) {
                note(NULL, ERROR, SYSTEM, "can't create temporary file '%s'", name);
                note(NULL, INFO, USER, "Please set PROOT_TMP_DIR env. variable "
                        "to an alternate location (with write permission).");
                return NULL;
        }
        close(fd);

        talloc_set_destructor(name, remove_temp_file);

        return name;
}

/**
 * Like create_temp_file() but returns an open file stream to the
 * created file.  It's up to the caller to close returned stream.
 */
FILE* open_temp_file(TALLOC_CTX *context, const char *prefix)
{
        char *name;
        FILE *file;
        int fd;

        name = create_temp_name(context, prefix);
        if (name == NULL)
                return NULL;

        fd = mkstemp(name);
        if (fd < 0)
                goto error;

        talloc_set_destructor(name, remove_temp_file);

        file = fdopen(fd, "w");
        if (file == NULL)
                goto error;

        return file;

error:
        if (fd >= 0)
                close(fd);
        note(NULL, ERROR, SYSTEM, "can't create temporary file '%s'", name);
        note(NULL, INFO, USER, "Please set PROOT_TMP_DIR env. variable "
                "to an alternate location (with write permission).");
        return NULL;
}
