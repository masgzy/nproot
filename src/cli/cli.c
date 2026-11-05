/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <stdio.h>         /* printf(3), */
#include <stdbool.h>       /* bool, true, false,  */
#include <linux/limits.h>  /* ARG_MAX, PATH_MAX, */
#include <string.h>        /* str*(3), basename(3),  */
#include <talloc.h>        /* talloc*,  */
#include <stdlib.h>        /* exit(3), EXIT_*, strtol(3), {g,s}etenv(3), */
#include <assert.h>        /* assert(3),  */
#include <sys/types.h>     /* getpid(2),  */
#include <unistd.h>        /* getpid(2), _exit(2), */
#include <errno.h>         /* errno(3), */
#include <libgen.h>        /* basename(3), */
#ifdef __GLIBC__
#include <execinfo.h>      /* backtrace_symbols(3), */
#endif
#include <limits.h>        /* INT_MAX, */

#include "cli/cli.h"
#include "cli/note.h"
#include "env_sanitize.h"
#include "extension/extension.h"
#include "proto/proto_launch.h"
#include "tracee/tracee.h"
#include "tracee/event.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/path.h"
#include <extension/extension.h>
#include <extension/sysvipc/sysvipc.h>

#include "build.h"

/**
 * Print a (@detailed) usage of PRoot.
 */
void print_usage(Tracee *tracee, const Cli *cli, bool detailed)
{
        const char *current_class = "none";
        const Option *options;
        size_t i, j;

#define DETAIL(a) if (detailed) a

        DETAIL(printf("%s %s: %s。\n\n", cli->name, cli->version, cli->subtitle));
        printf("用法：\n  %s\n", cli->synopsis);
        DETAIL(printf("\n"));

        options = cli->options;
        for (i = 0; options[i].class != NULL; i++) {
                for (j = 0; ; j++) {
                        const Argument *argument = &(options[i].arguments[j]);

                        if (!argument->name || (!detailed && j != 0)) {
                                DETAIL(printf("\n"));
                                printf("\t%s\n", options[i].description);
                                if (detailed) {
                                        if (options[i].detail[0] != '\0')
                                                printf("\n%s\n\n", options[i].detail);
                                        else
                                                printf("\n");
                                }
                                break;
                        }

                        if (strcmp(options[i].class, current_class) != 0) {
                                current_class = options[i].class;
                                printf("\n%s:\n", current_class);
                        }

                        if (j == 0)
                                printf("  %s", argument->name);
                        else
                                printf(", %s", argument->name);

                        if (argument->separator != '\0')
                                printf("%c*%s*", argument->separator, argument->value);
                        else if (!detailed)
                                printf("\t");
                }
        }

        notify_extensions(tracee, PRINT_USAGE, detailed, 0);

        if (detailed)
                printf("%s\n", cli->colophon);
}

/**
 * Print the version of PRoot.
 */
void print_version(const Cli *cli)
{
        printf("%s %s\n\n", cli->logo, cli->version);
        /* The LD_PRELOAD (proto) backend is the default since phase 1
         * of docs/BACKENDS.md; the ptrace backend remains the fallback
         * and can be forced with NPROOT_BACKEND=ptrace.  */
        printf("拦截后端：proto（默认，不可用时回退 ptrace）\n");
        printf("内置加速器：process_vm = %s，seccomp_filter = %s\n",
#if defined(HAVE_PROCESS_VM)
                "是",
#else
                "否",
#endif
#if defined(HAVE_SECCOMP_FILTER)
                "是"
#else
                "否"
#endif
                );
}

static void print_execve_help(const Tracee *tracee, const char *argv0, int status)
{
        note(tracee, ERROR, SYSTEM, "execve(\"%s\")", argv0);

        /* termux-exec replaced execve with path with one that doesn't exist inside nproot?  */
        if (status == -ENOENT && getenv("LD_PRELOAD") != NULL && strstr(getenv("LD_PRELOAD"), "libtermux-exec.so") != NULL) {
                note(tracee, INFO, USER,
"检测到 termux-exec 正在生效，它把可执行路径改写成了 /data/data/com.termux/... 前缀\n"
"如果该路径在 nproot 内不可用，请执行 \"unset LD_PRELOAD\"");
                return;
        }

        /* Ubuntu kernel bug?  */
        if (status == -EPERM && getenv("PROOT_NO_SECCOMP") == NULL) {
                note(tracee, INFO, USER,
"您的内核似乎存在此缺陷：https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1202161\n"
"要绕过它，请设置环境变量 PROOT_NO_SECCOMP=1。");
                return;
        }

        note(tracee, INFO, USER, "可能的原因：\n"
"  * 程序是脚本，但其解释器（如 /bin/sh）未找到；\n"
"  * 程序是 ELF，但其解释器（如 ld-linux.so）未找到；\n"
"  * 程序是异架构二进制，但未指定 qemu；\n"
"  * qemu（如已指定）无法正常工作；\n"
"  * 加载器未找到或无法运行。");
}

static void print_error_separator(const Tracee *tracee, const Argument *argument)
{
        if (argument->separator == '\0')
                note(tracee, ERROR, USER, "选项 '%s' 不接受值。", argument->name);
        else
                note(tracee, ERROR, USER, "选项 '%s' 与其值必须用 '%c' 分隔。",
                        argument->name, argument->separator);
}

static void print_argv(const Tracee *tracee, const char *prompt, char *const argv[])
{
        char string[ARG_MAX] = "";
        size_t i;

        if (!argv)
                return;

#define APPEND(post)                                                    \
        do {                                                            \
                ssize_t length = sizeof(string) - (strlen(string) + strlen(post)); \
                if (length <= 0)                                        \
                        return;                                         \
                strncat(string, post, length);                          \
        } while (0)

        APPEND(prompt);
        APPEND(" =");
        for (i = 0; argv[i] != NULL; i++) {
                APPEND(" ");
                APPEND(argv[i]);
        }
        string[sizeof(string) - 1] = '\0';

#undef APPEND

        note(tracee, INFO, USER, "%s", string);
}

static void print_config(Tracee *tracee, char *const argv[])
{
        assert(tracee != NULL);

        if (tracee->verbose <= 0)
                return;

        if (tracee->qemu)
                note(tracee, INFO, USER, "宿主根文件系统 = %s", HOST_ROOTFS);

        if (tracee->glue)
                note(tracee, INFO, USER, "胶水根文件系统 = %s", tracee->glue);

        note(tracee, INFO, USER, "可执行文件 = %s", tracee->exe);
        print_argv(tracee, "argv", argv);
        print_argv(tracee, "qemu", tracee->qemu);
        note(tracee, INFO, USER, "初始工作目录 = %s", tracee->fs->cwd);
        note(tracee, INFO, USER, "调试级别 = %d", tracee->verbose);

        notify_extensions(tracee, PRINT_CONFIG, 0, 0);
}

/**
 * Initialize @tracee's current working directory.  This function
 * returns -1 if an error occurred, otherwise 0.
 */
static int initialize_cwd(Tracee *tracee)
{
        char path2[PATH_MAX];
        char path[PATH_MAX];
        int status;

        /* Compute the base directory.  */
        if (tracee->fs->cwd[0] != '/') {
                status = getcwd2(tracee->reconf.tracee, path);
                if (status < 0) {
                        note(tracee, ERROR, INTERNAL, "getcwd: %s", strerror(-status));
                        return -1;
                }
        }
        else
                strcpy(path, "/");

        /* The ending "." ensures canonicalize() will report an error
         * if tracee->fs->cwd does not exist or if it is not a
         * directory.  */
        status = join_paths(3, path2, path, tracee->fs->cwd, ".");
        if (status < 0) {
                note(tracee, ERROR, INTERNAL, "getcwd: %s", strerror(-status));
                return -1;
        }

        /* Initiale state for canonicalization.  */
        strcpy(path, "/");

        status = canonicalize(tracee, path2, true, path, 0);
        if (status < 0) {
                note(tracee, WARNING, USER, "无法 chdir(\"%s\") 进入容器根文件系统：%s",
                        path2, strerror(-status));
                note(tracee, INFO, USER, "默认工作目录已改为 \"/\"");
                strcpy(path, "/");
        }
        chop_finality(path);

        /* Replace with the canonicalized working directory.  */
        TALLOC_FREE(tracee->fs->cwd);
        tracee->fs->cwd = talloc_strdup(tracee->fs, path);
        if (tracee->fs->cwd == NULL)
                return -1;
        talloc_set_name_const(tracee->fs->cwd, "$cwd");

        /* Keep this special environment variable consistent.  */
        setenv("PWD", path, 1);

        return 0;
}

/**
 * Initialize @tracee->exe from @exe, i.e. canonicalize it from a
 * guest point-of-view.
 */
static int initialize_exe(Tracee *tracee, const char *exe)
{
        char path[PATH_MAX];
        int status;

        status = which(tracee, tracee->reconf.paths, path, exe ?: "/bin/sh");
        if (status < 0)
                return -1;

        tracee->exe = talloc_strdup(tracee, path);
        if (tracee->exe == NULL)
                return -1;
        talloc_set_name_const(tracee->exe, "$exe");

        return 0;
}

/**
 * Configure @tracee according to the command-line arguments stored in
 * @argv[].  This function returns the index in @argv[] of the command
 * to launch, otherwise -1 if an error occured.
 */
static int parse_config(Tracee *tracee, size_t argc, char *const argv[])
{
        option_handler_t handler = NULL;
        const Option *options;
        const Cli *cli = NULL;
        size_t argc_offset;
        size_t i, j, k;
        int status;

        /* Unknown tool name?  Default to PRoot.  */
        if (cli == NULL)
                cli = get_proot_cli(tracee->ctx);
        tracee->tool_name = cli->name;

        if (argc == 1) {
                print_usage(tracee, cli, false);
                return -1;
        }

        for (i = 1; i < argc; i++) {
                const char *arg = argv[i];

                /* The current argument is the value of a short option.  */
                if (handler != NULL) {
                        status = handler(tracee, cli, arg);
                        if (status < 0)
                                return -1;
                        handler = NULL;
                        continue;
                }

                if (arg[0] != '-')
                        break; /* End of PRoot options. */

                /* "--" ends the options, as is customary: the next
                 * argument starts the command, whatever it looks like.  */
                if (strcmp(arg, "--") == 0) {
                        i++;
                        break;
                }

                options = cli->options;
                for (j = 0; options[j].class != NULL; j++) {
                        const Option *option = &options[j];

                        /* A given option has several aliases.  */
                        for (k = 0; ; k++) {
                                const Argument *argument;
                                size_t length;

                                argument = &option->arguments[k];

                                /* End of aliases for this option.  */
                                if (!argument->name)
                                        break;

                                length = strlen(argument->name);
                                if (strncmp(arg, argument->name, length) != 0)
                                        continue;

                                /* Avoid ambiguities.  */
                                if (strlen(arg) > length
                                    && arg[length] != argument->separator) {
                                        print_error_separator(tracee, argument);
                                        return -1;
                                }

                                /* No option value.  */
                                if (!argument->value) {
                                        status = option->handler(tracee, cli, NULL);
                                        if (status < 0)
                                                return -1;
                                        goto known_option;
                                }

                                /* Value coalesced with to its option.  */
                                if (argument->separator == arg[length]) {
                                        assert(strlen(arg) >= length);
                                        status = option->handler(tracee, cli, &arg[length + 1]);
                                        if (status < 0)
                                                return -1;
                                        goto known_option;
                                }

                                /* Avoid ambiguities.  */
                                if (argument->separator != ' ') {
                                        print_error_separator(tracee, argument);
                                        return -1;
                                }

                                /* Short option with a separated value.  */
                                handler = option->handler;
                                goto known_option;
                        }
                }

                note(tracee, ERROR, USER, "未知选项 '%s'。", arg);
                return -1;

        known_option:
                if (handler != NULL && i == argc - 1) {
                        note(tracee, ERROR, USER, "选项 '%s' 缺少值。", arg);
                        return -1;
                }
        }
        argc_offset = i;

#define HOOK_CONFIG(callback)                                           \
        do {                                                            \
                if (cli->callback != NULL) {                            \
                        status = cli->callback(tracee, cli, argc, argv, i); \
                        if (status < 0)                                 \
                                return -1;                              \
                        i = status;                                     \
                }                                                       \
        } while (0)

        HOOK_CONFIG(pre_initialize_bindings);

        /* The guest rootfs is now known: bindings specified by the
         * user (tracee->bindings.user) can be canonicalized.  */
        status = initialize_bindings(tracee);
        if (status < 0)
                return -1;

        HOOK_CONFIG(post_initialize_bindings);
        HOOK_CONFIG(pre_initialize_cwd);

        /* Bindings are now installed (tracee->bindings.guest &
         * tracee->bindings.host): the current working directory can
         * be canonicalized.  */
        status = initialize_cwd(tracee);
        if (status < 0)
                return -1;

        HOOK_CONFIG(post_initialize_cwd);
        HOOK_CONFIG(pre_initialize_exe);

        /* Bindings are now installed and the current working
         * directory is canonicalized: resolve path to @tracee->exe
         * and configure @tracee->cmdline.  */
        status = initialize_exe(tracee, argv[argc_offset]);
        if (status < 0)
                return -1;

        HOOK_CONFIG(post_initialize_exe);
#undef HOOK_CONFIG

        print_config(tracee, &argv[argc_offset]);

        return argc_offset;
}

bool exit_failure = true;

int main(int argc, char *const argv[])
{
        Tracee *tracee;
        pid_t pid;
        int status;

        /* Configure the memory allocator.  */
        talloc_enable_leak_report();

#if defined(TALLOC_VERSION_MAJOR) && TALLOC_VERSION_MAJOR >= 2
        talloc_set_log_stderr();
#endif

        if (argc == 2 && strcmp(argv[1], "--shm-helper") == 0) {
                sysvipc_shm_helper_main();
        }

        /* Pre-create the first tracee (pid == 0).  */
        tracee = get_tracee(NULL, 0, true);
        if (tracee == NULL)
                goto error;
        tracee->pid = getpid();

        /* Set verboseness from env variable, may be overriden by option */
        {
                const char *verbose_env = getenv("PROOT_VERBOSE");
                if (verbose_env != NULL) {
                        tracee->verbose = strtol(verbose_env, NULL, 10);
                        global_verbose_level = tracee->verbose;
                }
        }

        /* Pre-configure the first tracee.  */
        status = parse_config(tracee, argc, argv);
        if (status < 0)
                goto error;

        if (NULL == getenv("PROOT_NO_MOUNTINFO"))
                initialize_extension(tracee, mountinfo_callback, NULL);

        /* Backend selection (docs/BACKENDS.md): the LD_PRELOAD "proto"
         * backend is the default whenever it can carry the request;
         * the ptrace backend stays as the guaranteed fallback.
         * NPROOT_BACKEND overrides the default: "proto" forces it
         * (error when impossible), "ptrace" forces the classic
         * behavior, "auto" is the default.  */
        {
                const char *backend = getenv("NPROOT_BACKEND");
                bool forced_ptrace, forced_proto;

                if (backend != NULL && strcmp(backend, "auto") != 0 &&
                    strcmp(backend, "proto") != 0 &&
                    strcmp(backend, "ptrace") != 0) {
                        note(tracee, WARNING, USER,
                             "NPROOT_BACKEND 的值 '%s' 无法识别 "
                             "（应为 auto|proto|ptrace），按 auto 处理", backend);
                        backend = NULL;
                }
                forced_ptrace = (backend != NULL &&
                                 strcmp(backend, "ptrace") == 0);
                forced_proto = (backend != NULL &&
                                strcmp(backend, "proto") == 0);

                /* Name the no-ptrace backend on every start: it is
                 * the first thing a "why does this behave differently
                 * here" report needs.  The ptrace paths already say so
                 * (the auto-fallback below announces the fallback, and
                 * -V prints the backend), and every extra unconditional
                 * stderr line is output that output-comparing suites
                 * have to filter.  */
                if (!forced_ptrace) {
                        const char *why = proto_infeasible_reason(tracee);

                        if (why == NULL) {
                                note(tracee, INFO, USER,
                                     "拦截后端：proto"
                                     "（无 ptrace，容器 libc：%s）",
                                     proto_guest_libc());
                                proto_launch(tracee, &argv[status]);
                                        /* never returns */
                        } else if (forced_proto) {
                                note(tracee, ERROR, USER,
                                     "proto 后端无法运行当前配置：%s", why);
                                note(tracee, INFO, USER,
                                     "请改用 NPROOT_BACKEND=ptrace 重试，"
                                     "或在排除原因后取消 NPROOT_BACKEND。");
                                exit_failure = true;
                                goto error;
                        } else
                                note(tracee, INFO, USER,
                                     "proto 后端不可用（%s），改用 ptrace 后端。", why);
                }
        }

        /* Keep the host (Termux) environment out of the guest: a
         * Termux PATH makes "apt" inside an Alpine guest resolve to
         * the host's bionic binary, and host LD_* entries inject
         * bionic libraries into the guest loader.  A session without
         * a rootfs of its own has the host as the guest: nothing to
         * isolate there.  */
        {
                const char *root = get_root(tracee);

                sanitize_guest_environment(root != NULL &&
                                           strcmp(root, "/") != 0);
        }

        /* Start the first tracee.  */
        pid = getpid();
        status = launch_process(tracee, &argv[status]);
        if (status < 0) {
                print_execve_help(tracee, tracee->exe, status);

                /* This is the child of launch_process() if it couldn't
                 * execute the program.  Its syscalls are translated by
                 * the parent now, so the talloc destructors run on exit
                 * -- removal of the glue and of the placeholders of the
                 * bindings -- would act on whatever these paths lead to
                 * in the guest, the content of a host directory bound
                 * there for instance.  The parent removes them.  */
                if (getpid() != pid) {
                        fprintf(stderr, "致命错误：请查看 `%s --help`。\n", basename(argv[0]));
                        _exit(EXIT_FAILURE);
                }
                goto error;
        }

        /* Start tracing the first tracee and all its children.  */
        exit(event_loop());

error:
        TALLOC_FREE(tracee);

        if (exit_failure) {
                fprintf(stderr, "致命错误：请查看 `%s --help`。\n", basename(argv[0]));
                exit(EXIT_FAILURE);
        }
        else
                exit(EXIT_SUCCESS);
}

/**
 * Convert @value into an integer, then put the result into
 * *@variable.  This function prints a warning and returns -1 if a
 * conversion error occured, otherwise it returns 0.
 */
int parse_integer_option(const Tracee *tracee, int *variable, const char *value, const char *option)
{
        char *end_ptr = NULL;

        errno = 0;
        *variable = strtol(value, &end_ptr, 10);
        if (errno != 0 || end_ptr == value) {
                note(tracee, ERROR, USER, "选项 `%s` 需要一个整数值。", option);
                return -1;
        }

        return 0;
}

/**
 * Expand the environment variable in front of @string, if any.  For
 * example, this function can expand "$HOME" or "$HOME/.ICEauthority".
 */
const char *expand_front_variable(TALLOC_CTX *context, const char *string)
{
        const char *suffix;
        char *expanded;
        ptrdiff_t size;

        if (string[0] != '$')
                return string;

        suffix = strchr(string, '/');
        if (suffix == NULL)
                return (getenv(&string[1]) ?: string);

        size = suffix - string;
        if (size <= 1)
                return string;

        expanded = talloc_strndup(context, &string[1], size - 1);
        if (expanded == NULL)
                return string;

        expanded = getenv(expanded);
        if (expanded == NULL)
                return string;

        expanded = talloc_asprintf(context, "%s%s", expanded, suffix);
        if (expanded == NULL)
                return string;

        return expanded;
}

/* Here follows the support for GCC function instrumentation.  Build
 * with CFLAGS='-finstrument-functions -O0 -g' and LDFLAGS='-rdynamic'
 * to enable this mechanism.  */

static int indent_level = 0;

void __cyg_profile_func_enter(void *this_function, void *call_site) DONT_INSTRUMENT;
void __cyg_profile_func_enter(void *this_function, void *call_site)
{
        void *const pointers[] = { this_function, call_site };
        char **symbols = NULL;

#ifdef __GLIBC__
        symbols = backtrace_symbols(pointers, 2);
#endif
        if (symbols == NULL)
                goto end;

        fprintf(stderr, "%*s from %s\n", (int) strlen(symbols[0]) + indent_level, symbols[0], symbols[1]);

end:
        if (symbols != NULL)
                free(symbols);

        if (indent_level < INT_MAX)
                indent_level++;
}

void __cyg_profile_func_exit(void *this_function UNUSED, void *call_site UNUSED) DONT_INSTRUMENT;
void __cyg_profile_func_exit(void *this_function UNUSED, void *call_site UNUSED)
{
        if (indent_level > 0)
                indent_level--;
}
