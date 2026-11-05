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

#include <errno.h>  /* errno, */
#include <string.h> /* strerror(3), */
#include <stdarg.h> /* va_*, */
#include <stdio.h>  /* vfprintf(3), */
#include <limits.h> /* INT_MAX, */
#include <stdlib.h> /* getenv(3), */
#include <unistd.h> /* isatty(3), STDERR_FILENO, */

#include "cli/note.h"
#include "tracee/tracee.h"

int global_verbose_level;
const char *global_tool_name;

/* 用户界面文案默认中文；输出到终端时按 proot-distro-i18n (pd) 的
 * 配色上色：工具名粗体蓝，信息绿、警告黄、错误红，正文青/黄/红。
 * 仅当 stderr 是终端且未设 NPROOT_NO_COLOR 时启用，重定向到文件
 * 或管道（测试、日志）时保持纯文本。 */
#define C_RST    "\033[0m"
#define C_NAME   "\033[1;34m" /* 工具名：粗体蓝，对应 pd 的 "[*]" */
#define C_INFO   "\033[1;32m" /* "信息" 标签：粗体绿 */
#define C_WARN   "\033[1;33m" /* "警告" 标签：粗体黄 */
#define C_ERROR  "\033[1;31m" /* "错误" 标签：粗体红 */
#define C_IBODY  "\033[36m"   /* 信息正文：青 */
#define C_WBODY  "\033[33m"   /* 警告正文：黄 */
#define C_EBODY  "\033[31m"   /* 错误正文：红 */

static int colors_enabled(void)
{
        int saved_errno = errno;
        static int cached = -1;

        if (cached < 0) {
                const char *disable = getenv("NPROOT_NO_COLOR");

                cached = (disable == NULL && isatty(STDERR_FILENO));
        }
        /* isatty(3) on a piped stderr fails with ENOTTY and clobbers
         * errno; the ERROR+SYSTEM path below reports errno with
         * perror(3) and must still see the exec/whatever failure it
         * is about to report. */
        errno = saved_errno;
        return cached;
}

/**
 * Print @message to the standard error stream according to its
 * @severity and @origin.
 */
void note(const Tracee *tracee, Severity severity, Origin origin, const char *message, ...)
{
        const char *tool_name;
        va_list extra_params;
        int verbose_level;

        if (tracee == NULL) {
                verbose_level = global_verbose_level;
                tool_name     = global_tool_name ?: "";
        }
        else {
                verbose_level = tracee->verbose;
                tool_name     = tracee->tool_name;
        }

        if (verbose_level < 0 && severity != ERROR)
                return;

        {
                const char *label, *tag, *body;
                int colored = colors_enabled();

                switch (severity) {
                case WARNING:
                        label = "警告"; tag = C_WARN; body = C_WBODY;
                        break;

                case ERROR:
                        label = "错误"; tag = C_ERROR; body = C_EBODY;
                        break;

                case INFO:
                default:
                        label = "信息"; tag = C_INFO; body = C_IBODY;
                        break;
                }

                if (colored)
                        fprintf(stderr, C_NAME "%s" C_RST " %s%s" C_RST ": %s",
                                tool_name, tag, label, body);
                else
                        fprintf(stderr, "%s %s: ", tool_name, label);

                if (origin == TALLOC)
                        fprintf(stderr, "talloc: ");

                va_start(extra_params, message);
                vfprintf(stderr, message, extra_params);
                va_end(extra_params);

                switch (origin) {
                case SYSTEM:
                        fprintf(stderr, ": ");
                        perror(NULL);
                        break;

                case TALLOC:
                        break;

                case INTERNAL:
                case USER:
                default:
                        fprintf(stderr, "\n");
                        break;
                }

                if (colored)
                        fprintf(stderr, C_RST);
        }

        return;
}

