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

#include "cli/colors.h"
#include "cli/note.h"
#include "tracee/tracee.h"

int global_verbose_level;
const char *global_tool_name;

/* 用户界面文案默认中文；输出到终端时按 proot-distro-i18n (pd) 的
 * Catppuccin 配色上色：工具名粗体蓝（对应 pd 的 "[*]"），信息/
 * 警告/错误标签绿/黄/红，正文 sky/黄/红。配色与降级规则（Mocha/
 * Latte、truecolor、16 色回退、NO_COLOR）见 cli/colors.c——与 pd
 * 的 message.py 同一套。仅当 stderr 是终端且未设 NO_COLOR/
 * NPROOT_NO_COLOR 时启用，重定向到文件或管道（测试、日志）时
 * 保持纯文本。 */

static int colors_enabled(void)
{
        int saved_errno = errno;
        int enabled;

        enabled = cli_colors_enabled();
        /* isatty(3) on a piped stderr fails with ENOTTY and clobbers
         * errno; the ERROR+SYSTEM path below reports errno with
         * perror(3) and must still see the exec/whatever failure it
         * is about to report.  cli_colors_enabled() only probes
         * getenv/isatty, but the restore stays so nothing downstream
         * notices the probe. */
        errno = saved_errno;
        return enabled;
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
                const char *rst;
                int colored = colors_enabled();

                rst = cli_reset();
                switch (severity) {
                case WARNING:
                        label = "警告";
                        tag = colored ? cli_color_bold(CLI_HUE_PEACH) : "";
                        body = colored ? cli_color(CLI_HUE_YELLOW) : "";
                        break;

                case ERROR:
                        label = "错误";
                        tag = colored ? cli_color_bold(CLI_HUE_RED) : "";
                        body = colored ? cli_color(CLI_HUE_RED) : "";
                        break;

                case INFO:
                default:
                        label = "信息";
                        tag = colored ? cli_color_bold(CLI_HUE_GREEN) : "";
                        body = colored ? cli_color(CLI_HUE_SKY) : "";
                        break;
                }

                if (colored)
                        /* 8 conversions, 8 arguments: the trailing
                         * %s re-opens the body hue so the message
                         * vfprintf() writes next lands in it, and
                         * the reset below closes it.  With only 7
                         * arguments the 8th %s read a stale stack
                         * slot and dereferenced it -- note() then
                         * died of SIGSEGV before a byte reached the
                         * terminal on every colored run (device
                         * reports: pd sh / nproot -0 segfault with
                         * no output; pipes kept colors off, which
                         * is why every CI run stayed green). */
                        fprintf(stderr, "%s%s%s %s%s%s%s: %s",
                                cli_color_bold(CLI_HUE_BLUE), tool_name, rst,
                                tag, label, rst, body, body);
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
                        fprintf(stderr, "%s", rst);
        }

        return;
}

