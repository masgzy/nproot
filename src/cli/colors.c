/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * nproot color front end — Catppuccin for the C side of the toolchain.
 *
 * This mirrors proot-distro-i18n (pd)'s proot_distro/message.py so both
 * halves of the toolchain speak the same palette:
 *
 *   - Catppuccin Mocha by default, Latte on a light terminal
 *     (CLI_THEME=dark|light overrides; COLORFGBG probed when unset);
 *   - 24-bit SGR only when the terminal advertises truecolor
 *     (COLORTERM=truecolor|24bit); otherwise the same hues degrade to
 *     the nearest of the 16 base ANSI colors, so the semantic mapping
 *     (red errors, green success, cyan info) survives every level of
 *     degradation;
 *   - NO_COLOR (https://no-color.org), NPROOT_NO_COLOR and CLICOLOR=0
 *     disable color outright; NPROOT_FORCE_COLORS forces it on for
 *     pipes and CI logs.
 *
 * Which stream is being written decides the TTY probe: note()/the
 * runtime banner go to stderr, print_version() to stdout — the classic
 * `nproot -V | grep` has stdout piped while stderr stays on the
 * terminal, so the two must not share one answer.  Both share the
 * built sequences and the theme/truecolor decisions.
 *
 * The escape strings are built once at first use into static buffers;
 * the pointers callers receive live for the whole process.
 *
 * No external library: the sequences are plain SGR writes, exactly
 * what message.py emits on the Python side.  That is the whole point —
 * the C side needed "a library" only until the sequences were written
 * down.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>

#include "cli/colors.h"

/* ------------------------------------------------------------------ */
/* Catppuccin palettes: the ten hues this CLI speaks.
 * https://catppuccin.com/palette/ — Mocha (dark) and Latte (light).
 * The rgb tables are the official values, same as message.py. */

struct hue { unsigned char r, g, b; };

static const struct hue MOCHA[CLI_HUE_COUNT] = {
	[CLI_HUE_MAUVE]   = {203, 166, 247}, /* #cba6f7  titles, emphasis */
	[CLI_HUE_TEXT]    = {205, 214, 244}, /* #cdd6f4  body */
	[CLI_HUE_SUBTEXT] = {166, 173, 200}, /* #a6adc8  secondary */
	[CLI_HUE_GREEN]   = {166, 227, 161}, /* #a6e3a1  success */
	[CLI_HUE_PEACH]   = {250, 179, 135}, /* #fab387  warning */
	[CLI_HUE_RED]     = {243, 139, 168}, /* #f38ba8  error */
	[CLI_HUE_BLUE]    = {137, 180, 250}, /* #89b4fa  paths, URLs */
	[CLI_HUE_YELLOW]  = {249, 226, 175}, /* #f9e2af  numbers, counts */
	[CLI_HUE_SKY]     = {137, 220, 235}, /* #89dceb  info */
	[CLI_HUE_PINK]    = {245, 194, 231}, /* #f5c2e7  keywords */
};

static const struct hue LATTE[CLI_HUE_COUNT] = {
	[CLI_HUE_MAUVE]   = {136,  57, 239}, /* #8839ef */
	[CLI_HUE_TEXT]    = { 76,  79, 105}, /* #4c4f69 */
	[CLI_HUE_SUBTEXT] = {108, 111, 133}, /* #6c6f85 */
	[CLI_HUE_GREEN]   = { 64, 160,  43}, /* #40a02b */
	[CLI_HUE_PEACH]   = {254, 100,  11}, /* #fe640b */
	[CLI_HUE_RED]     = {210,  15,  57}, /* #d20f39 */
	[CLI_HUE_BLUE]    = { 30, 102, 245}, /* #1e66f5 */
	[CLI_HUE_YELLOW]  = {223, 142,  29}, /* #df8e1d */
	[CLI_HUE_SKY]     = {  4, 165, 229}, /* #04a5e5 */
	[CLI_HUE_PINK]    = {234, 118, 203}, /* #ea76cb */
};

/* 16-color fallback: one base hue per semantic color. */
static const char *const BASE16[CLI_HUE_COUNT] = {
	[CLI_HUE_MAUVE]   = "\033[35m", /* magenta */
	[CLI_HUE_TEXT]    = "\033[37m", /* white   */
	[CLI_HUE_SUBTEXT] = "\033[37m", /* white   */
	[CLI_HUE_GREEN]   = "\033[32m",
	[CLI_HUE_PEACH]   = "\033[33m", /* yellow  */
	[CLI_HUE_RED]     = "\033[31m",
	[CLI_HUE_BLUE]    = "\033[34m",
	[CLI_HUE_YELLOW]  = "\033[33m",
	[CLI_HUE_SKY]     = "\033[36m", /* cyan    */
	[CLI_HUE_PINK]    = "\033[35m", /* magenta */
};

/* ------------------------------------------------------------------ */
/* State, computed once. */

static int  seq_built;                       /* sequences built yet? */
static char seq[CLI_HUE_COUNT][48];          /* per-hue SGR */
static char seq_bright[CLI_HUE_COUNT][56];   /* per-hue bold SGR */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int env_flag(const char *name)
{
	const char *v = getenv(name);
	return v != NULL && *v != '\0' && strcmp(v, "0") != 0;
}

/* 'dark' or 'light' — CLI_THEME, else COLORFGBG's background half. */
static int light_theme(void)
{
	const char *theme = getenv("CLI_THEME");
	if (theme != NULL) {
		if (strcasecmp(theme, "light") == 0)
			return 1;
		if (strcasecmp(theme, "dark") == 0)
			return 0;
	}
	const char *fgbg = getenv("COLORFGBG");
	if (fgbg != NULL) {
		const char *semi = strrchr(fgbg, ';');
		if (semi != NULL) {
			int bg = atoi(semi + 1);
			/* 0-6 and 8 are dark backgrounds; 7 and 9-15 light. */
			if (bg != 0 && bg != 1 && bg != 2 && bg != 3
			    && bg != 4 && bg != 5 && bg != 6 && bg != 8)
				return 1;
		}
	}
	return 0;
}

static int truecolor(void)
{
	const char *ct = getenv("COLORTERM");
	if (ct == NULL)
		return 0;
	if (strstr(ct, "truecolor") != NULL || strstr(ct, "24bit") != NULL)
		return 1;
	return 0;
}

/* The kill switches that silence color no matter which stream. */
static int killed_by_env(void)
{
	if (getenv("NO_COLOR") != NULL)
		return 1;
	if (env_flag("NPROOT_NO_COLOR"))
		return 1;
	{
		const char *cc = getenv("CLICOLOR");
		if (cc != NULL && strcmp(cc, "0") == 0)
			return 1;
	}
	return 0;
}

/* Per-stream decision: forced on, else the stream's own TTY-ness. */
static int stream_on(int fd)
{
	if (env_flag("NPROOT_FORCE_COLORS"))
		return 1;
	return isatty(fd);
}

static void build_sequences(void)
{
	int i;

	seq_built = 1;

	for (i = 0; i < (int)ARRAY_SIZE(seq); i++) {
		if (truecolor()) {
			const struct hue *h = light_theme() ? &LATTE[i] : &MOCHA[i];
			snprintf(seq[i], sizeof(seq[i]),
				 "\033[0;38;2;%d;%d;%dm", h->r, h->g, h->b);
			snprintf(seq_bright[i], sizeof(seq_bright[i]),
				 "\033[0;1;38;2;%d;%d;%dm", h->r, h->g, h->b);
		} else {
			/* The 16-color fallback: the base hue, and bold
			 * as SGR 1 + the base hue. */
			snprintf(seq[i], sizeof(seq[i]), "%s", BASE16[i]);
			snprintf(seq_bright[i], sizeof(seq_bright[i]),
				 "\033[1m%s", BASE16[i]);
		}
	}
}

/* Shared color/kill state for one output stream. */
struct stream_colors {
	int  ready;
	int  on;
};

static struct stream_colors stderr_state;
static struct stream_colors stdout_state;

static void resolve(struct stream_colors *state, int fd)
{
	if (state->ready)
		return;
	state->ready = 1;
	state->on = 0;
	if (!killed_by_env() && stream_on(fd))
		state->on = 1;
}

const char *cli_color(enum cli_hue hue)
{
	if (!seq_built)
		build_sequences();
	resolve(&stderr_state, STDERR_FILENO);
	if (!stderr_state.on || hue < 0 || hue >= CLI_HUE_COUNT)
		return "";
	return seq[hue];
}

const char *cli_color_bold(enum cli_hue hue)
{
	if (!seq_built)
		build_sequences();
	resolve(&stderr_state, STDERR_FILENO);
	if (!stderr_state.on || hue < 0 || hue >= CLI_HUE_COUNT)
		return "";
	return seq_bright[hue];
}

int cli_colors_enabled(void)
{
	if (!seq_built)
		build_sequences();
	resolve(&stderr_state, STDERR_FILENO);
	return stderr_state.on;
}

const char *cli_reset(void)
{
	if (!seq_built)
		build_sequences();
	resolve(&stderr_state, STDERR_FILENO);
	if (!stderr_state.on)
		return "";
	return "\033[0m";
}

/* ---- stdout variants (print_version) ------------------------------ */

const char *cli_color_out(enum cli_hue hue)
{
	if (!seq_built)
		build_sequences();
	resolve(&stdout_state, STDOUT_FILENO);
	if (!stdout_state.on || hue < 0 || hue >= CLI_HUE_COUNT)
		return "";
	return seq[hue];
}

const char *cli_color_bold_out(enum cli_hue hue)
{
	if (!seq_built)
		build_sequences();
	resolve(&stdout_state, STDOUT_FILENO);
	if (!stdout_state.on || hue < 0 || hue >= CLI_HUE_COUNT)
		return "";
	return seq_bright[hue];
}

int cli_colors_enabled_stdout(void)
{
	if (!seq_built)
		build_sequences();
	resolve(&stdout_state, STDOUT_FILENO);
	return stdout_state.on;
}

const char *cli_reset_out(void)
{
	if (!seq_built)
		build_sequences();
	resolve(&stdout_state, STDOUT_FILENO);
	if (!stdout_state.on)
		return "";
	return "\033[0m";
}
