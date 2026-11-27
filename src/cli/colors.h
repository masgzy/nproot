/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * nproot color front end — Catppuccin, shared with pd's message.py.
 * See colors.c for the palette and the degradation rules.
 */

#ifndef CLI_COLORS_H
#define CLI_COLORS_H

/* The semantic hues this CLI speaks (Catppuccin's ten, same order and
 * same mapping as proot_distro/message.py). */
enum cli_hue {
	CLI_HUE_MAUVE,
	CLI_HUE_TEXT,
	CLI_HUE_SUBTEXT,
	CLI_HUE_GREEN,
	CLI_HUE_PEACH,
	CLI_HUE_RED,
	CLI_HUE_BLUE,
	CLI_HUE_YELLOW,
	CLI_HUE_SKY,
	CLI_HUE_PINK,
	CLI_HUE_COUNT
};

/* ---- stderr (note()/runtime banner) -------------------------------- */

/* The SGR sequence for a hue, or "" when color is off on stderr. */
const char *cli_color(enum cli_hue hue);

/* Same hue, bold. */
const char *cli_color_bold(enum cli_hue hue);

/* Whether any color escapes will be emitted on stderr. */
int cli_colors_enabled(void);

/* The reset sequence — "" when color is off, so the plain-text paths
 * of output-comparing suites stay byte-clean. */
const char *cli_reset(void);

/* ---- stdout (print_version) ----------------------------------------- */
/* `nproot -V | grep` is the classic use: stdout piped, stderr still a
 * TTY, so the streams keep separate on/off answers. */

const char *cli_color_out(enum cli_hue hue);
const char *cli_color_bold_out(enum cli_hue hue);
int cli_colors_enabled_stdout(void);
const char *cli_reset_out(void);

#endif /* CLI_COLORS_H */
