/*
 * A tiny PAM module for bursyk's session-setup tests.
 *
 * Every stage succeeds unless its argument asks otherwise:
 *
 *   auth required <this module> setcred-fail
 *       pam_sm_setcred returns PAM_SYSTEM_ERR.  pam_setcred runs the auth
 *       stack, so the module must be on the auth line for this to matter.
 *
 *   session required <this module> open-session-fail
 *       pam_sm_open_session returns PAM_SESSION_ERR.
 *
 * The remaining stages always succeed, so a test can isolate one failure.
 * Types and constants are declared here rather than including
 * <security/pam_modules.h>: the module ABI is stable, and the test machine
 * may have libpam without its development headers.
 */

#include <string.h>

#define PAM_SUCCESS 0
#define PAM_SYSTEM_ERR 4
#define PAM_SESSION_ERR 14

typedef struct pam_handle pam_handle_t;

static int
has_arg(int argc, const char **argv, const char *name)
{
	int i;

	for (i = 0; i < argc; i++)
		if (strcmp(argv[i], name) == 0)
			return 1;
	return 0;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	if (has_arg(argc, argv, "setcred-fail"))
		return PAM_SYSTEM_ERR;
	return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	(void)pamh;
	(void)flags;
	if (has_arg(argc, argv, "open-session-fail"))
		return PAM_SESSION_ERR;
	return PAM_SUCCESS;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}
