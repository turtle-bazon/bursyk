/*
 * A tiny PAM module for bursyk's tests.
 *
 * The modules in /etc/pam.d cannot produce PAM_NEW_AUTHTOK_REQD without a
 * real expired shadow entry, and pam_exec maps its child's exit status to a
 * PAM error instead of returning that code.  This module answers account
 * management with PAM_NEW_AUTHTOK_REQD and accepts a password change only
 * when Linux-PAM passes PAM_CHANGE_EXPIRED_AUTHTOK, so a passing test also
 * proves the server asked for the right kind of change.
 *
 * The few types and constants needed are declared here rather than including
 * <security/pam_modules.h>: the module ABI is stable, and the machine running
 * the tests may have libpam without its development headers.
 */

#define PAM_SUCCESS 0
#define PAM_SYSTEM_ERR 4
#define PAM_NEW_AUTHTOK_REQD 12
#define PAM_CHANGE_EXPIRED_AUTHTOK 0x0004

typedef struct pam_handle pam_handle_t;

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
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_NEW_AUTHTOK_REQD;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh;
	(void)argc;
	(void)argv;
	if ((flags & PAM_CHANGE_EXPIRED_AUTHTOK) == 0)
		return PAM_SYSTEM_ERR;
	return PAM_SUCCESS;
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
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
