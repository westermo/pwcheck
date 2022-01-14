/* Minimal cmdline front-end to libpwquality
 *
 * Copyright (C) 2021  Westermo Network Technologies AB
 *
 * Author(s): Andreas Egeberg <andreas.egeberg@westermo.se>
 *            Albert Veli <albert.veli@westermo.se>
 * */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwquality.h>

int verbose = 0;

/* Check password using libpwquality
 * 
 * Return EXIT_SUCCESS (0) if password meets quality, else EXIT_FAILURE (1)
 * is returned and pwquality error is printed to stdout.
 * */
int check_password_policy(const char *password, const char *user)
{
        void *auxerror;
        pwquality_settings_t *pwq;
        int r;

        pwq = pwquality_default_settings();
	/* Use default location (/etc/security/pwquality.conf) */
        r = pwquality_read_config(pwq, NULL, &auxerror);
        if (r) {
		printf("%s\n", pwquality_strerror(NULL, 0, r, auxerror));
                pwquality_free_settings(pwq);
                return EXIT_FAILURE;
        }

        r = pwquality_check(pwq, password, NULL, user, &auxerror);

	if (verbose) {
		printf("Password quality score is %d\n", r);
	}

	/* r < 0 means password failed to meet policy, print error */
        if (r < 0) {
		printf("%s\n", pwquality_strerror(NULL, 0, r, auxerror));
                pwquality_free_settings(pwq);
                return EXIT_FAILURE;
        }

        pwquality_free_settings(pwq);

        return EXIT_SUCCESS;
}

void usage(char *argv[])
{
	printf("Usage: %s [-v] [-u <username>] <password>\n\n", argv[0]);
	printf("  -v - Verbose output\n");
	printf("  -u - Passwords based on username lowers pwquality score\n");
}

int main(int argc, char *argv[])
{
	char *username = NULL;
	char *password = NULL;
	int index;
	int c;

	/* No error reporting from getopt(3) */
	opterr = 0;

	while ((c = getopt (argc, argv, "vu:")) != -1)
		switch (c) {

		case 'v':
			verbose = 1;
			break;

		case 'u':
			username = optarg;
			break;

		case 'h':
			usage(argv);
			return EXIT_SUCCESS;

		case '?':
			if (optopt == 'u')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
			usage(argv);
			return EXIT_FAILURE;
		default:
			usage(argv);
			return EXIT_FAILURE;
		}

	/* Non-optional argument(s) */
	for (index = optind; index < argc; index++) {
		password = argv[index];
	}

	if (!password) {
		usage(argv);
		return EXIT_FAILURE;
	}

	return check_password_policy(password, username);
}
