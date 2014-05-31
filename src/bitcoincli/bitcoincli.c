/*
 * See LICENSE for licensing information
 */

#include "bitcoincli.h"

/* all state is stored here */
struct _BitcoinCLI {
	/* the function we use to log messages
	 * needs level, functionname, and format */
	ShadowLogFunc slogf;
};

/* if option is specified, run as client, else run as server */
static const char* USAGE = "USAGE: \n";

BitcoinCLI* bitcoincli_new(int argc, char* argv[], ShadowLogFunc slogf) {
	assert(slogf);

	/* get memory for the new state */
	BitcoinCLI* bcc = calloc(1, sizeof(BitcoinCLI));
	assert(bcc);
	return bcc;
}

void bitcoincli_free(BitcoinCLI* bcc) {
	assert(bcc);

	free(bcc);
}

void bitcoincli_ready(BitcoinCLI* bcc) {
	assert(bcc);

}
