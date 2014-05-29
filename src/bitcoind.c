/*
 * See LICENSE for licensing information
 */

#include "bitcoind.h"

/* all state is stored here */
struct _BitcoinD {
	/* the function we use to log messages
	 * needs level, functionname, and format */
	ShadowLogFunc slogf;
};

/* if option is specified, run as client, else run as server */
static const char* USAGE = "USAGE: \n";

BitcoinD* bitcoind_new(int argc, char* argv[], ShadowLogFunc slogf) {
	assert(slogf);

	/* get memory for the new state */
	BitcoinD* bcd = calloc(1, sizeof(BitcoinD));
	assert(bcd);
	return bcd;
}

void bitcoind_free(BitcoinD* bcd) {
	assert(bcd);

	free(bcd);
}

void bitcoind_ready(BitcoinD* bcd) {
	assert(bcd);

}
