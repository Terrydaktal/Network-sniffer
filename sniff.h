#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pthread.h>

void sniff(char *interface, int verbose);
void dumpp(const unsigned char *data, int length);
#endif /* CS241_SNIFF_H */
