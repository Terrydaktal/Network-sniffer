#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(const unsigned char *packet,
              int verbose);

#endif /* CS241_DISPATCH_H */
