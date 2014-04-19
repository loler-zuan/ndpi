#ifndef _COMMUNICATE_H
#define _COMMUNICATE_H

#include <sys/un.h>
#include <sys/socket.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "detection.h"

int newChannel(void *);

int ncmdlines;
char results[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 10][256];
#endif
