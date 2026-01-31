#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/route.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

#define PACKET_MAX_SIZE 1600
#define DOMAIN_MAX_SIZE 300
#define EXIT_WAIT_SEC 5

#define FIRST_BIT_UINT16 0x8000
#define FIRST_TWO_BITS_UINT8 0xC0

#define BLACKLIST_MAX_COUNT 128

#define LISTEN_PORT_START 2000

#define DNS_TypeA 1
#define DNS_TypeCNAME 5

#define GET_DOMAIN_OK 0
#define GET_DOMAIN_FIRST_BYTE_ERROR 1
#define GET_DOMAIN_SECOND_BYTE_ERROR 3
#define GET_DOMAIN_LAST_CH_DOMAIN_ERROR 2
#define GET_DOMAIN_MAX_JUMP_COUNT 100
#define GET_DOMAIN_JUMP_COUNT_ERROR 4
#define GET_DOMAIN_TWO_BITS_ERROR 5
#define GET_DOMAIN_CH_BYTE_ERROR 6
#define GET_DOMAIN_ADD_CH_DOMAIN_ERROR 7
#define GET_DOMAIN_NULL_CH_DOMAIN_ERROR 8

#define DNS_ANS_CHECK_HEADER_SIZE_ERROR -2
#define DNS_ANS_CHECK_RES_TYPE_ERROR -3
#define DNS_ANS_CHECK_QUE_COUNT_ERROR -4
#define DNS_ANS_CHECK_ANS_COUNT_ERROR -5
#define DNS_ANS_CHECK_QUE_URL_GET_ERROR -6
#define DNS_ANS_CHECK_QUE_DATA_GET_ERROR -7
#define DNS_ANS_CHECK_ANS_URL_GET_ERROR -8
#define DNS_ANS_CHECK_ANS_DATA_GET_ERROR -9
#define DNS_ANS_CHECK_ANS_LEN_ERROR -10
#define DNS_ANS_CHECK_CNAME_URL_GET_ERROR -11
#define DNS_ANS_CHECK_NOT_END_ERROR -12

typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t quest;
    uint16_t ans;
    uint16_t auth;
    uint16_t add;
} __attribute__((packed)) dns_header_t;

typedef struct dns_que {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) dns_que_t;

typedef struct dns_ans {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t len;
    uint32_t ip4;
} __attribute__((packed)) dns_ans_t;

typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;

#ifndef _SUBNET_TYPE
#define _SUBNET_TYPE
typedef struct subnet {
    uint32_t ip;
    uint32_t mask;
} subnet_t;
#endif
