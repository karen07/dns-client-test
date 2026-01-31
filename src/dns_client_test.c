#include "dns_client_test.h"

FILE *in_domains_fp;
FILE *cache_fp;
FILE *out_domains_fp;
FILE *ips_fp;
FILE *log_fp;

char domains_file_path[PATH_MAX];
uint32_t rps;
uint16_t query_type = DNS_TypeA;
uint32_t sample_count;
uint32_t sample_seed;
int32_t sample_seed_set;
uint64_t total_domains;
int32_t is_save;
int32_t is_log;

volatile int32_t sended;
volatile int32_t readed;

static volatile double time_test_sink;

double one_cycle_ns;
volatile double coeff = 1;

struct sockaddr_in listen_addr, dns_addr;
int32_t listen_socket;

int32_t blacklist_count;
subnet_t blacklist[BLACKLIST_MAX_COUNT];

void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

void *send_dns(void *arg)
{
    (void)arg;

    char packet[PACKET_MAX_SIZE];
    char line_buf[PACKET_MAX_SIZE];
    int32_t line_count = 0;
    uint64_t domains_left = total_domains;
    uint64_t domains_need = sample_count;

    if (sample_count != 0 && sample_count < total_domains) {
        srand(sample_seed);
    }

    while (fscanf(in_domains_fp, "%s", line_buf) != EOF) {
        if (sample_count != 0 && sample_count < total_domains) {
            int32_t selected = ((uint64_t)(unsigned)rand() % domains_left) < domains_need;
            domains_left--;
            if (!selected) {
                continue;
            }
            domains_need--;
        }

        line_count++;

        dns_header_t *header = (dns_header_t *)packet;
        uint16_t id = line_count;
        header->id = htons(id);
        header->flags = htons(0x0100);
        header->quest = htons(1);
        header->ans = htons(0);
        header->auth = htons(0);
        header->add = htons(0);

        int32_t k = 0;
        char *dot_pos_new = line_buf;
        char *dot_pos_old = line_buf;
        while ((dot_pos_new = strchr(dot_pos_old + 1, '.')) != NULL) {
            dot_pos_new++;
            packet[12 + k] = dot_pos_new - dot_pos_old - 1;
            memcpy(&packet[12 + k + 1], dot_pos_old, packet[12 + k]);
            k += packet[12 + k] + 1;
            dot_pos_old = dot_pos_new;
        }

        packet[12 + k] = strlen(line_buf) - k;
        memcpy(&packet[12 + k + 1], &line_buf[k], packet[12 + k]);
        k += packet[12 + k] + 1;
        packet[12 + k] = 0;

        dns_que_t *end_name = (dns_que_t *)&packet[12 + k + 1];
        end_name->type = htons(query_type);
        end_name->class = htons(1);

        if (sendto(listen_socket, packet, 12 + k + 5, 0, (struct sockaddr *)&dns_addr,
                   sizeof(dns_addr)) < 0) {
            errmsg("Can't send %s\n", strerror(errno));
        }

        sended = line_count;

        volatile double time_test = 1.0;
        for (int32_t i = 0; i < 1000000000.0 / rps / one_cycle_ns / coeff; i++) {
            time_test *= 3.0;
        }
        time_test_sink = time_test;
    }

    return NULL;
}

int32_t get_domain_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                               memory_t *domain)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t domain_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_FIRST_BYTE_ERROR;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (domain_len >= (int32_t)domain->max_size) {
                        return GET_DOMAIN_LAST_CH_DOMAIN_ERROR;
                    }
                    domain->data[domain_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return GET_DOMAIN_SECOND_BYTE_ERROR;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > GET_DOMAIN_MAX_JUMP_COUNT) {
                    return GET_DOMAIN_JUMP_COUNT_ERROR;
                }
            } else {
                return GET_DOMAIN_TWO_BITS_ERROR;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_CH_BYTE_ERROR;
            }
            if (domain_len >= (int32_t)domain->max_size) {
                return GET_DOMAIN_ADD_CH_DOMAIN_ERROR;
            }
            domain->data[domain_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (domain_len >= (int32_t)domain->max_size) {
        return GET_DOMAIN_NULL_CH_DOMAIN_ERROR;
    }
    domain->data[domain_len] = 0;
    domain->size = domain_len;

    return GET_DOMAIN_OK;
}

int32_t in_subnet(uint32_t ip, subnet_t *subnet)
{
    uint32_t ip_h = ntohl(ip);
    uint32_t subnet_ip_h = ntohl(subnet->ip);

    return ((subnet_ip_h & subnet->mask) == (ip_h & subnet->mask));
}

static const char *domain_text(memory_t *domain)
{
    return domain->size == 0 ? "." : domain->data + 1;
}

static const char *rr_type_name(uint16_t type)
{
    switch (type) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    case 33:
        return "SRV";
    case 41:
        return "OPT";
    case DNS_TypeSVCB:
        return "SVCB";
    case DNS_TypeHTTPS:
        return "HTTPS";
    default:
        return NULL;
    }
}

static void log_clock(void)
{
    time_t now;
    struct tm tm_value;

    if (log_fp == NULL) {
        return;
    }

    now = time(NULL);
    if (localtime_r(&now, &tm_value) != NULL) {
        fprintf(log_fp, "\n%02d:%02d:%02d ", tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec);
    }
}

static int32_t log_svcb_https(memory_t *receive_msg, const char *section, const char *owner,
                              uint16_t type, uint32_t ttl, const char *rdata, uint16_t rdata_len)
{
    const char *rdata_end = rdata + rdata_len;
    uint16_t priority_net;
    uint16_t priority;
    char target_buf[DOMAIN_MAX_SIZE];
    memory_t target = { target_buf, 0, sizeof(target_buf) };
    char *target_end = NULL;
    const char *type_name = rr_type_name(type);
    const char *params_ptr;

    if (rdata_len < sizeof(uint16_t)) {
        return DNS_ANS_CHECK_ANS_LEN_ERROR;
    }

    memcpy(&priority_net, rdata, sizeof(priority_net));
    priority = ntohs(priority_net);

    if (get_domain_from_packet(receive_msg, (char *)rdata + sizeof(uint16_t), &target_end,
                               &target) != GET_DOMAIN_OK) {
        return DNS_ANS_CHECK_CNAME_URL_GET_ERROR;
    }
    if (target_end > rdata_end) {
        return DNS_ANS_CHECK_ANS_LEN_ERROR;
    }

    if (log_fp != NULL) {
        fprintf(log_fp, "    %s %s %s priority=%u target=%s ttl=%u", section, type_name, owner,
                (unsigned)priority, domain_text(&target), (unsigned)ttl);
    }

    params_ptr = target_end;
    while (params_ptr < rdata_end) {
        uint16_t key_net;
        uint16_t len_net;
        uint16_t key;
        uint16_t len;
        const char *value;

        if (params_ptr + 4 > rdata_end) {
            return DNS_ANS_CHECK_ANS_LEN_ERROR;
        }
        memcpy(&key_net, params_ptr, sizeof(key_net));
        memcpy(&len_net, params_ptr + 2, sizeof(len_net));
        key = ntohs(key_net);
        len = ntohs(len_net);
        params_ptr += 4;
        if (params_ptr + len > rdata_end) {
            return DNS_ANS_CHECK_ANS_LEN_ERROR;
        }
        value = params_ptr;

        if (log_fp != NULL && key == 4 && len != 0 && len % 4 == 0) {
            uint16_t i;
            fputs(" ipv4hint=", log_fp);
            for (i = 0; i < len; i += 4) {
                struct in_addr ip;
                char ip_buf[INET_ADDRSTRLEN];
                memcpy(&ip.s_addr, value + i, 4);
                if (i != 0) {
                    fputc(',', log_fp);
                }
                if (inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf)) != NULL) {
                    fputs(ip_buf, log_fp);
                } else {
                    fputc('?', log_fp);
                }
            }
        }

        params_ptr += len;
    }

    if (log_fp != NULL) {
        fputc('\n', log_fp);
    }
    return EXIT_SUCCESS;
}

static int32_t parse_rr_section(memory_t *receive_msg, char **cur_pos_ptr_io, uint16_t rr_count,
                                const char *section, memory_t *ans_domain, int32_t save_answer_ips)
{
    char *cur_pos_ptr = *cur_pos_ptr_io;
    char *receive_msg_end = receive_msg->data + receive_msg->size;
    uint16_t i;

    for (i = 0; i < rr_count; i++) {
        char *ans_domain_end = NULL;
        dns_rr_t rr;
        uint16_t rr_type;
        uint16_t rr_len;
        uint32_t rr_ttl;
        char *rdata;

        if (get_domain_from_packet(receive_msg, cur_pos_ptr, &ans_domain_end, ans_domain) !=
            GET_DOMAIN_OK) {
            return DNS_ANS_CHECK_ANS_URL_GET_ERROR;
        }
        cur_pos_ptr = ans_domain_end;

        if (cur_pos_ptr + sizeof(rr) > receive_msg_end) {
            return DNS_ANS_CHECK_ANS_DATA_GET_ERROR;
        }
        memcpy(&rr, cur_pos_ptr, sizeof(rr));
        cur_pos_ptr += sizeof(rr);

        rr_type = ntohs(rr.type);
        rr_ttl = ntohl(rr.ttl);
        rr_len = ntohs(rr.len);
        if (cur_pos_ptr + rr_len > receive_msg_end) {
            return DNS_ANS_CHECK_ANS_LEN_ERROR;
        }
        rdata = cur_pos_ptr;

        if (rr_type == DNS_TypeA && rr_len == 4) {
            uint32_t ip_be;
            struct in_addr ip;
            char ip_buf[INET_ADDRSTRLEN];
            int32_t correct_ip4_flag = 1;
            int32_t j;

            memcpy(&ip_be, rdata, sizeof(ip_be));
            ip.s_addr = ip_be;
            if (inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf)) == NULL) {
                strcpy(ip_buf, "?");
            }

            if (log_fp != NULL) {
                fprintf(log_fp, "    %s A %s %s ttl=%u\n", section, domain_text(ans_domain), ip_buf,
                        (unsigned)rr_ttl);
            }

            if (ip_be == 0) {
                correct_ip4_flag = 0;
            }
            for (j = 0; j < blacklist_count; j++) {
                if (in_subnet(ip_be, &blacklist[j])) {
                    correct_ip4_flag = 0;
                    break;
                }
            }
            if (is_save && save_answer_ips && correct_ip4_flag) {
                fprintf(ips_fp, "%s\n", ip_buf);
            }
        } else if (rr_type == DNS_TypeCNAME) {
            char target_buf[DOMAIN_MAX_SIZE];
            memory_t target = { target_buf, 0, sizeof(target_buf) };
            char *target_end = NULL;

            if (get_domain_from_packet(receive_msg, rdata, &target_end, &target) != GET_DOMAIN_OK) {
                return DNS_ANS_CHECK_CNAME_URL_GET_ERROR;
            }
            if (target_end > rdata + rr_len) {
                return DNS_ANS_CHECK_ANS_LEN_ERROR;
            }
            if (log_fp != NULL) {
                fprintf(log_fp, "    %s CNAME %s %s ttl=%u\n", section, domain_text(ans_domain),
                        domain_text(&target), (unsigned)rr_ttl);
            }
        } else if (rr_type == DNS_TypeSVCB || rr_type == DNS_TypeHTTPS) {
            int32_t res = log_svcb_https(receive_msg, section, domain_text(ans_domain), rr_type,
                                         rr_ttl, rdata, rr_len);
            if (res != EXIT_SUCCESS) {
                return res;
            }
        } else if (log_fp != NULL) {
            const char *type_name = rr_type_name(rr_type);
            if (type_name != NULL) {
                fprintf(log_fp, "    %s %s %s ttl=%u len=%u\n", section, type_name,
                        domain_text(ans_domain), (unsigned)rr_ttl, (unsigned)rr_len);
            } else {
                fprintf(log_fp, "    %s RR(%u) %s ttl=%u len=%u\n", section, (unsigned)rr_type,
                        domain_text(ans_domain), (unsigned)rr_ttl, (unsigned)rr_len);
            }
        }

        cur_pos_ptr += rr_len;
    }

    *cur_pos_ptr_io = cur_pos_ptr;
    return EXIT_SUCCESS;
}

int32_t dns_ans_check(memory_t *receive_msg, memory_t *que_domain, memory_t *ans_domain)
{
    char *cur_pos_ptr = receive_msg->data;
    char *receive_msg_end = receive_msg->data + receive_msg->size;
    dns_header_t header;
    uint16_t flags;
    uint16_t quest_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
    uint16_t question_type;
    char *que_domain_end = NULL;
    dns_que_t question;
    int32_t res;

    if (cur_pos_ptr + sizeof(header) > receive_msg_end) {
        return DNS_ANS_CHECK_HEADER_SIZE_ERROR;
    }
    memcpy(&header, cur_pos_ptr, sizeof(header));
    cur_pos_ptr += sizeof(header);

    flags = ntohs(header.flags);
    if ((flags & FIRST_BIT_UINT16) == 0) {
        return DNS_ANS_CHECK_RES_TYPE_ERROR;
    }

    quest_count = ntohs(header.quest);
    if (quest_count != 1) {
        return DNS_ANS_CHECK_QUE_COUNT_ERROR;
    }
    ans_count = ntohs(header.ans);
    auth_count = ntohs(header.auth);
    add_count = ntohs(header.add);

    if (get_domain_from_packet(receive_msg, cur_pos_ptr, &que_domain_end, que_domain) !=
        GET_DOMAIN_OK) {
        return DNS_ANS_CHECK_QUE_URL_GET_ERROR;
    }
    cur_pos_ptr = que_domain_end;

    if (cur_pos_ptr + sizeof(question) > receive_msg_end) {
        return DNS_ANS_CHECK_QUE_DATA_GET_ERROR;
    }
    memcpy(&question, cur_pos_ptr, sizeof(question));
    cur_pos_ptr += sizeof(question);
    question_type = ntohs(question.type);

    if (log_fp != NULL) {
        log_clock();
        fprintf(log_fp, "Q(%u) %s rcode=%u an=%u ns=%u ar=%u%s\n", (unsigned)question_type,
                domain_text(que_domain), (unsigned)(flags & 0x000f), (unsigned)ans_count,
                (unsigned)auth_count, (unsigned)add_count, (flags & 0x0200) != 0 ? " TC" : "");
    }

    res = parse_rr_section(receive_msg, &cur_pos_ptr, ans_count, "AN", ans_domain, 1);
    if (res != EXIT_SUCCESS) {
        return res;
    }
    res = parse_rr_section(receive_msg, &cur_pos_ptr, auth_count, "NS", ans_domain, 0);
    if (res != EXIT_SUCCESS) {
        return res;
    }
    res = parse_rr_section(receive_msg, &cur_pos_ptr, add_count, "AR", ans_domain, 0);
    if (res != EXIT_SUCCESS) {
        return res;
    }

    if (cur_pos_ptr != receive_msg_end) {
        return DNS_ANS_CHECK_NOT_END_ERROR;
    }

    if (is_save) {
        const char *qname = domain_text(que_domain);
        int32_t packet_size = (int32_t)receive_msg->size;
        fwrite(qname, sizeof(char), strlen(qname) + 1, cache_fp);
        fwrite(&packet_size, sizeof(packet_size), 1, cache_fp);
        fwrite(receive_msg->data, sizeof(char), receive_msg->size, cache_fp);
        fprintf(out_domains_fp, "%s\n", qname);
    }

    return EXIT_SUCCESS;
}

void *read_dns(void *arg)
{
    (void)arg;

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from DNS\n");
    }

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    memory_t ans_domain;
    ans_domain.size = 0;
    ans_domain.max_size = DOMAIN_MAX_SIZE;
    ans_domain.data = (char *)malloc(ans_domain.max_size * sizeof(char));
    if (ans_domain.data == 0) {
        errmsg("No free memory for ans_domain\n");
    }

    while (true) {
        ssize_t received = recv(listen_socket, receive_msg.data, receive_msg.max_size, 0);
        int32_t parse_res;

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            errmsg("Can't receive %s\n", strerror(errno));
        }
        receive_msg.size = (size_t)received;
        readed++;

        parse_res = dns_ans_check(&receive_msg, &que_domain, &ans_domain);
        if (parse_res != EXIT_SUCCESS && log_fp != NULL) {
            fprintf(log_fp, "    DNS parse error %d, %zu bytes\n", parse_res, receive_msg.size);
        }
    }

    return NULL;
}

void add_blacklist(const char *subnet_str)
{
    char tmp_subnet[100];
    strcpy(tmp_subnet, subnet_str);

    char *slash_ptr = strchr(tmp_subnet, '/');
    if (slash_ptr) {
        uint32_t tmp_prefix = 0;
        sscanf(slash_ptr + 1, "%u", &tmp_prefix);
        *slash_ptr = 0;
        if (strlen(tmp_subnet) < INET_ADDRSTRLEN) {
            if (blacklist_count < BLACKLIST_MAX_COUNT) {
                blacklist[blacklist_count].ip = inet_addr(tmp_subnet);
                blacklist[blacklist_count].mask = (0xFFFFFFFF << (32 - tmp_prefix)) & 0xFFFFFFFF;
            }
            blacklist_count++;
        }
        *slash_ptr = '/';
    } else {
        errmsg("Every blacklist line \"x.x.x.x/xx\"\n");
    }
}

void print_help(void)
{
    printf("Commands:\n"
           "  Required parameters:\n"
           "    -f  \"/test.txt\"   Domains file path\n"
           "    -d  \"x.x.x.x:xx\"  DNS address\n"
           "    -r  \"xxx\"         Request per second\n"
           "  Optional parameters:\n"
           "    -A, --a           Send A queries (default)\n"
           "    -H, --https       Send HTTPS queries\n"
           "    -n  \"count\"       Randomly query count domains; without -n query all\n"
           "    --seed \"seed\"     Random sample seed\n"
           "    -b  \"/test.txt\"   Subnets not add to ips output\n"
           "    --save            Save complete valid DNS responses and results\n"
           "    --log             Write human-readable DNS responses\n");
}

static void main_catch_function(int32_t signo)
{
    if (signo == SIGINT) {
        errmsg("SIGINT catched main\n");
    } else if (signo == SIGSEGV) {
        errmsg("SIGSEGV catched main\n");
    } else if (signo == SIGTERM) {
        errmsg("SIGTERM catched main\n");
    }
}

int32_t main(int32_t argc, char *argv[])
{
    printf("DNS client test started\n\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    // Timer based on for
    {
        struct timeval now_timeval_start;
        gettimeofday(&now_timeval_start, NULL);
        volatile double time_test = 1.0;
        for (int32_t j = 0; j < 1000; j++) {
            for (int32_t i = 0; i < 1000; i++) {
                time_test *= 3.0;
            }
        }
        time_test_sink = time_test;
        struct timeval now_timeval_end;
        gettimeofday(&now_timeval_end, NULL);
        uint64_t now_us_start = now_timeval_start.tv_sec * 1000000 + now_timeval_start.tv_usec;
        uint64_t now_us_end = now_timeval_end.tv_sec * 1000000 + now_timeval_end.tv_usec;
        one_cycle_ns = ((now_us_end - now_us_start) * 1000.0) / 1000.0 / 1000.0;
    }
    // Timer based on for

    char blacklist_file_path[PATH_MAX];
    memset(blacklist_file_path, 0, PATH_MAX);

    dns_addr.sin_addr.s_addr = INADDR_NONE;

    // Args
    {
        printf("Launch parameters:\n");
        for (int32_t i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-f")) {
                if (i != argc - 1) {
                    printf("  File  \"%s\"\n", argv[i + 1]);
                    if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                        strcpy(domains_file_path, argv[i + 1]);
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-d")) {
                if (i != argc - 1) {
                    printf("  DNS   \"%s\"\n", argv[i + 1]);
                    char *colon_ptr = strchr(argv[i + 1], ':');
                    if (colon_ptr) {
                        uint16_t tmp_port = 0;
                        sscanf(colon_ptr + 1, "%hu", &tmp_port);
                        *colon_ptr = 0;
                        if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                            dns_addr.sin_family = AF_INET;
                            dns_addr.sin_port = htons(tmp_port);
                            dns_addr.sin_addr.s_addr = inet_addr(argv[i + 1]);
                        }
                        *colon_ptr = ':';
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-r")) {
                if (i != argc - 1) {
                    printf("  RPS   \"%s\"\n", argv[i + 1]);
                    sscanf(argv[i + 1], "%u", &rps);
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-A") || !strcmp(argv[i], "--a")) {
                query_type = DNS_TypeA;
                printf("  Type  A\n");
                continue;
            }
            if (!strcmp(argv[i], "-H") || !strcmp(argv[i], "--https")) {
                query_type = DNS_TypeHTTPS;
                printf("  Type  HTTPS\n");
                continue;
            }
            if (!strcmp(argv[i], "-n")) {
                if (i != argc - 1) {
                    char *end_ptr = NULL;
                    unsigned long tmp_count = strtoul(argv[i + 1], &end_ptr, 10);
                    if (end_ptr == argv[i + 1] || *end_ptr != 0 || tmp_count == 0 ||
                        tmp_count > UINT32_MAX) {
                        errmsg("Invalid sample count %s\n", argv[i + 1]);
                    }
                    sample_count = (uint32_t)tmp_count;
                    printf("  Sample  \"%u\"\n", sample_count);
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "--seed")) {
                if (i != argc - 1) {
                    char *end_ptr = NULL;
                    unsigned long tmp_seed = strtoul(argv[i + 1], &end_ptr, 10);
                    if (end_ptr == argv[i + 1] || *end_ptr != 0 || tmp_seed > UINT32_MAX) {
                        errmsg("Invalid sample seed %s\n", argv[i + 1]);
                    }
                    sample_seed = (uint32_t)tmp_seed;
                    sample_seed_set = 1;
                    printf("  Seed  \"%u\"\n", sample_seed);
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-b")) {
                if (i != argc - 1) {
                    if (strlen(argv[i + 1]) < PATH_MAX) {
                        strcpy(blacklist_file_path, argv[i + 1]);
                        printf("  Blacklist  \"%s\"\n", blacklist_file_path);
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "--save")) {
                printf("  Save  enabled\n");
                is_save = 1;
                continue;
            }
            if (!strcmp(argv[i], "--log")) {
                printf("  Log   enabled\n");
                is_log = 1;
                continue;
            }
            print_help();
            errmsg("Unknown command %s\n", argv[i]);
        }

        if (domains_file_path[0] == 0) {
            print_help();
            errmsg("Programm need domains file path\n");
        }

        if (dns_addr.sin_addr.s_addr == INADDR_NONE) {
            print_help();
            errmsg("Programm need DNS IP\n");
        }

        if (dns_addr.sin_port == 0) {
            print_help();
            errmsg("Programm need DNS port\n");
        }

        if (rps == 0) {
            print_help();
            errmsg("Programm need RPS\n");
        }
    }
    // Args

    // Open files
    {
        const char *type_name = query_type == DNS_TypeHTTPS ? "HTTPS" : "A";
        char cache_file_name[64];
        char domains_file_name[64];
        char ips_file_name[64];
        char log_file_name[64];

        in_domains_fp = fopen(domains_file_path, "r");
        if (!in_domains_fp) {
            errmsg("Can't open file %s\n", domains_file_path);
        }

        if (sample_count != 0) {
            char line_buf[PACKET_MAX_SIZE];
            while (fscanf(in_domains_fp, "%s", line_buf) != EOF) {
                total_domains++;
            }
            rewind(in_domains_fp);
            if (total_domains == 0) {
                errmsg("Domains file is empty\n");
            }
            if (sample_count < total_domains) {
                if (!sample_seed_set) {
                    sample_seed = (uint32_t)time(NULL);
                }
                printf("  Random sample  %u of %llu, seed %u\n", sample_count,
                       (unsigned long long)total_domains, sample_seed);
            } else {
                printf("  Random sample  requested %u, file has %llu: query all domains\n",
                       sample_count, (unsigned long long)total_domains);
            }
        }

        snprintf(cache_file_name, sizeof(cache_file_name), "cache-%s.data", type_name);
        snprintf(domains_file_name, sizeof(domains_file_name), "out_domains-%s.txt", type_name);
        snprintf(ips_file_name, sizeof(ips_file_name), "ips-%s.txt", type_name);
        snprintf(log_file_name, sizeof(log_file_name), "log-%s.txt", type_name);

        if (is_save) {
            cache_fp = fopen(cache_file_name, "wb");
            if (!cache_fp) {
                errmsg("Can't open file %s\n", cache_file_name);
            }
            out_domains_fp = fopen(domains_file_name, "w");
            if (!out_domains_fp) {
                errmsg("Can't open file %s\n", domains_file_name);
            }
            ips_fp = fopen(ips_file_name, "w");
            if (!ips_fp) {
                errmsg("Can't open file %s\n", ips_file_name);
            }
            setvbuf(cache_fp, NULL, _IOFBF, 1024 * 1024);
            setvbuf(out_domains_fp, NULL, _IOFBF, 1024 * 1024);
            setvbuf(ips_fp, NULL, _IOFBF, 1024 * 1024);
        }

        if (is_log) {
            log_fp = fopen(log_file_name, "w");
            if (!log_fp) {
                errmsg("Can't open file %s\n", log_file_name);
            }
            setvbuf(log_fp, NULL, _IOFBF, 1024 * 1024);
            fputs("Reductions:\n"
                  "    Q(x)       DNS question type\n"
                  "    AN         Answer section\n"
                  "    NS         Authority section\n"
                  "    AR         Additional section\n"
                  "    TC         Truncated UDP response\n"
                  "    priority=0 HTTPS/SVCB AliasMode\n"
                  "    priority>0 HTTPS/SVCB ServiceMode\n",
                  log_fp);
        }
    }
    // Open files

    // Blacklist read
    {
        add_blacklist("0.0.0.0/8");
        add_blacklist("10.0.0.0/8");
        add_blacklist("100.64.0.0/10");
        add_blacklist("127.0.0.0/8");
        add_blacklist("172.16.0.0/12");
        add_blacklist("192.168.0.0/16");

        if (blacklist_file_path[0] != 0) {
            FILE *blacklist_fd;
            blacklist_fd = fopen(blacklist_file_path, "r");
            if (blacklist_fd == NULL) {
                errmsg("Can't open blacklist file %s\n", blacklist_file_path);
            }

            char tmp_line[100];

            while (fscanf(blacklist_fd, "%s", tmp_line) != EOF) {
                add_blacklist(tmp_line);
            }

            if (blacklist_count > BLACKLIST_MAX_COUNT) {
                errmsg("The program needs a maximum of %d blacklist subnets, seted %d\n",
                       BLACKLIST_MAX_COUNT, blacklist_count);
            }
        }
    }
    // Blacklist read

    // Open socket
    {
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(LISTEN_PORT_START);
        listen_addr.sin_addr.s_addr = 0;

        listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (listen_socket < 0) {
            errmsg("Can't create socket %s\n", strerror(errno));
        }

        while (bind(listen_socket, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
            listen_addr.sin_port = htons(ntohs(listen_addr.sin_port) + 1);
        }
    }
    // Open socket

    // Threads
    {
        pthread_t send_thread;
        if (pthread_create(&send_thread, NULL, send_dns, NULL)) {
            errmsg("Can't create send_thread\n");
        }

        if (pthread_detach(send_thread)) {
            errmsg("Can't detach send_thread\n");
        }

        pthread_t read_thread;
        if (pthread_create(&read_thread, NULL, read_dns, NULL)) {
            errmsg("Can't create read_thread\n");
        }

        if (pthread_detach(read_thread)) {
            errmsg("Can't detach read_thread\n");
        }
    }
    // Threads

    // Stat
    {
        int32_t sended_old = 0;
        int32_t readed_old = 0;

        int32_t exit_wait = 0;

        struct timeval now_timeval_start;
        struct timeval now_timeval_end;

        memset(&now_timeval_start, 0, sizeof(now_timeval_start));

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("\nStart time %02d.%02d.%04d %02d:%02d:%02d\n\n", tm_struct->tm_mday,
               tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
               tm_struct->tm_min, tm_struct->tm_sec);

        char print_format[100];
        char *print_data[100];
        print_data[0] = "Send_RPS;";
        print_data[1] = " Read_RPS;";
        print_data[2] = "   Sended;";
        print_data[3] = "   Readed;";
        print_data[4] = "     Diff;";

        for (int32_t i = 0; i < 5; i++) {
            printf("%s", print_data[i]);
        }
        printf("\n");

        while (true) {
            sleep(1);

            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[0]) - 1));
            printf(print_format, sended - sended_old);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[1]) - 1));
            printf(print_format, readed - readed_old);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[2]) - 1));
            printf(print_format, sended);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[3]) - 1));
            printf(print_format, readed);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[4]) - 1));
            printf(print_format, sended - readed);
            printf("\n");
            fflush(stdout);

            if (readed == readed_old) {
                exit_wait++;
            } else {
                exit_wait = 0;
            }

            if (exit_wait >= EXIT_WAIT_SEC) {
                break;
            }

            gettimeofday(&now_timeval_end, NULL);

            if (now_timeval_start.tv_sec != 0) {
                uint64_t now_us_start =
                    now_timeval_start.tv_sec * 1000000 + now_timeval_start.tv_usec;
                uint64_t now_us_end = now_timeval_end.tv_sec * 1000000 + now_timeval_end.tv_usec;
                double real_rps = (sended - sended_old) / ((now_us_end - now_us_start) / 1000000.0);
                coeff *= rps / real_rps;
            }

            gettimeofday(&now_timeval_start, NULL);

            sended_old = sended;
            readed_old = readed;
        }

        now = time(NULL);
        tm_struct = localtime(&now);
        printf("\nEnd time %02d.%02d.%04d %02d:%02d:%02d\n", tm_struct->tm_mday,
               tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
               tm_struct->tm_min, tm_struct->tm_sec);
        fflush(stdout);
    }
    // Stat

    return EXIT_SUCCESS;
}
