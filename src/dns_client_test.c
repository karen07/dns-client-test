#include "dns_client_test.h"

FILE *in_domains_fp;
FILE *cache_fp;
FILE *out_domains_fp;
FILE *ips_fp;

char domains_file_path[PATH_MAX];
uint32_t rps;
int32_t is_save;

volatile int32_t sended;
volatile int32_t readed;

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

    while (fscanf(in_domains_fp, "%s", line_buf) != EOF) {
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
        end_name->type = htons(1);
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

int32_t dns_ans_check(memory_t *receive_msg, memory_t *que_domain, memory_t *ans_domain)
{
    char *cur_pos_ptr = receive_msg->data;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    // DNS HEADER
    if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
        return DNS_ANS_CHECK_HEADER_SIZE_ERROR;
    }

    dns_header_t *header = (dns_header_t *)cur_pos_ptr;

    uint16_t first_bit_mark = FIRST_BIT_UINT16;
    uint16_t flags = ntohs(header->flags);
    if ((flags & first_bit_mark) == 0) {
        return DNS_ANS_CHECK_RES_TYPE_ERROR;
    }

    uint16_t quest_count = ntohs(header->quest);
    if (quest_count != 1) {
        return DNS_ANS_CHECK_QUE_COUNT_ERROR;
    }

    uint16_t ans_count = ntohs(header->ans);
    if (ans_count == 0) {
        return DNS_ANS_CHECK_ANS_COUNT_ERROR;
    }

    cur_pos_ptr += sizeof(dns_header_t);
    // DNS HEADER

    // QUE DOMAIN
    char *que_domain_start = cur_pos_ptr;
    char *que_domain_end = NULL;
    if (get_domain_from_packet(receive_msg, que_domain_start, &que_domain_end, que_domain) != 0) {
        return DNS_ANS_CHECK_QUE_URL_GET_ERROR;
    }
    cur_pos_ptr = que_domain_end;

    if (is_save) {
        fwrite(que_domain->data + 1, sizeof(char), strlen(que_domain->data), cache_fp);
        fwrite(&receive_msg->size, sizeof(int32_t), 1, cache_fp);
        fwrite(receive_msg->data, sizeof(char), receive_msg->size, cache_fp);
        fprintf(out_domains_fp, "%s\n", que_domain->data + 1);
    }

    // QUE DOMAIN

    // QUE DATA
    if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
        return DNS_ANS_CHECK_QUE_DATA_GET_ERROR;
    }

    cur_pos_ptr += sizeof(dns_que_t);
    // QUE DATA

    for (int32_t i = 0; i < ans_count; i++) {
        // ANS DOMAIN
        char *ans_domain_start = cur_pos_ptr;
        char *ans_domain_end = NULL;
        if (get_domain_from_packet(receive_msg, ans_domain_start, &ans_domain_end, ans_domain) !=
            0) {
            return DNS_ANS_CHECK_ANS_URL_GET_ERROR;
        }
        cur_pos_ptr = ans_domain_end;
        // ANS DOMAIN

        // ANS DATA
        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
            return DNS_ANS_CHECK_ANS_DATA_GET_ERROR;
        }

        dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

        uint16_t ans_type = ntohs(ans->type);
        uint32_t ans_ttl = ntohl(ans->ttl);
        (void)ans_ttl;
        uint16_t ans_len = ntohs(ans->len);

        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
            return DNS_ANS_CHECK_ANS_LEN_ERROR;
        }

        if (ans_type == DNS_TypeA) {
            struct in_addr new_ip;
            new_ip.s_addr = ans->ip4;

            int32_t correct_ip4_flag = 1;
            if (ans->ip4 == 0) {
                correct_ip4_flag = 0;
            }

            for (int32_t j = 0; j < blacklist_count; j++) {
                if (in_subnet(ans->ip4, &blacklist[j])) {
                    correct_ip4_flag = 0;
                    break;
                }
            }

            if (is_save && correct_ip4_flag) {
                fprintf(ips_fp, "%s\n", inet_ntoa(new_ip));
            }
        }

        cur_pos_ptr += sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len;
        // ANS DATA
    }

    if ((header->auth == 0) && (header->add == 0)) {
        if (cur_pos_ptr != receive_msg_end) {
            return DNS_ANS_CHECK_NOT_END_ERROR;
        }
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
        receive_msg.size = recv(listen_socket, receive_msg.data, receive_msg.max_size, 0);

        readed++;

        dns_ans_check(&receive_msg, &que_domain, &ans_domain);
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
           "    -b  \"/test.txt\"   Subnets not add to the routing table\n"
           "    --save            Save DNS answer data to cache.data,\n"
           "                      DNS answer domains to out_domains.txt,\n"
           "                      DNS answer IPs to ips.txt\n");
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

    //Timer based on for
    {
        struct timeval now_timeval_start;
        gettimeofday(&now_timeval_start, NULL);
        volatile double time_test = 1.0;
        for (int32_t j = 0; j < 1000; j++) {
            for (int32_t i = 0; i < 1000; i++) {
                time_test *= 3.0;
            }
        }
        struct timeval now_timeval_end;
        gettimeofday(&now_timeval_end, NULL);
        uint64_t now_us_start = now_timeval_start.tv_sec * 1000000 + now_timeval_start.tv_usec;
        uint64_t now_us_end = now_timeval_end.tv_sec * 1000000 + now_timeval_end.tv_usec;
        one_cycle_ns = ((now_us_end - now_us_start) * 1000.0) / 1000.0 / 1000.0;
    }
    //Timer based on for

    char blacklist_file_path[PATH_MAX];
    memset(blacklist_file_path, 0, PATH_MAX);

    dns_addr.sin_addr.s_addr = INADDR_NONE;

    //Args
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
    //Args

    //Open files
    {
        in_domains_fp = fopen(domains_file_path, "r");
        if (!in_domains_fp) {
            errmsg("Can't open file %s\n", domains_file_path);
        }

        if (is_save) {
            cache_fp = fopen("cache.data", "w");
            if (!cache_fp) {
                errmsg("Can't open file cache.data\n");
            }
            out_domains_fp = fopen("out_domains.txt", "w");
            if (!out_domains_fp) {
                errmsg("Can't open file out_domains.txt\n");
            }
            ips_fp = fopen("ips.txt", "w");
            if (!ips_fp) {
                errmsg("Can't open file ips.txt\n");
            }
        }
    }
    //Open files

    //Blacklist read
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
    //Blacklist read

    //Open socket
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
    //Open socket

    //Threads
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
    //Threads

    //Stat
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
    //Stat

    return EXIT_SUCCESS;
}
