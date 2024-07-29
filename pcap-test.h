struct eth_header {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
};

struct ip_header {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    u_char ip_src[4];
    u_char ip_dst[4];
};

struct tcp_header {
    u_short tcp_src;
    u_short tcp_dst;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

struct payload {
    u_char data[20];
};