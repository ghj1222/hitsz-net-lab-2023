#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    buf_t fuck;
    uint8_t *data = req_buf->data+sizeof(icmp_hdr_t);
    int len = req_buf->len-sizeof(icmp_hdr_t);
    buf_init(&fuck, len);
    memcpy(fuck.data, data, len);
    buf_add_header(&fuck, sizeof(icmp_hdr_t));
    icmp_hdr_t *hdr = (icmp_hdr_t*)fuck.data;
    icmp_hdr_t *old_hdr = (icmp_hdr_t*)(req_buf->data);
    *hdr = (icmp_hdr_t){
        .type=ICMP_TYPE_ECHO_REPLY,
        .code=0,
        .checksum16=0,
        .id16=old_hdr->id16,
        .seq16=old_hdr->seq16,
    };
    hdr->checksum16=checksum16((uint16_t*)fuck.data, fuck.len);

    // TO-DO
    ip_out(&fuck, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(icmp_hdr_t)) return;

    icmp_hdr_t *hdr = (icmp_hdr_t*)buf->data;

    if (hdr->type == ICMP_TYPE_ECHO_REQUEST)
    {
        icmp_resp(buf, src_ip);
    }

    // TO-DO
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    printf("send icmp unreachable!\n");
    buf_t fuck;

    uint8_t *data = recv_buf->data;
    int len = ((ip_hdr_t*)(recv_buf->data))->hdr_len;
    printf("your len=%d\n", len);
    len=len*4+8;
    printf("your len=%d\n", len);
    buf_init(&fuck, len);
    memcpy(fuck.data, data, len);
    buf_add_header(&fuck, sizeof(icmp_hdr_t));
    icmp_hdr_t *hdr = (icmp_hdr_t*)fuck.data;
    *hdr = (icmp_hdr_t){
        .type=ICMP_TYPE_UNREACH,
        .code=code,
        .checksum16=0,
        .id16=0,
        .seq16=0,
    };
    hdr->checksum16=checksum16((uint16_t*)fuck.data, fuck.len);

    // TO-DO
    ip_out(&fuck, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}