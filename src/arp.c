#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_t fuck;
    buf_init(&fuck, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t*)fuck.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    ethernet_out(&fuck, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_t fuck;
    buf_init(&fuck, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t*)fuck.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    ethernet_out(&fuck, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < sizeof(arp_pkt_t)) return;
    arp_pkt_t *pkt = (arp_pkt_t*)buf->data;
    if (pkt->hw_type16 != swap16(ARP_HW_ETHER)) return;
    if (pkt->pro_type16 != swap16(NET_PROTOCOL_IP)) return;
    if (pkt->hw_len != NET_MAC_LEN) return;
    if (pkt->pro_len != NET_IP_LEN) return;
    if (pkt->opcode16 != swap16(ARP_REQUEST) && pkt->opcode16 != swap16(ARP_REPLY)) return;
    map_set(&arp_table, pkt->sender_ip, pkt->sender_mac);
    buf_t *buf2 = map_get(&arp_buf, pkt->sender_ip);
    if (buf2 != NULL)
    {
        ethernet_out(buf2, pkt->sender_mac, NET_PROTOCOL_IP); // TODO
        map_delete(&arp_buf, pkt->sender_ip);
    }
    if (pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN) == 0)
    {
        arp_resp(pkt->sender_ip, pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *mac = (uint8_t*)map_get(&arp_table, ip);
    if (mac != NULL)
    {
        ethernet_out(buf, mac, NET_PROTOCOL_IP); // todo
    }
    else
    {
        buf_t *buf2 = (buf_t*)map_get(&arp_buf, ip);
        if (buf2 != NULL)
        {
            
        }
        else
        {
            arp_req(ip);
            map_set(&arp_buf, ip, buf);
        }
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}