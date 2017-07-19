/* Copyright (c) 2017, MariaDB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */
   
#include <my_global.h>
#include <mysql.h>
#include <mysql_com.h>
#include <mysqld_error.h>
#include <my_sys.h>
#include <m_string.h>
#include <my_net.h>
#include <violite.h>
#include <proxy_protocol.h>
#include <log.h>

static int parse_proxy_protocol_v1_header(char *hdr, size_t len, proxy_peer_info *peer_info)
{
  char *ctx= NULL;
  char *token;
  int   address_family;


  // Parse PROXY
  token= strtok_r(hdr, " ", &ctx);
  if (!token)
    return -1;
  if (strcmp(token, "PROXY"))
    return -1;

  // Parse address Family : TCP4, TCP6 or UNKNOWN
  token= strtok_r(NULL, " ", &ctx);
  if (!token)
    return -1;

  if (strcmp(token, "TCP4") == 0)
    address_family= AF_INET;
  else if (strcmp(token, "TCP6") == 0)
    address_family= AF_INET6;
  else if (strcmp(token, "UNKNOWN") == 0)
    address_family= AF_UNSPEC;
  else
    return -1;

  // Parse client IP address
  token= strtok_r(NULL, " ", &ctx);
  if (!token)
    return -1;

  void *addr;
  if (address_family == AF_INET)
    addr= &((struct sockaddr_in *)(&peer_info->peer_addr))->sin_addr;
  else
    addr= &((struct sockaddr_in6 *)(&peer_info->peer_addr))->sin6_addr;

  peer_info->peer_addr.ss_family= address_family;

  if (!inet_pton(address_family, token, addr))
    return -1;

  // Parse server IP address
  token= strtok_r(NULL, " ", &ctx);
  if (!token)
    return -1;

  // Parse client port.
  token= strtok_r(NULL, " ", &ctx);
  peer_info->port= atoi(token);

  if (address_family == AF_INET)
    ((struct sockaddr_in *)(&peer_info->peer_addr))->sin_port= (ushort) peer_info->port;
  else
    ((struct sockaddr_in6 *)(&peer_info->peer_addr))->sin6_port= (ushort) peer_info->port;

  // Parse server port
  token= strtok_r(NULL, " ", &ctx);

  return 0;
}

static int parse_proxy_protocol_v2_header(char *hdr, size_t len,proxy_peer_info *peer_info)
{
  peer_info->is_local_connection= false;
  /* V2 Signature */
  if (memcmp(hdr, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12))
    return -1;

  /* version  + command */
  uint8 ver= (hdr[12] & 0xF0);
  if (ver != 0x20)
    return -1; /* Wrong version*/

  uint cmd= (hdr[12] & 0xF);

  /* Address family */
  uint8 fam= hdr[13];

  if (cmd == 0)
  {
    /* LOCAL command*/
    peer_info->is_local_connection= true;
    return 0;
  }

  if (cmd != 0x01)
  {
    /* Not PROXY COMMAND */
    return -1;
  }

  struct sockaddr_in *sin= (struct sockaddr_in *)(&peer_info->peer_addr);
  struct sockaddr_in6 *sin6= (struct sockaddr_in6 *)(&peer_info->peer_addr);
  switch (fam)
  {
  case 0x11:  /* TCPv4 */
    sin->sin_family= AF_INET;
    memcpy(&(sin->sin_addr.s_addr), hdr + 16, 4);
    peer_info->port= ((uchar)hdr[24] << 8) + (uchar)hdr[25];
    break;
  case 0x21:  /* TCPv6 */
    sin6->sin6_family= AF_INET6;
    memcpy(&(sin6->sin6_addr), hdr + 16, 16);
    peer_info->port= ((uchar)hdr[48] << 8) + (uchar)hdr[49];
    break;
  default:
    peer_info->is_local_connection= true;
  }
  return 0;
}


int parse_proxy_protocol_header(NET *net, proxy_peer_info *peer_info)
{
  char hdr[108];
  size_t hdr_len= 0;

  DBUG_ASSERT(!net->compress);
  const uchar *preread_bytes= net->buff + net->where_b;
  bool is_v1_header= !memcmp(preread_bytes, "PROX", 4);
  bool is_v2_header= !is_v1_header && !memcmp(preread_bytes, "\x0D\x0A\x0D\x0A", 4);
  if (!is_v1_header && !is_v2_header)
  {
    // not a proxy protocol header
    return -1;
  }
  memcpy(hdr, preread_bytes, 4);
  hdr_len= 4;
  Vio *vio= net->vio;
  memset(peer_info, 0, sizeof (*peer_info));

  if (is_v1_header)
  {
    while(hdr_len < sizeof(hdr))
    {
      long len= (long)vio_read(vio, (uchar *)hdr + hdr_len, 1);
      if (len < 0)
        return -1;
      hdr_len++;
      if (hdr[hdr_len-1] == '\n')
        break;
    }
    hdr[hdr_len]= 0;

    if (parse_proxy_protocol_v1_header(hdr, hdr_len, peer_info))
      return -1;
  }
  else // if (is_v2_header)
  {
    /* read off 16 bytes of the header*/
    long len= vio_read(vio, (uchar *)hdr + 4, 12);
    if (len < 0)
      return -1;
    // 2 last bytes are the length in network byte order of the part following header
    ushort trail_len= (hdr[14] >> 8) + hdr[15];
    if (trail_len > sizeof(hdr) - 16)
      return -1;
    len= vio_read(vio, (uchar *)hdr + 16, trail_len);
    hdr_len= 16 + trail_len;
    if (parse_proxy_protocol_v2_header(hdr, hdr_len, peer_info))
      return -1;
  }
  return 0;
}


/**
 CIDR address matching etc (for the proxy_protocol_networks parameter)
*/

/**
  Subnetwork address in CIDR format, e.g
  192.168.1.0/24 or 2001:db8::/32
*/
struct subnet
{
  char addr[16]; /* Binary representation of the address, big endian*/
  unsigned short family; /* Address family, AF_INET or AF_INET6 */
  unsigned short bits; /* subnetwork size */
};

static  subnet* proxy_protocol_subnets;
size_t  proxy_protocol_subnet_count;

#define MAX_MASK_BITS(family) (family == AF_INET ? 32 : 128)

/**
  Convert string representation of a subnet to subnet struct.
*/
static int parse_single_subnet(char *addr_str, struct subnet *subnet)
{
  subnet->family= strchr(addr_str, ':') ? AF_INET6 : AF_INET;

  char *pmask= strchr(addr_str, '/');
  if (!pmask)
  {
    subnet->bits= MAX_MASK_BITS(subnet->family);
  }
  else
  {
    *pmask= 0;
    pmask++;
    int b= 0;
    do
    {
      if (*pmask < '0' || *pmask > '9')
        return -1;
      b= 10 * b + *pmask - '0';
      if (b > MAX_MASK_BITS(subnet->family))
        return -1;
      pmask++;
    } while (*pmask);
    subnet->bits= (unsigned short)b;
  }
  if (!inet_pton(subnet->family, addr_str, subnet->addr))
  {
    return -1;
  }
  return 0;
}

/**
  Parse comma separated string subnet list into subnets array
*/
int set_proxy_protocol_networks(const char *subnets_str)
{
  if (!subnets_str || !*subnets_str)
    return 0;

  size_t max_subnets= MY_MAX(2,strlen(subnets_str)/2); /* upper bound for number of subnets in list, reached only if subnet_str is "".*/
  proxy_protocol_subnets= (subnet *)my_malloc(max_subnets * sizeof(subnet),MY_ZEROFILL); 

  /* Check for special case '*'. */
  if (strcmp(subnets_str, "*") == 0)
  {

    proxy_protocol_subnets[0].family= AF_INET;
    proxy_protocol_subnets[1].family= AF_INET6;
    proxy_protocol_subnet_count= 2;
    return 0;
  }

  char token[256];
  const char *p= subnets_str;
  for(proxy_protocol_subnet_count= 0;; proxy_protocol_subnet_count++)
  {
    while(*p && (*p ==',' || *p == ' '))
      p++;
    if (!*p)
      break;

    size_t cnt= 0;
    while(*p && *p != ',' && *p != ' ' && cnt < sizeof(token)-1)
      token[cnt++]= *p++;

    token[cnt++]=0;
    if (cnt ==  sizeof(token))
      return -1;

    if (parse_single_subnet(token, &proxy_protocol_subnets[proxy_protocol_subnet_count]))
      return -1;
  }
  return 0;
}

/**
   Compare memory areas, in memcmp().similar fashion.
   The difference to memcmp() is that size parameter is the
   bit count, not byte count.
*/
static int compare_bits(const void *s1, const void *s2, int bit_count)
{
  int result= 0;
  int byte_count= bit_count / 8;
  if (byte_count && (result= memcmp(s1, s2, byte_count)))
    return result;
  int rem= byte_count % 8;
  if (rem)
  {
    // compare remaining bits (
    unsigned char s1_bits= (((char *)s1)[byte_count]) >> (8 - rem);
    unsigned char s2_bits= (((char *)s2)[byte_count]) >> (8 - rem);
    if (s1_bits > s2_bits)
      return 1;
    if (s1_bits < s2_bits)
      return -1;
  }
  return 0;
}

/**
  Check whether networks address matches network.
*/
bool addr_matches_subnet(const sockaddr *sock_addr, const subnet *subnet)
{
  if (sock_addr->sa_family != subnet->family)
    return false;

  void *addr= (subnet->family == AF_INET) ?
    (void *)&((struct sockaddr_in *)sock_addr)->sin_addr :
    (void *)&((struct sockaddr_in6 *)sock_addr)->sin6_addr;

  return (compare_bits(subnet->addr, addr, subnet->bits) == 0);
}


bool is_proxy_protocol_allowed(const sockaddr *addr, int len)
{
  sockaddr_storage addr_storage;
  struct sockaddr *normalized_addr= (struct sockaddr *)&addr_storage;
  int dst_len;
  vio_get_normalized_ip(addr, len,normalized_addr, &dst_len);

  for (size_t i= 0; i < proxy_protocol_subnet_count; i++)
    if (addr_matches_subnet(normalized_addr, &proxy_protocol_subnets[i]))
      return true;

  return false;
}

void cleanup_proxy_protocol_networks()
{
  my_free(proxy_protocol_subnets);
  proxy_protocol_subnets= 0;
  proxy_protocol_subnet_count= 0;
}


