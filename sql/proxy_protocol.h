#include "my_net.h"

struct proxy_peer_info
{
  struct sockaddr_storage peer_addr;
  char ip_string[256];
  int port;
  bool is_local_connection;
};

extern int parse_proxy_protocol_header(NET *net, proxy_peer_info *peer_info);