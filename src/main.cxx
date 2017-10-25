/**
 * zprd / main.cxx
 *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap
 * interfaces and UDP.
 *
 * (C) 2010 Davide Brini.
 * (C) 2017 Erik Zscheile.
 *
 * License: GPL-3
 *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is
 * ugly, the algorithms are naive, error checking and input validation
 * are very basic, and of course there can be bugs. If that's not enough,
 * the program has not been thoroughly tested, so it might even fail at
 * the few simple things it should be supposed to do right.
 * Needless to say, I take no responsibility whatsoever for what the
 * program might do. The program has been written mostly for learning
 * purposes, and can be used in the hope that is useful, but everything
 * is to be taken "as is" and without any kind of warranty, implicit or
 * explicit. See the file LICENSE for further details.
 **/

#define __USE_MISC 1
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

// C++
#include <string>
#include <vector>
#include <forward_list>
#include <set>
#include <unordered_map>
#include <fstream>
#include <algorithm>

// own parts
#include "addr.hpp"
#include "cksum.h"
#include "crw.h"
#include "recentpkts.hpp"
#include "resolve.hpp"
#include "zsig.h"

// buffer for reading from tun/tap interface, must be greater than 1500
#define BUFSIZE 65536

// timeout in seconds after which remotes are silently discarded
#define REMOTE_TIMEOUT 900 // 0.25 hour

using namespace std;

/** file descriptors
 *
 * local_fd  = the tun device
 * server_fd = the server udp socket
 **/
static int local_fd, server_fd;

/** data port **/
static uint16_t data_port;

struct remote_peer_t {
  time_t  seen;
  ssize_t cent; // config entry

  remote_peer_t()
    : seen(time(0)), cent(-1) { }

  explicit remote_peer_t(size_t cfgent)
    : seen(time(0)), cent(static_cast<ssize_t>(cfgent)) { }

  void refresh() {
    seen = time(0);
  }

  bool outdated() const {
    return (time(0) - seen) >= REMOTE_TIMEOUT;
  }
};

static unordered_map<uint32_t, remote_peer_t> remotes;

struct via_router_t {
  uint32_t addr;
  time_t   seen;
  uint8_t  hops;

  via_router_t(const uint32_t _addr, const uint8_t _hops)
    : addr(_addr), seen(time(0)), hops(_hops) { }
};

// collection of via_route_t's
class route_via_t {
  std::forward_list<via_router_t> _routers;

 public:
  // deletes all outdates routers and sort routers
  template<typename Fn>
  void cleanup(const Fn f) {
    _routers.remove_if(
      [f](const via_router_t &a) {
        if((time(0) - a.seen) < (2 * REMOTE_TIMEOUT))
          return false;

        f(a.addr);
        return true;
      }
    );

    _routers.sort(
      [](const via_router_t &a, const via_router_t &b) {
        return (a.hops < b.hops)
            || (a.hops == b.hops && a.seen > b.seen);
      }
    );
  }

  bool empty() const noexcept {
    return _routers.empty();
  }

  uint32_t get_router() const noexcept {
    return empty() ? INADDR_ANY : _routers.front().addr;
  }

  // add or modify a router
  bool add_router(const uint32_t router, const uint8_t hops) {
    for(auto &i : _routers)
      if(router == i.addr) {
        // we found it
        i.seen = time(0);
        i.hops = hops;
        return false;
      }

    _routers.emplace_front(router, hops);
    return true;
  }

  bool del_router(const uint32_t router) {
    bool ret = false;
    _routers.remove_if(
      [router, &ret](const via_router_t &a) -> bool {
        const bool tmp = (router == a.addr);
        ret = ret || tmp;
        return tmp;
      }
    );
    return ret;
  }

  bool del_primary_router() noexcept {
    if(empty()) return false;
    _routers.pop_front();
    return true;
  }
};

typedef unordered_map<uint32_t, route_via_t> routes_t;
static routes_t routes;

static in_addr local_ip, local_netmask;
static bool have_local_ip, have_local_netmask;

struct {
  string iface;
  vector<string> remotes;
} zprd_conf;

static void init_all(const string &confpath) {
  // redirect stdin (don't block terminals)
  {
    const int ofd = open("/dev/null", O_RDONLY);
    if(ofd < 0) {
      fprintf(stderr, "ERROR: unable to open nullfile '/dev/null'\n");
      perror("open()");
      exit(1);
    }
    if(dup2(ofd, 0)) {
      perror("dup2()");
      exit(1);
    }
    close(ofd);
  }

  // read config
  {
    ifstream in(confpath.c_str());
    if(!in) {
      fprintf(stderr, "ERROR: unable to open config file '%s'\n", confpath.c_str());
      exit(1);
    }

    /** DEFAULTS
     *  (data_port) P45940
     **/
    data_port = 45940;

    // is used when we are root and see the 'U' setting in the conf to drop privilegis
    string run_as_user;

    string line;
    while(getline(in, line)) {
      if(line.empty()) continue;
      switch(line.front()) {
        case '#':
          break;

        case 'A':
          // used and applied by startup script
          break;

        case 'I':
          zprd_conf.iface = line.substr(1);
          break;

        case 'P':
          data_port = stoi(line.substr(1));
          break;

        case 'R':
          zprd_conf.remotes.emplace_back(line.substr(1));
          break;

        case 'U':
          run_as_user = line.substr(1);
          break;

        default:
          fprintf(stderr, "CONFIG ERROR: unknown stmt in config file: '%s'\n", line.c_str());
          break;
      }
    }
    in.close();

    if(!run_as_user.empty()) {
      printf("running daemon as user: '%s'\n", run_as_user.c_str());

      // NOTE: we don't need to use getpwnam_r because this function is always
      //  called before threads are spawned
      struct passwd *pwresult = getpwnam(run_as_user.c_str());

      if(!pwresult) {
        perror("STARTUP ERROR: getpwnam() failed");
        exit(1);
      }

      if(setuid(pwresult->pw_uid) < 0) {
        perror("STARTUP ERROR: setuid() failed");
        exit(1);
      }
    }
  }

  chdir("/");
  srand(time(0));

  // init tundev
  {
    char if_name[IFNAMSIZ];
    strncpy(if_name, zprd_conf.iface.c_str(), IFNAMSIZ - 1);
    if_name[IFNAMSIZ - 1] = 0;

    if( (local_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
      fprintf(stderr, "failed to connect to interface '%s'\n", if_name);
      exit(1);
    }
    zprd_conf.iface = if_name;

    printf("connected to interface %s\n", zprd_conf.iface.c_str());
  }

  {
    struct in_addr remote;
    size_t i = 0;
    for(auto &&r : zprd_conf.remotes) {
      if(resolve_hostname(r.c_str(), remote)) {
        remotes[remote.s_addr] = remote_peer_t(i);
        printf("CLIENT: connected to server %s\n", inet_ntoa(remote));
      }
      ++i;
    }
  }

  if(remotes.empty() && !zprd_conf.remotes.empty()) {
    printf("CLIENT ERROR: can't connect to any server. QUIT\n");
    exit(1);
  }

  // prepare server
  if( (server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  // avoid EADDRINUSE error on bind()
  int optval = 1;
  if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    exit(1);
  }

  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(data_port);
  if(bind(server_fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
    perror("bind()");
    exit(1);
  }
}

static bool get_local_xxxip_generic(struct in_addr &ret, struct ifreq &ifr, const unsigned long what, struct sockaddr &sa) {
  memset(&ret, 0, sizeof(ret));

  if(server_fd < 0) return false;

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, zprd_conf.iface.c_str(), IFNAMSIZ - 1);

  if(ioctl(server_fd, what, static_cast<void *>(&ifr)) < 0 ) {
    perror("ioctl(SIOCGIF...ADDR)");
    return false;
  }

  ret = reinterpret_cast<struct sockaddr_in*>(&sa)->sin_addr;

  return true;
}

// get_remote_desc: returns a description string of socket ip
static string get_remote_desc(const uint32_t addr) {
  return (addr == local_ip.s_addr)
         ? string("local")
         : (string("peer ") + inet_ntoa({addr}));
}

/** parse_control_message:
 * detects if a block is a control message (ICMP)
 * updates the routing table (drops outdated entries)
 *
 * @param src_addr  the source router
 * @param buffer    the buffer
 * @param buflen    the length of the buffer
 * @ret             discard packet?
 **/
static bool parse_control_message(const uint32_t &src_addr, const char *buffer, const int buflen) {
  {
    constexpr const uint16_t expect_buflen = 2 * sizeof(struct ip) + sizeof(struct icmphdr);
    if(!buffer || buflen != expect_buflen) return false;
  }

  const struct ip * const h_ip = reinterpret_cast<const struct ip*>(buffer);
  const struct icmphdr * const h_icmp = reinterpret_cast<const struct icmphdr*>(buffer + sizeof(struct ip));

  if(h_ip->ip_p != IPPROTO_ICMP) return false;
  if(in_cksum(reinterpret_cast<const uint16_t*>(h_icmp), sizeof(struct icmphdr))) {
    printf("ROUTER ERROR: invalid icmp packet (wrong checksum; chksum = %u)\n", h_icmp->checksum);
    return true;
  }

  bool discard_route = false;

  switch(h_icmp->type) {
    case ICMP_TIMXCEED:
      if(h_icmp->code == ICMP_TIMXCEED_INTRANS)
        discard_route = true;
      break;

    case ICMP_UNREACH:
      switch(h_icmp->code) {
        case ICMP_UNREACH_HOST:
        case ICMP_UNREACH_NET:
          discard_route = true;
          break;
      }
      break;

    default:
      return false;
  }

  if(discard_route) {
    const struct ip * const h_ip2 = reinterpret_cast<const struct ip*>(buffer + sizeof(struct ip) + sizeof(struct icmphdr));
    const uint32_t router = src_addr;             // dropped from
    const uint32_t target = h_ip2->ip_dst.s_addr; // original destination
    if(routes[target].del_router(router)) {
      printf("ROUTER: delete route to %s ", inet_ntoa({target}));
      const auto d = get_remote_desc(router);
      printf("via %s\n", d.c_str());
    }
  }

  return false;
}

/** send_packet:
 * handles the sending of packets to a remote or local (identified by a)
 *
 * @param ent     the ip of the destination
 * @param buffer  the buffer
 * @param buflen  the length of the buffer
 * @ret           written bytes count
 **/
static int send_packet(const uint32_t ent, const char *buffer, const int buflen) {
  if((have_local_ip && ent == local_ip.s_addr) || (ent == htonl(0)))
    return cwrite(local_fd, buffer, buflen);

  struct sockaddr_in dsta;
  memset(&dsta, 0, sizeof(dsta));
  dsta.sin_family = AF_INET;
  dsta.sin_addr.s_addr = ent;
  dsta.sin_port = htons(data_port);
  return csendto(server_fd, buffer, buflen, &dsta);
}

/** set_ip_df
 * sets or unsets the dont-frag bit in the outer ip header
 **/
static void set_ip_df(const struct ip *h_ip) {
  const bool df = h_ip->ip_off & htons(IP_DF);
  const int tmp_df = df ?
#if defined(IP_DONTFRAG)
    1 : 0;
  if(setsockopt(server_fd, IPPROTO_IP, IP_DONTFRAG, &tmp_df, sizeof(tmp_df)) < 0)
    perror("ROUTER WARNING: setsockopt(IP_DONTFRAG) failed");
#elif defined(IP_MTU_DISCOVER)
    IP_PMTUDISC_WANT : IP_PMTUDISC_DONT;
  if(setsockopt(server_fd, IPPROTO_IP, IP_MTU_DISCOVER, &tmp_df, sizeof(tmp_df)) < 0)
    perror("ROUTER WARNING: setsockopt(IP_MTU_DISCOVER) failed");
#else
# warning "set_ip_df: no method available to manage the dont-frag bit"
    0 : 0;
#endif
}

enum zprd_icmpe {
  ZICMPM_TTL, ZICMPM_UNREACH, ZICMPM_UNREACH_NET, ZICMPM_QUENCH
};

static void send_icmp_msg(const zprd_icmpe msg, const struct ip * const orig_hip, const uint32_t source_ip) {
  constexpr const uint16_t buflen = 2 * sizeof(struct ip) + sizeof(struct icmphdr);
  char buffer[buflen];

  struct ip * const h_ip = reinterpret_cast<struct ip*>(buffer);
  struct icmphdr * const h_icmp = reinterpret_cast<struct icmphdr*>(buffer + sizeof(struct ip));

  memset(buffer, 0, buflen);

  h_ip->ip_v   = 4;
  h_ip->ip_hl  = 5;
  h_ip->ip_tos = 0;
  h_ip->ip_len = htons(buflen);
  h_ip->ip_id  = rand();
  h_ip->ip_off = 0;
  h_ip->ip_ttl = 255;
  h_ip->ip_p   = IPPROTO_ICMP;

  h_ip->ip_src = local_ip;
  h_ip->ip_dst = orig_hip->ip_src;
  h_ip->ip_sum = 0;

  h_icmp->code = 0;

  switch(msg) {
    case ZICMPM_TTL:
      h_icmp->type = ICMP_TIMXCEED;
      h_icmp->code = ICMP_TIMXCEED_INTRANS;
      break;

    case ZICMPM_UNREACH:
      h_icmp->type = ICMP_UNREACH;
      h_icmp->code = ICMP_UNREACH_HOST;
      break;

    case ZICMPM_UNREACH_NET:
      h_icmp->type = ICMP_UNREACH;
      h_icmp->code = ICMP_UNREACH_NET;
      break;

    case ZICMPM_QUENCH:
      h_icmp->type = ICMP_SOURCEQUENCH;
      break;

    default:
      printf("SEND ERROR: invalid ZICMP Message code: %d\n", msg);
      exit(1);
  }

  // calculate icmp checksum
  h_icmp->checksum = 0;
  h_icmp->checksum = in_cksum(reinterpret_cast<const uint16_t*>(h_icmp), sizeof(struct icmphdr));

  // setup payload = orig ip header
  memcpy(buffer + sizeof(struct ip) + sizeof(struct icmphdr), orig_hip, sizeof(struct ip));

  // calculate ip checksum
  h_ip->ip_sum = in_cksum(reinterpret_cast<const uint16_t*>(h_ip), sizeof(struct ip));

  // setup outer header
  set_ip_df(h_ip);

  if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &h_ip->ip_tos, sizeof(h_ip->ip_tos)) < 0)
    perror("ROUTER WARNING: setsockopt(IP_TOS) failed");

  send_packet(source_ip, buffer, buflen);
}

/** route_packet:
 *
 * decide which fd is the destination,
 * based on the destination ip and the routing table,
 * decrement the ttl
 *
 * @param source_ip the source peer ip
 * @param buffer    (in/out) packet data
 * @param buflen    length of buffer / packet data
 *                  (often = nread)
 *
 * @ret             the ips of the destination sockets
 **/
static vector<uint32_t> route_packet(const uint32_t source_peer_ip, char buffer[], const uint16_t buflen) {
  // broadcast ip
  const struct in_addr brdcip = { (local_ip.s_addr & local_netmask.s_addr) | (~local_netmask.s_addr) };
  const bool have_brdcip = have_local_ip && have_local_netmask;

  vector<uint32_t> ret;
  const string source_desc = get_remote_desc(source_peer_ip);
  const char * const source_desc_c = source_desc.c_str();

  struct ip *ipheader = reinterpret_cast<struct ip*>(buffer);
  const uint16_t pkid = ntohs(ipheader->ip_id);

  // get packet src/dst ips
  const struct in_addr &ip_src = ipheader->ip_src;
  const struct in_addr &ip_dst = ipheader->ip_dst;

  const bool is_unknown_src = is_broadcast_addr(ip_src) || (have_brdcip && brdcip == ip_src);

  /* is_icmp_errmsg : flag if packet is an icmp error message
   *   reason : an echo packet could be used to establish an route without interference on application protos
   */
  const bool is_icmp_errmsg = (ipheader->ip_p == IPPROTO_ICMP)
    && ([buffer, buflen]() -> bool {
      if((sizeof(struct ip) + sizeof(struct icmphdr) > buflen)) return true;
      struct icmphdr * icmpheader = reinterpret_cast<struct icmphdr*>(buffer + sizeof(ip));
      switch(icmpheader->type) {
        case ICMP_ECHO:      // = 8
        case ICMP_ECHOREPLY: // = 0
        case  9: // Router advert
        case 10: // Router select
        case 13: // timestamp
        case 14: // timestamp reply
          return false;
        default:
          return true;
      }
    })();

  // am I an endpoint
  const bool iam_ep = have_local_ip && (source_peer_ip == local_ip.s_addr || ip_dst == local_ip);

  if(buflen > 2000) {
    // packet is too big
    printf("ROUTER: drop packet %u (too big, size = %u) from %s\n", pkid, buflen, source_desc_c);
    if(!is_unknown_src && !is_icmp_errmsg)
      send_icmp_msg(ZICMPM_QUENCH, ipheader, source_peer_ip);
    return ret;
  }

  // we can use the ttl directly, it is 1 byte long
  if((!ipheader->ip_ttl) || (!iam_ep && ipheader->ip_ttl == 1)) {
    // ttl is too low -> DROP
    printf("ROUTER: drop packet %u (too low ttl = %u) from %s\n", pkid, ipheader->ip_ttl, source_desc_c);
    if(!is_unknown_src && !is_icmp_errmsg)
      send_icmp_msg(ZICMPM_TTL, ipheader, source_peer_ip);
    return ret;
  }

  // check this late (don't register discarded packets)
  // use case : two ways to one destination, merge at destination (or before)
  if(RecentPkts_append(in_hashsum(reinterpret_cast<const uint8_t*>(buffer), buflen))) {
    printf("ROUTER WARNING: drop packet %u (DUP!) from %s\n", pkid, source_desc_c);
    return ret;
  }

  // decrement ttl
  if(!iam_ep) --(ipheader->ip_ttl);

  // update checksum (because we changed the header)
  ipheader->ip_sum = 0;
  ipheader->ip_sum = in_cksum(reinterpret_cast<const uint16_t*>(ipheader), sizeof(struct ip));

  // update routes
  if(!is_unknown_src
    && routes[ip_src.s_addr].add_router(source_peer_ip, 255 - (ipheader->ip_ttl)))
    printf("ROUTER: add route to %s via %s\n", inet_ntoa(ip_src), source_desc_c);

  // is a broadcast needed
  bool is_broadcast = is_broadcast_addr(ip_dst) || (have_brdcip && brdcip == ip_dst);

  if(!is_broadcast) {
    if(have_local_ip
      && ip_dst == local_ip
      && routes[local_ip.s_addr].add_router(local_ip.s_addr, 0))
    {
      printf("ROUTER: add route to %s via local\n", inet_ntoa(ip_dst));
    } else if(routes.find(ip_dst.s_addr) == routes.end()) {
      printf("ROUTER: no known route to %s\n", inet_ntoa(ip_dst));
      is_broadcast = true;
    }
  }

  // get route to destination
  if(is_broadcast) {
    printf("ROUTER: broadcast packet %u from %s\n", pkid, source_desc_c);
    for(auto &&i : remotes)
      ret.emplace_back(i.first);
    ret.emplace_back(local_ip.s_addr);
  } else {
    ret.emplace_back(routes[ip_dst.s_addr].get_router());
  }

  // split horizon
  for(auto it = ret.begin(); it != ret.end();) {
    if(*it == source_peer_ip)
      it = ret.erase(it);
    else
      ++it;
  }

  if(ret.empty()) {
    printf("ROUTER: drop packet %u (no destination) from %s\n", pkid, source_desc_c);
    if(!is_unknown_src && !is_broadcast && !is_icmp_errmsg) {
      if(have_local_netmask && (local_ip.s_addr & local_netmask.s_addr) != (ip_dst.s_addr & local_netmask.s_addr))
        send_icmp_msg(ZICMPM_UNREACH_NET, ipheader, source_peer_ip);
      else
        send_icmp_msg(ZICMPM_UNREACH,     ipheader, source_peer_ip);

      // to prevent routing loops
      // drop routing table entry, if there is any
      auto &route = routes[ip_dst.s_addr];
      const auto router = route.get_router();
      if(route.del_primary_router()) {
        printf("ROUTER: delete route to %s ", inet_ntoa({ip_dst.s_addr}));
        const auto d = get_remote_desc(router);
        printf("via %s\n", d.c_str());
      }
    }
  } else {
    // setup outer headers
    set_ip_df(ipheader);
    if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &ipheader->ip_tos, sizeof(ipheader->ip_tos)) < 0)
      perror("ROUTER WARNING: setsockopt(IP_TOS) failed");
  }

  return ret;
}

static void progress_packet(const struct in_addr &sin_addr, char buffer[], const uint16_t len) {
  remotes[sin_addr.s_addr].refresh();
  for(auto &&dest : route_packet(sin_addr.s_addr, buffer, len)) {
    bool discard = false;

    if((have_local_ip && dest == local_ip.s_addr) || (dest == htonl(0)))
      discard = parse_control_message(sin_addr.s_addr, buffer, len);

    if(!discard)
      send_packet(dest, buffer, len);
  }
}

/** read_ip_packet
 * reads an variable length ipv4 packet
 *
 * @param srca    (out) the source ip
 * @param buffer  (out) the target storage
 * @param len     (out) the length of the packet
 * @ret           succesful marker
 **/
static bool read_ip_packet(struct in_addr &srca, char buffer[], uint16_t &len) {
  struct sockaddr_in source;
  const uint16_t nread = recv_n(server_fd, buffer, BUFSIZE, &source);
  srca = source.sin_addr;

  const string source_desc = get_remote_desc(srca.s_addr);
  const char * const source_desc_c = source_desc.c_str();

  if(sizeof(struct ip) > nread) {
    printf("ROUTER ERROR: invalid ip packet (too small, size = %u) from %s\n", nread, source_desc_c);
    return false;
  }

  const struct ip *const ipheader = reinterpret_cast<struct ip*>(buffer);
  if(ipheader->ip_v != 4) {
    printf("ROUTER ERROR: received a non-ipv4 packet (wrong version = %u) from %s\n", ipheader->ip_v, source_desc_c);
    return false;
  }

  {
    const uint16_t dsum = in_cksum(reinterpret_cast<const uint16_t*>(ipheader), sizeof(struct ip));
    if(dsum) {
      printf("ROUTER ERROR: invalid ipv4 packet (wrong checksum, chksum = %u, d = %u) from %s\n",
             ipheader->ip_sum, dsum, source_desc_c);
      return false;
    }
  }

  // get total length
  len = ntohs(ipheader->ip_len);

  if(nread < len) {
    printf("ROUTER ERROR: can't read whole ipv4 packet (too small, size = %u) from %s\n", nread, source_desc_c);
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  // parse command line
  {
    string confpath = "/etc/zprd.conf";
    for(int i = 0; i < argc; ++i) {
      const string cur = argv[i];
      if(cur.empty()) continue;

      if(cur == "-h" || cur == "--help") {
        puts("USAGE: zprd [--help] [L<logfile>] [C<conffile>]");
        return 0;
      }

      if(cur.front() == 'L') {
        // redirect output to logfile
        const auto lfp = cur.substr(1);
        const int ofd = open(lfp.c_str(), O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
        if(ofd < 0) {
          fprintf(stderr, "ERROR: unable to open logfile '%s'\n", lfp.c_str());
          perror("open()");
          return 1;
        }
        if(dup2(ofd, 1) < 0 || dup2(ofd, 2) < 0) {
          perror("dup2()");
          return 1;
        }
        close(ofd);
        my_signal(SIGHUP, SIG_IGN);
      } else if(cur.front() == 'C') {
        // use another config file
        confpath = cur.substr(1);
      }
    }

    init_all(confpath);
    fflush(stdout);
    fflush(stderr);
  }

  while(1) {
    {
      struct ifreq ifr;
      have_local_ip      = get_local_xxxip_generic(local_ip,      ifr, SIOCGIFADDR,    ifr.ifr_addr);
      have_local_netmask = get_local_xxxip_generic(local_netmask, ifr, SIOCGIFNETMASK, ifr.ifr_netmask);
    }

    if(have_local_ip && !have_local_netmask) {
      printf("ROUTER ERROR: got local ip but no local netmask ip\n");
      exit(1);
    }

    // use select() to handle two descriptors at once
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(local_fd, &rd_set);
    FD_SET(server_fd, &rd_set);
    const int maxfd = (server_fd > local_fd) ? server_fd : local_fd;

    if(select(maxfd + 1, &rd_set, 0, 0, 0) < 0) {
      if(errno == EINTR) continue;
      perror("select()");
      exit(1);
    }

    uint16_t nread;
    char buffer[BUFSIZE];

    if(FD_ISSET(local_fd, &rd_set)) {
      // data from tun/tap: just read it and write it to the network
      nread = cread(local_fd, buffer, BUFSIZE);
      progress_packet(local_ip, buffer, nread);
    }

    if(FD_ISSET(server_fd, &rd_set)) {
      // data from the network: read it, and write it to the tun/tap interface.
      struct in_addr addr;
      if(read_ip_packet(addr, buffer, nread))
        progress_packet(addr, buffer, nread);
    }

    auto del_route_msg = [](const uint32_t addr, const uint32_t router) {
      // discard route
      printf("ROUTER: delete route to %s ", inet_ntoa({addr}));
      const auto d = get_remote_desc(router);
      printf("via %s\n", d.c_str());
    };

    set<size_t> found_remotes;

    for(auto it = remotes.begin(); it != remotes.end();) {
      // skip local, and remotes which aren't timed out
      if(it->first == local_ip.s_addr || !it->second.outdated()) {
        // update found remotes list
        if(it->second.cent != -1)
          found_remotes.emplace(it->second.cent);

        ++it;
        continue;
      }

      for(auto itr = routes.begin(); itr != routes.end();) {
        if(itr->second.del_router(it->first))
          del_route_msg(itr->first, it->first);

        ++itr;
      }

      // discard remote
      it = remotes.erase(it);
    }

    // cleanup routes, needs to be done after del_router calls
    for(auto it = routes.begin(); it != routes.end();) {
      it->second.cleanup([it, del_route_msg](const uint32_t router) {
        del_route_msg(it->first, router);
      });

      if(it->second.empty())
        it = routes.erase(it);
      else
        ++it;
    }

    if(found_remotes.size() < zprd_conf.remotes.size()) {
      struct in_addr remote;
      size_t i = 0;

      // reconnect
      for(auto &&r : zprd_conf.remotes) {
        if(!found_remotes.erase(i) && resolve_hostname(r.c_str(), remote)) {
          remotes[remote.s_addr] = remote_peer_t(i);
          printf("CLIENT: reconnected to server %s\n", inet_ntoa(remote));
        }
        ++i;
      }
    }

    // flush output
    fflush(stdout);
  }

  return 0;
}
