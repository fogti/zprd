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

using namespace std;

/** file descriptors
 *
 * local_fd  = the tun device
 * server_fd = the server udp socket
 **/
static int local_fd, server_fd;

// data port
static uint16_t data_port;

// timeout in seconds after which remotes are silently discarded
static time_t remote_timeout;

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
    return (time(0) - seen) >= remote_timeout;
  }
};

static unordered_map<uint32_t, remote_peer_t> remotes;

struct via_router_t {
  uint32_t addr;
  time_t   seen;
  double   latency;
  uint8_t  hops;

  via_router_t(const uint32_t _addr, const uint8_t _hops)
    : addr(_addr), seen(time(0)), latency(0), hops(_hops) { }
};

struct ping_cache_match {
  double diff;
  uint32_t dst, router;
  bool match;
};

// TODO: handle failure of clock_gettime
class ping_cache_t {
  double _seen;
  uint32_t _src, _dst, _router;
  uint16_t _id, _seq;

  static double get_ms_time() {
    struct timespec curt;
    clock_gettime(CLOCK_MONOTONIC, &curt);
    return curt.tv_sec * 1000 + curt.tv_nsec / 1000000.0;
  }

 public:
  ping_cache_t(): _seen(0), _src(0), _dst(0), _router(0), _id(0), _seq(0) { }

  void clear() {
    _seen = 0;
    _seq  = 0;
  }

  bool empty() const {
    return (!_seen && !_seq);
  }

  void init(const uint32_t src, const uint32_t dst, const uint32_t router, const uint16_t id, const uint16_t seq) {
    _seen   = get_ms_time();
    _src    = src;
    _dst    = dst;
    _router = router;
    _id     = id;
    _seq    = seq;
  }

  ping_cache_match match(const uint32_t src, const uint32_t dst, const uint32_t router, const uint16_t id, const uint16_t seq) {
    if(src == _src && dst == _dst && _router == router && id == _id && seq == _seq) {
      const ping_cache_match ret = { get_ms_time() - _seen, dst, router, true };
      clear();
      return ret;
    } else {
      return { 1, 0, 0, false };
    }
  }
};

static ping_cache_t ping_cache;

// collection of via_route_t's
struct route_via_t {
  std::forward_list<via_router_t> _routers;

  // deletes all outdates routers and sort routers
  template<typename Fn>
  void cleanup(const Fn f) {
    _routers.remove_if(
      [f](const via_router_t &a) {
        if((time(0) - a.seen) < (2 * remote_timeout))
          return false;

        f(a.addr);
        return true;
      }
    );

    _routers.sort(
      // priority high to low: hop count > latency > seen time
      [](const via_router_t &a, const via_router_t &b) {
        if(a.hops    < b.hops) return true;
        if(a.hops    > b.hops) return false;
        if(a.latency < b.latency) return true;
        if(a.latency > b.latency) return false;
        if(a.seen    > b.seen) return true;
        return false;
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
    const auto it_e = _routers.end();
    const auto it = find_if(_routers.begin(), it_e,
      [router](const via_router_t &i) noexcept {
        return i.addr == router;
      }
    );

    const bool ret = (it == it_e);
    if(ret) {
      _routers.emplace_front(router, hops);
    } else {
      it->seen = time(0);
      it->hops = hops;
    }
    return ret;
  }

  void update_latency(const uint32_t router, const double latency) {
    const auto it_e = _routers.end();
    const auto it = find_if(_routers.begin(), it_e,
      [router](const via_router_t &i) noexcept {
        return i.addr == router;
      }
    );
    if(it == it_e) return;
    it->latency = latency;
  }

  bool del_router(const uint32_t router) {
    bool ret = false;
    _routers.remove_if(
      [router, &ret](const via_router_t &a) noexcept -> bool {
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
static bool have_local_ip;

struct {
  string iface;
  vector<string> remotes;
} zprd_conf;

static void init_all(const string &confpath) {
  static const auto runcmd = [](const string &cmd) {
    printf("CONFIG APPLY: %s\n", cmd.c_str());
    if(system(cmd.c_str())) {
      perror("system()");
      exit(1);
    }
  };

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

    // DEFAULTS
    data_port      = 45940; // P45940
    remote_timeout = 900;   // T900
    have_local_ip  = false;

    // is used when we are root and see the 'U' setting in the conf to drop privilegis
    string run_as_user;

    string addr_stmt;

    string line;
    while(getline(in, line)) {
      if(line.empty()) continue;
      const string arg = line.substr(1);
      switch(line.front()) {
        case '#':
          break;

        case 'A':
          addr_stmt = arg;
          break;

        case 'I':
          zprd_conf.iface = arg;
          break;

        case 'P':
          data_port = stoi(arg);
          break;

        case 'R':
          zprd_conf.remotes.emplace_back(arg);
          break;

        case 'T':
          remote_timeout = stoi(arg);
          break;

        case 'U':
          run_as_user = arg;
          break;

        default:
          fprintf(stderr, "CONFIG ERROR: unknown stmt in config file: '%s'\n", line.c_str());
          break;
      }
    }
    in.close();

    if(zprd_conf.iface.empty()) {
      fprintf(stderr, "CONFIG ERROR: no interface specified\n");
      exit(1);
    }

    if(!addr_stmt.empty()) {
      const size_t marker = addr_stmt.find('/');
      const string ip = addr_stmt.substr(0, marker);
      string cidrsf = "32";
      if(marker != string::npos)
        cidrsf = addr_stmt.substr(marker + 1);

      if(!resolve_hostname(ip.c_str(), local_ip)) {
        fprintf(stderr, "CONFIG ERROR: invalid 'A' statement: '%s'\n", line.c_str());
        exit(1);
      }

      local_netmask.s_addr = cidr_to_netmask(stoi(cidrsf));

      runcmd("ip addr flush '" + zprd_conf.iface + "'");
      runcmd("ip addr add '" + addr_stmt + "' dev '" + zprd_conf.iface + "'");
    }

    runcmd("ip link set dev '" + zprd_conf.iface + "' mtu 1472");
    runcmd("ip link set dev '" + zprd_conf.iface + "' up");

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

    printf("connected to interface %s\n", if_name);
  }

  {
    size_t i = 0;
    for(auto &&r : zprd_conf.remotes) {
      struct in_addr remote;
      if(resolve_hostname(r.c_str(), remote)) {
        remotes[remote.s_addr] = remote_peer_t(i);
        printf("CLIENT: connected to server %s\n", inet_ntoa(remote));
      }
      ++i;
    }
  }

  if(remotes.empty() && !zprd_conf.remotes.empty()) {
    puts("CLIENT ERROR: can't connect to any server. QUIT");
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

/** send_packet:
 * handles the sending of packets to a remote or local (identified by a)
 *
 * @param ent     the ip of the destination
 * @param buffer  the buffer
 * @param buflen  the length of the buffer
 * @ret           written bytes count
 **/
static int send_packet(const uint32_t ent, const char *buffer, const int buflen) {
  if((have_local_ip && ent == local_ip.s_addr) || ent == htonl(0))
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
  constexpr const uint16_t buflen = 2 * sizeof(struct ip) + sizeof(struct icmphdr) + 8;
  char buffer[buflen] = { 0 };

  const auto h_ip = reinterpret_cast<struct ip*>(buffer);
  const auto h_icmp = reinterpret_cast<struct icmphdr*>(buffer + sizeof(struct ip));

  h_ip->ip_v   = 4;
  h_ip->ip_hl  = 5;
  h_ip->ip_tos = 0;
  h_ip->ip_len = htons(buflen);
  h_ip->ip_id  = rand();
  h_ip->ip_off = 0;
  h_ip->ip_ttl = MAXTTL;
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

  // setup secondary payload = first 8 bytes of original payload
  {
    const size_t diff = ntohs(orig_hip->ip_len);
    memcpy(buffer + 2 * sizeof(struct ip) + sizeof(struct icmphdr), orig_hip + sizeof(ip), (diff > 8) ? 8 : diff);
  }

  // calculate ip checksum
  h_ip->ip_sum = in_cksum(reinterpret_cast<const uint16_t*>(h_ip), sizeof(struct ip));

  // setup outer header
  set_ip_df(h_ip);

  if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &h_ip->ip_tos, sizeof(h_ip->ip_tos)) < 0)
    perror("ROUTER WARNING: setsockopt(IP_TOS) failed");

  send_packet(source_ip, buffer, buflen);
}

static void apply_ping_cache_match(const ping_cache_match &m) {
  if(!m.match) return;
  const auto rit = routes.find(m.dst);
  if(rit == routes.end()) return;
  auto &route = rit->second;
  route.update_latency(m.router, m.diff);
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
  const string source_desc = get_remote_desc(source_peer_ip);
  const auto source_desc_c = source_desc.c_str();
  const auto h_ip          = reinterpret_cast<struct ip*>(buffer);
  const uint16_t pkid      = ntohs(h_ip->ip_id);
  const bool is_icmp       = (h_ip->ip_p == IPPROTO_ICMP);

  if(is_icmp && (sizeof(struct ip) + sizeof(struct icmphdr)) > buflen) {
    printf("ROUTER: drop packet %u (too small icmp packet; size = %u) from %s\n", pkid, buflen, source_desc_c);
    return {};
  }

  /* is_icmp_errmsg : flag if packet is an icmp error message
   *   reason : an echo packet could be used to establish an route without interference on application protos
   */
  const bool is_icmp_errmsg = is_icmp
    && ([buffer]() -> bool {
      const auto h_icmp = reinterpret_cast<struct icmphdr*>(buffer + sizeof(ip));
      switch(h_icmp->type) {
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

  // broadcast ip
  const struct in_addr brdcip = { (local_ip.s_addr & local_netmask.s_addr) | (~local_netmask.s_addr) };
  const bool have_brdcip      = have_local_ip;

  const auto &ip_src          = h_ip->ip_src;
  const auto &ip_dst          = h_ip->ip_dst;

  const bool is_unknown_src   = is_broadcast_addr(ip_src) || (have_brdcip && brdcip == ip_src);

  if(buflen > 2000) {
    printf("ROUTER: drop packet %u (too big, size = %u) from %s\n", pkid, buflen, source_desc_c);
    if(!is_unknown_src && !is_icmp_errmsg)
      send_icmp_msg(ZICMPM_QUENCH, h_ip, source_peer_ip);
    return {};
  }

  // am I an endpoint
  const bool iam_ep = have_local_ip && (source_peer_ip == local_ip.s_addr || ip_dst == local_ip);

  // we can use the ttl directly, it is 1 byte long
  if((!h_ip->ip_ttl) || (!iam_ep && h_ip->ip_ttl == 1)) {
    // ttl is too low -> DROP
    printf("ROUTER: drop packet %u (too low ttl = %u) from %s\n", pkid, h_ip->ip_ttl, source_desc_c);
    if(!is_unknown_src && !is_icmp_errmsg)
      send_icmp_msg(ZICMPM_TTL, h_ip, source_peer_ip);
    return {};
  }

  // check this late (don't register discarded packets)
  // use case : two ways to one destination, merge at destination (or before)
  if(RecentPkts_append(in_hashsum(reinterpret_cast<const uint8_t*>(buffer), buflen))) {
    printf("ROUTER WARNING: drop packet %u (DUP!) from %s\n", pkid, source_desc_c);
    return {};
  }

  // decrement ttl
  if(!iam_ep) --(h_ip->ip_ttl);

  // update checksum (because we changed the header)
  h_ip->ip_sum = 0;
  h_ip->ip_sum = in_cksum(reinterpret_cast<const uint16_t*>(h_ip), sizeof(struct ip));

  // update routes
  if(!is_unknown_src) {
    if(have_local_ip && local_ip.s_addr == ip_src.s_addr) {
      if(routes[local_ip.s_addr].add_router(local_ip.s_addr, 0))
        printf("ROUTER: add route to %s via local\n", inet_ntoa(ip_src));
    } else if(routes[ip_src.s_addr].add_router(source_peer_ip, MAXTTL - h_ip->ip_ttl)) {
      printf("ROUTER: add route to %s via %s\n", inet_ntoa(ip_src), source_desc_c);
    }
  }

  // is a broadcast needed
  const bool broadcast_is_dst = is_broadcast_addr(ip_dst) || (have_brdcip && brdcip == ip_dst);
  bool is_broadcast = broadcast_is_dst;

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
  vector<uint32_t> ret;

  if(is_broadcast) {
    for(auto &&i : remotes)
      ret.emplace_back(i.first);
    ret.emplace_back(local_ip.s_addr);
  } else {
    ret.emplace_back(routes[ip_dst.s_addr].get_router());
  }

  const bool netmask_match = have_local_ip && (local_ip.s_addr & local_netmask.s_addr) == (ip_dst.s_addr & local_netmask.s_addr);

  { // split horizon
    auto it_e = ret.end();
    ret.erase(std::remove(ret.begin(), it_e, source_peer_ip), it_e);

    if(!broadcast_is_dst && netmask_match && ip_dst != local_ip) {
      // catch bouncing packets in *local iface* network earlier
      it_e = ret.end();
      ret.erase(std::remove(ret.begin(), it_e, local_ip.s_addr), it_e);
    }
  }

  if(ret.empty()) {
    printf("ROUTER: drop packet %u (no destination) from %s\n", pkid, source_desc_c);
    if(!is_unknown_src && !broadcast_is_dst && !is_icmp_errmsg) {
      if(netmask_match)
        send_icmp_msg(ZICMPM_UNREACH,     h_ip, source_peer_ip);
      else
        send_icmp_msg(ZICMPM_UNREACH_NET, h_ip, source_peer_ip);

      // to prevent routing loops
      // drop routing table entry, if there is any
      auto &route = routes[ip_dst.s_addr];
      const auto router = route.get_router();
      if(route.del_primary_router()) {
        printf("ROUTER: delete route to %s ", inet_ntoa(ip_dst));
        const auto d = get_remote_desc(router);
        printf("via %s\n", d.c_str());
      }
    }
  } else {
    if(is_icmp) {
      const auto h_icmp = reinterpret_cast<const struct icmphdr*>(buffer + sizeof(ip));
      if(is_icmp_errmsg && ((2 * sizeof(struct ip) + sizeof(struct icmphdr)) <= buflen)) {
        // drop outdated routing table entries
        bool rm_route = false;
        switch(h_icmp->type) {
          case ICMP_TIMXCEED:
            if(h_icmp->code == ICMP_TIMXCEED_INTRANS) rm_route = true;
            break;

          case ICMP_UNREACH:
            switch(h_icmp->code) {
              case ICMP_UNREACH_HOST:
              case ICMP_UNREACH_NET:
                rm_route = true;
                break;
            }
            break;
        }
        if(rm_route) {
          // drop routing table entry, if there is any
          const auto h_ip2 = reinterpret_cast<const struct ip*>(buffer + sizeof(struct ip) + sizeof(struct icmphdr));
          const auto target = h_ip2->ip_dst; // original destination
          const auto rit = routes.find(target.s_addr);
          if(rit != routes.end() && !rit->second.empty()) {
            auto &route = rit->second;
            if(route.del_router(source_peer_ip)) {
              // routing table entry dropped
              printf("ROUTER: delete route to %s ", inet_ntoa(target));
              const auto d = get_remote_desc(source_peer_ip);
              printf("via %s\n", d.c_str());
            }
            // if there is a routing table entry left -> discard
            if(!route.empty()) ret.clear();
          }
        }
      } else if(!is_unknown_src && !is_broadcast) {
        /** evaluate ping packets to determine the latency of this route
         *  echoreply : source and destination are swapped
         **/
        const auto &echo = h_icmp->un.echo;
        switch(h_icmp->type) {
          case ICMP_ECHO:
            ping_cache.init(ip_src.s_addr, ip_dst.s_addr, ret.front(), echo.id, echo.sequence);
            break;

          case ICMP_ECHOREPLY:
            if(!ping_cache.empty())
              apply_ping_cache_match(ping_cache.match(ip_dst.s_addr, ip_src.s_addr, source_peer_ip, echo.id, echo.sequence));
            break;
        }
      }
    }

    if(!ret.empty()) {
      // setup outer headers
      set_ip_df(h_ip);
      if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &h_ip->ip_tos, sizeof(h_ip->ip_tos)) < 0)
        perror("ROUTER WARNING: setsockopt(IP_TOS) failed");
    }
  }

  return ret;
}

static void progress_packet(const struct in_addr &sin_addr, char buffer[], const uint16_t len) {
  remotes[sin_addr.s_addr].refresh();
  for(auto &&dest : route_packet(sin_addr.s_addr, buffer, len))
    send_packet(dest, buffer, len);
}

/** is_ipv4_packet
 * checks, if packet is a valid ipv4 packet
 *
 * @param buffer  the packet data
 * @param len     the length of the packet
 * @ret           is valid
 **/
static bool is_ipv4_packet(const char * const source_desc_c, const char buffer[], const uint16_t len) {
  if(sizeof(struct ip) > len) {
    printf("ROUTER ERROR: received invalid ip packet (too small, size = %u) from %s\n", len, source_desc_c);
    return false;
  }

  const auto h_ip = reinterpret_cast<const struct ip*>(buffer);
  if(h_ip->ip_v != 4) {
    printf("ROUTER ERROR: received a non-ipv4 packet (wrong version = %u) from %s\n", h_ip->ip_v, source_desc_c);
    return false;
  }

  const uint16_t dsum = in_cksum(reinterpret_cast<const uint16_t*>(h_ip), sizeof(struct ip));
  if(dsum) {
    printf("ROUTER ERROR: invalid ipv4 packet (wrong checksum, chksum = %u, d = %u) from %s\n",
           h_ip->ip_sum, dsum, source_desc_c);
    return false;
  }

  return true;
}

/** read_ip_packet
 * reads an variable length ipv4 packet
 *
 * @param srca    (out) the source ip
 * @param buffer  (out) the target storage (with size BUFSIZE)
 * @param len     (out) the length of the packet
 * @ret           succesful marker
 **/
static bool read_ip_packet(struct in_addr &srca, char buffer[], uint16_t &len) {
  struct sockaddr_in source;
  const uint16_t nread = recv_n(server_fd, buffer, BUFSIZE, &source);
  srca = source.sin_addr;

  const string source_desc = get_remote_desc(srca.s_addr);
  const char * const source_desc_c = source_desc.c_str();

  if(!is_ipv4_packet(source_desc_c, buffer, nread)) return false;

  const auto h_ip = reinterpret_cast<const struct ip*>(buffer);

  // get total length
  len = ntohs(h_ip->ip_len);

  if(nread < len) {
    printf("ROUTER ERROR: can't read whole ipv4 packet (too small, size = %u) from %s\n", nread, source_desc_c);
    return false;
  }

  if(have_local_ip && h_ip->ip_src == local_ip) {
    printf("ROUTER WARNING: drop packet %u (looped with local as source)\n", ntohs(h_ip->ip_id));
    return false;
  }

  return true;
}

static string format_time(const time_t x) {
  char buffer[10];
  const struct tm *const tmi = localtime(&x);
  strftime(buffer, 10, "%H:%M:%S", tmi);
  return buffer;
}

static void print_routing_table(int) {
  puts("-- connected peers:");
  puts("Peer\t\tSeen\t\tConfig Entry");
  {
    for(auto &&i: remotes) {
      const string seen = format_time(i.second.seen);
      printf("%s\t%s\t", inet_ntoa({i.first}), seen.c_str());
      if(i.second.cent < 0) putchar('-');
      else if(i.second.cent >= zprd_conf.remotes.size()) printf("####");
      else printf("%s", zprd_conf.remotes[i.second.cent].c_str());
      puts("");
    }
  }
  puts("-- routing table:");
  puts("Destination\tGateway\t\tSeen\t\tLatency\tHops");
  for(auto &&i: routes) {
    const string dest = inet_ntoa({i.first});
    for(auto &&r: i.second._routers) {
      const string gateway = inet_ntoa({r.addr});
      const string seen = format_time(r.seen);
      printf("%s\t%s\t%s\t%4.2f\t%u\n", dest.c_str(), gateway.c_str(), seen.c_str(), r.latency, static_cast<unsigned>(r.hops));
    }
  }
  fflush(stdout);
}

int main(int argc, char *argv[]) {
  { // parse command line
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
    my_signal(SIGUSR1, print_routing_table);
    fflush(stdout);
    fflush(stderr);
  }

  {
    struct ifreq ifr;
    have_local_ip      = get_local_xxxip_generic(local_ip,      ifr, SIOCGIFADDR,    ifr.ifr_addr);
    bool have_local_netmask = get_local_xxxip_generic(local_netmask, ifr, SIOCGIFNETMASK, ifr.ifr_netmask);

    if(have_local_ip && !have_local_netmask) {
      puts("ROUTER ERROR: got local ip but no local netmask ip");
      exit(1);
    }
  }

  while(1) {
    { // use select() to handle two descriptors at once
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
        if(is_ipv4_packet("local", buffer, nread))
          progress_packet(local_ip, buffer, nread);
      }

      if(FD_ISSET(server_fd, &rd_set)) {
        // data from the network: read it, and write it to the tun/tap interface.
        struct in_addr addr;
        if(read_ip_packet(addr, buffer, nread))
          progress_packet(addr, buffer, nread);
      }
    }

    auto del_route_msg = [](const uint32_t addr, const uint32_t router) {
      // discard route
      printf("ROUTER: delete route to %s ", inet_ntoa({addr}));
      const auto d = get_remote_desc(router);
      printf("via %s\n", d.c_str());
    };

    set<size_t> found_remotes;

    for(auto it = remotes.cbegin(); it != remotes.cend();) {
      // skip local, and remotes which aren't timed out
      if(it->first == local_ip.s_addr || !it->second.outdated()) {
        // update found remotes list
        if(it->second.cent != -1)
          found_remotes.emplace(it->second.cent);

        ++it;
        continue;
      }

      for(auto &r: routes)
        if(r.second.del_router(it->first))
          del_route_msg(r.first, it->first);

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
      size_t i = 0;

      // reconnect
      for(auto &&r : zprd_conf.remotes) {
        struct in_addr remote;
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
