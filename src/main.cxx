/**
 * zprd / main.cxx
 *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap
 * interfaces and UDP.
 *
 * (C) 2010 Davide Brini.
 * (C) 2017 - 2018 Erik Zscheile.
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
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>

// C++
#include <atomic>
#include <forward_list>
#include <tuple>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <utility>

// 3rdparty
#include <ThreadPool.h>

// own parts
#include "addr.hpp"
#include "cksum.h"
#include "crw.h"
#include "ping_cache.hpp"
#include "recentpkts.hpp"
#include "remote_peer.hpp"
#include "resolve.hpp"
#include "zprd_conf.hpp"
#include "zprn.hpp"
#include "zsig.h"

// buffer for reading from tun/tap interface, must be greater than 1500
#define BUFSIZE 65536

using namespace std;

zprd_conf_t zprd_conf;

struct via_router_t final {
  uint32_t addr;
  time_t   seen;
  double   latency;
  uint8_t  hops;

  via_router_t(const uint32_t _addr, const uint8_t _hops)
    : addr(_addr), seen(time(0)), latency(0), hops(_hops) { }
};

// collection of via_route_t's
struct route_via_t final {
  std::forward_list<via_router_t> _routers;
  bool _fresh_add;

  route_via_t(): _fresh_add(false) { }

  // deletes all outdates routers and sort routers
  template<typename Fn>
  void cleanup(const Fn f) {
    const auto ct = time(0) - 2 * zprd_conf.remote_timeout;
    _routers.remove_if(
      [ct,f](const via_router_t &a) {
        if(ct < a.seen) return false;
        f(a.addr);
        return true;
      }
    );

    _routers.sort(
      // priority high to low: hop count > latency > seen time
      [](const via_router_t &a, const via_router_t &b) noexcept {
        return tie(a.hops, a.latency, b.seen) < tie(b.hops, b.latency, a.seen);
      }
    );
  }

  bool empty() const noexcept {
    return _routers.empty();
  }

  uint32_t get_router() const noexcept {
    return empty() ? htonl(INADDR_ANY) : _routers.front().addr;
  }

  // add or modify a router
  bool add_router(const uint32_t router, const uint8_t hops) {
    if(empty()) _fresh_add = true;

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

  void update_router(const uint32_t router, const uint8_t hops, const double latency) noexcept {
    const auto it = find_if(_routers.begin(), _routers.end(),
      [router](const via_router_t &i) noexcept {
        return i.addr == router;
      }
    );
    if(it == _routers.end()) return;
    it->seen = time(0);
    it->hops = hops;
    it->latency = latency;
  }

  /** replace_router:
   *
   * invariant: rold != rnew
   * timing:
   *  base:             n (all routers except if we reach both rold + rnew before)
   *  if o + n found:  +n
   *
   * @param rold, rnew   old and new router addr
   **/
  void replace_router(const uint32_t rold, const uint32_t rnew) {
    const auto it_e = _routers.end();
    auto it_ob = it_e; // (iterator to old router) - 1
    bool nf = true;    // new router not found?

    for(auto it = _routers.begin(), itb = _routers.before_begin(); it != it_e; ++it, ++itb) {
      if(it->addr == rold)
        it_ob = itb;
      else if(it->addr == rnew)
        nf = false;
      else
        continue;

      if(!(nf || it_ob == it_e))
        break;
    }

    if(it_ob == it_e) {
      // found [!o ?n]
    } else if(nf) {
      // found [o !n]
      ++it_ob;
      it_ob->addr = rnew;
    } else {
      // found [o n]
      _routers.erase_after(it_ob);
    }
  }

  bool del_router(const uint32_t router) noexcept {
    bool ret = false;
    _routers.remove_if(
      [router, &ret](const via_router_t &a) noexcept -> bool {
        const bool tmp = (router == a.addr);
        ret |= tmp;
        return tmp;
      }
    );
    return ret;
  }

  bool del_primary_router() noexcept {
    if(!empty()) _routers.pop_front();
    return empty();
  }
};

struct negative_route final {
  uint32_t former_router;
};

struct send_data final {
  vector<char> buffer;
  vector<uint32_t> rdests;
  uint8_t frag, tos;
  bool islcldest;

  send_data() noexcept
    : frag(0), tos(0), islcldest(false) { }
};

class sender_t final {
  queue<send_data> _tasks;
  struct sockaddr_in _dstab;

  // sync
  mutex _mtx;
  condition_variable _cond;
  bool _stop;

  // thread (should come last)
  thread _worker;

  void handle_data(const send_data &dat) const noexcept;
  void worker_fn() noexcept;

 public:
  sender_t();
  ~sender_t() noexcept { stop(); }

  void enqueue(send_data &&dat);
  void stop() noexcept;
};

/*** global vars ***/

/** file descriptors
 *
 * local_fd  = the tun device
 * server_fd = the server udp socket
 **/
static int local_fd, server_fd;

// make sure that there are at least 1 normal worker thread + 1 send thread
static ThreadPool threadpool(std::max(2u, thread::hardware_concurrency()) - 1);
static sender_t sender;

static unordered_map<uint32_t, remote_peer_t>  remotes;
static unordered_map<uint32_t, route_via_t>    routes;
static unordered_map<uint32_t, negative_route> neg_routes;
static ping_cache_t ping_cache;

static in_addr local_ip, local_netmask;
static bool have_local_ip;

static bool init_all(const string &confpath) {
  static const auto runcmd_fn = [](const string &cmd) -> bool {
    if(system(cmd.c_str())) {
      printf("CONFIG APPLY ERROR: %s\n", cmd.c_str());
      perror("system()");
      return false;
    }
    return true;
  };

#define runcmd(X) do { const auto rcf_ret = runcmd_fn(X); if(!rcf_ret) return false; } while(0)

  // redirect stdin (don't block terminals)
  {
    const int ofd = open("/dev/null", O_RDONLY);
    if(ofd < 0) {
      fprintf(stderr, "ERROR: unable to open nullfile '/dev/null'\n");
      perror("open()");
      return false;
    }
    if(dup2(ofd, 0)) {
      perror("dup2()");
      return false;
    }
    close(ofd);
  }

  // read config
  {
    ifstream in(confpath.c_str());
    if(!in) {
      fprintf(stderr, "ERROR: unable to open config file '%s'\n", confpath.c_str());
      return false;
    }

    // DEFAULTS
    zprd_conf.data_port      = 45940; // P45940
    zprd_conf.remote_timeout = 600;   // T600   = 10 min
    local_ip.s_addr          = htonl(0);
    have_local_ip            = false;

    // is used when we are root and see the 'U' setting in the conf to drop privilegis
    string run_as_user;

    string addr_stmt, line;
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
          zprd_conf.data_port = stoi(arg);
          break;

        case 'R':
          zprd_conf.remotes.push_back(arg);
          break;

        case 'T':
          zprd_conf.remote_timeout = stoi(arg);
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
      return false;
    }

    if(!addr_stmt.empty()) {
      const size_t marker = addr_stmt.find('/');
      const string ip = addr_stmt.substr(0, marker);
      string cidrsf = "32";
      if(marker != string::npos)
        cidrsf = addr_stmt.substr(marker + 1);

      if(!resolve_hostname(ip.c_str(), local_ip)) {
        fprintf(stderr, "CONFIG ERROR: invalid 'A' statement: 'A%s'\n", addr_stmt.c_str());
        return false;
      }

      have_local_ip = true;
      local_netmask.s_addr = cidr_to_netmask(stoi(cidrsf));

      runcmd("ip addr flush '" + zprd_conf.iface + "'");
      runcmd("ip addr add '" + addr_stmt + "' dev '" + zprd_conf.iface + "'");
    }

    runcmd("ip link set dev '" + zprd_conf.iface + "' mtu 1472");
    runcmd("ip link set dev '" + zprd_conf.iface + "' up");

# undef runcmd

    if(!run_as_user.empty()) {
      printf("running daemon as user: '%s'\n", run_as_user.c_str());

      // NOTE: we don't need to use getpwnam_r because this function is always
      //  called before threads are spawned
      struct passwd *pwresult = getpwnam(run_as_user.c_str());

      if(!pwresult) {
        perror("STARTUP ERROR: getpwnam() failed");
        return false;
      }

      if(setuid(pwresult->pw_uid) < 0) {
        perror("STARTUP ERROR: setuid() failed");
        return false;
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
      return false;
    }
    zprd_conf.iface = if_name;

    printf("connected to interface %s\n", if_name);
  }

  {
    size_t i = 0;
    for(const auto &r : zprd_conf.remotes) {
      struct in_addr remote;
      if(resolve_hostname(r.c_str(), remote)) {
        remotes[remote.s_addr] = {i};
        printf("CLIENT: connected to server %s\n", inet_ntoa(remote));
      }
      ++i;
    }
  }

  if(remotes.empty() && !zprd_conf.remotes.empty()) {
    puts("CLIENT ERROR: can't connect to any server. QUIT");
    return false;
  }

  // prepare server
  if( (server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    return false;
  }

  // avoid EADDRINUSE error on bind()
  int optval = 1;
  if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }

  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(zprd_conf.data_port);
  if(bind(server_fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
    perror("bind()");
    return false;
  }
  return true;
}

static route_via_t* have_route(const uint32_t dsta) noexcept {
  const auto it = routes.find(dsta);
  return (
    (it == routes.end() || it->second.empty())
      ? 0 : &(it->second)
  );
}

static void ping_cache_match_apply_fn(const ping_cache_t::match_t &m) noexcept {
  if(const auto r = have_route(m.dst))
    r->update_router(m.router, m.hops, m.diff);
}

// get_remote_desc: returns a description string of socket ip
static string get_remote_desc(const uint32_t addr) {
  return (addr == local_ip.s_addr)
         ? string("local")
         : (string("peer ") + inet_ntoa({addr}));
}

/** binary_find:
 * a simple binary search function
 **/
template<class TCont, class T>
auto binary_find(TCont &c, const T &value) noexcept -> typename TCont::iterator {
  const auto it = lower_bound(c.begin(), c.end(), value);
  return (it != c.end() && *it == value) ? it : c.end();
}

/** uniquify:
 * make all elems in a container unique
 **/
template<class TCont>
void uniquify(TCont &c) {
  std::sort(c.begin(), c.end());
  c.erase(std::unique(c.begin(), c.end()), c.end());
}

/** set_ip_df
 * sets or unsets the dont-frag bit in the outer ip header
 **/
static void set_ip_df(const uint8_t frag) noexcept {
  const bool df = frag & htons(IP_DF);
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

void sender_t::handle_data(const send_data &dat) const noexcept {
  // setup outer header
  set_ip_df(dat.frag);

  if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &dat.tos, 1) < 0)
    perror("ROUTER WARNING: setsockopt(IP_TOS) failed");

  // send data
  if(dat.islcldest)
    cwrite(local_fd, dat.buffer.data(), dat.buffer.size());

  struct sockaddr_in dsta = _dstab;
  for(const auto &i : dat.rdests) {
    dsta.sin_addr.s_addr = i;
    csendto(server_fd, dat.buffer.data(), dat.buffer.size(), &dsta);
  }
}

void sender_t::worker_fn() noexcept {
  send_data dat;
  while(1) {
    {
      unique_lock<mutex> lock(_mtx);
      _cond.wait(lock, [this] { return _stop || !_tasks.empty(); });
      if(_stop || _tasks.empty()) return;
      dat = std::move(_tasks.front());
      _tasks.pop();
    }

    handle_data(dat);
  }
}

sender_t::sender_t()
  : _stop(false), _worker(&sender_t::worker_fn, this)
{
  memset(&_dstab, 0, sizeof(_dstab));
  _dstab.sin_family = AF_INET;
  _dstab.sin_port   = htons(zprd_conf.data_port);
}

void sender_t::enqueue(send_data &&dat) {
  {
    lock_guard<mutex> lock(_mtx);

    if(_stop)
      handle_data(dat);
    else
      _tasks.emplace(std::move(dat));
  }
  _cond.notify_one();
}

void sender_t::stop() noexcept {
  {
    lock_guard<mutex> lock(_mtx);
    if(_stop) return;
    _stop = true;
  }
  _cond.notify_all();
  _worker.join();
}

enum zprd_icmpe {
  ZICMPM_TTL, ZICMPM_UNREACH, ZICMPM_UNREACH_NET
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
  h_icmp->checksum = 0;

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

    default:
      printf("SEND ERROR: invalid ZICMP Message code: %d\n", msg);
      exit(1);
  }

  // calculate icmp checksum
  auto fut_icmp_sum = threadpool.enqueue([h_icmp] { return IN_CKSUM(h_icmp); });

  // calculate ip checksum
  auto fut_ip_sum = threadpool.enqueue([h_ip] { return IN_CKSUM(h_ip); });

  // setup payload = orig ip header
  memcpy(buffer + sizeof(struct ip) + sizeof(struct icmphdr), orig_hip, sizeof(struct ip));

  // setup secondary payload = first 8 bytes of original payload
  memcpy(buffer + 2 * sizeof(struct ip) + sizeof(struct icmphdr),
         orig_hip + sizeof(ip),
         std::min(static_cast<unsigned short>(8), ntohs(orig_hip->ip_len)));

  h_icmp->checksum = fut_icmp_sum.get();
  h_ip->ip_sum     = fut_ip_sum.get();

  send_data dat;
  dat.buffer.assign(buffer, buffer + buflen);
  if(source_ip == local_ip.s_addr)
    dat.islcldest = true;
  else
    dat.rdests = {source_ip};
  sender.enqueue(move(dat));
}

static void send_zprn_msg(const zprn &msg) {
  vector<uint32_t> peers;
  peers.reserve(remotes.size());
  for(const auto &i: remotes) peers.push_back(i.first);

  const auto rem_peer = [&peers](const uint32_t peer) {
    peers.erase(std::remove(peers.begin(), peers.end(), peer), peers.end());
  };

  // filter local tun interface
  rem_peer(local_ip.s_addr);

  // split horizon
  if(msg.zprn_cmd == ZPRN_ROUTEMOD) {
    if(msg.zprn_prio == ZPRN_ROUTEMOD_DELETE) {
      const auto it = neg_routes.find(msg.zprn_un.route.dsta);
      if(it != neg_routes.end()) {
        rem_peer(it->second.former_router);
        neg_routes.erase(it);
      }
    } else if(const auto r = have_route(msg.zprn_un.route.dsta)) {
      rem_peer(r->get_router());
    }
  }

  send_data dat;
  const auto msgptr = reinterpret_cast<const char *>(&msg);
  dat.buffer.assign(msgptr, msgptr + sizeof(msg));
  dat.rdests = move(peers);
  sender.enqueue(move(dat));
}

/** route_packet:
 *
 * decide which socket is the destination,
 * based on the destination ip and the routing table,
 * decrement the ttl, send the packet
 *
 * @param source_ip the source peer ip
 * @param buffer    (in/out) packet data
 * @param buflen    length of buffer / packet data
 *                  (often = nread)
 *
 * @do              send packets to the destination sockets
 * @ret             none
 **/
static void route_packet(const uint32_t source_peer_ip, char buffer[], const uint16_t buflen) {
  remotes[source_peer_ip].refresh();

  const string source_desc = get_remote_desc(source_peer_ip);
  const auto source_desc_c = source_desc.c_str();
  const auto h_ip          = reinterpret_cast<struct ip*>(buffer);
  const auto pkid          = ntohs(h_ip->ip_id);
  const bool is_icmp       = (h_ip->ip_p == IPPROTO_ICMP);

  if(is_icmp && (sizeof(struct ip) + sizeof(struct icmphdr)) > buflen) {
    printf("ROUTER: drop packet %u (too small icmp packet; size = %u) from %s\n", pkid, buflen, source_desc_c);
    return;
  }

  /* is_icmp_errmsg : flag if packet is an icmp error message
   *   reason : an echo packet could be used to establish an route without interference on application protos
   */
  const bool is_icmp_errmsg = is_icmp && ([buffer] {
    switch(reinterpret_cast<struct icmphdr*>(buffer + sizeof(ip))->type) {
      case ICMP_ECHOREPLY: // = 0
      case ICMP_ECHO:      // = 8
      case  9: // Router advert
      case 10: // Router select
      case 13: // timestamp
      case 14: // timestamp reply
        return false;
      default:
        return true;
    }
  })();

  const auto &ip_src = h_ip->ip_src;
  const auto &ip_dst = h_ip->ip_dst;

  // am I an endpoint
  const bool iam_ep = have_local_ip && (source_peer_ip == local_ip.s_addr || ip_dst == local_ip);

  // we can use the ttl directly, it is 1 byte long
  if((!h_ip->ip_ttl) || (!iam_ep && h_ip->ip_ttl == 1)) {
    // ttl is too low -> DROP
    printf("ROUTER: drop packet %u (too low ttl = %u) from %s\n", pkid, h_ip->ip_ttl, source_desc_c);
    if(!is_icmp_errmsg)
      send_icmp_msg(ZICMPM_TTL, h_ip, source_peer_ip);
    return;
  }

  // decrement ttl
  if(!iam_ep) --(h_ip->ip_ttl);

  // check this late (don't register discarded packets)
  // use case : two ways to one destination, merge at destination (or before)
  // check this parallel, as most packets aren't DUPs
  // NOTE: make sure that no changes are done to buffer
  h_ip->ip_sum = 0;
  auto fut_rctpka = threadpool.enqueue([buffer, buflen] {
    return RecentPkts_append(reinterpret_cast<const uint8_t*>(buffer), buflen);
  });

  // update checksum (because we changed the header)
  auto fut_ip_sum = threadpool.enqueue([h_ip] { return IN_CKSUM(h_ip); });

  // update routes
  if(routes[ip_src.s_addr].add_router(
      source_peer_ip,
      (have_local_ip && local_ip.s_addr == ip_src.s_addr) ? 0 : (MAXTTL - h_ip->ip_ttl)
  ))
    printf("ROUTER: add route to %s via %s\n", inet_ntoa(ip_src), source_desc_c);

  // is a broadcast needed
  bool is_broadcast = false;

  if(have_local_ip && ip_dst == local_ip) {
    if(routes[local_ip.s_addr].add_router(local_ip.s_addr, 0))
      printf("ROUTER: add route to %s via local\n", inet_ntoa(ip_dst));
  } else if(routes.find(ip_dst.s_addr) == routes.end()) {
    printf("ROUTER: no known route to %s\n", inet_ntoa(ip_dst));
    is_broadcast = true;
  }

  if(fut_rctpka.get()) {
    printf("ROUTER WARNING: drop packet %u (DUP!) from %s\n", pkid, source_desc_c);
    return;
  }

  // get route to destination
  vector<uint32_t> ret;
  if(is_broadcast) {
    ret.reserve(remotes.size() + 1);
    for(const auto &i : remotes) ret.push_back(i.first);
    ret.push_back(local_ip.s_addr);
    uniquify(ret);
  } else {
    ret.emplace_back(routes[ip_dst.s_addr].get_router());
  }

  // function to filter a peer
  const auto rem_peer = [&ret](const uint32_t addr) {
    const auto it = binary_find(ret, addr);
    if(it != ret.end()) ret.erase(it);
  };

  // split horizon
  rem_peer(source_peer_ip);

  // catch bouncing packets in *local iface* network earlier
  if(!iam_ep) rem_peer(local_ip.s_addr);

  // fetch chksum before possible send_icmp_msg
  h_ip->ip_sum = fut_ip_sum.get();

  if(ret.empty()) {
    printf("ROUTER: drop packet %u (no destination) from %s\n", pkid, source_desc_c);
    if(!is_icmp_errmsg) {
      send_icmp_msg((
        (have_local_ip && (local_ip.s_addr & local_netmask.s_addr) == (ip_dst.s_addr & local_netmask.s_addr))
          ? ZICMPM_UNREACH : ZICMPM_UNREACH_NET
      ), h_ip, source_peer_ip);

      // to prevent routing loops
      // drop routing table entry, if there is any
      auto &route = routes[ip_dst.s_addr];
      const auto router = route.get_router();
      if(route.del_primary_router()) {
        printf("ROUTER: delete route to %s via ", inet_ntoa(ip_dst));
        const auto d = get_remote_desc(router);
        printf("%s (invalid)\n", d.c_str());
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
              default: break;
            }
            break;

          default: break;
        }
        if(rm_route) {
          // drop routing table entry, if there is any
          //  target = original destination
          const auto target = reinterpret_cast<const struct ip*>(buffer +
                              sizeof(struct ip) + sizeof(struct icmphdr))->ip_dst;
          if(const auto r = have_route(target.s_addr)) {
            if(r->del_router(source_peer_ip)) {
              // routing table entry dropped
              printf("ROUTER: delete route to %s via %s (unreachable)\n", inet_ntoa(target), source_desc_c);
            }
            // if there is a routing table entry left -> discard
            if(!r->empty()) ret.clear();
          }
        }
      } else if(!is_broadcast) {
        /** evaluate ping packets to determine the latency of this route
         *  echoreply : source and destination are swapped
         **/
        const auto &echo = h_icmp->un.echo;
        const ping_cache_t::data_t edat(ip_src.s_addr, ip_dst.s_addr, echo.id, echo.sequence);
        switch(h_icmp->type) {
          case ICMP_ECHO:
            ping_cache.init(edat, ret.front());
            break;

          case ICMP_ECHOREPLY:
            ping_cache.match(edat, source_peer_ip, h_ip->ip_ttl).apply();
            break;

          default: break;
        }
      }
    }

    if(!ret.empty()) {
      send_data dat;
      dat.buffer.assign(buffer, buffer + buflen);
      dat.frag = h_ip->ip_off;
      dat.tos  = h_ip->ip_tos;

      if(iam_ep) {
        const auto it = binary_find(ret, local_ip.s_addr);
        if(it != ret.end()) {
          ret.erase(it);
          dat.islcldest = true;
        }
      }
      dat.rdests = move(ret);
      sender.enqueue(move(dat));
    }
  }
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

  if(const uint16_t dsum = IN_CKSUM(h_ip)) {
    printf("ROUTER ERROR: invalid ipv4 packet (wrong checksum, chksum = %u, d = %u) from %s\n",
           h_ip->ip_sum, dsum, source_desc_c);
    return false;
  }

  return true;
}

/** is_zprn_packet
 * checks, if packet is a valid ZPRN packet
 *
 * @param buffer  the packet data
 * @param len     the length of the packet
 * @ret           is valid
 **/
inline bool is_zprn_packet(const char * const source_desc_c, const char buffer[], const uint16_t len) noexcept {
  return (sizeof(struct zprn) <= len) && reinterpret_cast<const zprn*>(buffer)->valid();
}

/** read_packet
 * reads an variable length ipv4 packet
 *
 * @param srca    (out) the source ip
 * @param buffer  (out) the target storage (with size BUFSIZE)
 * @param len     (out) the length of the packet
 * @ret           succesful marker
 **/
static bool read_packet(struct in_addr &srca, char buffer[], uint16_t &len) {
  struct sockaddr_in source;
  const uint16_t nread = recv_n(server_fd, buffer, BUFSIZE, &source);
  srca = source.sin_addr;

  const string source_desc = get_remote_desc(srca.s_addr);
  const char * const source_desc_c = source_desc.c_str();

  if(is_zprn_packet(source_desc_c, buffer, nread)) {
    const auto d_zprn = reinterpret_cast<const struct zprn*>(buffer);
    switch(d_zprn->zprn_cmd) {
      case ZPRN_ROUTEMOD:
        {
          const auto dsta = d_zprn->zprn_un.route.dsta;
          if(d_zprn->zprn_prio == ZPRN_ROUTEMOD_DELETE) {
            const auto r = have_route(dsta);
            // delete route
            if(r && r->del_router(srca.s_addr))
              printf("ROUTER: delete route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);

            zprn msg;
            msg.zprn_cmd = ZPRN_ROUTEMOD;
            msg.zprn_un.route.dsta = dsta;
            if(dsta == local_ip.s_addr) {
              // a route to us is deleted (and we know we are here)
              msg.zprn_prio = 0;
              send_zprn_msg(msg);
            } else if(r) {
              if(r->empty()) {
                // former router was srca
                neg_routes[dsta].former_router = srca.s_addr;
              } else {
                // we have a route
                msg.zprn_prio = r->_routers.front().hops;
                send_zprn_msg(msg);
              }
            }
          } else {
            // add route
            if(routes[dsta].add_router(srca.s_addr, d_zprn->zprn_prio + 1))
              printf("ROUTER: add route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);
          }
        }
        break;

      case ZPRN_CONNMGMT:
        if(d_zprn->zprn_prio == ZPRN_CONNMGMT_CLOSE) {
          for(auto &r: routes)
            if(r.second.del_router(srca.s_addr)) {
              printf("ROUTER: delete route to %s via %s (notified)\n", inet_ntoa({r.first}), source_desc_c);
              if(r.second.empty())
                neg_routes[r.first].former_router = srca.s_addr;
            }

          const auto dsta = d_zprn->zprn_un.route.dsta;
          if(const auto r = have_route(dsta)) {
            r->_routers.clear();
            printf("ROUTER: delete route to %s (notified)\n", inet_ntoa({dsta}));
          }
        }

      default: break;
    }

    // don't forward
    return false;
  }

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
  for(auto &&i: remotes) {
    const auto seen = format_time(i.second.seen);
    printf("%s\t%s\t", inet_ntoa({i.first}), seen.c_str());
    puts(i.second.cfgent_name());
  }
  puts("-- routing table:");
  puts("Destination\tGateway\t\tSeen\t\tLatency\tHops");
  for(auto &&i: routes) {
    const string dest = inet_ntoa({i.first});
    for(auto &&r: i.second._routers) {
      const string gateway = inet_ntoa({r.addr});
      const auto seen = format_time(r.seen);
      printf("%s\t%s\t%s\t%4.2f\t%u\n", dest.c_str(), gateway.c_str(), seen.c_str(), r.latency, static_cast<unsigned>(r.hops));
    }
  }
  fflush(stdout);
}

static atomic<bool> b_do_shutdown;

static void do_shutdown(int) noexcept {
  b_do_shutdown = true;
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

    if(!init_all(confpath)) return 1;
  }

  b_do_shutdown = false;
  ping_cache_t::match_t::apply_fn = ping_cache_match_apply_fn;
  my_signal(SIGHUP,  SIG_IGN);
  my_signal(SIGUSR1, print_routing_table);
  fflush(stdout);
  fflush(stderr);

  {
    // notify our peers that we are here
    zprn msg;
    msg.zprn_cmd = ZPRN_CONNMGMT;
    msg.zprn_prio = ZPRN_CONNMGMT_OPEN;
    msg.zprn_un.route.dsta = local_ip.s_addr;
    send_zprn_msg(msg);
  }

  // add route to ourselves to avoid sending two 'ZPRN add route' packets
  routes[local_ip.s_addr].add_router(local_ip.s_addr, 0);

  my_signal(SIGINT, do_shutdown);
  my_signal(SIGTERM, do_shutdown);

  int retcode = 0;

  while(!b_do_shutdown) {
    { // use select() to handle two descriptors at once
      fd_set rd_set;
      FD_ZERO(&rd_set);
      FD_SET(local_fd, &rd_set);
      FD_SET(server_fd, &rd_set);

      if(select(std::max(local_fd, server_fd) + 1, &rd_set, 0, 0, 0) < 0) {
        if(errno == EINTR) continue;
        perror("select()");
        retcode = 1;
        break;
      }

      uint16_t nread;
      char buffer[BUFSIZE];

      if(FD_ISSET(local_fd, &rd_set)) {
        // data from tun/tap: just read it and write it to the network
        nread = cread(local_fd, buffer, BUFSIZE);
        if(is_ipv4_packet("local", buffer, nread))
          route_packet(local_ip.s_addr, buffer, nread);
      }

      if(FD_ISSET(server_fd, &rd_set)) {
        struct in_addr addr;
        // data from the network: read it, and write it to the tun/tap interface.
        if(read_packet(addr, buffer, nread))
          route_packet(addr.s_addr, buffer, nread);
      }
    }

    const auto del_route_msg = [](const uint32_t addr, const uint32_t router) {
      // discard route
      printf("ROUTER: delete route to %s via ", inet_ntoa({addr}));
      const auto d = get_remote_desc(router);
      printf("%s (outdated)\n", d.c_str());
    };

    vector<uint32_t> discard_remotes;
    vector<size_t>   found_remotes;
    unordered_map<uint32_t, uint32_t> tr_remotes;

    for(auto &i : remotes) {
      if(i.second.cent != -1)
        found_remotes.push_back(i.second.cent);

      bool discard = true;

      // skip local, and remotes which aren't timed out
      if(i.first == local_ip.s_addr || !i.second.outdated()) {
        discard = false;
      } else if(i.second.cent != -1) {
        // try to update ip
        struct in_addr remote;
        if(resolve_hostname(i.second.cfgent_name(), remote)) {
          i.second.refresh();
          if(remote.s_addr != i.first) {
            tr_remotes[i.first] = remote.s_addr;
            for(auto &r: routes)
              r.second.replace_router(i.first, remote.s_addr);
          }
          discard = false;
        }
      }

      if(discard) {
        for(auto &r: routes)
          if(r.second.del_router(i.first))
            del_route_msg(r.first, i.first);

        discard_remotes.push_back(i.first);
      }
    }

    // cleanup routes, needs to be done after del_router calls
    for(auto it = routes.begin(); it != routes.end();) {
      it->second.cleanup([it, del_route_msg](const uint32_t router) {
        del_route_msg(it->first, router);
      });

      auto &ise = it->second;
      if(ise.empty() || ise._fresh_add) {
        ise._fresh_add = false;

        zprn msg;
        msg.zprn_cmd = ZPRN_ROUTEMOD;
        msg.zprn_un.route.dsta = it->first;
        msg.zprn_prio = (ise.empty()
          ? ZPRN_ROUTEMOD_DELETE
          : ise._routers.front().hops);
        send_zprn_msg(msg);

        if(ise.empty()) it = routes.erase(it);
      }

      if(!ise.empty()) ++it;
    }

    // flush output
    fflush(stdout);

    // replace remotes (after cleanup -> lesser remotes to process)
    // we can't merge this loop and the following, because this loop iterates and only inserts
    // but the next loop erases elements
    for(const auto &i : tr_remotes) {
      remotes[i.second] = std::move(remotes[i.first]);
      discard_remotes.push_back(i.first);
    }
    tr_remotes.clear();

    // discard remotes (after cleanup -> cleanup has a chance to notify them)
    std::sort(discard_remotes.begin(), discard_remotes.end());
    for(auto it = remotes.cbegin(); it != remotes.cend();) {
      const auto drit = binary_find(discard_remotes, it->first);
      if(drit != discard_remotes.end()) {
        discard_remotes.erase(drit);
        it = remotes.erase(it);
      } else {
        ++it;
      }
    }

    uniquify(found_remotes);
    if(found_remotes.size() < zprd_conf.remotes.size()) {
      size_t i = 0;
      for(const auto &r : zprd_conf.remotes) {
        const auto frit = binary_find(found_remotes, i);
        if(frit != found_remotes.end()) {
          found_remotes.erase(frit);
          struct in_addr remote;
          if(resolve_hostname(r.c_str(), remote)) {
            remotes[remote.s_addr] = {i};
            printf("CLIENT: connected to server %s\n", inet_ntoa(remote));
          }
        }
        ++i;
      }
    }

    // flush output
    fflush(stdout);
    fflush(stderr);
  }

  // shutdown the sender thread
  sender.stop();

  // notify our peers that we quit
  puts("ROUTER: disconnect from peers");
  zprn msg;
  msg.zprn_cmd = ZPRN_CONNMGMT;
  msg.zprn_prio = ZPRN_CONNMGMT_CLOSE;
  msg.zprn_un.route.dsta = local_ip.s_addr;
  send_zprn_msg(msg);
  puts("QUIT");
  fflush(stdout);
  fflush(stderr);

  return retcode;
}
