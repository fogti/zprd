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
#include <pwd.h>    // struct passwd
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "config.h"

// C++
#include <atomic>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <utility>

#ifdef TBB_FOUND
# include <tbb/parallel_sort.h>
#endif

// 3rdparty
#include <ThreadPool.h>

// own parts
#include "addr.hpp"
#include "crest.h"
#include "crw.h"
#include "ping_cache.hpp"
#include "remote_peer.hpp"
#include "resolve.hpp"
#include "routes.hpp"
#include "zprd_conf.hpp"
#include "zprn.hpp"

// buffer for reading from tun/tap interface, must be greater than 1500
#define BUFSIZE 0xffff

using namespace std;

zprd_conf_t zprd_conf;
time_t last_time;

struct send_data final {
  vector<char> buffer;
  vector<uint32_t> dests;
  uint16_t frag;
  uint8_t  tos;

  send_data() noexcept: frag(0), tos(0) { }

  send_data(const send_data &o) = default;

  send_data(send_data &&o) noexcept
    : buffer(move(o.buffer)), dests(move(o.dests)),
      frag(o.frag), tos(o.tos) { }

  send_data(vector<char> &&buf, vector<uint32_t> &&d,
            const uint16_t frag_ = 0, const uint8_t tos_ = 0) noexcept
    : buffer(move(buf)), dests(move(d)), frag(frag_), tos(tos_) { }

  send_data& operator=(const send_data &o) = default;

  send_data& operator=(send_data &&o) noexcept {
    if(this != &o) {
      buffer = move(o.buffer);
      dests  = move(o.dests);
      frag = o.frag; tos = o.tos;
    }
    return *this;
  }
};

class sender_t final {
  vector<send_data> _tasks;

  // sync
  mutex _mtx;
  condition_variable _cond;
  bool _stop = false;

  void worker_fn() noexcept;

 public:
  ~sender_t() noexcept { stop(); }

  void enqueue(send_data &&dat);
  void start();
  void stop() noexcept;
};

/*** global vars ***/

/** file descriptors
 *
 * local_fd  = the tun device
 * server_fd = the server udp socket
 **/
static int local_fd, server_fd;

// make sure that there are at least 1 (at most 2) normal worker thread + 1 send thread
static ThreadPool threadpool(std::min(2u, std::max(2u, thread::hardware_concurrency()) - 1));
static sender_t sender;

static unordered_map<uint32_t, remote_peer_t> remotes;
static unordered_map<uint32_t, route_via_t> routes;
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

#define runcmd(X) do { const auto rcf_ret = runcmd_fn(X); if(!rcf_ret) return false; } while(false)

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
  // last_time must be set before any call to routing classes happen
  srand((last_time = time(nullptr)));

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

  sender.start();
  return true;
}

static route_via_t* have_route(const uint32_t dsta) noexcept {
  const auto it = routes.find(dsta);
  return (
    (it == routes.end() || it->second.empty())
      ? nullptr : &(it->second)
  );
}

// get_remote_desc: returns a description string of socket ip
static string get_remote_desc(const uint32_t addr) {
  return (addr == local_ip.s_addr)
         ? string("local")
         : (string("peer ") + inet_ntoa({addr}));
}

/** uniquify:
 * make all elems in a container unique
 **/
template<class TCont>
void uniquify(TCont &c) noexcept {
#ifdef TBB_FOUND
  tbb::parallel_sort
#else
  std::sort
#endif
    (c.begin(), c.end());
  c.erase(std::unique(c.begin(), c.end()), c.end());
}

template<class TCont>
TCont uniquify_move(TCont &&c) noexcept {
  uniquify(c);
  return forward<TCont>(c);
}

/** rem_peer_t
 * a functor which erases a vector item from a sorted vector
 **/
template<typename T>
class rem_peer_t final {
  vector<T> &_vec;

 public:
  explicit rem_peer_t(vector<T> &vec) noexcept: _vec(vec) { }

  bool operator()(const T &item) const noexcept {
    // perform a binary find
    const auto it = lower_bound(_vec.begin(), _vec.end(), item);
    if(it == _vec.end() || *it != item) return false;
    // erase element
    // NOTE: don't swap [back] with [*it], as that destructs sorted range
    _vec.erase(it);
    return true;
  }
};

// automatic type deducing support for rem_peer_t
template<typename T>
auto make_rem_peer(vector<T> &vec) noexcept -> rem_peer_t<T> {
  return rem_peer_t<T>(vec);
}

// compact definition for rem_peer_t
#define GET_REM_PEER(C) const auto rem_peer = make_rem_peer(C)

/** get_map_keys
 * generate a vector from the keys of an map
 **/
template<class Cont>
auto get_map_keys(const Cont &c) -> vector<typename Cont::key_type> {
  vector<typename Cont::key_type> ret;
  ret.reserve(c.size());
  for(const auto &i : c) ret.push_back(i.first);
  return ret;
}

/** get_cksum_fut
 * returns a future to an in_cksum{ptr...} result
 **/
template<class T>
auto get_cksum_fut(const T *const ptr) -> future<uint16_t> {
  return threadpool.enqueue([ptr]() noexcept { return IN_CKSUM(ptr); });
}

void sender_t::worker_fn() noexcept {
  prctl(PR_SET_NAME, "sender", 0, 0, 0);

  bool df = false;
  uint8_t tos = 0;

  const auto set_df = [&df](const bool cdf) noexcept {
    const int tmp_df = cdf ?
# if defined(IP_DONTFRAG)
      1 : 0;
    if(setsockopt(server_fd, IPPROTO_IP, IP_DONTFRAG, &tmp_df, sizeof(tmp_df)) < 0)
      perror("ROUTER WARNING: setsockopt(IP_DONTFRAG) failed");
# elif defined(IP_MTU_DISCOVER)
      IP_PMTUDISC_WANT : IP_PMTUDISC_DONT;
    if(setsockopt(server_fd, IPPROTO_IP, IP_MTU_DISCOVER, &tmp_df, sizeof(tmp_df)) < 0)
      perror("ROUTER WARNING: setsockopt(IP_MTU_DISCOVER) failed");
# else
#  warning "set_ip_df: no method available to manage the dont-frag bit"
      0 : 0;
    if(0) {}
# endif
    else df = cdf;
  };

  const auto set_tos = [&tos](const uint8_t ctos) noexcept {
    if(setsockopt(server_fd, IPPROTO_IP, IP_TOS, &ctos, 1) < 0)
      perror("ROUTER WARNING: setsockopt(IP_TOS) failed");
    else tos = ctos;
  };

  set_df(false);
  set_tos(0);

  vector<send_data> tasks;
  struct sockaddr_in dsta;
  memset(&dsta, 0, sizeof(dsta));
  dsta.sin_family = AF_INET;
  dsta.sin_port   = htons(zprd_conf.data_port);

  while(true) {
    {
      unique_lock<mutex> lock(_mtx);
      _cond.wait(lock, [this] { return _stop || !_tasks.empty(); });
      if(_tasks.empty()) return;
      tasks = move(_tasks);
      _tasks = {};
    }

    // send data
    for(auto &dat: tasks) {
      const auto buf = dat.buffer.data();
      const auto buflen = dat.buffer.size();
      if(make_rem_peer(dat.dests)(local_ip.s_addr))
        if(write(local_fd, buf, buflen) < 0)
          perror("write()");

      if(dat.dests.empty()) continue;

      { // setup outer Dont-Frag bit
        const bool cdf = dat.frag & htons(IP_DF);
        if(df != cdf) set_df(cdf);
      }

      // setup outer TOS
      if(tos != dat.tos) set_tos(dat.tos);

      for(const auto &i : dat.dests) {
        dsta.sin_addr.s_addr = i;
        if(sendto(server_fd, buf, buflen, 0, reinterpret_cast<struct sockaddr *>(&dsta), sizeof(dsta)) < 0)
          perror("sendto()");
      }
    }

    // flush output
    fflush(stdout);
    fflush(stderr);
  }
}

void sender_t::enqueue(send_data &&dat) {
  dat.dests.shrink_to_fit();
  {
    lock_guard<mutex> lock(_mtx);
    _tasks.emplace_back(std::move(dat));
  }
  _cond.notify_one();
}

void sender_t::start() {
  {
    lock_guard<mutex> lock(_mtx);
    _stop = false;
  }
  thread(&sender_t::worker_fn, this).detach();
}

void sender_t::stop() noexcept {
  {
    lock_guard<mutex> lock(_mtx);
    _stop = true;
  }
  _cond.notify_all();
}

enum zprd_icmpe {
  ZICMPM_TTL, ZICMPM_UNREACH, ZICMPM_UNREACH_NET
};

static void send_icmp_msg(const zprd_icmpe msg, const struct ip * const orig_hip, const uint32_t source_ip) {
  constexpr const size_t buflen = 2 * sizeof(struct ip) + sizeof(struct icmphdr) + 8;
  send_data dat(vector<char>{buflen, 0}, {source_ip});
  char *const buffer = dat.buffer.data();

  const auto h_ip = reinterpret_cast<struct ip*>(buffer);
  h_ip->ip_v   = 4;
  h_ip->ip_hl  = 5;
  h_ip->ip_len = htons(static_cast<uint16_t>(buflen));
  h_ip->ip_id  = rand();
  h_ip->ip_ttl = MAXTTL;
  h_ip->ip_p   = IPPROTO_ICMP;
  h_ip->ip_src = local_ip;
  h_ip->ip_dst = orig_hip->ip_src;

  // calculate ip checksum
  auto fut_ip_sum = get_cksum_fut(h_ip);

  const auto h_icmp = reinterpret_cast<struct icmphdr*>(buffer + sizeof(struct ip));

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
      fprintf(stderr, "SEND ERROR: invalid ZICMP Message code: %d\n", msg);
      return;
  }

  // calculate icmp checksum
  auto fut_icmp_sum = get_cksum_fut(h_icmp);

  // setup payload = orig ip header
  memcpy(buffer + sizeof(struct ip) + sizeof(struct icmphdr), orig_hip, sizeof(struct ip));

  // setup secondary payload = first 8 bytes of original payload
  memcpy(buffer + 2 * sizeof(struct ip) + sizeof(struct icmphdr),
         orig_hip + sizeof(ip),
         std::min(static_cast<unsigned short>(8), ntohs(orig_hip->ip_len)));

  h_icmp->checksum = fut_icmp_sum.get();
  h_ip->ip_sum     = fut_ip_sum.get();
  sender.enqueue(move(dat));
}

static void send_zprn_msg(const zprn &msg) {
  vector<uint32_t> peers = uniquify_move(get_map_keys(remotes));
  GET_REM_PEER(peers);

  // filter local tun interface
  rem_peer(local_ip.s_addr);

  // split horizon
  if(msg.zprn_cmd == ZPRN_ROUTEMOD && msg.zprn_prio != ZPRN_ROUTEMOD_DELETE)
    if(const auto r = have_route(msg.zprn_un.route.dsta))
      rem_peer(r->get_router());

  const auto msgptr = reinterpret_cast<const char *>(&msg);
  sender.enqueue({{msgptr, msgptr + sizeof(msg)}, move(peers)});
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
  remotes[source_peer_ip].seen = last_time;

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

  // NOTE: make sure that no changes are done to buffer
  h_ip->ip_sum = 0;

  // update checksum (because we changed the header)
  auto fut_ip_sum = get_cksum_fut(h_ip);

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
  } else if(!have_route(ip_dst.s_addr)) {
    printf("ROUTER: no known route to %s\n", inet_ntoa(ip_dst));
    is_broadcast = true;
  }

  // get route to destination
  vector<uint32_t> ret;

  // function to filter a peer
  GET_REM_PEER(ret);

  if(is_broadcast) {
    ret = get_map_keys(remotes);
    if(iam_ep) ret.push_back(local_ip.s_addr);
    uniquify(ret);
  } else {
    ret.emplace_back(routes[ip_dst.s_addr].get_router());
    // catch bouncing packets in *local iface* network earlier
    if(!iam_ep) rem_peer(local_ip.s_addr);
  }

  // split horizon
  rem_peer(source_peer_ip);

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
      if(const auto route = have_route(ip_dst.s_addr)) {
        const auto d = get_remote_desc(route->get_router());
        printf("ROUTER: delete route to %s via %s (invalid)\n", inet_ntoa(ip_dst), d.c_str());
        route->del_primary_router();
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
            {
              const auto m = ping_cache.match(edat, source_peer_ip, h_ip->ip_ttl);
              if(m.match)
                if(const auto r = have_route(m.dst))
                  r->update_router(m.router, m.hops, m.diff);
            }
            break;

          default: break;
        }
      }
    }

    if(!ret.empty())
      sender.enqueue({{buffer, buffer + buflen}, move(ret), h_ip->ip_off, h_ip->ip_tos});
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

// handlers for incoming ZPRN packets
typedef void (*zprn_handler_t)(const char * const, const uint32_t, const zprn&);

static void zprn_routemod_handler(const char *const source_desc_c, const uint32_t srca, const zprn &d) {
  const auto dsta = d.zprn_un.route.dsta;
  if(d.zprn_prio != ZPRN_ROUTEMOD_DELETE) {
    // add route
    if(routes[dsta].add_router(srca, d.zprn_prio + 1))
      printf("ROUTER: add route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);
    return;
  }

  // delete route
  const auto r = have_route(dsta);
  if(r && r->del_router(srca))
    printf("ROUTER: delete route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);

  bool doit = true;
  zprn msg;
  msg.zprn_cmd = ZPRN_ROUTEMOD;
  msg.zprn_un.route.dsta = dsta;

  if(dsta == local_ip.s_addr) // a route to us is deleted (and we know we are here)
    msg.zprn_prio = 0;
  else if(r && !r->empty()) // we have a route
    msg.zprn_prio = r->_routers.front().hops;
  else
    doit = false;

  if(doit) send_zprn_msg(msg);
}

static void zprn_connmgmt_handler(const char *const source_desc_c, const uint32_t srca, const zprn &d) noexcept {
  const auto dsta = d.zprn_un.route.dsta;
  if(d.zprn_prio == ZPRN_CONNMGMT_OPEN) {
    if(routes[dsta].add_router(srca, 1))
      printf("ROUTER: add route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);
    return;
  }

  for(auto &r: routes)
    if(r.second.del_router(srca))
      printf("ROUTER: delete route to %s via %s (notified)\n", inet_ntoa({r.first}), source_desc_c);

  if(const auto r = have_route(dsta)) {
    r->_routers.clear();
    printf("ROUTER: delete route to %s (notified)\n", inet_ntoa({dsta}));
  }
}

/** read_packet
 * reads an variable length packet
 *
 * @param srca    (out) the source ip
 * @param buffer  (out) the target storage (with size len)
 * @param len     (in/out) the length of the packet
 * @ret           succesful marker
 **/
static bool read_packet(struct in_addr &srca, char buffer[], uint16_t &len) {
  static const unordered_map<uint8_t, zprn_handler_t> zprn_dpt = {
    { ZPRN_ROUTEMOD, zprn_routemod_handler },
    { ZPRN_CONNMGMT, zprn_connmgmt_handler },
  };

  struct sockaddr_in source;
  const uint16_t nread = recv_n(server_fd, buffer, len, &source);
  srca = source.sin_addr;

  const string source_desc = get_remote_desc(srca.s_addr);
  const char * const source_desc_c = source_desc.c_str();

  if(sizeof(struct zprn) <= nread && reinterpret_cast<const zprn*>(buffer)->valid()) {
    const auto d_zprn = *reinterpret_cast<const struct zprn*>(buffer);
    const auto it = zprn_dpt.find(d_zprn.zprn_cmd);
    if(it != zprn_dpt.end()) it->second(source_desc_c, srca.s_addr, d_zprn);
    return false; // don't forward
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
  for(const auto &i: remotes) {
    const auto seen = format_time(i.second.seen);
    printf("%s\t%s\t", inet_ntoa({i.first}), seen.c_str());
    puts(i.second.cfgent_name());
  }
  puts("-- routing table:");
  puts("Destination\tGateway\t\tSeen\t\tLatency\tHops");
  for(const auto &i: routes) {
    const string dest = inet_ntoa({i.first});
    for(const auto &r: i.second._routers) {
      const string gateway = inet_ntoa({r.addr}), seen = format_time(r.seen);
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
  my_signal(SIGHUP,  SIG_IGN);
  my_signal(SIGUSR1, print_routing_table);
  fflush(stdout);
  fflush(stderr);

  // notify our peers that we are here
  zprn msg;
  msg.zprn_cmd = ZPRN_CONNMGMT;
  msg.zprn_prio = ZPRN_CONNMGMT_OPEN;
  msg.zprn_un.route.dsta = local_ip.s_addr;
  send_zprn_msg(msg);

  // add route to ourselves to avoid sending two 'ZPRN add route' packets
  routes[local_ip.s_addr].add_router(local_ip.s_addr, 0);

  my_signal(SIGINT, do_shutdown);
  my_signal(SIGTERM, do_shutdown);

  int retcode = 0;
  // define the peer transaction temp vars outside of the loop to avoid unnecessarily mem allocs
  vector<uint32_t> discard_remotes;
  vector<size_t>   found_remotes;
  unordered_map<uint32_t, uint32_t> tr_remotes;

  while(!b_do_shutdown) {
    /* last_time - global time, updated after select
       pastt - time before select
       curt  - time after select
      */
    const auto pastt = last_time;
    { // use select() to handle two descriptors at once
      fd_set rd_set;
      FD_ZERO(&rd_set);
      FD_SET(local_fd, &rd_set);
      FD_SET(server_fd, &rd_set);

      if(select(std::max(local_fd, server_fd) + 1, &rd_set, nullptr, nullptr, nullptr) < 0) {
        if(errno == EINTR) continue;
        perror("select()");
        retcode = 1;
        break;
      }

      last_time = time(nullptr);

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
        nread = BUFSIZE;
        if(read_packet(addr, buffer, nread))
          route_packet(addr.s_addr, buffer, nread);
      }
    }

    const auto del_route_msg = [](const uint32_t addr, const uint32_t router) {
      // discard route
      const auto d = get_remote_desc(router);
      printf("ROUTER: delete route to %s via %s (outdated)\n", inet_ntoa({addr}), d.c_str());
    };

    // only cleanup things if at least 1 second passed since last iteration
    if(last_time == pastt) continue;
    const auto curt = last_time;

    for(auto &i : remotes) {
      if(i.second.cent != -1)
        found_remotes.push_back(i.second.cent);

      bool discard = true;

      // skip local, and remotes which aren't timed out
      if(i.first == local_ip.s_addr || (curt - zprd_conf.remote_timeout) < i.second.seen) {
        discard = false;
      } else if(i.second.cent != -1) {
        // try to update ip
        struct in_addr remote;
        if(resolve_hostname(i.second.cfgent_name(), remote)) {
          i.second.seen = curt;
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

    auto fut_ufr = threadpool.enqueue([&found_remotes] { uniquify(found_remotes); });
    mutex peermtx;
    auto fut_trr = threadpool.enqueue([&] {
      // replace remotes (after cleanup -> lesser remotes to process)
      discard_remotes.reserve(discard_remotes.size() + tr_remotes.size());
      for(const auto &i : tr_remotes) {
        lock_guard<mutex> pl(peermtx);
        remotes[i.second] = std::move(remotes[i.first]);
        discard_remotes.push_back(i.first);
      }
      tr_remotes.clear();
      uniquify(discard_remotes);
    });

    // cleanup routes, needs to be done after del_router calls
    for(auto it = routes.begin(); it != routes.end();) {
      auto &ise = it->second;
      ise.cleanup([it, del_route_msg](const uint32_t router) {
        del_route_msg(it->first, router);
      });

      const bool iee = ise.empty();
      if(iee || ise._fresh_add) {
        ise._fresh_add = false;

        msg.zprn_cmd = ZPRN_ROUTEMOD;
        msg.zprn_un.route.dsta = it->first;
        msg.zprn_prio = (iee ? ZPRN_ROUTEMOD_DELETE : ise._routers.front().hops);
        // this is the only part of this loop which uses remotes
        lock_guard<mutex> pl(peermtx);
        send_zprn_msg(msg);
      }

      // NOTE: don't use *it after erase (see Issue #1)
      if(iee) it = routes.erase(it);
      else ++it;
    }

    // discard remotes (after cleanup -> cleanup has a chance to notify them)
    fut_trr.wait();
    {
      GET_REM_PEER(discard_remotes);
      for(auto it = remotes.cbegin(); it != remotes.cend();) {
        if(rem_peer(it->first))
          it = remotes.erase(it);
        else
          ++it;
      }
    }

    fut_ufr.wait();
    if(found_remotes.size() < zprd_conf.remotes.size()) {
      size_t i = 0;
      GET_REM_PEER(found_remotes);
      for(const auto &r : zprd_conf.remotes) {
        if(rem_peer(i)) {
          struct in_addr remote;
          if(resolve_hostname(r.c_str(), remote)) {
            remotes[remote.s_addr] = {i};
            printf("CLIENT: connected to server %s\n", inet_ntoa(remote));
          }
        }
        ++i;
      }
    }
    found_remotes.clear();

    // flush output
    fflush(stdout);
    fflush(stderr);
  }

  // notify our peers that we quit
  puts("ROUTER: disconnect from peers");
  msg.zprn_cmd = ZPRN_CONNMGMT;
  msg.zprn_prio = ZPRN_CONNMGMT_CLOSE;
  msg.zprn_un.route.dsta = local_ip.s_addr;
  send_zprn_msg(msg);

  // shutdown the sender thread
  sender.stop();

  puts("QUIT");
  fflush(stdout);
  fflush(stderr);

  return retcode;
}
