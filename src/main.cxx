/**
 * zprd / main.cxx
 *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap
 * interfaces and UDP.
 *
 * (C) 2010 Davide Brini.
 * (C) 2017 - 2018 Erik Zscheile.
 *
 * License: GPL-2+
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
#include <grp.h>    // struct group
#include <pwd.h>    // struct passwd
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h> // linux-specific epoll
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <fcntl.h>

// C++
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <functional>
#include <utility>

#include <atomic>
#include <thread>
#include <condition_variable>

// own parts
#include <config.h>
#include <addr.hpp>
#include <addr_t.hpp>
#include "crest.h"
#include "crw.h"
#include "ping_cache.hpp"
#include "remote_peer.hpp"
#include "resolve.hpp"
#include "routes.hpp"
#include "zprd_conf.hpp"
#include "zprn.hpp"

// -lowlevelzs
#include <zs/ll/zsig.h>

// TBB
#ifdef TBB_FOUND
# include <tbb/parallel_sort.h>
#endif

// buffer for reading from tun/tap interface, must be greater than 1500
#define BUFSIZE 0xffff

using namespace std;

/*** global vars ***/
zprd_conf_t zprd_conf;
time_t last_time;

/*** helper classes ***/

struct send_data final {
  vector<char> buffer;
  vector<shared_ptr<remote_peer_t>> dests;
  uint16_t frag;
  uint8_t  tos;

  send_data() noexcept: frag(0), tos(0) { }

  send_data(const send_data &o) = default;

  send_data(send_data &&o) noexcept
    : buffer(move(o.buffer)), dests(move(o.dests)),
      frag(o.frag), tos(o.tos) { }

  send_data(vector<char> &&buf, decltype(dests) &&d,
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

/*** file-scope global vars ***/

/** file descriptors
 *
 * local_fd  = the tun device
 * server_fd = the server udp sockets
 **/
static int local_fd;
static unordered_map<sa_family_t, int> server_fds;

static vector<shared_ptr<remote_peer_detail_t>> remotes;
static unordered_map<zs_addr_t, route_via_t> routes;

static sender_t     sender;
static ping_cache_t ping_cache;

static in_addr local_ip, local_netmask;
static bool have_local_ip;

/*** helper functions ***/

static sa_family_t str2preferred_af(string afdesc) {
  static const unordered_map<string, sa_family_t> trt = {
    { "INET" , AF_INET  }, { "IPV4", AF_INET  },
#ifdef USE_IPV6
    { "INET6", AF_INET6 }, { "IPV6", AF_INET6 },
#endif
  };
  std::transform(afdesc.begin(), afdesc.end(), afdesc.begin(), ::toupper);
  const auto it = trt.find(afdesc);
  if(it != trt.end()) return it->second;
  printf("CONFIG WARNING: unsupported address_family AF_*: %s\n", afdesc.c_str());
  return AF_UNSPEC;
}

static bool setup_server_fd(const sa_family_t sa_family) {
  // prepare server

  // declare all variables here, to allow 'goto error'
  const int server_fd = socket(sa_family, SOCK_DGRAM, 0);
  int optval = 1;
  remote_peer_t local_pt;
  struct sockaddr_storage &ss = local_pt.saddr;

  if(server_fd < 0) {
    perror("socket()");
    goto error;
  }

  // avoid EADDRINUSE error on bind()
  if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    goto error;
  }

  // FIXME: create multiple server_fd's and store them in a hashmap AF_ -> fd
  // use remote_peer_t as abstraction layer + helper
  ss.ss_family = sa_family;
  local_pt.set_port(zprd_conf.data_port, false);
  if(!local_pt.set2catchall()) {
    fprintf(stderr, "STARTUP ERROR: setup_server_fd: unsupported address family %u\n", static_cast<unsigned>(sa_family));
    goto error;
  }

  if(bind(server_fd, reinterpret_cast<struct sockaddr*>(&ss), sizeof(ss)) < 0) {
    perror("bind()");
    return false;
  }

  server_fds[sa_family] = server_fd;
  return true;

 error:
  close(server_fd);
  return false;
}

static void connect2server(const string &r, const size_t cent) {
  struct sockaddr_storage remote;
  if(resolve_hostname(r.c_str(), remote, zprd_conf.preferred_af)) {
    auto ptr = make_shared<remote_peer_detail_t>(remote_peer_t(remote), cent);
    ptr->set_port(zprd_conf.data_port, false);
    const string remote_desc = ptr->addr2string();
    remotes.emplace_back(move(ptr));
    printf("CLIENT: connected to server %s\n", remote_desc.c_str());
  }
}

static bool update_server_addr(remote_peer_detail_t &pdat) {
  struct sockaddr_storage remote;
  // try to update ip
  if(pdat.cent && resolve_hostname(pdat.cfgent_name(), remote, zprd_conf.preferred_af)) {
    pdat.locked_run([&remote](remote_peer_detail_t &o) {
      o.seen = last_time;
      o.set_saddr(remote, false);
      o.set_port(zprd_conf.data_port, false);
    });
    return true;
  }
  return false;
}

static bool init_all(const string &confpath) {
  static const auto runcmd_fn = [](const string &cmd) -> bool {
    if(const int ret = system(cmd.c_str())) {
      printf("CONFIG APPLY ERROR: %s; $? = %d\n", cmd.c_str(), ret);
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

#define runcmd(X) do { if(!runcmd_fn(X)) return false; } while(false)

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
    zprd_conf.preferred_af   = AF_UNSPEC;
    local_ip.s_addr          = htonl(0);
    have_local_ip            = false;

    // is used when we are root and see the 'U' setting in the conf to drop privilegis
    string run_as_user;

    string addr_stmt, line;
    while(getline(in, line)) {
      if(line.empty() || line.front() == '#') continue;
      string arg = line.substr(1);
      switch(line.front()) {
        case 'A':
          addr_stmt = move(arg);
          break;

        case 'I':
          zprd_conf.iface = move(arg);
          break;

        case 'P':
          zprd_conf.data_port = stoi(arg);
          break;

        case 'R':
          zprd_conf.remotes.emplace_back(move(arg));
          break;

        case 'T':
          zprd_conf.remote_timeout = stoi(arg);
          break;

        case 'U':
          run_as_user = move(arg);
          break;

        case '^':
          zprd_conf.preferred_af = str2preferred_af(move(arg));
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

    // NOTE: don't convert zprd_conf.data_port to big-endian; that's done in remote_peer_t::set_port

    if(!addr_stmt.empty()) {
      const size_t marker = addr_stmt.find('/');
      const string ip = addr_stmt.substr(0, marker);
      const string cidrsf =
        ((marker == string::npos)
          ? "32"
          : addr_stmt.substr(marker + 1));

      remote_peer_t rp_local;

      if(!resolve_hostname(ip.c_str(), rp_local.saddr, AF_INET)) {
        fprintf(stderr, "CONFIG ERROR: invalid 'A' statement: 'A%s'\n", addr_stmt.c_str());
        return false;
      }

      local_ip = reinterpret_cast<struct sockaddr_in*>(&rp_local.saddr)->sin_addr;
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
        fprintf(stderr, "ERROR: failed to connect to interface '%s'\n", if_name);
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

      puts("running daemon as group: 'nogroup'");
      struct group *grresult = getgrnam("nogroup");

      if(!grresult) {
        perror("STARTUP ERROR: getgrnam() failed");
        return false;
      }

      const gid_t newgid = grresult->gr_gid;
      setgroups(1, &newgid);
#ifndef linux
      setegid(newgid);
      if(setgid(newgid) < 0)
#else
      if(setregid(newgid, newgid) < 0)
#endif
      {
        perror("STARTUP ERROR: set*gid() failed");
        return false;
      }

      const uid_t newuid = pwresult->pw_uid;
#ifndef linux
      seteuid(newuid);
      if(setuid(newuid) < 0)
#else
      if(setreuid(newuid, newuid) < 0)
#endif
      {
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
    remotes.reserve(zprd_conf.remotes.size());
    for(const auto &r : zprd_conf.remotes) {
      connect2server(r, i);
      ++i;
    }
  }

  if(remotes.empty() && !zprd_conf.remotes.empty()) {
    puts("CLIENT ERROR: can't connect to any server. QUIT");
    return false;
  }

  // prepare server
  if(!setup_server_fd(AF_INET))
    return false;

#ifdef USE_IPV6
  if(!setup_server_fd(AF_INET6))
    return false;
#endif

  sender.start();
  return true;
}

// get_remote_desc: returns a description string of socket ip
[[gnu::hot]]
static string get_remote_desc(const remote_peer_t &addr) {
  return (addr == remote_peer_t())
         ? string("local")
         : (string("peer ") + addr.addr2string());
}
[[gnu::hot]]
static string get_remote_desc(const remote_peer_ptr_t &addr) {
  if(addr.unique())
    return get_remote_desc(addr);
  return addr->locked_crun([](const remote_peer_t &o) {
    return get_remote_desc(o);
  });
}

template<typename T, typename Fn>
static bool xg_rem_peer(vector<T> &vec, const T &item, const Fn &fn) {
  // perform a binary find
  const auto it = lower_bound(vec.cbegin(), vec.cend(), item, fn);
  if(it == vec.cend() || *it != item)
   return false;
  // erase element
  // NOTE: don't swap [back] with [*it], as that destructs sorted range
  vec.erase(it);
  return true;
}

static bool rem_peer(vector<remote_peer_ptr_t> &vec, const remote_peer_ptr_t &item) {
  typedef remote_peer_ptr_t ptr_t;

  if(xg_rem_peer(vec, item, less<ptr_t>())) return true;
  if(xg_rem_peer(vec, item,
    [](const ptr_t &a, const ptr_t &b) { return (*a) < (*b); }
  )) return true;

  return false;

  found: // DEBUG
  const string peerdesc = get_remote_desc(item);
  printf("DEBUG: rem_peer %s found\n", peerdesc.c_str());
  return true;
}

void sender_t::worker_fn() noexcept {
  prctl(PR_SET_NAME, "sender", 0, 0, 0);

  bool df = false;
  uint8_t tos = 0;

  const auto set_df = [&df](const bool cdf) noexcept {
    const int tmp_df = cdf
# if defined(IP_DONTFRAG)
      ;
    if(setsockopt(server_fds[AF_INET], IPPROTO_IP, IP_DONTFRAG, &tmp_df, sizeof(tmp_df)) < 0)
      perror("ROUTER WARNING: setsockopt(IP_DONTFRAG) failed");
# elif defined(IP_MTU_DISCOVER)
      ? IP_PMTUDISC_WANT : IP_PMTUDISC_DONT;
    if(setsockopt(server_fds[AF_INET], IPPROTO_IP, IP_MTU_DISCOVER, &tmp_df, sizeof(tmp_df)) < 0)
      perror("ROUTER WARNING: setsockopt(IP_MTU_DISCOVER) failed");
# else
#  warning "set_ip_df: no method available to manage the dont-frag bit"
      ;
    if(0) {}
# endif
    else df = cdf;
  };

  const auto set_tos = [&tos](const uint8_t ctos) noexcept {
    if(setsockopt(server_fds[AF_INET], IPPROTO_IP, IP_TOS, &ctos, 1) < 0)
      perror("ROUTER WARNING: setsockopt(IP_TOS) failed");
    else tos = ctos;
  };

  set_df(false);
  set_tos(0);

  vector<send_data> tasks;

  while(true) {
    {
      unique_lock<mutex> lock(_mtx);
      _cond.wait(lock, [this] { return _stop || !_tasks.empty(); });
      if(_tasks.empty()) return;
      tasks = move(_tasks);
      _tasks = {};
    }

    bool got_error = false;

    for(auto &dat: tasks) {
      auto buf = dat.buffer.data();
      const auto buflen = dat.buffer.size();

      // send data
      // NOTE: it is impossible that local_ip and others are destinations together
      if(dat.dests.empty()) {
        { // update checksum if ipv4
          const auto h_ip = reinterpret_cast<struct ip*>(buf);
          if(buflen >= sizeof(struct ip) && h_ip->ip_v == 4)
            h_ip->ip_sum = IN_CKSUM(h_ip);
        }
        if(write(local_fd, buf, buflen) < 0) {
          got_error = true;
          perror("write()");
        }
        continue;
      }

      // detect if we need to set the df and tos bits
      for(const auto &i : dat.dests)
        if(i->get_saddr().ss_family == AF_INET)
          goto cont_ipv4hs;
      goto cont_nohs;

     cont_ipv4hs:
      { // setup outer Dont-Frag bit
        const bool cdf = dat.frag & htons(IP_DF);
        if(df != cdf) set_df(cdf);
      }

      // setup outer TOS
      if(tos != dat.tos) set_tos(dat.tos);

     cont_nohs:
      // TODO: use the correct server_fd depending on ss_family / AF_*
      for(const auto &i : dat.dests) {
        i->locked_crun([&](const remote_peer_t &o) noexcept {
          if(sendto(server_fds[o.saddr.ss_family], buf, buflen, 0, reinterpret_cast<const struct sockaddr *>(&o.saddr), sizeof(o.saddr)) < 0) {
            got_error = true;
            perror("sendto()");
          }
          return true;
        });
      }
    }

    if(got_error) fflush(stderr);
  }
}

void sender_t::enqueue(send_data &&dat) {
  // sanitize dat.dests
  if(dat.dests.empty())
    return;
  if(*dat.dests.front() == remote_peer_t())
    dat.dests.clear();
  dat.dests.shrink_to_fit();

  // move into queue
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

static void send_icmp_msg(const zprd_icmpe msg, struct ip * const orig_hip, const remote_peer_ptr_t &source_ip) {
  constexpr const size_t buflen = 2 * sizeof(struct ip) + sizeof(struct icmphdr) + 8;
  send_data dat{vector<char>(buflen, 0), {source_ip}};
  char *const buffer = dat.buffer.data();

  const auto h_ip = reinterpret_cast<struct ip*>(buffer);
  char * bufnxt = buffer + sizeof(struct ip);
  h_ip->ip_v   = 4;
  h_ip->ip_hl  = 5;
  h_ip->ip_len = htons(static_cast<uint16_t>(buflen));
  h_ip->ip_id  = rand();
  h_ip->ip_ttl = MAXTTL;
  h_ip->ip_p   = IPPROTO_ICMP;
  h_ip->ip_src = local_ip;
  h_ip->ip_dst = orig_hip->ip_src;

  const auto h_icmp = reinterpret_cast<struct icmphdr*>(bufnxt);
  bufnxt += sizeof(struct icmphdr);

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

  // setup payload = orig ip header
  orig_hip->ip_sum = IN_CKSUM(orig_hip);
  memcpy(bufnxt, orig_hip, sizeof(struct ip));
  bufnxt += sizeof(struct ip);

  // setup secondary payload = first 8 bytes of original payload
  memcpy(bufnxt, orig_hip + sizeof(ip),
         std::max(static_cast<unsigned short>(8), ntohs(orig_hip->ip_len)));

  // calculate icmp checksum
  h_icmp->checksum = IN_CKSUM(h_icmp);
  sender.enqueue(move(dat));
}

static route_via_t* have_route(const zs_addr_t dsta) noexcept {
  const auto it = routes.find(dsta);
  return (
    (it == routes.end() || it->second.empty())
      ? nullptr : &(it->second)
  );
}

/** get_peers
 * generate a sorted vector from the keys of remotes map
 **/
static auto get_peers() {
  vector<remote_peer_ptr_t> ret;
  ret.reserve(remotes.size());
  for(const auto &i : remotes) ret.emplace_back(i);

  /* sort all elems in 'ret' */
#ifdef TBB_FOUND
  tbb::parallel_sort
#else
  std::sort
#endif
    (ret.begin(), ret.end());

  return ret;
}

static void send_zprn_msg(const zprn &msg) {
  auto peers = get_peers();

  // split horizon
  if(msg.zprn_cmd == ZPRN_ROUTEMOD && msg.zprn_prio != ZPRN_ROUTEMOD_DELETE)
    if(const auto r = have_route(msg.zprn_un.route.dsta))
      rem_peer(peers, r->get_router());

  if(!peers.empty()) {
    const auto msgptr = reinterpret_cast<const char *>(&msg);
    sender.enqueue({{msgptr, msgptr + sizeof(msg)}, move(peers)});
  }
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
[[gnu::hot]]
static void route_packet(const shared_ptr<remote_peer_detail_t> &source_peer, char *const __restrict__ buffer, const uint16_t buflen, const char *const __restrict__ source_desc_c) {
  const bool source_is_local = have_local_ip && (*source_peer == remote_peer_t());
  if(!source_is_local)
    source_peer->seen = last_time;

  const auto h_ip          = reinterpret_cast<struct ip*>(buffer);
  const auto pkid          = ntohs(h_ip->ip_id);
  const bool is_icmp       = (h_ip->ip_p == IPPROTO_ICMP);

  if(is_icmp && (sizeof(struct ip) + sizeof(struct icmphdr)) > buflen) {
    printf("ROUTER: drop packet %u (too small icmp packet; size = %u) from %s\n", pkid, buflen, source_desc_c);
    return;
  }

  // NOTE: h_icmp is only valid if is_icmp is true
  const auto h_icmp        = reinterpret_cast<const struct icmphdr*>(buffer + sizeof(ip));

  /* === EVALUATE ICMP MESSAGES
   * is_icmp_errmsg : flag if packet is an icmp error message
   *   reason : an echo packet could be used to establish an route without interference on application protos
   * rm_route : flag, if packet isn't filtered (through split horizon or other peer filters), if primary router
   *              is considered outdated ^^ see @ 'drop outdated routing table entries'
   */
  bool rm_route = false;
  const bool is_icmp_errmsg = is_icmp && ([h_icmp, &rm_route] {
    switch(h_icmp->type) {
      case ICMP_ECHOREPLY: // = 0
      case ICMP_ECHO:      // = 8
      case  9: // Router advert
      case 10: // Router select
      case 13: // timestamp
      case 14: // timestamp reply
        return false;

      case ICMP_TIMXCEED:
        if(h_icmp->code == ICMP_TIMXCEED_INTRANS)
          rm_route = true;
        return true;

      case ICMP_UNREACH:
        switch(h_icmp->code) {
          case ICMP_UNREACH_HOST:
          case ICMP_UNREACH_NET:
            rm_route = true;
            break;
          default: break;
        }

      default:
        return true;
    }
  })();

  const auto &ip_src = h_ip->ip_src;
  const auto &ip_dst = h_ip->ip_dst;

  // am I an endpoint
  const bool iam_ep = have_local_ip && (source_is_local || ip_dst == local_ip);

  // we can use the ttl directly, it is 1 byte long
  if((!h_ip->ip_ttl) || (!iam_ep && h_ip->ip_ttl == 1)) {
    // ttl is too low -> DROP
    printf("ROUTER: drop packet %u (too low ttl = %u) from %s\n", pkid, h_ip->ip_ttl, source_desc_c);
    if(!is_icmp_errmsg)
      send_icmp_msg(ZICMPM_TTL, h_ip, source_peer);
    return;
  }

  // decrement ttl
  if(!iam_ep) --(h_ip->ip_ttl);

  // NOTE: make sure that no changes are done to buffer
  h_ip->ip_sum = 0;

  // update routes
  if(routes[ip_src.s_addr].add_router(
      source_peer,
      (have_local_ip && local_ip == ip_src) ? 0 : (MAXTTL - h_ip->ip_ttl)
  ))
    printf("ROUTER: add route to %s via %s\n", inet_ntoa(ip_src), source_desc_c);

  vector<remote_peer_ptr_t> ret;

  // get route to destination
  if(iam_ep && ip_dst == local_ip) {
    ret.emplace_back(make_shared<remote_peer_t>());
  } else if(const auto r = have_route(ip_dst.s_addr)) {
    ret.emplace_back(r->get_router());
  } else {
    printf("ROUTER: no known route to %s\n", inet_ntoa(ip_dst));
    ret = get_peers();
  }

  // split horizon
  rem_peer(ret, source_peer);

  // assert(!iam_ep && !rem_peer(local_ip.s_addr));

  if(ret.empty()) {
    printf("ROUTER: drop packet %u (no destination) from %s\n", pkid, source_desc_c);
    if(is_icmp_errmsg) return;

    send_icmp_msg((
      (have_local_ip && (local_ip.s_addr & local_netmask.s_addr) == (ip_dst.s_addr & local_netmask.s_addr))
        ? ZICMPM_UNREACH : ZICMPM_UNREACH_NET
    ), h_ip, source_peer);

    // to prevent routing loops
    // drop routing table entry, if there is any
    if(const auto route = have_route(ip_dst.s_addr)) {
      const auto d = get_remote_desc(route->get_router());
      printf("ROUTER: delete route to %s via %s (invalid)\n", inet_ntoa(ip_dst), d.c_str());
      route->del_primary_router();
    }
    return;
  }

  if(is_icmp) {
    if(is_icmp_errmsg) {
      if(rm_route && ((2 * sizeof(struct ip) + sizeof(struct icmphdr)) <= buflen)) {
        // drop outdated routing table entry, if there is any
        //  target = original destination
        const auto target = reinterpret_cast<const struct ip*>(buffer +
                            sizeof(struct ip) + sizeof(struct icmphdr))->ip_dst;
        if(const auto r = have_route(target.s_addr)) {
          if(r->del_router(source_peer)) {
            // routing table entry dropped
            printf("ROUTER: delete route to %s via %s (unreachable)\n", inet_ntoa(target), source_desc_c);
          }
          // if there is a routing table entry left -> discard
          if(!r->empty()) return;
        }
      }
    } else if(ret.size() == 1) {
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
            const auto m = ping_cache.match(edat, source_peer, h_ip->ip_ttl);
            if(m.match)
              if(const auto r = have_route(edat.src))
                r->update_router(m.router, m.hops, m.diff);
          }
          break;

        default: break;
      }
    }
  }

  sender.enqueue({{buffer, buffer + buflen}, move(ret), h_ip->ip_off, h_ip->ip_tos});
}

/** is_ipv4_packet
 * checks, if packet is a valid ipv4 packet
 *
 * @param buffer  the packet data
 * @param len     the length of the packet
 * @ret           is valid
 **/
static bool is_ipv4_packet(const char * const source_desc_c, const char buffer[], const uint16_t len) {
  const auto h_ip = reinterpret_cast<const struct ip*>(buffer);

  if(sizeof(struct ip) > len) {
    printf("ROUTER ERROR: received invalid ip packet (too small, size = %u)", len);
  } else if(h_ip->ip_v != 4) {
    printf("ROUTER ERROR: received a non-ipv4 packet (wrong version = %u)", h_ip->ip_v);
  } else {
    return true;
  }

  printf(" from %s\n", source_desc_c);
  return false;
}

// handlers for incoming ZPRN packets
typedef void (*zprn_handler_t)(const char * const, const remote_peer_ptr_t, const zprn&);

static void zprn_routemod_handler(const char *const source_desc_c, const remote_peer_ptr_t srca, const zprn &d) {
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

  zprn msg;
  msg.zprn_cmd = ZPRN_ROUTEMOD;
  msg.zprn_un.route.dsta = dsta;

  if(dsta == local_ip.s_addr) // a route to us is deleted (and we know we are here)
    msg.zprn_prio = 0;
  else if(r && !r->empty()) // we have a route
    msg.zprn_prio = r->_routers.front().hops;
  else
    return;

  send_zprn_msg(msg);
}

static void zprn_connmgmt_handler(const char *const source_desc_c, const remote_peer_ptr_t srca, const zprn &d) noexcept {
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

static void print_packet(const char buffer[], const uint16_t len) {
  printf("ROUTER DEBUG: pktdat:");
  const char * const ie = buffer + std::min(len, static_cast<uint16_t>(80));
  for(const char *i = buffer; i != ie; ++i)
    printf(" %02x", static_cast<unsigned>(*i));
  puts("");
}

/** read_packet
 * reads an variable length packet
 *
 * @param srca    (in/out) the source ip (router), expects srca = local_router
 * @param buffer  (out) the target storage (with size len)
 * @param len     (in/out) the length of the packet
 * @ret           succesful marker
 **/
static bool read_packet(const int server_fd, shared_ptr<remote_peer_detail_t> &srca, char buffer[], uint16_t &len, string &source_desc) {
  static const unordered_map<uint8_t, zprn_handler_t> zprn_dpt = {
    { ZPRN_ROUTEMOD, zprn_routemod_handler },
    { ZPRN_CONNMGMT, zprn_connmgmt_handler },
  };

  const auto local_router = srca;
  // create new shared_ptr, so that we don't overwrite local_router
  srca = make_shared<remote_peer_detail_t>();
  const uint16_t nread = recv_n(server_fd, buffer, len, &srca->saddr);

  // resolve remote --> shared_ptr
  for(const auto &i : remotes)
    if((*i) == (*srca)) {
      srca = i;
      break;
    }

  source_desc = get_remote_desc(srca);
  const char * const source_desc_c = source_desc.c_str();

  {
    const auto &d_zprn = *reinterpret_cast<const struct zprn*>(buffer);
    if(sizeof(struct zprn) <= nread && d_zprn.valid()) {
      const auto it = zprn_dpt.find(d_zprn.zprn_cmd);
      if(zs_likely(it != zprn_dpt.end())) it->second(source_desc_c, srca, d_zprn);
      return false; // don't forward
    }
  }

  if(!is_ipv4_packet(source_desc_c, buffer, nread))
    return false;

  const auto h_ip = reinterpret_cast<const struct ip*>(buffer);

  if(have_local_ip && srca == local_router)
    if(const uint16_t dsum = IN_CKSUM(h_ip)) {
      printf("ROUTER ERROR: invalid ipv4 packet (wrong checksum, chksum = %u, d = %u) from local\n",
        h_ip->ip_sum, dsum);
      return false;
    }

  // get total length
  len = ntohs(h_ip->ip_len);

  if(zs_unlikely(nread < len)) {
    printf("ROUTER ERROR: can't read whole ipv4 packet (too small, size = %u of %u) from %s\n", nread, len, source_desc_c);
    print_packet(buffer, nread);
  } else if(have_local_ip && h_ip->ip_src == local_ip) {
    printf("ROUTER WARNING: drop packet %u (looped with local as source)\n", ntohs(h_ip->ip_id));
  } else if(zs_unlikely(nread != len)) {
    printf("ROUTER WARNING: ipv4 packet size differ (size read %u / expected %u) from %s\n", nread, len, source_desc_c);
    print_packet(buffer, nread);
    return true;
  } else {
    return true;
  }
  return false;
}

static string format_time(const time_t x) {
  string buffer(10u, '\0');
  const struct tm *const tmi = localtime(&x);
  strftime(&buffer.front(), 10, "%H:%M:%S", tmi);
  return buffer;
}

static void print_routing_table(int) {
  puts("-- connected peers:");
  puts("Peer\t\tSeen\t\tConfig Entry");
  for(const auto &i: remotes)
    i->locked_crun([](const remote_peer_detail_t &o) {
      const string addr = o.addr2string();
      const auto seen = format_time(o.seen);
      printf("%s\t%s\t", addr.c_str(), seen.c_str());
      puts(o.cfgent_name());
    });
  puts("-- routing table:");
  puts("Destination\tGateway\t\tSeen\t\tLatency\tHops");
  for(const auto &i: routes) {
    const string dest = inet_ntoa({i.first});
    for(const auto &r: i.second._routers) {
      const string seen = format_time(r.seen),
        gateway = r.addr->locked_crun(
          [](const remote_peer_t &o) { return o.addr2string(); });
      printf("%s\t%s\t%s\t%4.2f\t%u\n", dest.c_str(), gateway.c_str(), seen.c_str(), r.latency, static_cast<unsigned>(r.hops));
    }
  }
  fflush(stdout);
}

static atomic<bool> b_do_shutdown;

static void do_shutdown(int) noexcept
  { b_do_shutdown = true; }

static void del_route_msg(const decltype(routes)::value_type &addr_v, const remote_peer_ptr_t &router) {
  // discard route message
  const auto d = get_remote_desc(router);
  printf("ROUTER: delete route to %s via %s (outdated)\n", inet_ntoa({addr_v.first}), d.c_str());
}

static bool do_epoll_add(const int epoll_fd, const int fd_to_add) {
  struct epoll_event epevent;
  epevent.events = EPOLLIN;
  epevent.data.fd = fd_to_add;
  if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd_to_add, &epevent)) {
    fprintf(stderr, "STARTUP ERROR: epoll_ctl(%d, ADD, %d,) failed\n", epoll_fd, fd_to_add);
    close(epoll_fd);
    return false;
  }
  return true;
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
          fprintf(stderr, "STARTUP ERROR: unable to open logfile '%s'\n", lfp.c_str());
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

  // add all local + server file descriptors to epoll
  const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);

  if(epoll_fd == -1) {
    fprintf(stderr, "STARTUP ERROR: epoll_create1() failed\n");
    return 1;
  }

  if(!do_epoll_add(epoll_fd, local_fd))
    return 1;

  for(const auto &i : server_fds)
    if(!do_epoll_add(epoll_fd, i.second))
      return 1;

  // notify our peers that we are here
  zprn msg;
  msg.zprn_cmd = ZPRN_CONNMGMT;
  msg.zprn_prio = ZPRN_CONNMGMT_OPEN;
  msg.zprn_un.route.dsta = local_ip.s_addr;
  send_zprn_msg(msg);

  // add route to ourselves to avoid sending two 'ZPRN add route' packets
  const auto local_router = make_shared<remote_peer_detail_t>();
  routes[local_ip.s_addr].add_router(local_router, 0);

  my_signal(SIGINT, do_shutdown);
  my_signal(SIGTERM, do_shutdown);

  int retcode = 0, epevcnt;

  // define the peer transaction temp vars outside of the loop to avoid unnecessarily mem allocs
  vector<bool> found_remotes(zprd_conf.remotes.size(), false);
#define MAX_EVENTS 32
  struct epoll_event epevents[MAX_EVENTS];

  while(!b_do_shutdown) {
    /* last_time - global time, updated after select
       pastt     - time before select
      */
    { // use select() to handle two descriptors at once
      const auto pastt = last_time;

      epevcnt = epoll_wait(epoll_fd, epevents, MAX_EVENTS, -1);

      if(epevcnt == -1) {
        if(errno == EINTR) continue;
        perror("epoll_wait()");
        retcode = 1;
        break;
      }

      uint16_t nread = BUFSIZE;
      char buffer[BUFSIZE];
      shared_ptr<remote_peer_detail_t> peer_ptr;
      string source_desc;

      for(int i = 0; i < epevcnt; ++i) {
        const int cur_fd = epevents[i].data.fd;
        if(!(epevents[i].events & EPOLLIN)) continue;
        if(cur_fd == local_fd) {
          // data from tun/tap: just read it and write it to the network
          nread = cread(local_fd, buffer, BUFSIZE);
          if(is_ipv4_packet("local", buffer, nread))
            route_packet(local_router, buffer, nread, "local");
        } else {
          // data from the network: read it, and write it to the tun/tap interface.
          peer_ptr = local_router;
          if(read_packet(cur_fd, peer_ptr, buffer, nread, source_desc))
            route_packet(peer_ptr, buffer, nread, source_desc.c_str());
        }
      }

      // only cleanup things if at least 1 second passed since last iteration
      last_time = time(nullptr);
      if(last_time == pastt) continue;
    }

    for(auto &i : remotes) {
      auto &pdat = *i;

      if(pdat.cent)
        found_remotes[pdat.cent - 1] = true;

      // skip remotes which aren't timed out
      if(zs_likely((last_time - zprd_conf.remote_timeout) < pdat.seen))
        continue;

      // try to update ip
      if(update_server_addr(pdat))
        continue;

      for(auto &r: routes)
        if(r.second.del_router(i))
          del_route_msg(r, i);

      pdat.to_discard = true;
    }

    // cleanup routes, needs to be done after del_router calls
    for(auto it = routes.begin(); it != routes.end();) {
      auto &ise = it->second;
      ise.cleanup([=](const remote_peer_ptr_t &router)
        { del_route_msg(*it, router); });

      const bool iee = ise.empty();
      if(iee || ise._fresh_add) {
        ise._fresh_add = false;

        msg.zprn_cmd = ZPRN_ROUTEMOD;
        msg.zprn_un.route.dsta = it->first;
        msg.zprn_prio = (iee ? ZPRN_ROUTEMOD_DELETE : ise._routers.front().hops);
        send_zprn_msg(msg);
      }

      // NOTE: don't use *it after erase (see Issue #1)
      if(iee) it = routes.erase(it);
      else ++it;
    }

    // discard remotes (after cleanup -> cleanup has a chance to notify them)
    for(auto it = remotes.cbegin(); it != remotes.cend();) {
      auto &spdat = *it;
      auto &pdat = *spdat;
      if(pdat.to_discard)
        goto do_discard;
      // check for duplicates
      for(auto kt = it + 1; kt != remotes.cend();) {
        auto &odat = **kt;
        if(!odat.to_discard && pdat == odat) {
          // we found a duplicate
          // delete the one which has a corresponding config entry or a lower use count
          ((!pdat.cent && odat.cent) || (spdat.use_count() < kt->use_count()) ? &pdat : &odat)
            ->to_discard = true;
        }
        ++kt;
      }
      if(pdat.to_discard)
        goto do_discard;
      ++it;
      continue;

     do_discard:
      for(auto &r: routes)
        if(r.second.del_router(spdat))
          del_route_msg(r, spdat);

      it = remotes.erase(it);
    }

    size_t i = 0;
    for(auto fri : found_remotes) {
      if(fri) {
        fri = false;
      } else {
        // remote from config wasn't found in 'remotes' map
        connect2server(zprd_conf.remotes[i], i);
      }
      ++i;
    }

    // flush output
    fflush(stdout);
    fflush(stderr);
  }

  close(epoll_fd);

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
