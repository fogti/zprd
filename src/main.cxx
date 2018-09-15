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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h> // linux-specific epoll
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <fcntl.h>

// TODO: use getifaddrs(3) #include <ifaddrs.h>

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
#include "crest.h"
#include "crw.h"
#include "iAFa.hpp"
#include "ping_cache.hpp"
#include "remote_peer.hpp"
#include "resolve.hpp"
#include "routes.hpp"
#include "zprd_conf.hpp"
#include "zprn.hpp"

// -lowlevelzs
#include <zs/ll/zsig.h>

// buffer for reading from tun/tap interface, must be greater than 1500
#define BUFSIZE 0xffff

using namespace std;

/*** global vars ***/
zprd_conf_t zprd_conf;
time_t last_time;

/*** helper classes ***/

struct send_data final {
  vector<char> buffer;
  vector<remote_peer_ptr_t> dests;
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

struct zprn2_sdat {
  zprn_v2 zprn;
  vector<remote_peer_ptr_t> dests;

  zprn2_sdat(const zprn2_sdat &o) = default;
  zprn2_sdat(zprn2_sdat &&o) noexcept
    : zprn(move(o.zprn)), dests(move(o.dests)) { }

  zprn2_sdat(const zprn_v2 &zprn_, decltype(dests) &&d) noexcept
    : zprn(zprn_), dests(move(d)) { }

  zprn2_sdat(zprn_v2 &&zprn_, decltype(dests) &&d) noexcept
    : zprn(move(zprn_)), dests(move(d)) { }

  zprn2_sdat& operator=(const zprn2_sdat &o) = default;

  zprn2_sdat& operator=(zprn2_sdat &&o) noexcept {
    if(this != &o) {
      zprn  = move(o.zprn);
      dests = move(o.dests);
    }
    return *this;
  }
};

class sender_t final {
  vector<send_data> _tasks;
  vector<zprn2_sdat> _zprn_msgs;

  // sync
  mutex _mtx;
  condition_variable _cond;
  bool _stop = false;

  void worker_fn() noexcept;

 public:
  ~sender_t() noexcept { stop(); }

  void enqueue(send_data &&dat);
  void enqueue(zprn2_sdat &&dat);
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

static vector<remote_peer_detail_ptr_t> remotes;
static vector<xner_addr_t> locals;
static unordered_map<inner_addr_t, route_via_t, inner_addr_hash> routes;

static sender_t     sender;
static ping_cache_t ping_cache;

// FIXME: replace local_{ip,netmask} with locals...
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

  // use remote_peer_t as abstraction layer + helper
  ss.ss_family = sa_family;
  local_pt.set_port(zprd_conf.data_port, false);
  if(!local_pt.set2catchall()) {
    fprintf(stderr, "STARTUP ERROR: setup_server_fd: unsupported address family %u\n", static_cast<unsigned>(sa_family));
    goto error;
  }

  if(bind(server_fd, reinterpret_cast<struct sockaddr*>(&ss), sizeof(ss)) < 0) {
    perror("bind()");
    goto error;
  }

  server_fds[sa_family] = server_fd;
  return true;

 error:
  close(server_fd);
  return false;
}

static void connect2server(const string &r, const size_t cent) {
  struct sockaddr_storage remote;
  memset(&remote, 0, sizeof(remote));
  if(!resolve_hostname(r.c_str(), remote, zprd_conf.preferred_af))
    return;
  auto ptr = make_shared<remote_peer_detail_t>(remote_peer_t(remote), cent);
  ptr->set_port_if_unset(zprd_conf.data_port, false);
  const string remote_desc = ptr->addr2string();
  remotes.emplace_back(move(ptr));
  printf("CLIENT: connected to server %s\n", remote_desc.c_str());
}

static bool update_server_addr(remote_peer_detail_t &pdat) {
  struct sockaddr_storage remote;
  // try to update ip
  if(pdat.cent && resolve_hostname(pdat.cfgent_name(), remote, zprd_conf.preferred_af)) {
    pdat.locked_run([&remote](remote_peer_detail_t &o) {
      o.seen = last_time;
      o.set_saddr(remote, false);
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
    string line;
    vector<string> addrs;
    while(getline(in, line)) {
      if(line.empty() || line.front() == '#') continue;
      string arg = line.substr(1);
      switch(line.front()) {
        case 'A':
          addrs.emplace_back(move(arg));
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

    const string zs_devstr = " dev '" + zprd_conf.iface + "'";

    if(!addrs.empty()) {
      have_local_ip = true;

      runcmd("ip addr flush '" + zprd_conf.iface + "'");
      for(const auto &i : addrs)
        runcmd("ip addr add '" + i + "'" + zs_devstr);

      // TODO: use getifaddrs
    }

    runcmd("ip link set" + zs_devstr + " mtu 1472");
    runcmd("ip link set" + zs_devstr + " up");

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
  const remote_peer_t &peer = *addr;
  return (addr.unique()
    ? get_remote_desc(peer)
    : peer.locked_crun([](const remote_peer_t &o)
        { return get_remote_desc(o); })
  );
}

static bool x_less(const remote_peer_ptr_t &a, const remote_peer_ptr_t &b) {
  return (*a) < (*b);
}

/* find_or_emplace_peer
 * @return
 *   true  found
 *   false emplace'd
 */
static bool find_or_emplace_peer(vector<remote_peer_detail_ptr_t> &vec, remote_peer_detail_ptr_t &item) {
  // perform a binary find
  const auto it = lower_bound(vec.cbegin(), vec.cend(), item, x_less);
  if(it == vec.cend() || **it != *item) {
    vec.emplace(it, item);
    return false;
  }
  if(*it != item)
    item = *it;
  return true;
}

static bool rem_peer(vector<remote_peer_ptr_t> &vec, const remote_peer_ptr_t &item) {
  // perform a binary find
  const auto it = lower_bound(vec.cbegin(), vec.cend(), item, x_less);
  if(it == vec.cend() || (*it != item && **it != *item))
    return false;
  // erase element
  // NOTE: don't swap [back] with [*it], as that destructs sorted range
  vec.erase(it);
  return true;
}

static bool sendto_peer(const remote_peer_ptr_t &i, const char * const buf, const size_t buflen) noexcept {
  return i->locked_crun([&](const remote_peer_t &o) noexcept {
    if(sendto(server_fds[o.saddr.ss_family], buf, buflen, 0, reinterpret_cast<const struct sockaddr *>(&o.saddr), sizeof(o.saddr)) < 0) {
      perror("sendto()");
      return false;
    }
    return true;
  });
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
  vector<zprn2_sdat> zprn_msgs;
  unordered_map<remote_peer_ptr_t, vector<char>> zprn_buf;
  vector<char> zprn_hdrv(sizeof(zprn_v2hdr), 0);
  {
    const auto h_zprn = reinterpret_cast<zprn_v2hdr *>(zprn_hdrv.data());
    h_zprn->zprn_ver = 2;
  }

  while(true) {
    {
      unique_lock<mutex> lock(_mtx);
      _cond.wait(lock, [this] { return _stop || !(_tasks.empty() && _zprn_msgs.empty()); });
      if(_tasks.empty() && _zprn_msgs.empty()) return;
      tasks = move(_tasks);
      _tasks = {};
      zprn_msgs = move(_zprn_msgs);
      _zprn_msgs = {};
    }

    bool got_error = false;

    // send normal data
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
      for(const auto &i : dat.dests)
        if(!sendto_peer(i, buf, buflen))
          got_error = true;
    }

    if(got_error) fflush(stderr);
    if(zprn_msgs.empty()) continue;
    got_error = false;
    tasks.clear();

    // setup outer Dont-Frag bit + TOS
    if(df)  set_df(false);
    if(tos) set_tos(0);

    // build ZPRN v2 messages for each destination
    // FIXME: split zprn packet in multiple parts if it exceeds a certain size (e.g. 1232 bytes = 35 packets in worst case),
    //  but it is irrealistic, that this happens.
    //  This is a problem because IPv6 does not perform fragmentation.
    for(auto &i : zprn_msgs) {
      const size_t zmsiz = i.zprn.get_needed_size();
      zprn_buf.reserve(i.dests.size());
      {
        auto &x = i.zprn.route.type;
        x = htons(x);
      }
      const char *const zmbeg = reinterpret_cast<const char *>(&i.zprn), *const zmend = zmbeg + zmsiz;
      for(const auto &dest : i.dests) {
        auto bufitem = zprn_buf.try_emplace(dest, zprn_hdrv).first->second;
        bufitem.reserve(bufitem.size() + zmsiz);
        bufitem.insert(bufitem.end(), zmbeg, zmend);
      }
    }

    zprn_msgs.clear();

    // send ZPRN v2 messages
    for(const auto &dat : zprn_buf)
      if(!sendto_peer(dat.first, dat.second.data(), dat.second.size()))
        got_error = true;

    zprn_buf.clear();
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

void sender_t::enqueue(zprn2_sdat &&dat) {
  // sanitize dat.dests
  if(dat.dests.empty())
    return;
  dat.dests.shrink_to_fit();

  // move into queue
  {
    lock_guard<mutex> lock(_mtx);
    _zprn_msgs.emplace_back(std::move(dat));
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
         std::min(static_cast<unsigned short>(8), ntohs(orig_hip->ip_len)));

  // calculate icmp checksum
  h_icmp->checksum = IN_CKSUM(h_icmp);
  sender.enqueue(move(dat));
}

static void send_icmp6_msg(const zprd_icmpe msg, struct ip6_hdr * const orig_hip, const remote_peer_ptr_t &source_ip) {
  constexpr const size_t ip6hlen = sizeof(struct ip6_hdr);
  constexpr const size_t buflen = 2 * ip6hlen + sizeof(struct icmp6_hdr) + 8;
  send_data dat{vector<char>(buflen, 0), {source_ip}, htons(IP_DF)};
  char *const buffer = dat.buffer.data();

  const auto h_ip = reinterpret_cast<struct ip6_hdr*>(buffer);
  char * bufnxt  = buffer + ip6hlen;
  h_ip->ip6_vfc  = 0x60;
  h_ip->ip6_plen = htons(static_cast<uint16_t>(buflen - ip6hlen));
  h_ip->ip6_nxt  = 0x3a;
  h_ip->ip6_hops = MAXTTL;

  // copy ip addrs
  for(const auto &i : locals) {
    if(i.type != IAFA_AT_INET6)
      continue;
    memcpy(&h_ip->ip6_src, i.addr, sizeof(struct in6_addr));
    break;
  }
  memcpy(&h_ip->ip6_dst, &orig_hip->ip6_src, sizeof(struct in6_addr));

  // setup ICMPv6 part
  const auto h_icmp = reinterpret_cast<struct icmp6_hdr*>(bufnxt);
  bufnxt += sizeof(struct icmp6_hdr);

  switch(msg) {
    case ZICMPM_TTL:
      h_icmp->icmp6_type = 0x03;
      h_icmp->icmp6_code = 0x00;
      break;

    case ZICMPM_UNREACH:
      h_icmp->icmp6_type = 0x01;
      h_icmp->icmp6_code = 0x00;
      break;

    case ZICMPM_UNREACH_NET:
      h_icmp->icmp6_type = 0x01;
      h_icmp->icmp6_code = 0x03;
      break;

    default:
      fprintf(stderr, "SEND ERROR: invalid ZICMP Message code: %d\n", msg);
      return;
  }

  // setup payload = orig ip header
  memcpy(bufnxt, orig_hip, ip6hlen);
  bufnxt += ip6hlen;

  // setup secondary payload = first 8 bytes of original payload
  memcpy(bufnxt, orig_hip + ip6hlen,
         std::min(static_cast<unsigned short>(8), ntohs(orig_hip->ip6_plen)));

  // calculate ICMPv6 checksum
  // - create pseudo-header
  // - calculate chksum
  {
    vector<char> pseudohdr;
    pseudohdr.reserve(buflen);
    // ip addrs
    pseudohdr.insert(pseudohdr.end(), buffer + 8, buffer + 32);
    // payload length
    const uint32_t pll = htons(static_cast<uint32_t>(buflen - ip6hlen));
    pseudohdr.insert(pseudohdr.end(), &pll, &pll + sizeof(pll));
    // NULL
    pseudohdr.emplace_back(0);
    pseudohdr.emplace_back(0);
    pseudohdr.emplace_back(0);
    // ip6_nxt = 0x3a
    pseudohdr.emplace_back(0x3a);
    // REST
    pseudohdr.insert(pseudohdr.end(), buffer + ip6hlen, buffer + buflen);
    // update checksum
    h_icmp->icmp6_cksum = in_cksum(reinterpret_cast<const uint16_t*>(pseudohdr.data()), pseudohdr.size());
  }

  sender.enqueue(move(dat));
}

static route_via_t* have_route(const inner_addr_t &dsta) noexcept {
  const auto it = routes.find(dsta);
  return (
    (it == routes.end() || it->second.empty())
      ? nullptr : &(it->second)
  );
}

static route_via_t* have_route(const uint32_t dsta) noexcept {
  return have_route(inner_addr_t(dsta));
}

static void sort_peers() {
  std::sort(remotes.begin(), remotes.end(), x_less);
}

static auto get_peers() {
  vector<remote_peer_ptr_t> ret(remotes.begin(), remotes.end());
  return ret;
}

static void send_zprn_msg(const zprn_v1 &msg) {
  auto peers = get_peers();

  // split horizon
  if(msg.zprn_cmd == ZPRN_ROUTEMOD && msg.zprn_prio != ZPRN_ROUTEMOD_DELETE)
    if(const auto r = have_route(inner_addr_t(msg.zprn_un.route.dsta)))
      rem_peer(peers, r->get_router());

  const auto msgptr = reinterpret_cast<const char *>(&msg);
  sender.enqueue(send_data{{msgptr, msgptr + sizeof(msg)}, move(peers)});
}

static void send_zprn_msg(const zprn_v2 &msg) {
  auto peers = get_peers();

  // split horizon
  if(msg.zprn_cmd == ZPRN_ROUTEMOD && msg.zprn_prio != ZPRN_ROUTEMOD_DELETE)
    if(const auto r = have_route(msg.route))
      rem_peer(peers, r->get_router());

  sender.enqueue(zprn2_sdat{msg, move(peers)});
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
static void route_packet(const remote_peer_detail_ptr_t &source_peer, char *const __restrict__ buffer, const uint16_t buflen, const char *const __restrict__ source_desc_c) {
  const bool source_is_local = (*source_peer == remote_peer_t());

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
  if(routes[inner_addr_t(ip_src.s_addr)].add_router(
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
      const ping_cache_t::data_t edat(inner_addr_t(ip_src.s_addr), inner_addr_t(ip_dst.s_addr), echo.id, echo.sequence);
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
[[gnu::hot]]
static void route6_packet(const remote_peer_detail_ptr_t &source_peer, char *const __restrict__ buffer, const uint16_t buflen, const char *const __restrict__ source_desc_c) {
  const bool source_is_local = (*source_peer == remote_peer_t());

  const auto h_ip    = reinterpret_cast<struct ip6_hdr*>(buffer);
  const bool is_icmp = (h_ip->ip6_nxt == 0x3a);

  if(is_icmp && (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) > buflen) {
    printf("ROUTER: drop packet (too small icmp6 packet; size = %u) from %s\n", buflen, source_desc_c);
    return;
  }

  // NOTE: h_icmp is only valid if is_icmp is true
  const auto h_icmp  = reinterpret_cast<const struct icmp6_hdr*>(buffer + sizeof(ip6_hdr));

  // TODO
}

static uint8_t get_ip_version(const char buffer[], const uint16_t len) {
  if(len < 2) return 255;
  return reinterpret_cast<const struct ip*>(buffer)->ip_v;
}

// function to route a generic IP-whatever packet
static void route_genip_packet(const remote_peer_detail_ptr_t &source_peer, char *const __restrict__ buffer, const uint16_t buflen, const char *const __restrict__ source_desc_c) {
  typedef void (*genip_route_fn)(const remote_peer_detail_ptr_t&, char * __restrict__, uint16_t, const char * __restrict__);
  static const unordered_map<uint8_t, genip_route_fn> jt = {
    { 4, route_packet },
    { 6, route6_packet },
  };

  if(*source_peer != remote_peer_t())
    source_peer->seen = last_time;

  const auto it = jt.find(get_ip_version(buffer, buflen));
  if(it != jt.end()) (it->second)(source_peer, buffer, buflen, source_desc_c);
}

// is inner_addr:o a local ip?
static bool am_ii_addr(const inner_addr_t &o) noexcept {
  for(const auto &i : locals)
    if(*reinterpret_cast<const inner_addr_t *>(&i) == o)
      return true;
  return false;
}

// handlers for incoming ZPRN packets
typedef void (*zprn_v1_handler_t)(const char * const, const remote_peer_ptr_t&, const zprn_v1&);

static void zprn_v1_routemod_handler(const char *const source_desc_c, const remote_peer_ptr_t &srca, const zprn_v1 &d) {
  const auto dsta = d.zprn_un.route.dsta;
  if(d.zprn_prio != ZPRN_ROUTEMOD_DELETE) {
    // add route
    if(routes[inner_addr_t(dsta)].add_router(srca, d.zprn_prio + 1))
      printf("ROUTER: add route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);
    return;
  }

  // delete route
  const auto r = have_route(dsta);
  if(r && r->del_router(srca))
    printf("ROUTER: delete route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);

  zprn_v1 msg;
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

static void zprn_v1_connmgmt_handler(const char *const source_desc_c, const remote_peer_ptr_t &srca, const zprn_v1 &d) noexcept {
  const auto dsta = d.zprn_un.route.dsta;
  if(d.zprn_prio == ZPRN_CONNMGMT_OPEN) {
    if(routes[inner_addr_t(dsta)].add_router(srca, 1))
      printf("ROUTER: add route to %s via %s (notified)\n", inet_ntoa({dsta}), source_desc_c);
    return;
  }

  for(auto &r: routes) {
    const string dest_name = r.first.to_string();
    if(r.second.del_router(srca))
      printf("ROUTER: delete route to %s via %s (notified)\n", dest_name.c_str(), source_desc_c);
  }

  if(const auto r = have_route(dsta)) {
    r->_routers.clear();
    printf("ROUTER: delete route to %s (notified)\n", inet_ntoa({dsta}));
  }
}

typedef void (*zprn_v2_handler_t)(const remote_peer_ptr_t&, const char * const, const zprn_v2&);

static void zprn_v2_routemod_handler(const remote_peer_ptr_t &srca, const char * const source_desc_c, const zprn_v2 &d) noexcept {
  const auto &dsta = d.route;
  const string dstdesc = dsta.to_string();
  const char * const ddcs = dstdesc.c_str();
  if(d.zprn_prio != ZPRN_ROUTEMOD_DELETE) {
    // add route
    if(routes[dsta].add_router(srca, d.zprn_prio + 1))
      printf("ROUTER: add route to %s via %s (notified)\n", ddcs, source_desc_c);
    return;
  }

  // delete route
  const auto r = have_route(dsta);
  if(r && r->del_router(srca))
    printf("ROUTER: delete route to %s via %s (notified)\n", ddcs, source_desc_c);

  zprn_v2 msg = d;
  if(am_ii_addr(dsta)) // a route to us is deleted (and we know we are here)
    msg.zprn_prio = 0;
  else if(r && !r->empty()) // we have a route
    msg.zprn_prio = r->_routers.front().hops;
  else
    return;

  send_zprn_msg(msg);
}

static void zprn_v2_connmgmt_handler(const remote_peer_ptr_t &srca, const char * const source_desc_c, const zprn_v2 &d) noexcept {
  const auto &dsta = d.route;
  const string dstdesc = dsta.to_string();
  const char * const ddcs = dstdesc.c_str();
  if(d.zprn_prio == ZPRN_CONNMGMT_OPEN) {
    if(routes[dsta].add_router(srca, 1))
      printf("ROUTER: add route to %s via %s (notified)\n", ddcs, source_desc_c);
    return;
  }

  // close connection
  for(auto &r: routes) {
    const string dest_name = r.first.to_string();
    if(r.second.del_router(srca))
      printf("ROUTER: delete route to %s via %s (notified)\n", dest_name.c_str(), source_desc_c);
  }

  if(const auto r = have_route(dsta)) {
    r->_routers.clear();
    printf("ROUTER: delete route to %s via %s (notified)\n", ddcs, source_desc_c);
  }
}

static void print_packet(const char buffer[], const uint16_t len) {
  printf("ROUTER DEBUG: pktdat:");
  const char * const ie = buffer + std::min(len, static_cast<uint16_t>(80));
  for(const char *i = buffer; i != ie; ++i)
    printf(" %02x", static_cast<unsigned>(*i));
  puts("");
}

static bool handle_zprn_v1_pkt(const remote_peer_detail_ptr_t &srca, const char buffer[], const uint16_t len, const char * const __restrict__ source_desc_c) {
  static const unordered_map<uint8_t, zprn_v1_handler_t> dpt = {
    { ZPRN_ROUTEMOD, zprn_v1_routemod_handler },
    { ZPRN_CONNMGMT, zprn_v1_connmgmt_handler },
  };
  const auto &d_zprn = *reinterpret_cast<const struct zprn_v1*>(buffer);
  if(sizeof(struct zprn_v1) <= len && d_zprn.valid()) {
    const auto it = dpt.find(d_zprn.zprn_cmd);
    if(zs_likely(it != dpt.end())) it->second(source_desc_c, srca, d_zprn);
    return true;
  }
  return false;
}

static bool handle_zprn_v2_pkt(const remote_peer_detail_ptr_t &srca, char buffer[], const uint16_t len, const char * const __restrict__ source_desc_c) {
  static const unordered_map<uint8_t, zprn_v2_handler_t> dpt = {
    { ZPRN_ROUTEMOD, zprn_v2_routemod_handler },
    { ZPRN_CONNMGMT, zprn_v2_connmgmt_handler },
  };

  const auto h_zprn = reinterpret_cast<const struct zprn_v2hdr*>(buffer);
  if(!((sizeof(struct zprn_v2hdr) + sizeof(struct zprn_v2)) < len && h_zprn->valid()))
    return false;

  char *bptr = buffer + sizeof(struct zprn_v2hdr);
  const char * const eobptr = buffer + len;
  while(bptr < eobptr) {
    const auto cur_ent = reinterpret_cast<struct zprn_v2*>(bptr);
    { // ^ sender_t::worker_fn
      auto &x = cur_ent->route.type;
      x = ntohs(x);
    }

    if((bptr + cur_ent->get_needed_size()) > eobptr)
      break;

    // handle entry
    const auto it = dpt.find(cur_ent->zprn_cmd);
    if(zs_likely(it != dpt.end())) it->second(srca, source_desc_c, *cur_ent);

    // next entry
    bptr += cur_ent->get_needed_size();
  }
  return true;
}

static bool handle_zprn_pkt(const remote_peer_detail_ptr_t &srca, char buffer[], const uint16_t len, const char * const __restrict__ source_desc_c) {
  if(len < 4 || buffer[0]) return false;
  switch(buffer[1]) {
    case 1: return handle_zprn_v1_pkt(srca, buffer, len, source_desc_c);
    case 2: return handle_zprn_v2_pkt(srca, buffer, len, source_desc_c);
    default: return false;
  }
}

static bool verify_ipv4_packet(const remote_peer_detail_ptr_t &srca, const char buffer[], uint16_t &len, const char *source_desc_c) {
  const uint16_t nread = len;
  const auto h_ip = reinterpret_cast<const struct ip*>(buffer);
  const auto local_router = make_shared<remote_peer_detail_t>();

  if(have_local_ip && srca == local_router)
    if(const uint16_t dsum = IN_CKSUM(h_ip)) {
      printf("ROUTER ERROR: invalid ipv4 packet (wrong checksum, chksum = %u, d = %u) from local\n",
        h_ip->ip_sum, dsum);
      print_packet(buffer, nread);
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

static bool verify_ipv6_packet(const remote_peer_detail_ptr_t &srca, const char buffer[], uint16_t &len, const char *source_desc_c) {
  const uint16_t nread = len;
  const auto h_ip = reinterpret_cast<const struct ip6_hdr*>(buffer);

  // get total length
  len = ntohs(h_ip->ip6_plen) + sizeof(struct ip6_hdr);

  if(zs_unlikely(nread < len)) {
    printf("ROUTER ERROR: can't read whole ipv6 packet (too small, size = %u of %u) from %s\n", nread, len, source_desc_c);
    print_packet(buffer, nread);
  } else if(have_local_ip && am_ii_addr(inner_addr_t(h_ip->ip6_src))) {
    printf("ROUTER WARNING: drop ipv6 packet (looped with local as source)\n");
  } else {
    if(zs_unlikely(nread != len)) {
      printf("ROUTER WARNING: ipv6 packet size differ (size read %u / expected %u) from %s\n", nread, len, source_desc_c);
      print_packet(buffer, nread);
    }
    return true;
  }
  return false;
}

/** read_packet
 * reads an variable length packet
 *
 * @param srca    (in/out) the source ip (router)
 * @param buffer  (out) the target storage (with size len)
 * @param len     (in/out) the length of the packet
 **/
static void read_packet(const int server_fd, remote_peer_detail_ptr_t &srca, char buffer[], uint16_t &len) {
  // create new shared_ptr, so that we don't overwrite previous src'peer
  srca = make_shared<remote_peer_detail_t>();
  len  = recv_n(server_fd, buffer, len, &srca->saddr);

  // resolve remote --> shared_ptr
  find_or_emplace_peer(remotes, srca);
}

/** verify_packet
 * verifies an variable length packet
 */
static bool verify_packet(const remote_peer_detail_ptr_t &srca, char buffer[], uint16_t &len, string &source_desc) {
  source_desc = get_remote_desc(srca);
  const auto source_desc_c = source_desc.c_str();

  switch(const auto ipver = get_ip_version(buffer, len)) {
    case 0:
      if(!handle_zprn_pkt(srca, buffer, len, source_desc_c))
        printf("ROUTER ERROR: got invalid ZPRN packet from %s\n", source_desc_c);
      break;

    case 4:
      if(sizeof(struct ip) > len)
        goto length_error;
      return verify_ipv4_packet(srca, buffer, len, source_desc_c);

    case 6:
      if(sizeof(struct ip6_hdr) > len)
        goto length_error;
      return verify_ipv6_packet(srca, buffer, len, source_desc_c);

    default:
      printf("ROUTER ERROR: received a packet with unknown payload type (wrong ip_ver = %u) from %s\n", ipver, source_desc_c);
  }
  return false;

  length_error:
    printf("ROUTER ERROR: received invalid ip packet (too small, size = %u) from %s\n", len, source_desc_c);
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
    const string dest = i.first.to_string();
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
  const auto destn = addr_v.first.to_string();
  const auto d = get_remote_desc(router);
  printf("ROUTER: delete route to %s via %s (outdated)\n", destn.c_str(), d.c_str());
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

static void send_zprn_connmgmt_msg(const uint8_t prio) {
  // notify our peers that we are here
  // FIXME: handle other AF_*, e.g. IPv6
  zprn_v2 msg;
  msg.zprn_cmd = ZPRN_CONNMGMT;
  msg.zprn_prio = prio;
  if(locals.empty())
    memset(&msg.route, 0, sizeof(msg.route));
  else
    msg.route = locals.front();
  send_zprn_msg(msg);
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
  send_zprn_connmgmt_msg(ZPRN_CONNMGMT_OPEN);

  // add route to ourselves to avoid sending two 'ZPRN add route' packets
  const auto local_router = make_shared<remote_peer_detail_t>();
  routes[inner_addr_t(local_ip.s_addr)].add_router(local_router, 0);

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
      remote_peer_detail_ptr_t peer_ptr;
      string source_desc;

      for(int i = 0; i < epevcnt; ++i) {
        const int cur_fd = epevents[i].data.fd;
        if(!(epevents[i].events & EPOLLIN)) continue;
        if(cur_fd == local_fd) {
          // data from tun/tap: just read it and write it to the network
          nread = cread(local_fd, buffer, BUFSIZE);
          peer_ptr = local_router;
        } else {
          // data from the network: read it, and write it to the tun/tap interface.
          read_packet(cur_fd, peer_ptr, buffer, nread);
        }
        if(nread && verify_packet(peer_ptr, buffer, nread, source_desc))
          route_genip_packet(peer_ptr, buffer, nread, source_desc.c_str());
      }

      // only cleanup things if at least 1 second passed since last iteration
      last_time = time(nullptr);
      if(last_time == pastt) continue;
    }

    for(auto it = remotes.cbegin(); it != remotes.cend(); ++it) {
      auto &i = *it;
      auto &pdat = *i;

      if(pdat.cent)
        found_remotes[pdat.cent - 1] = true;

      // skip remotes which aren't timed out or try to update ip
      if(zs_likely((last_time - zprd_conf.remote_timeout) < pdat.seen) || update_server_addr(pdat)) {
        // check for duplicates
        for(auto kt = it + 1; kt != remotes.cend();) {
          auto &odat = **kt;
          if(!odat.to_discard && pdat == odat) {
            // we found a duplicate
            // delete the one which has a corresponding config entry or a lower use count
            ((!pdat.cent && odat.cent) || (i.use_count() < kt->use_count()) ? &pdat : &odat)
              ->to_discard = true;
          }
          ++kt;
        }
        if(!pdat.to_discard)
          continue;
      }

     do_discard:
      for(auto &r: routes)
        if(r.second.del_router(i))
          del_route_msg(r, i);

      pdat.to_discard = true;
    }

    // cleanup routes, needs to be done after del_router calls
    zprn_v2 msg;
    msg.zprn_cmd = ZPRN_ROUTEMOD;
    for(auto it = routes.begin(); it != routes.end();) {
      auto &ise = it->second;
      ise.cleanup([=](const remote_peer_ptr_t &router)
        { del_route_msg(*it, router); });

      const bool iee = ise.empty();
      if(iee || ise._fresh_add) {
        ise._fresh_add = false;

        msg.zprn_prio = (iee ? ZPRN_ROUTEMOD_DELETE : ise._routers.front().hops);
        msg.route = it->first;
        send_zprn_msg(msg);
      }

      // NOTE: don't use *it after erase (see Issue #1)
      if(iee) it = routes.erase(it);
      else ++it;
    }

    // discard remotes (after cleanup -> cleanup has a chance to notify them)
    for(auto it = remotes.cbegin(); it != remotes.cend();) {
      if((*it)->to_discard)
        it = remotes.erase(it);
      else
        ++it;
    }

    size_t i = 0;
    for(const auto fri : found_remotes) {
      if(!fri) // remote from config wasn't found in 'remotes' map
        connect2server(zprd_conf.remotes[i], i);
      ++i;
    }

    sort_peers();

    // flush output
    fflush(stdout);
    fflush(stderr);
  }

  close(epoll_fd);

  // notify our peers that we quit
  puts("ROUTER: disconnect from peers");
  send_zprn_connmgmt_msg(ZPRN_CONNMGMT_CLOSE);

  // shutdown the sender thread
  sender.stop();

  puts("QUIT");
  fflush(stdout);
  fflush(stderr);

  return retcode;
}
