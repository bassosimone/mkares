// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_MKARES_H
#define MEASUREMENT_KIT_MKARES_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct mkares_query mkares_query_t;

mkares_query_t *mkares_query_new_nonnull(void);

void mkares_query_set_name(mkares_query_t *query, const char *name);

void mkares_query_add_server(
    mkares_query_t *query, const char *address, const char *port);

void mkares_query_set_AAAA(mkares_query_t *query);

int64_t mkares_query_perform_nonnull(mkares_query_t *query);

void mkares_query_delete(mkares_query_t *query);

#ifdef __cplusplus
}  // extern "C"

#include <memory>
#include <string>

struct mkares_query_deleter {
  void operator()(mkares_query_t *query) {
    mkares_query_delete(query);
  }
};

using mkares_query_uptr = std::unique_ptr<mkares_query_t, mkares_query_deleter>;

#ifdef MKARES_INLINE_IMPL

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#endif

#include <utility>
#include <vector>

#include <ares.h>

#ifndef MKARES_ABORT
#define MKARES_ABORT() abort()
#endif

#ifndef MKARES_HOOK
#include <iostream>
#define MKARES_HOOK(T, V) std::clog << #T << ": " << V << std::endl
#endif

#ifndef MKARES_LOG
#include <iostream>
#define MKARES_LOG(Args) std::clog << Args << std::endl
#endif

struct mkares_server {
  std::string address;
  std::string port;
};

struct mkares_query {
  size_t attempts = 3;
  int dnsclass = ns_c_in;
  int id = 0; // XXX
  std::string name;
  std::vector<mkares_server> servers;
  int timeout = 3000;  // millisecond
  int type = ns_t_a;
};

mkares_query_t *mkares_query_new_nonnull() { return new mkares_query_t; }

void mkares_query_set_name(mkares_query_t *query, const char *name) {
  if (query == nullptr || name == nullptr) {
    MKARES_ABORT();
  }
  query->name = name;
}

void mkares_query_add_server(
    mkares_query_t *query, const char *address, const char *port) {
  if (query == nullptr || address == nullptr || port == nullptr) {
    MKARES_ABORT();
  }
  mkares_server server;
  server.address = address;
  server.port = port;
  query->servers.push_back(std::move(server));
}

void mkares_query_set_AAAA(mkares_query_t *query) {
  if (query == nullptr) {
    MKARES_ABORT();
  }
  query->type = ns_t_aaaa;
}

static int64_t mkares_query_complete_(mkares_query_t *q, hostent *host) {
  if (q == nullptr || host == nullptr) {
    MKARES_ABORT();
  }
  if (host->h_name != nullptr) {
    MKARES_LOG("cname: " << host->h_name);
  }
  for (char **addr = host->h_addr_list; (addr && *addr); ++addr) {
    char name[46];  // see https://stackoverflow.com/questions/1076714
    const char *s = nullptr;
    // XXX: more consistency checks here
    switch (host->h_addrtype) {
      case AF_INET:
      s = inet_ntop(AF_INET, *addr, name, sizeof(name));
      break;
    case AF_INET6:
      s = inet_ntop(AF_INET6, *addr, name, sizeof(name));
      break;
    default:
      abort();
    }
    if (s == nullptr) {
      MKARES_LOG("cannot process address returned by c-ares");
      return -1;
    }
    MKARES_LOG("address: " << name);
  }
  return 0;
}

// mkares_query_recv_ receives the response to a query. Returns zero
// in case of success and -1 in case of failure.
static int64_t mkares_query_recv_(
    mkares_query_t *q, int64_t fd, unsigned char *rbuff, size_t rbufsiz) {
  if (q == nullptr || fd == -1 || rbuff == nullptr || rbufsiz <= 0) {
    MKARES_ABORT();
  }
  pollfd pfd{};
  pfd.events = POLLIN;
#ifdef _WIN32
  pfd.fd = static_cast<SOCKET>(fd);
  int ret = WSAPoll(&pfd, 1, q->timeout);
#else
  pfd.fd = static_cast<int>(fd);
  int ret = poll(&pfd, 1, q->timeout);
#endif
  MKARES_HOOK(poll, ret);
  if (ret < 0) {
    MKARES_LOG("poll failed");
    return -1;
  }
  if (ret == 0) {
    MKARES_LOG("poll timed out");
    return -1;
  }
#ifdef _WIN32
  if (rbufsiz > INT_MAX) {
    MKARES_LOG("recv buffer size too large");
    return -1;
  }
  int n = recv(static_cast<SOCKET>(fd), rbuff, static_cast<int>(rbufsiz), 0);
#else
  ssize_t n = recv(static_cast<int>(fd), rbuff, rbufsiz, 0);
#endif
  if (n <= 0) {
    MKARES_LOG("recv failed");
    return -1;
  }
  hostent *host = nullptr;
  switch (q->type) {
    case ns_t_a:
      ret = ares_parse_a_reply(rbuff, rbufsiz, &host, nullptr, 0);
      break;
    case ns_t_aaaa:
      ret = ares_parse_aaaa_reply(rbuff, rbufsiz, &host, nullptr, 0);
      break;
    default:
      abort();  // should not happen
  }
  if (ret != 0) {
    return -1;
  }
  ret = mkares_query_complete_(q, host);
  ares_free_hostent(host);
  return ret;
}

// mkares_query_sendrecv_ sends a query and receives the response. It retries
// in case of timeout. Returns -1 on failure, and 0 on success.
static int64_t mkares_query_sendrecv_(
    mkares_query_t *q, const unsigned char *sbuff, size_t sbufsiz,
    addrinfo *aip, int64_t fd) {
  if (q == nullptr || sbuff == nullptr || sbufsiz <= 0 ||
      aip == nullptr || fd == -1) {
    MKARES_ABORT();
  }
#ifdef _WIN32
  int ret = connect(static_cast<SOCKET>(fd), aip->ai_addr, aip->ai_addrlen);
#else
  int ret = connect(static_cast<int>(fd), aip->ai_addr, aip->ai_addrlen);
#endif
  MKARES_HOOK(connect, ret);
  if (ret != 0) {
    MKARES_LOG("cannot connect to remote endpoint");
    return -1;
  }
  for (size_t i = 0; i < q->attempts; ++i) {
#ifdef _WIN32
    if (sbufsiz > INT_MAX) {
      MKARES_LOG("buffer too larger");
      return -1;
    }
    int n = send(static_cast<SOCKET>(fd), sbuff, static_cast<int>(sbufsiz), 0);
#else
    ssize_t n = send(static_cast<int>(fd), sbuff, sbufsiz, 0);
#endif
    MKARES_HOOK(send, n);
    if (n < 0) {
      MKARES_LOG("cannot send query");
      return -1;
    }
    if (static_cast<size_t>(n) != sbufsiz) {
      MKARES_LOG("short write");
      return -1;
    }
    size_t rbuffsiz = 2048;
    unsigned char *rbuff = reinterpret_cast<unsigned char *>(malloc(rbuffsiz));
    MKARES_HOOK(malloc, rbuff);
    if (rbuff == nullptr) {
      MKARES_LOG("cannot allocate receive buffer");
      return -1;
    }
    int ret = mkares_query_recv_(q, fd, rbuff, rbuffsiz);
    MKARES_HOOK(mkares_query_recv_, ret);
    free(rbuff);
    if (ret == 0) {
      return 0;
    }
  }
  return -1;
}

// mkares_query_try_server_ tries sending a serialised query to a specific
// server. Returns 0 on success, and -1 on failure.
static int64_t mkares_query_try_server_(
    mkares_query_t *q, const unsigned char *buff,
    size_t bufsiz, addrinfo *aip) {
  if (q == nullptr || buff == nullptr || bufsiz <= 0 || aip == nullptr) {
    MKARES_ABORT();
  }
  int64_t fd = static_cast<int64_t>(socket(aip->ai_family, SOCK_DGRAM, 0));
  MKARES_HOOK(socket, fd);
  if (fd == -1) {
    MKARES_LOG("cannot create datagram socket");
    return -1;
  }
  int ret = mkares_query_sendrecv_(q, buff, bufsiz, aip, fd);
  MKARES_HOOK(mkares_query_sendrecv_, ret);
#ifdef _WIN32
  closesocket(static_cast<SOCKET>(fd));
#else
  close(static_cast<int>(fd));
#endif
  return ret;
}

// mkares_query_try_each_server_ tries sending the query to each server. It
// returns 0 on success, and -1 on failure.
static int64_t mkares_query_try_each_server_(
    mkares_query_t *q, const unsigned char *buff, size_t bufsiz) {
  if (q == nullptr || buff == nullptr || bufsiz <= 0) {
    MKARES_ABORT();
  }
  for (auto &s : q->servers) {
    addrinfo hints{};
    hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo *rp = nullptr;
    int ret = getaddrinfo(s.address.c_str(), s.port.c_str(), &hints, &rp);
    MKARES_HOOK(getaddrinfo, ret);
    if (ret != 0) {
      MKARES_LOG("cannot parse server address and/or port");
      continue;
    }
    ret = mkares_query_try_server_(q, buff, bufsiz, rp);
    MKARES_HOOK(mkares_query_try_server_, ret);
    freeaddrinfo(rp);
    if (ret == 0) {
      return 0;
    }
  }
  MKARES_LOG("all servers have failed");
  return -1;
}

int64_t mkares_query_perform_nonnull(mkares_query_t *q) {
  if (q == nullptr) {
    MKARES_ABORT();
  }
  unsigned char *buff = nullptr;
  int bufsiz = 0;
  int ret = ares_create_query(q->name.c_str(), q->dnsclass, q->type, q->id, 1,
                              &buff, &bufsiz, 0);
  MKARES_HOOK(ares_create_query, ret);
  if (ret != 0) {
    MKARES_LOG("cannot create query");
    return -1;
  }
  if (buff == nullptr || bufsiz < 0 || static_cast<size_t>(bufsiz) > SIZE_MAX) {
    MKARES_ABORT();
  }
  ret = mkares_query_try_each_server_(q, buff, static_cast<size_t>(bufsiz));
  MKARES_HOOK(mkares_query_try_each_server_, ret);
  ares_free_string(buff);
  return ret;
}

void mkares_query_delete(mkares_query_t *query) { delete query; }

#endif // MKARES_INLINE_IMPL
#endif // __cplusplus
#endif // MEASUREMENT_KIT_MKARES_H
