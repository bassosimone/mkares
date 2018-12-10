// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_MKARES_H
#define MEASUREMENT_KIT_MKARES_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct mkares_query mkares_query_t;

mkares_query_t *mkares_query_new_nonnull(void);

void mkares_query_set_name(mkares_query_t *query, const char *name);

void mkares_query_set_type_AAAA(mkares_query_t *query);

void mkares_query_set_id(mkares_query_t *query, uint16_t id);

void mkares_query_delete(mkares_query_t *query);

typedef struct mkares_server mkares_server_t;

mkares_server_t *mkares_server_new_nonnull(void);

void mkares_server_set_address(mkares_server_t *server, const char *address);

void mkares_server_set_port(mkares_server_t *server, const char *port);

int64_t mkares_server_send(
    mkares_server_t *server, const mkares_query_t *query);

typedef struct mkares_response mkares_response_t;

mkares_response_t *mkares_server_recv_nonnull(
    const mkares_server_t *server, const mkares_query_t *query);

void mkares_server_delete(mkares_server_t *server);

const char *mkares_response_get_cname(const mkares_response_t *response);

size_t mkares_response_get_addresses_size(const mkares_response_t *response);

const char *mkares_response_get_address_at(
    const mkares_response_t *response, size_t idx);

void mkares_response_delete(mkares_response_t *response);

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

struct mkares_server_deleter {
  void operator()(mkares_server_t *server) {
    mkares_server_delete(server);
  }
};

using mkares_server_uptr = std::unique_ptr<mkares_server_t,
                                           mkares_server_deleter>;

struct mkares_response_deleter {
  void operator()(mkares_response_t *response) {
    mkares_response_delete(response);
  }
};

using mkares_response_uptr = std::unique_ptr<mkares_response_t,
                                             mkares_response_deleter>;

#ifdef MKARES_INLINE_IMPL

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <utility>
#include <vector>

#include <ares.h>

#include "json.hpp"

#include "mkdata.h"

#ifndef MKARES_ABORT
#define MKARES_ABORT() abort()
#endif

#ifndef MKARES_HOOK
#define MKARES_HOOK(T, V)  // Nothing
#endif

struct mkares_query {
  std::string name;
  int dnsclass = ns_c_in;
  uint16_t id = 0;
  int type = ns_t_a;
};

mkares_query_t *mkares_query_new_nonnull() { return new mkares_query_t; }

void mkares_query_set_name(mkares_query_t *query, const char *name) {
  if (query == nullptr || name == nullptr) {
    MKARES_ABORT();
  }
  query->name = name;
}

void mkares_query_set_type_AAAA(mkares_query_t *query) {
  if (query == nullptr) {
    MKARES_ABORT();
  }
  query->type = ns_t_aaaa;
}

void mkares_query_set_id(mkares_query_t *query, uint16_t id) {
  if (query == nullptr) {
    MKARES_ABORT();
  }
  query->id = id;
}

void mkares_query_delete(mkares_query_t *query) { delete query; }

struct mkares_server {
  std::string address;
  std::string port = "53";
  int64_t timeout = 3000;  // millisecond
  int64_t fd = -1;
  FILE *logfile = stderr;
};

mkares_server_t *mkares_server_new_nonnull() { return new mkares_server; }

void mkares_server_set_address(mkares_server_t *server, const char *address) {
  if (server == nullptr || address == nullptr) {
    MKARES_ABORT();
  }
  server->address = address;
}

void mkares_server_set_port(mkares_server_t *server, const char *port) {
  if (server == nullptr || port == nullptr) {
    MKARES_ABORT();
  }
  server->port = port;
}

// MKARES_LOG logs @p Event using @p Query's logfile.
#define MKARES_LOG(Query, Event)                                      \
  do {                                                                \
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>( \
        std::chrono::steady_clock::now().time_since_epoch());         \
    nlohmann::json ev = Event;                                        \
    ev["now"] = now.count();                                          \
    (void)fprintf(Query->logfile, "%s\n", ev.dump().c_str());         \
  } while (0)

static int64_t
mkares_server_connect_addrinfo(mkares_server_t *server, addrinfo *aip) {
  server->fd = static_cast<int64_t>(socket(aip->ai_family, SOCK_DGRAM, 0));
  MKARES_HOOK(socket, server->fd);
  MKARES_LOG(server, (nlohmann::json{
                    {"func", "socket"},
                    {"ret", server->fd},
                }));
  if (server->fd == -1) {
    return -1;
  }
  int ret = connect(
#ifdef _WIN32
      static_cast<SOCKET>(server->fd),
#else
      static_cast<int>(server->fd),
#endif
      aip->ai_addr, aip->ai_addrlen);
  MKARES_HOOK(connect, ret);
  MKARES_LOG(server, (nlohmann::json{
                    {"func", "connect"},
                    {"ret", ret},
                }));
  if (ret != 0) {
#ifdef _WIN32
    (void)closesocket(static_cast<SOCKET>(server->fd));
#else
    (void)close(static_cast<int>(server->fd));
#endif
    server->fd = -1;
    return -1;
  }
  return 0;
}

static int64_t mkares_server_connect(mkares_server_t *server) {
  if (server == nullptr) {
    MKARES_ABORT();
  }
  if (server->fd != -1) {
    return 0;
  }
  addrinfo hints{};
  hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *rp = nullptr;
  int ret = getaddrinfo(server->address.c_str(),
                        server->port.c_str(),
                        &hints, &rp);
  MKARES_HOOK(getaddrinfo, ret);
  MKARES_LOG(server, (nlohmann::json{
                    {"func", "getaddrinfo"},
                    {"ret", ret},
                }));
  if (ret != 0) {
    return -1;
  }
  int64_t err = mkares_server_connect_addrinfo(server, rp);
  freeaddrinfo(rp);
  return err;
}

// mkares_maybe_base64 returns a base64 encoded string if @p count is
// positive, otherwise it returns an empty string.
template <typename BufferType, typename SizeType>
std::string mkares_maybe_base64(const BufferType buff, SizeType count) {
  if (count <= 0 || static_cast<uint64_t>(count) > SIZE_MAX) {
    return "";
  }
  mkdata_uptr data{mkdata_new_nonnull()};
  mkdata_movein_data(data, std::string{reinterpret_cast<const char *>(buff),
                                       static_cast<size_t>(count)});
  return mkdata_moveout_base64(data);
}

static int64_t mkares_server_send_buffer(
    mkares_server_t *server, const uint8_t *base, size_t count) {
  int64_t err = mkares_server_connect(server);
  if (err != 0) {
    return err;
  }
#ifdef _WIN32
  if (count > INT_MAX) {
    MKARES_ABORT();
  }
  int n = send(static_cast<SOCKET>(server->fd),
               reinterpret_cast<const char *>(base),
               static_cast<int>(count), 0);
#else
  ssize_t n = send(static_cast<int>(server->fd), base, count, 0);
#endif
  MKARES_HOOK(send, n);
  MKARES_LOG(server, (nlohmann::json{
                    {"func", "send"},
                    {"ret", n},
                    {"data", mkares_maybe_base64(base, n)},
                }));
  if (n < 0 || static_cast<size_t>(n) != count) {
    return -1;
  }
  return 0;
}

int64_t mkares_server_send(
    mkares_server_t *server, const mkares_query_t *query) {
  if (server == nullptr || query == nullptr) {
    MKARES_ABORT();
  }
  uint8_t *buff = nullptr;
  int bufsiz = 0;
  int ret = ares_create_query(query->name.c_str(), query->dnsclass, query->type,
                              query->id, 1, &buff, &bufsiz, 0);
  MKARES_HOOK(ares_create_query, ret);
  MKARES_LOG(server, (nlohmann::json{
                    {"func", "ares_create_query"},
                    {"ret", ret},
                }));
  if (ret != 0) {
    return -1;
  }
  if (buff == nullptr || bufsiz < 0 || static_cast<size_t>(bufsiz) > SIZE_MAX) {
    MKARES_ABORT();
  }
  int64_t err = mkares_server_send_buffer(
      server, buff, static_cast<size_t>(bufsiz));
  ares_free_string(buff);
  return err;
}

void mkares_server_delete(mkares_server_t *server) {
  if (server != nullptr && server->fd != -1) {
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(server->fd));
#else
    close(static_cast<int>(server->fd));
#endif
  }
  delete server;  // gracefully handles nullptr
}

struct mkares_response {
  std::vector<std::string> addresses;
  std::string cname;
  int64_t good = false;
};

static void mkares_response_parse_hostent(
    const mkares_server_t *server, mkares_response_t *response, hostent *host) {
  if (host->h_name != nullptr) {
    response->cname = host->h_name;
  }
  for (char **addr = host->h_addr_list; (addr && *addr); ++addr) {
    char name[46];  // see https://stackoverflow.com/questions/1076714
    const char *s = nullptr;
    switch (host->h_addrtype) {
      case AF_INET:
        if (host->h_length != 4) {
          MKARES_ABORT();
        }
        s = inet_ntop(AF_INET, *addr, name, sizeof(name));
        break;
      case AF_INET6:
        if (host->h_length != 16) {
          MKARES_ABORT();
        }
        s = inet_ntop(AF_INET6, *addr, name, sizeof(name));
        break;
      default: MKARES_ABORT();
    }
    MKARES_LOG(server, (nlohmann::json{
                      {"func", "inet_ntop"},
                      {"ret", s},
                  }));
    if (s == nullptr) {
      return;
    }
    response->addresses.push_back(s);
  }
}

static void mkares_server_recvparse(const mkares_server_t *server,
                                    const mkares_query_t *query,
                                    mkares_response_uptr &response) {
  if (server == nullptr || query == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
  char buff[2048];
#ifdef _WIN32
  int n = recv(static_cast<SOCKET>(server->fd), buff, sizeof(buff), 0);
#else
  ssize_t n = recv(static_cast<int>(server->fd), buff, sizeof(buff), 0);
#endif
  MKARES_HOOK(recv, n);
  MKARES_LOG(server, (nlohmann::json{
                         {"func", "recv"},
                         {"ret", n},
                         {"data", mkares_maybe_base64(buff, n)},
                     }));
  if (n <= 0) {
    return;
  }
  hostent *host = nullptr;
  int ret = 0;
  switch (query->type) {
    case ns_t_a:
      ret = ares_parse_a_reply(
          reinterpret_cast<unsigned char *>(buff),
          static_cast<int>(n), &host, nullptr, nullptr);
      MKARES_HOOK(ares_parse_a_reply, ret);
      MKARES_LOG(server, (nlohmann::json{
                             {"func", "ares_parse_a_reply"},
                             {"ret", ret},
                         }));
      break;
    case ns_t_aaaa:
      ret = ares_parse_aaaa_reply(
          reinterpret_cast<unsigned char *>(buff),
          static_cast<int>(n), &host, nullptr, nullptr);
      MKARES_HOOK(ares_parse_aaaa_reply, ret);
      MKARES_LOG(server, (nlohmann::json{
                             {"func", "ares_parse_aaaa_reply"},
                             {"ret", ret},
                         }));
      break;
    default: MKARES_ABORT();  // should not happen
  }
  if (ret != ARES_SUCCESS) {
    return;
  }
  // TODO(bassosimone): consider that this function MIGHT fail
  mkares_response_parse_hostent(server, response.get(), host);
  ares_free_hostent(host);
  response->good = true;
}

mkares_response_t *mkares_server_recv_nonnull(
    const mkares_server_t *server, const mkares_query_t *query) {
  if (server == nullptr || query == nullptr) {
    MKARES_ABORT();
  }
  mkares_response_uptr response{new mkares_response_t};
  pollfd pfd{};
  pfd.events = POLLIN;
  int64_t t = server->timeout;
  t = (t < 0) ? -1 : (t < INT_MAX) ? t : INT_MAX;
#ifdef _WIN32
  pfd.fd = static_cast<SOCKET>(server->fd);
  int ret = WSAPoll(&pfd, 1, static_cast<int>(t));
#else
  pfd.fd = static_cast<int>(server->fd);
  int ret = poll(&pfd, 1, static_cast<int>(t));
#endif
  MKARES_HOOK(poll, ret);
  MKARES_LOG(server, (nlohmann::json{
                         {"func", "poll"},
                         {"ret", ret},
                     }));
  if (ret <= 0) {
    return response.release();
  }
  mkares_server_recvparse(server, query, response);
  return response.release();
}

const char *mkares_response_get_cname(const mkares_response_t *response) {
  if (response == nullptr) {
    MKARES_ABORT();
  }
  return response->cname.c_str();
}

size_t mkares_response_get_addresses_size(const mkares_response_t *response) {
  if (response == nullptr) {
    MKARES_ABORT();
  }
  return response->addresses.size();
}

const char *mkares_response_get_address_at(
    const mkares_response_t *response, size_t idx) {
  if (response == nullptr || idx >= response->addresses.size()) {
    MKARES_ABORT();
  }
  return response->addresses[idx].c_str();
}

void mkares_response_delete(mkares_response_t *response) {
  delete response;
}

#endif  // MKARES_INLINE_IMPL
#endif  // __cplusplus
#endif  // MEASUREMENT_KIT_MKARES_H
