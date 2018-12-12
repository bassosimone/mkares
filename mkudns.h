// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_MKUDNS_H
#define MEASUREMENT_KIT_MKUDNS_H

/// @file mkudns.h. Measurement Kit UDP based DNS resolver. This code
/// implements the following OONI DNS requirements:
///
/// 1. we can issue A and AAAA UDP queries
///
/// 2. we can specify the nameserver
///
/// 3. we can save the sent and received DNS messages
///
/// 4. we can save the timing of messages
///
/// 5. we can gather network errors
///
/// 6. we can perform a parasitic traceroute
///
/// This is currently implementd using https://github.com/c-ares/c-ares
/// however any backend resolver library that allows us to implement these
/// functionalities is actually good.
///
/// This code does not meet the following requirements:
///
/// 1. possibility of sending queries over TCP
///
/// 2. possibility of sending queries different from A and AAAA
///
/// 3. possibility of noticing if we receive subsequent DNS responses
///    after the first response has been received
///
/// 4. possibility of performing non stub resolutions

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/// mkudns_query_t is a DNS query.
typedef struct mkudns_query mkudns_query_t;

/// mkudns_response_t is the response to a DNS query.
typedef struct mkudns_response mkudns_response_t;

/// mkudns_query_new_nonnull creates a DNS query. This function never
/// returns null and will abort if memory allocations fail.
mkudns_query_t *mkudns_query_new_nonnull(void);

/// mkudns_query_set_name sets the name to query for. You must set this
/// value for the query to be valid. Aborts if passed null pointers.
void mkudns_query_set_name(mkudns_query_t *query, const char *name);

/// mkudns_query_set_type_AAAA queries for AAAA. Default is to query for
/// A, which is the most common case. Aborts if the @p query is null.
void mkudns_query_set_type_AAAA(mkudns_query_t *query);

/// mkudns_query_set_ttl allows to set the TTL. Values above 255 will
/// be clamped down to 255. Negative values will disable setting a
/// TTL (which is the default). Passing a null @p query causes this
/// function to call abort.
void mkudns_query_set_ttl(mkudns_query_t *query, int64_t ttl);

/// mkudns_query_set_timeout sets the query timeout.
/// TODO(bassosimone): document
void mkudns_query_set_timeout(mkudns_query_t *query, int64_t timeout);

/// mkudns_query_set_server_address sets the server address. The address must be
/// a valid IPv4 or IPv6 address. This function aborts if passed null pointers.
void mkudns_query_set_server_address(
    mkudns_query_t *query, const char *address);

/// mkudns_query_set_server_address sets the server port. The port must be a
/// valid port number. This function aborts if passed null pointers.
void mkudns_query_set_server_port(
    mkudns_query_t *query, const char *port);

/// mkudns_query_perform_nonnull performs @p query. It aborts if @p query is a
/// null pointer. It always return a valid pointer, that you own. You must use
/// mkudns_response_good to check whether the query succeeded.
mkudns_response_t *mkudns_query_perform_nonnull(const mkudns_query_t *query);

/// mkudns_query_delete destroys @p query, which may be null.
void mkudns_query_delete(mkudns_query_t *query);

/// mkudns_response_good returns true if the response is successful (i.e.
/// we have at least one IP address) and false otherwise. This function will
/// also abort if passed a null @p response argument.
int64_t mkudns_response_good(const mkudns_response_t *response);

/// mkudns_response_get_cname returns the CNAME. This function always returns
/// a valid string owned by @p response. If no CNAME is know, this function
/// will return an empty string. It will abort if @p response is null.
const char *mkudns_response_get_cname(const mkudns_response_t *response);

/// mkudns_response_get_addresses_size returns the number of addresses in the
/// response, which may be zero on failure. Aborts if @p response is null.
size_t mkudns_response_get_addresses_size(const mkudns_response_t *response);

/// mkudns_response_get_address_at returns the address at index @p idx. This
/// function aborts if @p response is null or @p idx is out of bounds with
/// respect to the addresses size. The returned string is owned by the @p
/// response instance and will be destroyed when it is destroyed.
const char *mkudns_response_get_address_at(
    const mkudns_response_t *response, size_t idx);

/// mkudns_response_get_send_event returns the send event serialised as
/// a JSON object. In case of failure, this function will return an empty
/// JSON object, i.e., `"{}"`. The returned string is owned by the @p
/// response object and have the same lifecycle. The returned event is
/// like in the following example:
///
/// TODO(bassosimone): finish providing example.
const char *mkudns_response_get_send_event(const mkudns_response_t *response);

// TODO(bassosimone): document
const char *mkudns_response_get_recv_event(const mkudns_response_t *response);

/// mkudns_response_delete destroys @p response, which may be null.
void mkudns_response_delete(mkudns_response_t *response);

#ifdef __cplusplus
}  // extern "C"

#include <memory>

/// mkudns_query_deleter is a deleter for mkudns_query_t.
struct mkudns_query_deleter {
  void operator()(mkudns_query_t *query) {
    mkudns_query_delete(query);
  }
};

/// mkudns_query_deleter is a unique pointer to mkudns_query_t.
using mkudns_query_uptr = std::unique_ptr<mkudns_query_t,
                                          mkudns_query_deleter>;

/// mkudns_response_deleter is a deleter for mkudns_response_t.
struct mkudns_response_deleter {
  void operator()(mkudns_response_t *response) {
    mkudns_response_delete(response);
  }
};

/// mkudns_response_deleter is a unique pointer to mkudns_response_t.
using mkudns_response_uptr = std::unique_ptr<mkudns_response_t,
                                             mkudns_response_deleter>;

// MKUDNS_INLINE_IMPL controls whether to inline the implementation.
#ifdef MKUDNS_INLINE_IMPL

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

#include <iostream>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include <ares.h>

#include <openssl/rand.h>

#include "json.hpp"

#include "mkdata.h"

// MKUDNS_ABORT allows to check in unit tests that we correctly abort.
#ifndef MKUDNS_ABORT
#define MKUDNS_ABORT() abort()
#endif

// MKUDNS_HOOK allows to override a return value in unit tests.
#ifndef MKUDNS_HOOK
//#define MKUDNS_HOOK(T, V)  // Nothing
#define MKUDNS_HOOK(T, V) std::clog << #T << ": " << V << std::endl
#endif

// mkudns_ids
// ----------

// mkudns_ids allows to generate unique, random query IDs.
struct mkudns_ids {
  // ids contains the IDs currently in use.
  std::set<uint16_t> ids;

  // mutex protects ids against concurrent accesses.
  std::mutex mutex;
};

// mkudns_ids_singleton_nonnull returns a singleton suitable for generating
// and remembering currently-in-use query IDs. This function will never
// return a null pointer and will abort if any allocation fails or it is
// not possible to initialise a CSRNG.
static mkudns_ids *mkudns_ids_singleton_nonnull() {
  static std::mutex mutex;
  static std::unique_ptr<mkudns_ids> singleton = nullptr;
  std::unique_lock<std::mutex> _{mutex};
  if (singleton == nullptr) {
    singleton.reset(new mkudns_ids);
    int ret = RAND_poll();
    MKUDNS_HOOK(RAND_poll, ret);
    if (ret != 1) MKUDNS_ABORT();
  }
  return singleton.get();
}

// mkudns_ids_get returns a ID suitable for a DNS query. The returned ID is
// in use until you mkudns_ids_put it. This function will abort if it cannot
// gather enough entropy to generate a random ID.
static uint16_t mkudns_ids_get() {
  mkudns_ids *ids = mkudns_ids_singleton_nonnull();
  if (ids == nullptr) MKUDNS_ABORT();
  uint16_t id = 0;
  std::unique_lock<std::mutex> _{ids->mutex};
  for (;;) {
    int ret = RAND_bytes(reinterpret_cast<unsigned char *>(&id), sizeof(id));
    MKUDNS_HOOK(RAND_bytes, ret);
    if (ret != 1) MKUDNS_ABORT();
    if (ids->ids.count(id) <= 0) break;
  }
  ids->ids.insert(id);  // covered by unique_lock
  return id;
}

// mkudns_ids_put stops using @p id.
static void mkudns_ids_put(uint16_t id) {
  mkudns_ids *ids = mkudns_ids_singleton_nonnull();
  if (ids == nullptr) MKUDNS_ABORT();
  std::unique_lock<std::mutex> _{ids->mutex};
  ids->ids.erase(id);
}

// mkudns_query w/o perform
// ------------------------

// mkudns_query is the private data bound to mkudns_query_t.
struct mkudns_query {
  // dnsclass is the class of the query.
  int dnsclass = ns_c_in;

  // id is the ID of the query.
  uint16_t id = mkudns_ids_get();

  // name is the name to query for.
  std::string name;

  // server_address is the DNS server address.
  std::string server_address = "8.8.8.8";

  // server_port is the DNS server port.
  std::string server_port = "53";

  // timeout is the timeout in milliseconds.
  int64_t timeout = 3000;

  // ttl to use for the query.
  int64_t ttl = -1;

  // type is the type of the query.
  int type = ns_t_a;
};

mkudns_query_t *mkudns_query_new_nonnull() { return new mkudns_query_t; }

void mkudns_query_set_name(mkudns_query_t *query, const char *name) {
  if (query == nullptr || name == nullptr) MKUDNS_ABORT();
  query->name = name;
}

void mkudns_query_set_type_AAAA(mkudns_query_t *query) {
  if (query == nullptr) MKUDNS_ABORT();
  query->type = ns_t_aaaa;
}

void mkudns_query_set_ttl(mkudns_query_t *query, int64_t ttl) {
  if (query == nullptr) MKUDNS_ABORT();
  query->ttl = ttl;
}

void mkudns_query_set_timeout(mkudns_query_t *query, int64_t timeout) {
  if (query == nullptr) MKUDNS_ABORT();
  query->timeout = timeout;
}

void mkudns_query_set_server_address(
    mkudns_query_t *query, const char *address) {
  if (query == nullptr || address == nullptr) MKUDNS_ABORT();
  query->server_address = address;
}

void mkudns_query_set_server_port(
    mkudns_query_t *query, const char *port) {
  if (query == nullptr || port == nullptr) MKUDNS_ABORT();
  query->server_port = port;
}

void mkudns_query_delete(mkudns_query_t *query) {
  if (query != nullptr) {
    mkudns_ids_put(query->id);
    delete query;
  }
}

// mkudns_response
// ---------------

// mkudns_response is the private data of mkudns_response_t.
struct mkudns_response {
  // addresses contains the resolved addresses.
  std::vector<std::string> addresses;

  // events contains the events occurred when performing the query.
  std::vector<std::string> events;

  // cname contains the response CNAME.
  std::string cname;

  // good indicates whether the query succeeded.
  int64_t good = false;

  // recv_event is the receive event.
  std::string recv_event;

  // send_event is the send event.
  std::string send_event;
};

int64_t mkudns_response_good(const mkudns_response_t *response) {
  if (response == nullptr) MKUDNS_ABORT();
  return response->good;
}

const char *mkudns_response_get_cname(const mkudns_response_t *response) {
  if (response == nullptr) MKUDNS_ABORT();
  return response->cname.c_str();
}

size_t mkudns_response_get_addresses_size(const mkudns_response_t *response) {
  if (response == nullptr) MKUDNS_ABORT();
  return response->addresses.size();
}

const char *mkudns_response_get_address_at(
    const mkudns_response_t *response, size_t idx) {
  if (response == nullptr || idx >= response->addresses.size()) MKUDNS_ABORT();
  return response->addresses[idx].c_str();
}

const char *mkudns_response_get_send_event(const mkudns_response_t *response) {
  if (response == nullptr) MKUDNS_ABORT();
  return response->send_event.c_str();
}

const char *mkudns_response_get_recv_event(const mkudns_response_t *response) {
  if (response == nullptr) MKUDNS_ABORT();
  return response->recv_event.c_str();
}

void mkudns_response_delete(mkudns_response_t *response) { delete response; }

// mkudns_query_perform
// --------------------

// mkudns_socket_t is a system socket.
#ifdef _WIN32
using mkudns_socket_t = SOCKET;
#else
using mkudns_socket_t = int;
#endif

// mkudns_socket_invalid is the value indicating an invalid socket.
#ifdef _WIN32
constexpr mkudns_socket_t mkudns_socket_invalid = INVALID_SOCKET;
#else
constexpr mkudns_socket_t mkudns_socket_invalid = -1;
#endif

// mkudns_now returns the monitonic clock's "now" in milliseconds.
static int64_t mkudns_now() {
  auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  return now.count();
}

// MKUDNS_CLOSESOCKET closes a socket
#ifdef _WIN32
#define MKUDNS_CLOSESOCKET closesocket
#else
#define MKUDNS_CLOSESOCKET close
#endif

// mkudns_maybe_errno returns the error that occurred if retval is
// negative and `"no_error"` otherwise.
static std::string mkudns_maybe_errno(int64_t retval) {
  if (retval >= 0) return "no_error";
  // TODO(bassosimone): map interesting system errors.
  return "io_error";
}

// mkudns_maybe_base64 returns buff as a base64 string if count is
// positive, and returns an empty string otherwise.
static std::string mkudns_maybe_base64(const void *buff, int64_t count) {
  if (buff == nullptr) MKUDNS_ABORT();
  if (count <= 0) return "";
  if (static_cast<uint64_t>(count) > SIZE_MAX) MKUDNS_ABORT();
  mkdata_uptr data{mkdata_new_nonnull()};
  mkdata_movein_data(data, std::string{reinterpret_cast<const char *>(buff),
                                       static_cast<size_t>(count)});
  return mkdata_moveout_base64(data);
}

// mkudns_generic_event_new creates a new generic event.
static std::string mkudns_generic_event_new(
    const mkudns_query_t *query, std::string event_key, std::string event_data,
    std::string event_errno, int64_t retval) {
  if (query == nullptr) MKUDNS_ABORT();
  nlohmann::json json;
  json["key"] = event_key;
  json["value"]["data"] = event_data;
  json["value"]["error"] = event_errno;
  json["value"]["ret"] = retval;
  json["value"]["server_address"] = query->server_address;
  json["value"]["server_port"] = query->server_port;
  json["value"]["t"] = mkudns_now();
  json["value"]["timeout"] = query->timeout;
  json["value"]["ttl"] = query->ttl;
  return json.dump();
}

// mkudns_recv_event_new creates a new recv event.
static std::string mkudns_recv_event_new(
    const mkudns_query_t *query, const void *data, int64_t retval) {
  if (query == nullptr || data == nullptr) MKUDNS_ABORT();
  return mkudns_generic_event_new(
      query, "mkudns.recv",
      mkudns_maybe_base64(data, retval),
      mkudns_maybe_errno(retval),
      retval);
}

// mkudns_send_event_new creates a new send event.
static std::string mkudns_send_event_new(
    const mkudns_query_t *query, const void *data,
    size_t count, int64_t retval) {
  if (query == nullptr || data == nullptr || count > INT64_MAX) MKUDNS_ABORT();
  return mkudns_generic_event_new(
      query, "mkudns.send",
      mkudns_maybe_base64(data, static_cast<int64_t>(count)),
      mkudns_maybe_errno(retval),
      retval);
}

// mkudns_parse_hostent parses @p host into @p response.
static bool mkudns_parse_hostent(mkudns_response_t *response, hostent *host) {
  if (response == nullptr || host == nullptr) MKUDNS_ABORT();
  if (host->h_name != nullptr) response->cname = host->h_name;
  for (char **addr = host->h_addr_list; (addr && *addr); ++addr) {
    char name[46];  // see https://stackoverflow.com/questions/1076714
    const char *s = nullptr;
    switch (host->h_addrtype) {
      case AF_INET:
        if (host->h_length != 4) MKUDNS_ABORT();
        s = inet_ntop(AF_INET, *addr, name, sizeof(name));
        break;
      case AF_INET6:
        if (host->h_length != 16) MKUDNS_ABORT();
        s = inet_ntop(AF_INET6, *addr, name, sizeof(name));
        break;
      default: MKUDNS_ABORT();  // should not happen
    }
    if (s == nullptr) return false;  // unlikely but better not to abort here
    response->addresses.push_back(s);
  }
  return true;
}

// mkudns_parse parses the response.
static bool mkudns_parse(
    const mkudns_query_t *query, mkudns_response_t *response,
    const uint8_t *data, size_t count) {
  if (query == nullptr || response == nullptr || data == nullptr ||
      count <= 0 || count > INT_MAX) {
    MKUDNS_ABORT();
  }
  hostent *host = nullptr;
  int ret = 0;
  switch (query->type) {
    case ns_t_a:
      ret = ares_parse_a_reply(
          data, static_cast<int>(count), &host, nullptr, nullptr);
      MKUDNS_HOOK(ares_parse_a_reply, ret);
      break;
    case ns_t_aaaa:
      ret = ares_parse_aaaa_reply(
          data, static_cast<int>(count), &host, nullptr, nullptr);
      MKUDNS_HOOK(ares_parse_aaaa_reply, ret);
      break;
    default: MKUDNS_ABORT();  // should not happen
  }
  if (ret != ARES_SUCCESS) return false;
  bool good = mkudns_parse_hostent(response, host);
  ares_free_hostent(host);
  return good;
}

// mkudns_recv receives the query using @p sock.
static bool mkudns_recv(
    const mkudns_query_t *query, mkudns_response_t *response,
    mkudns_socket_t sock) {
  if (query == nullptr || response == nullptr ||
      sock == mkudns_socket_invalid) {
    MKUDNS_ABORT();
  }
  pollfd pfd{};
  pfd.events = POLLIN;
  pfd.fd = sock;
  int64_t t = query->timeout;
  t = (t < 0) ? -1 : (t < INT_MAX) ? t : INT_MAX;
#ifdef _WIN32
  int ret = WSAPoll(&pfd, 1, static_cast<int>(t));
#else
  int ret = poll(&pfd, 1, static_cast<int>(t));
#endif
  MKUDNS_HOOK(poll, ret);
  if (ret < 0) {
    response->recv_event = mkudns_recv_event_new(query, "", -1);
    return false;
  }
  if (ret == 0) {
    response->recv_event = mkudns_generic_event_new(
        query, "mkudns.recv", "", "timed_out", -1);
    return false;
  }
  std::array<char, 2048> buff;
  auto n = recv(sock, buff.data(), buff.max_size(), 0);
  MKUDNS_HOOK(recv, n);
  response->recv_event = mkudns_recv_event_new(query, buff.data(), n);
  if (n <= 0) return false;
  return mkudns_parse(query, response, reinterpret_cast<uint8_t *>(buff.data()),
                      static_cast<size_t>(n));
}

// mkudns_sendbuf sends the specified buffer using @p sock.
static bool mkudns_sendbuf(
    const mkudns_query_t *query, mkudns_response_t *response,
    mkudns_socket_t sock, const uint8_t *base, size_t count) {
  if (query == nullptr || response == nullptr || sock == mkudns_socket_invalid
      || base == nullptr || count <= 0) {
    MKUDNS_ABORT();
  }
#ifdef _WIN32
  if (count > INT_MAX) MKUDNS_ABORT();
  int n = send(sock, reinterpret_cast<const char *>(base),
               static_cast<int>(count), 0);
#else
  ssize_t n = send(sock, base, count, 0);
#endif
  MKUDNS_HOOK(send, n);
  response->send_event = mkudns_send_event_new(query, base, count, n);
  return n > 0 && static_cast<size_t>(n) == count;
}

// mkudns_send sends the query using @p sock.
static bool mkudns_send(
    const mkudns_query_t *query, mkudns_response_t *response,
    mkudns_socket_t sock) {
  if (query == nullptr || response == nullptr ||
      sock == mkudns_socket_invalid) {
    MKUDNS_ABORT();
  }
  uint8_t *buff = nullptr;
  int bufsiz = 0;
  int ret = ares_create_query(query->name.c_str(), query->dnsclass, query->type,
                              query->id, 1, &buff, &bufsiz, 0);
  MKUDNS_HOOK(ares_create_query, ret);
  if (ret != 0) return false;
  if (buff == nullptr || bufsiz < 0 || static_cast<size_t>(bufsiz) > SIZE_MAX) {
    MKUDNS_ABORT();
  }
  bool good = mkudns_sendbuf(
      query, response, sock, buff, static_cast<size_t>(bufsiz));
  ares_free_string(buff);
  return good;
}

// mkudns_sendrecv_ainfo sends the query and receives a response using
// the specified @p sock for sending and receiving.
static bool mkudns_sendrecv_sock(
    const mkudns_query_t *query, mkudns_response_t *response,
    addrinfo *aip, mkudns_socket_t sock) {
  if (query == nullptr || response == nullptr || aip == nullptr ||
      sock == mkudns_socket_invalid) {
    MKUDNS_ABORT();
  }
  int ret = connect(sock, aip->ai_addr, aip->ai_addrlen);
  MKUDNS_HOOK(connect, ret);
  if (ret != 0) return false;
  if (query->ttl >= 0) {
    int ttl = (query->ttl < 255) ? static_cast<int>(query->ttl) : 255;
    ret = setsockopt(sock, IPPROTO_IP, IP_TTL,
                     reinterpret_cast<char *>(&ttl), sizeof(ttl));
    if (ret != 0) return false;
  }
  bool good = mkudns_send(query, response, sock);
  if (!good) return false;
  return mkudns_recv(query, response, sock);
}

// mkudns_sendrecv_ainfo sends the query and receives a response using
// @p aip to create and connect a datagram socket.
static bool mkudns_sendrecv_ainfo(
    const mkudns_query_t *query, mkudns_response_t *response, addrinfo *aip) {
  if (query == nullptr || response == nullptr || aip == nullptr) MKUDNS_ABORT();
  mkudns_socket_t sock = socket(aip->ai_family, SOCK_DGRAM, 0);
  MKUDNS_HOOK(socket, sock);
  if (sock == mkudns_socket_invalid) return false;
  bool good = mkudns_sendrecv_sock(query, response, aip, sock);
  MKUDNS_CLOSESOCKET(sock);
  return good;
}

// mkudns_sendrecv sends the query and receives the response.
static bool mkudns_sendrecv(
    const mkudns_query_t *query, mkudns_response_t *response) {
  if (query == nullptr || response == nullptr) MKUDNS_ABORT();
  addrinfo hints{};
  hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *rp = nullptr;
  int ret = getaddrinfo(query->server_address.c_str(),
                        query->server_port.c_str(), &hints, &rp);
  MKUDNS_HOOK(getaddrinfo, ret);
  if (ret != 0) {
    response->send_event = mkudns_generic_event_new(
        query, "mkudns.send", "", "invalid_server_endpoint", -1);
    return false;
  }
  if (rp == nullptr || rp->ai_next != nullptr) MKUDNS_ABORT();
  bool good = mkudns_sendrecv_ainfo(query, response, rp);
  freeaddrinfo(rp);
  return good;
}

mkudns_response_t *mkudns_query_perform_nonnull(const mkudns_query_t *query) {
  if (query == nullptr) MKUDNS_ABORT();
  mkudns_response_uptr response{new mkudns_response_t};
  if (!mkudns_sendrecv(query, response.get())) return response.release();
  response->good = true;
  return response.release();
}

#endif  // MKUDNS_INLINE_IMPL
#endif  // __cplusplus
#endif  // MEASUREMENT_KIT_MKUDNS_H
