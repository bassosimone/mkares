// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_MKARES_H
#define MEASUREMENT_KIT_MKARES_H

/// @file mkares.h. Measurement Kit c-ares wrappers.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/// mkares_query_t is a DNS query.
typedef struct mkares_query mkares_query_t;

/// mkares_query_new_nonnull creates a DNS query. This function never
/// returns null and will abort if memory allocations fail.
mkares_query_t *mkares_query_new_nonnull(void);

/// mkares_query_set_name sets the name to query for. You must set this
/// value for the query to be valid. Aborts if passed null pointers.
void mkares_query_set_name(mkares_query_t *query, const char *name);

/// mkares_query_set_type_AAAA queries for AAAA. Default is to query for
/// A. Aborts if @p query is null.
void mkares_query_set_type_AAAA(mkares_query_t *query);

/// mkares_query_delete destroys @p query, which may be null.
void mkares_query_delete(mkares_query_t *query);

/// mkares_response_t is the response to a DNS query.
typedef struct mkares_response mkares_response_t;

/// mkares_response_good returns true if the response is successful (i.e.
/// we have at least one IP address) and false otherwise. This function will
/// also abort if passed a null @p response argument.
int64_t mkares_response_good(const mkares_response_t *response);

/// mkares_response_get_cname returns the CNAME. This function always returns
/// a valid string owned by @p response. If no CNAME is know, this function
/// will return an empty string. It will abort if @p response is null.
const char *mkares_response_get_cname(const mkares_response_t *response);

/// mkares_response_get_addresses_size returns the number of addresses in the
/// response, which may be zero on failure. Aborts if @p response is null.
size_t mkares_response_get_addresses_size(const mkares_response_t *response);

/// mkares_response_get_address_at returns the address at index @p idx. This
/// function aborts if @p response is null or @p idx is out of bounds with
/// respect to the addresses size. The returned string is owned by the @p
/// response instance and will be destroyed when it is destroyed.
const char *mkares_response_get_address_at(
    const mkares_response_t *response, size_t idx);

/// mkares_response_get_events_size is like mkares_response_get_addresses_size
/// but for events rather than addresses. Events are a sequence of string
/// serialised JSON objects that describe all the events occurring at the API
/// level during the execution of the query. The general event is like:
///
/// ```json
/// {"func":"inet_ntop","now":35200981, ...}
/// ```
///
/// Where `func` is the API name, `now` is the number of milliseconds since
/// the zero of the C++ steady clock, and additional fields may include, for
/// example, the return value of an API, and the data that has been sent
/// or received. Because DNS is a binary protocol, the data will be encoded
/// as a base64 string. In case of API failure, the data will instead be
/// represented as an empty string, if no data has been read.
size_t mkares_response_get_events_size(const mkares_response_t *response);

/// mkares_response_get_event_at is like mkares_response_get_address_at
/// except that it returns events rather than addresses. The format of events
/// is documented in mkares_response_get_events_size docs.
const char *mkares_response_get_event_at(
    const mkares_response_t *response, size_t idx);

/// mkares_response_delete destroys @p response, which may be null.
void mkares_response_delete(mkares_response_t *response);

/// mkares_channel_t is a socket for sending a DNS request.
typedef struct mkares_channel mkares_channel_t;

/// mkares_channel_new_nonnull creates a new channel. This function will always
/// return a valid pointer and will abort if any malloc fails.
mkares_channel_t *mkares_channel_new_nonnull(void);

/// mkares_channel_set_address sets the server address. The address must be
/// a valid IPv4 or IPv6 address. This function aborts if passed null pointers.
void mkares_channel_set_address(mkares_channel_t *channel, const char *address);

/// mkares_channel_set_address sets the server port. The port must be a valid
/// port number. This function aborts if passed null pointers.
void mkares_channel_set_port(mkares_channel_t *channel, const char *port);

/// mkares_channel_sendrecv_nonnull sends @p query and receives a response
/// using @p channel. This function will always return a valid pointer
/// and will abort on memory allocation errors. It will also abort when
/// passed null pointer arguments. To check whether the returned response
/// succeeded, you mkares_reponse_good.
mkares_response_t *mkares_channel_sendrecv_nonnull(
    mkares_channel_t *channel, const mkares_query_t *query);

/// mkares_channel_delete destroys @p channel, which may be null.
void mkares_channel_delete(mkares_channel_t *channel);

/// mkares_event_t is an asynchronous event occurring when a channel
/// is being managed by the reaper (described below).
typedef struct mkares_event mkares_event_t;

/// mkares_event_str returns the string representation of the event. This
/// is a serialised JSON as described above in the documentation of the
/// mkares_response_get_events_size function. This function will abort if
/// the @p event argument is a null pointer.
const char *mkares_event_str(const mkares_event_t *event);

/// mkares_event_delete destroys @p event, which may be null.
void mkares_event_delete(mkares_event_t *event);

/// mkares_reaper_t will manage channels where a response has already been
/// received, to check whether subsequent responses are received. This
/// operation will be done by polling several channels at once in a background
/// thread. If subsequent responses are received they're saved in the reaper.
typedef struct mkares_reaper mkares_reaper_t;

/// mkares_reaper_new_nonnull creates a new reaper. This function will never
/// fail and will always return a valid pointer. Aborts on malloc error.
mkares_reaper_t *mkares_reaper_new_nonnull(void);

/// mkares_reaper_movein_channel_and_query transfers the ownership of @p
/// channel and @p query to @p reaper. You must not use either of them after
/// this function has been called. This function will abort if passed any
/// null pointer argument.
void mkares_reaper_movein_channel_and_query(
    mkares_reaper_t *reaper,
    mkares_channel_t *channel, mkares_query_t *query);

//TODO(bassosimone): specify the format of the returned events
// that should be such that one can easily link with other data.

/// mkares_reaper_get_next_event returns the next event registered by the
/// reaper. This function may return a null pointer if no events have been
/// saved in @p reaper. This function aborts if @p reaper is null.
mkares_event_t *mkares_reaper_get_next_event(
    mkares_reaper_t *reaper);

/// mkares_repaer_delete destroys @p repear, which may be null.
void mkares_reaper_delete(mkares_reaper_t *reaper);

#ifdef __cplusplus
}  // extern "C"

#include <memory>
#include <string>

/// mkares_query_deleter is a deleter for mkares_query_t.
struct mkares_query_deleter {
  void operator()(mkares_query_t *query) {
    mkares_query_delete(query);
  }
};

/// mkares_query_deleter is a unique pointer to mkares_query_t.
using mkares_query_uptr = std::unique_ptr<mkares_query_t,
                                          mkares_query_deleter>;

/// mkares_response_deleter is a deleter for mkares_response_t.
struct mkares_response_deleter {
  void operator()(mkares_response_t *response) {
    mkares_response_delete(response);
  }
};

/// mkares_response_deleter is a unique pointer to mkares_response_t.
using mkares_response_uptr = std::unique_ptr<mkares_response_t,
                                             mkares_response_deleter>;

/// mkares_channel_deleter is a deleter for mkares_channel_t.
struct mkares_channel_deleter {
  void operator()(mkares_channel_t *channel) {
    mkares_channel_delete(channel);
  }
};

/// mkares_channel_deleter is a unique pointer to mkares_channel_t.
using mkares_channel_uptr = std::unique_ptr<mkares_channel_t,
                                            mkares_channel_deleter>;

/// mkares_event_deleter is a deleter for mkares_event_t.
struct mkares_event_deleter {
  void operator()(mkares_event_t *event) {
    mkares_event_delete(event);
  }
};

/// mkares_event_deleter is a unique pointer to mkares_event_t.
using mkares_event_uptr = std::unique_ptr<mkares_event_t,
                                          mkares_event_deleter>;

/// mkares_repaer_deleter is a deleter for mkares_repaer_t.
struct mkares_reaper_deleter {
  void operator()(mkares_reaper_t *reaper) {
    mkares_reaper_delete(reaper);
  }
};

/// mkares_repaer_deleter is a unique pointer to mkares_repaer_t.
using mkares_reaper_uptr = std::unique_ptr<mkares_reaper_t,
                                           mkares_reaper_deleter>;

// MKARES_INLINE_IMPL controls whether to inline the implementation.
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

#include <deque>
#include <mutex>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include <ares.h>

#include <openssl/rand.h>

#include "json.hpp"

#include "mkdata.h"

// MKARES_ABORT allows to check in unit tests that we correctly abort.
#ifndef MKARES_ABORT
#define MKARES_ABORT() abort()
#endif

// MKARES_HOOK allows to override a return value in unit tests.
#ifndef MKARES_HOOK
#define MKARES_HOOK(T, V)  // Nothing
#endif

// mkares_ids
// ----------

// mkares_ids allows to generate unique, random query IDs.
struct mkares_ids {
  // ids contains the IDs currently in use.
  std::set<uint16_t> ids;

  // mutex protects ids against concurrent accesses.
  std::mutex mutex;
};

// mkares_ids_singleton_nonnull returns a singleton suitable for generating
// and remembering currently-in-use query IDs. This function will never
// return a null pointer and will abort if any allocation fails or it is
// not possible to initialise a CSRNG.
static mkares_ids *mkares_ids_singleton_nonnull() {
  static std::mutex mutex;
  static std::unique_ptr<mkares_ids> singleton = nullptr;
  std::unique_lock<std::mutex> _{mutex};
  if (singleton == nullptr) {
    singleton.reset(new mkares_ids);
    int ret = RAND_poll();
    MKARES_HOOK(RAND_poll, ret);
    if (ret != 1) MKARES_ABORT();
  }
  return singleton.get();
}

// mkares_ids_get returns a ID suitable for a DNS query. The returned ID is
// in use until you mkares_ids_put it. This function will abort if it cannot
// gather enough entropy to generate a random ID.
static uint16_t mkares_ids_get() {
  mkares_ids *ids = mkares_ids_singleton_nonnull();
  if (ids == nullptr) MKARES_ABORT();
  uint16_t id = 0;
  std::unique_lock<std::mutex> _{ids->mutex};
  for (;;) {
    int ret = RAND_bytes(reinterpret_cast<unsigned char *>(&id), sizeof(id));
    MKARES_HOOK(RAND_bytes, ret);
    if (ret != 1) MKARES_ABORT();
    if (ids->ids.count(id) <= 0) break;
  }
  ids->ids.insert(id);  // covered by unique_lock
  return id;
}

// mkares_ids_put stops using @p id.
static void mkares_ids_put(uint16_t id) {
  mkares_ids *ids = mkares_ids_singleton_nonnull();
  if (ids == nullptr) MKARES_ABORT();
  std::unique_lock<std::mutex> _{ids->mutex};
  ids->ids.erase(id);
}

// mkares_query
// ------------

// mkares_query is the private data bound to mkares_query_t.
struct mkares_query {
  // name is the name of the query.
  std::string name;

  // dnsclass is the class of the query.
  int dnsclass = ns_c_in;

  // id is the ID of the query.
  uint16_t id = mkares_ids_get();

  // type is the type of the query.
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

void mkares_query_delete(mkares_query_t *query) {
  if (query != nullptr) {
    mkares_ids_put(query->id);
    delete query;
  }
}

// mkares_response
// ---------------

// mkares_response is the private data of mkares_response_t.
struct mkares_response {
  // addresses contains the resolved addresses.
  std::vector<std::string> addresses;

  // events contains the events occurred when performing the query.
  std::vector<std::string> events;

  // cname contains the response CNAME.
  std::string cname;

  // good indicates whether the query succeeded.
  int64_t good = false;
};

int64_t mkares_response_good(const mkares_response_t *response) {
  if (response == nullptr) {
    MKARES_ABORT();
  }
  return response->good;
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

size_t mkares_response_get_events_size(const mkares_response_t *response) {
  if (response == nullptr) {
    MKARES_ABORT();
  }
  return response->events.size();
}

const char *mkares_response_get_event_at(
    const mkares_response_t *response, size_t idx) {
  if (response == nullptr || idx >= response->events.size()) {
    MKARES_ABORT();
  }
  return response->events[idx].c_str();
}

void mkares_response_delete(mkares_response_t *response) {
  delete response;
}

// mkares_channel
// --------------

// mkares_channels is the private data of mkares_channel_t.
struct mkares_channel {
  // address is the address of the server.
  std::string address;

  // port is the port of the server.
  std::string port = "53";

  // timeout is the query timeout in millisecond.
  int64_t timeout = 3000;

  // fd is the socket.
  int64_t fd = -1;
};

mkares_channel_t *mkares_channel_new_nonnull() { return new mkares_channel; }

void mkares_channel_set_address(mkares_channel_t *channel, const char *address) {
  if (channel == nullptr || address == nullptr) {
    MKARES_ABORT();
  }
  channel->address = address;
}

void mkares_channel_set_port(mkares_channel_t *channel, const char *port) {
  if (channel == nullptr || port == nullptr) {
    MKARES_ABORT();
  }
  channel->port = port;
}

static int64_t mkares_now() {
  auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  return now.count();
}

// MKARES_EVADD adds @p Event to @p Response events.
#define MKARES_EVADD(Response, Event)      \
  do {                                     \
    nlohmann::json ev = Event;             \
    ev["now"] = mkares_now();              \
    Response->events.push_back(ev.dump()); \
  } while (0)

// mkares_channel_connect_addrinfo connects @p channel to the socket
// identifier by @p aip and adds events to @p response's events. Will
// abort if passed any null pointer or if @p channel's socket is not
// invalid (meaning that we're already connected). Returns a bool value
// indicating whether it succeeded or not.
static bool
mkares_channel_connect_addrinfo(mkares_channel_t *channel, addrinfo *aip,
                                mkares_response_uptr &response) {
  if (channel == nullptr || aip == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
  if (channel->fd != -1) MKARES_ABORT();
  channel->fd = static_cast<int64_t>(socket(aip->ai_family, SOCK_DGRAM, 0));
  MKARES_HOOK(socket, channel->fd);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "socket"},
                             {"ret", channel->fd},
                         }));
  if (channel->fd == -1) return false;
  int ret = connect(
#ifdef _WIN32
      static_cast<SOCKET>(channel->fd),
#else
      static_cast<int>(channel->fd),
#endif
      aip->ai_addr, aip->ai_addrlen);
  MKARES_HOOK(connect, ret);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "connect"},
                             {"ret", ret},
                         }));
  if (ret != 0) {
#ifdef _WIN32
    (void)closesocket(static_cast<SOCKET>(channel->fd));
#else
    (void)close(static_cast<int>(channel->fd));
#endif
    channel->fd = -1;
    return false;
  }
  return true;
}

// mkares_channel_connect connects @p channel to the endpoint stored inside
// @p channel and logs events to @p response. Will abort if passed any
// null pointer or if @p channel is already bound to a valid socket. Returns
// whether it succeded or not.
static bool mkares_channel_connect(
    mkares_channel_t *channel, mkares_response_uptr &response) {
  if (channel == nullptr || channel->fd != -1 || response == nullptr) {
    MKARES_ABORT();
  }
  addrinfo hints{};
  hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *rp = nullptr;
  int ret = getaddrinfo(channel->address.c_str(),
                        channel->port.c_str(), &hints, &rp);
  MKARES_HOOK(getaddrinfo, ret);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "getaddrinfo"},
                             {"ret", ret},
                         }));
  if (ret != 0) return false;
  if (rp == nullptr || rp->ai_next != nullptr) MKARES_ABORT();
  bool ok = mkares_channel_connect_addrinfo(channel, rp, response);
  freeaddrinfo(rp);
  return ok;
}

// mkares_maybe_base64 returns a base64 encoded string if @p count is
// positive. Otherwise, if @p count is negative (i.e. recv or send failed)
// or too large (should not happen), it returns an empty string. It will
// instead abort if it's pased a null pointer @p buff.
template <typename BufferType, typename SizeType>
std::string mkares_maybe_base64(const BufferType buff, SizeType count) {
  if (buff == nullptr) MKARES_ABORT();
  if (count <= 0) return "";
  if (static_cast<uint64_t>(count) > SIZE_MAX) MKARES_ABORT();
  mkdata_uptr data{mkdata_new_nonnull()};
  mkdata_movein_data(data, std::string{reinterpret_cast<const char *>(buff),
                                       static_cast<size_t>(count)});
  return mkdata_moveout_base64(data);
}

// mkares_channel_send_buffer sends @p count bytes buffer starting at
// @p base over @p channel and logs events in @p response. This function will
// abort if passed any null pointer, if @p count is not positive, or if
// @p channel is already connected. Returns a boolean valud indicating whether
// it succeded or not. Note that not being able to send a full packet with
// @p count bytes is considered a failure.
static bool mkares_channel_send_buffer(
    mkares_channel_t *channel, const uint8_t *base, size_t count,
    mkares_response_uptr &response) {
  if (channel == nullptr || base == nullptr || count <= 0 ||
      response == nullptr) {
    MKARES_ABORT();
  }
  if (channel->fd != -1) MKARES_ABORT();
  if (!mkares_channel_connect(channel, response)) return false;
#ifdef _WIN32
  if (count > INT_MAX) MKARES_ABORT();
  int n = send(static_cast<SOCKET>(channel->fd),
               reinterpret_cast<const char *>(base),
               static_cast<int>(count), 0);
#else
  ssize_t n = send(static_cast<int>(channel->fd), base, count, 0);
#endif
  MKARES_HOOK(send, n);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "send"},
                             {"ret", n},
                             {"data", mkares_maybe_base64(base, count)},
                         }));
  if (n < 0 || static_cast<size_t>(n) != count) return false;
  return true;
}

// mkares_channel_send sends @p query over @p channel logging events
// in @p response. Aborts if passed null pointers, or if @p channel
// socket's is already connected. Returns a bool value indicating whether
// it succeeded or not.
static bool
mkares_channel_send(mkares_channel_t *channel, const mkares_query_t *query,
                    mkares_response_uptr &response) {
  if (channel == nullptr || query == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
  if (channel->fd != -1) MKARES_ABORT();
  uint8_t *buff = nullptr;
  int bufsiz = 0;
  int ret = ares_create_query(query->name.c_str(), query->dnsclass, query->type,
                              query->id, 1, &buff, &bufsiz, 0);
  MKARES_HOOK(ares_create_query, ret);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "ares_create_query"},
                             {"ret", ret},
                         }));
  if (ret != 0) return false;
  if (buff == nullptr || bufsiz < 0 || static_cast<size_t>(bufsiz) > SIZE_MAX) {
    MKARES_ABORT();
  }
  bool good = mkares_channel_send_buffer(
      channel, buff, static_cast<size_t>(bufsiz), response);
  ares_free_string(buff);
  return good;
}

// mkares_response_parse_hostent parses @p host into @p response. Aborts
// if passed null pointers. Returns whether it succeeded or not.
static bool
mkares_response_parse_hostent(mkares_response_uptr &response, hostent *host) {
  if (response == nullptr || host == nullptr) {
    MKARES_ABORT();
  }
  if (host->h_name != nullptr) response->cname = host->h_name;
  for (char **addr = host->h_addr_list; (addr && *addr); ++addr) {
    char name[46];  // see https://stackoverflow.com/questions/1076714
    const char *s = nullptr;
    switch (host->h_addrtype) {
      case AF_INET:
        if (host->h_length != 4) MKARES_ABORT();
        s = inet_ntop(AF_INET, *addr, name, sizeof(name));
        break;
      case AF_INET6:
        if (host->h_length != 16) MKARES_ABORT();
        s = inet_ntop(AF_INET6, *addr, name, sizeof(name));
        break;
      default: MKARES_ABORT();  // should not happen
    }
    MKARES_EVADD(response, (nlohmann::json{
                               {"func", "inet_ntop"},
                               {"ret", s},
                           }));
    if (s == nullptr) return false;  // unlikely but better not to abort here
    response->addresses.push_back(s);
  }
  return true;
}

// mkares_channel_recv receives a @p response for @p query from @p channel. It
// aborts if passed null pointers or if @p channel's socket is invalid.
static void mkares_channel_recv(const mkares_channel_t *channel,
                                const mkares_query_t *query,
                                mkares_response_uptr &response) {
  if (channel == nullptr || query == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
  if (channel->fd == -1) MKARES_ABORT();
  char buff[2048];  // small enough to stay on the stack
#ifdef _WIN32
  int n = recv(static_cast<SOCKET>(channel->fd), buff, sizeof(buff), 0);
#else
  ssize_t n = recv(static_cast<int>(channel->fd), buff, sizeof(buff), 0);
#endif
  MKARES_HOOK(recv, n);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "recv"},
                             {"ret", n},
                             {"data", mkares_maybe_base64(buff, n)},
                         }));
  if (n <= 0) return;
  if (static_cast<size_t>(n) > sizeof(buff)) MKARES_ABORT();
  static_assert(sizeof(buff) <= INT_MAX, "Buffer size MAY cause overflow");
  hostent *host = nullptr;
  int ret = 0;
  switch (query->type) {
    case ns_t_a:
      ret = ares_parse_a_reply(
          reinterpret_cast<unsigned char *>(buff),
          static_cast<int>(n), &host, nullptr, nullptr);
      MKARES_HOOK(ares_parse_a_reply, ret);
      MKARES_EVADD(response, (nlohmann::json{
                                 {"func", "ares_parse_a_reply"},
                                 {"ret", ret},
                             }));
      break;
    case ns_t_aaaa:
      ret = ares_parse_aaaa_reply(
          reinterpret_cast<unsigned char *>(buff),
          static_cast<int>(n), &host, nullptr, nullptr);
      MKARES_HOOK(ares_parse_aaaa_reply, ret);
      MKARES_EVADD(response, (nlohmann::json{
                                 {"func", "ares_parse_aaaa_reply"},
                                 {"ret", ret},
                             }));
      break;
    default: MKARES_ABORT();  // should not happen
  }
  if (ret != ARES_SUCCESS) return;
  response->good = mkares_response_parse_hostent(response, host);
  ares_free_hostent(host);
}

// mkares_channel_pollrecv polls @p channel waiting for the socket becoming
// readable or a timeout. If polling is successful, then the response is
// read from the @p channel. @p query is the query that has been sent and @p
// response is where to save the response. Aborts if passed any null pointer
// argument, of if @p channel's socket is invalid.
static void mkares_channel_pollrecv(const mkares_channel_t *channel,
                                    const mkares_query_t *query,
                                    mkares_response_uptr &response) {
  if (channel == nullptr || query == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
  if (channel->fd == -1) MKARES_ABORT();
  pollfd pfd{};
  pfd.events = POLLIN;
  int64_t t = channel->timeout;
  t = (t < 0) ? -1 : (t < INT_MAX) ? t : INT_MAX;
#ifdef _WIN32
  pfd.fd = static_cast<SOCKET>(channel->fd);
  int ret = WSAPoll(&pfd, 1, static_cast<int>(t));
#else
  pfd.fd = static_cast<int>(channel->fd);
  int ret = poll(&pfd, 1, static_cast<int>(t));
#endif
  MKARES_HOOK(poll, ret);
  MKARES_EVADD(response, (nlohmann::json{
                             {"func", "poll"},
                             {"ret", ret},
                         }));
  if (ret > 0) {
    mkares_channel_recv(channel, query, response);
  }
}

mkares_response_t *mkares_channel_sendrecv_nonnull(
    mkares_channel_t *channel, const mkares_query_t *query) {
  if (channel == nullptr || query == nullptr) MKARES_ABORT();
  mkares_response_uptr response{new mkares_response_t};
  if (!mkares_channel_send(channel, query, response)) return response.release();
  mkares_channel_pollrecv(channel, query, response);
  return response.release();
}

void mkares_channel_delete(mkares_channel_t *channel) {
  if (channel != nullptr && channel->fd != -1) {
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(channel->fd));
#else
    close(static_cast<int>(channel->fd));
#endif
  }
  delete channel;  // gracefully handles nullptr
}

// mkares_event
// ------------

// mkares_event is the private data of mkares_event_t.
struct mkares_event {
  // s is the serialised event.
  std::string s;
};

const char *mkares_event_str(const mkares_event_t *event) {
  if (event == nullptr) MKARES_ABORT();
  return event->s.c_str();
}

void mkares_event_delete(mkares_event_t *event) { delete event; }

// mkares_reaper
// --------------------

// mkares_dead_context is the context of a dying channel and query.
struct mkares_dead_context {
  // since saves the number of milliseconds when we started monitoring
  // this channel and query for subsequent responses.
  int64_t since = 0;

  // channel is the channel previously used for sending a query and that
  // already received a response for such query.
  mkares_channel_uptr channel;

  // query is the query that was sent.
  mkares_query_uptr query;
};

// mkares_dead_context_uptr is a unique pointer to mkares_dead_context.
using mkares_dead_context_uptr = std::unique_ptr<mkares_dead_context>;

// mkares_reaper is the private data of mkares_reaper_t.
struct mkares_reaper {
  // context is the list of contexts we're monitoring.
  std::deque<mkares_dead_context_uptr> contexts;

  // events contains the events occurred when receiving subsequent
  // responses after we've already received a response.
  std::deque<mkares_event_uptr> events;

  // mutex protects data structure against concurrent access.
  std::mutex mutex;

  // stop is a flag used to stop the worker thread.
  std::atomic_bool stop{false};

  // thread is a worker thread that checks for subsequent responses.
  std::thread thread;
};

// mkares_reaper_loop loops over @p reaper's contexts until the @p reaper
// is ordered to stop. For each context, it waits until either its channel
// socket becomes readable or there is a timeout. When it's readable, it
// reads and saves the response. After reading a response, or in case there
// is a timeout, the context is then discarded.
static void mkares_reaper_loop(mkares_reaper_t *reaper) {
  if (reaper == nullptr) MKARES_ABORT();
  while (!reaper->stop) {
    std::deque<mkares_dead_context_uptr> contexts;
    {
      std::unique_lock<std::mutex> _{reaper->mutex};
      while (!reaper->contexts.empty()) {
        mkares_dead_context_uptr context;
        std::swap(context, reaper->contexts.front());
        reaper->contexts.pop_front();
        if (context->channel->fd == -1) continue;  // safety net
        contexts.push_back(std::move(context));
      }
    }
    std::vector<pollfd> pfds;
    for (mkares_dead_context_uptr &context : contexts) {
      pollfd pfd{};
      pfd.events = POLLIN;
#ifdef _WIN32
      pfd.fd = static_cast<SOCKET>(context->channel->fd);
#else
      pfd.fd = static_cast<int>(context->channel->fd);
#endif
    }
    constexpr int timeout = 250;
    // TODO(bassosimone): make sure we don't overflow the size
    // TODO(bassosimone): on Windows specifically, we should sleep
    // if there is no available file descriptor.
#ifdef _WIN32
    int ret = WSAPoll(pfds.data(), pfds.size(), timeout);
#else
    int ret = poll(pfds.data(), pfds.size(), timeout);
#endif
    // TODO(bassosimone): specifically handle all poll errors
    if (ret < 0) continue;
    std::set<int64_t> readable_or_error;
    for (const pollfd &pfd : pfds) {
      if (pfd.revents != 0) readable_or_error.insert(pfd.fd);
    }
    while (!contexts.empty()) {
      mkares_dead_context_uptr context;
      std::swap(context, contexts.front());
      contexts.pop_front();
      if (readable_or_error.count(context->channel->fd) <= 0 &&
          (context->channel->timeout < 0 ||
           mkares_now() - context->since > context->channel->timeout)) {
        reaper->contexts.push_back(std::move(context));
        continue;  // try again
      }
      if (readable_or_error.count(context->channel->fd) <= 0) {
        continue;  // timed out (good!)
      }
      // If we arrive here, the channel is readable (or there has been an
      // error). So, re-execute the recv path and store the results.
      mkares_response_uptr response{new mkares_response_t};
      mkares_channel_recv(
          context->channel.get(), context->query.get(), response);
      for (std::string &s : response->events) {
        mkares_event_uptr event{new mkares_event_t};
        std::swap(s, event->s);
        std::unique_lock<std::mutex> _{reaper->mutex};
        reaper->events.push_back(std::move(event));
      }
    }
  }
}

mkares_reaper_t *mkares_reaper_new_nonnull() {
  mkares_reaper_uptr reaper{new mkares_reaper_t};
  reaper->thread = std::thread{
      mkares_reaper_loop,
      reaper.get()};
  return reaper.release();
}

void mkares_reaper_movein_channel_and_query(
    mkares_reaper_t *reaper, mkares_channel_t *channel,
    mkares_query_t *query) {
  if (reaper == nullptr || channel == nullptr || query == nullptr) {
    MKARES_ABORT();
  }
  std::unique_lock<std::mutex> _{reaper->mutex};
  mkares_dead_context_uptr dead_context{new mkares_dead_context};
  dead_context->since = mkares_now();
  dead_context->channel.reset(channel);
  dead_context->query.reset(query);
  reaper->contexts.push_back(std::move(dead_context));
}

mkares_event_t *mkares_reaper_get_next_event(mkares_reaper_t *reaper) {
  if (reaper == nullptr) MKARES_ABORT();
  mkares_event_uptr event;
  std::unique_lock<std::mutex> _{reaper->mutex};
  if (!reaper->events.empty()) {
    std::swap(event, reaper->events.front());
    reaper->events.pop_front();
  }
  return event.release();
}

void mkares_reaper_delete(mkares_reaper_t *reaper) {
  if (reaper != nullptr) {
    reaper->stop = true;
    reaper->thread.join();
    delete reaper;
  }
}

#endif  // MKARES_INLINE_IMPL
#endif  // __cplusplus
#endif  // MEASUREMENT_KIT_MKARES_H
