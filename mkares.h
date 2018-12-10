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

typedef struct mkares_response mkares_response_t;

const char *mkares_response_get_cname(const mkares_response_t *response);

size_t mkares_response_get_addresses_size(const mkares_response_t *response);

const char *mkares_response_get_address_at(
    const mkares_response_t *response, size_t idx);

size_t mkares_response_get_events_size(const mkares_response_t *response);

const char *mkares_response_get_event_at(
    const mkares_response_t *response, size_t idx);

void mkares_response_delete(mkares_response_t *response);

typedef struct mkares_channel mkares_channel_t;

mkares_channel_t *mkares_channel_new_nonnull(void);

void mkares_channel_set_address(mkares_channel_t *channel, const char *address);

void mkares_channel_set_port(mkares_channel_t *channel, const char *port);

mkares_response_t *mkares_channel_sendrecv_nonnull(
    mkares_channel_t *channel, const mkares_query_t *query);

void mkares_channel_delete(mkares_channel_t *channel);

typedef struct mkares_event mkares_event_t;

const char *mkares_event_str(const mkares_event_t *event);

void mkares_event_delete(mkares_event_t *event);

typedef struct mkares_reaper mkares_reaper_t;

mkares_reaper_t *mkares_reaper_new_nonnull(void);

void mkares_reaper_movein_channel_and_query(
    mkares_reaper_t *reaper,
    mkares_channel_t *channel, mkares_query_t *query);

mkares_event_t *mkares_reaper_get_next_event(
    mkares_reaper_t *reaper);

void mkares_reaper_delete(mkares_reaper_t *reaper);

#ifdef __cplusplus
}  // extern "C"

#include <memory>
#include <string>

struct mkares_query_deleter {
  void operator()(mkares_query_t *query) {
    mkares_query_delete(query);
  }
};

using mkares_query_uptr = std::unique_ptr<mkares_query_t,
                                          mkares_query_deleter>;

struct mkares_response_deleter {
  void operator()(mkares_response_t *response) {
    mkares_response_delete(response);
  }
};

using mkares_response_uptr = std::unique_ptr<mkares_response_t,
                                             mkares_response_deleter>;

struct mkares_channel_deleter {
  void operator()(mkares_channel_t *channel) {
    mkares_channel_delete(channel);
  }
};

using mkares_channel_uptr = std::unique_ptr<mkares_channel_t,
                                            mkares_channel_deleter>;

struct mkares_event_deleter {
  void operator()(mkares_event_t *event) {
    mkares_event_delete(event);
  }
};

using mkares_event_uptr = std::unique_ptr<mkares_event_t,
                                          mkares_event_deleter>;

struct mkares_reaper_deleter {
  void operator()(mkares_reaper_t *reaper) {
    mkares_reaper_delete(reaper);
  }
};

using mkares_reaper_uptr = std::unique_ptr<mkares_reaper_t,
                                           mkares_reaper_deleter>;

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

#include "json.hpp"

#include "mkdata.h"

#ifndef MKARES_ABORT
#define MKARES_ABORT() abort()
#endif

#ifndef MKARES_HOOK
#define MKARES_HOOK(T, V)  // Nothing
#endif

// mkares_query
// ------------

struct mkares_query {
  std::string name;
  int dnsclass = ns_c_in;
  uint16_t id = 0;
  int type = ns_t_a;
};

// TODO(bassosimone): as suggested by @irl we SHOULD NOT emit requests
// with predictable queries to avoid being fingerprintable.

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

// mkares_response
// ---------------

struct mkares_response {
  std::vector<std::string> addresses;
  std::vector<std::string> events;
  std::string cname;
  int64_t good = false;
};

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

struct mkares_channel {
  std::string address;
  std::string port = "53";
  int64_t timeout = 3000;  // millisecond
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
  if (count <= 0 || static_cast<uint64_t>(count) > SIZE_MAX) {
    return "";
  }
  mkdata_uptr data{mkdata_new_nonnull()};
  mkdata_movein_data(data, std::string{reinterpret_cast<const char *>(buff),
                                       static_cast<size_t>(count)});
  return mkdata_moveout_base64(data);
}

// mkares_channel_send_buffer sends @p count bytes buffer starting at
// @p base over @p channel and logs events in @p response. This function will
// abort if passed any null pointer, if @p count is not positive, or if
// @p channel is already connected. Returns a boolean valud indicating whether
// it succeded or not.
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
                             {"data", mkares_maybe_base64(base, n)},
                         }));
  if (n < 0 || static_cast<size_t>(n) != count) return false;
  return true;
}

// mkares_channel_send sends @p query over @p channel logging events
// in @p response. Aborts if passed null pointers. Returns a bool value
// indicating whether it succeeded or not.
static bool
mkares_channel_send(mkares_channel_t *channel, const mkares_query_t *query,
                    mkares_response_uptr &response) {
  if (channel == nullptr || query == nullptr || response == nullptr) {
    MKARES_ABORT();
  }
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
      default: MKARES_ABORT();
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
// readable or a timeout. @p query is the query that has been sent and @p
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

struct mkares_event {
  std::string s;
};

const char *mkares_event_str(const mkares_event_t *event) {
  if (event == nullptr) MKARES_ABORT();
  return event->s.c_str();
}

void mkares_event_delete(mkares_event_t *event) { delete event; }

// mkares_reaper
// --------------------

struct mkares_dead_context {
  int64_t since = 0;
  mkares_channel_uptr channel;
  mkares_query_uptr query;
};

using mkares_dead_context_uptr = std::unique_ptr<mkares_dead_context>;

struct mkares_reaper {
  std::deque<mkares_dead_context_uptr> contexts;
  std::deque<mkares_event_uptr> events;
  std::mutex mutex;
  std::atomic_bool stop{false};
  std::thread thread;
};

static void mkares_reaper_loop(
    mkares_reaper_t *reaper) {
  if (reaper == nullptr) MKARES_ABORT();
  while (!reaper->stop) {
    std::deque<mkares_dead_context_uptr> contexts;
    {
      std::unique_lock<std::mutex> _{reaper->mutex};
      while (!reaper->contexts.empty()) {
        mkares_dead_context_uptr context;
        std::swap(context, reaper->contexts.front());
        reaper->contexts.pop_front();
        if (context->channel->fd == -1) continue;
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
        continue;
      }
      if (readable_or_error.count(context->channel->fd) <= 0) {
        continue;
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

mkares_event_t *mkares_reaper_get_next_event(
    mkares_reaper_t *reaper) {
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
