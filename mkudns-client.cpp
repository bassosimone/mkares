#include <iostream>

#include <stdlib.h>

#include <iostream>
#include <sstream>

#include "mkudns.h"

#define MKDATA_INLINE_IMPL
#include "mkdata.hpp"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif  // __clang__
#include "argh.h"
#ifdef __clang__
#pragma clang diagnostic pop
#endif  // __clang__

// LCOV_EXCL_START
static void usage() {
  // clang-format off
  std::clog << "\n";
  std::clog << "Usage: mkudns-client [options] <domain>\n";
  std::clog << "\n";
  std::clog << "Options can start with either a single dash (i.e. -option) or\n";
  std::clog << "a double dash (i.e. --option). Available options:\n";
  std::clog << "\n";
  std::clog << "  --server-address <ip> : name server address\n";
  std::clog << std::endl;
  // clang-format on
}
// LCOV_EXCL_STOP

static void summary(mkudns_response_uptr &response) {
  std::clog << "=== BEGIN SUMMARY ==="
            << std::endl
            << "Response good: "
            << mkudns_response_good(response.get())
            << std::endl
            << "Response cname: "
            << mkudns_response_get_cname(response.get())
            << std::endl
            << "Send event: "
            << mkudns_response_get_send_event(response.get())
            << std::endl
            << "Recv event: "
            << mkudns_response_get_recv_event(response.get())
            << std::endl
            << "=== END SUMMARY ==="
            << std::endl
            << std::endl;
  std::clog << "=== BEGIN ADDRESSES ==="
            << std::endl;
  {
    size_t total = mkudns_response_get_addresses_size(response.get());
    for (size_t i = 0; i < total; ++i) {
      std::clog << "- "
                << mkudns_response_get_address_at(response.get(), i)
                << std::endl;
    }
  }
  std::clog << "=== END ADDRESSES ==="
            << std::endl
            << std::endl;
}

int main(int, char **argv) {
  mkudns_query_uptr query{mkudns_query_new_nonnull()};
  {
    argh::parser cmdline;
    cmdline.add_param("server-address");
    cmdline.parse(argv);
    for (auto &flag : cmdline.flags()) {
      if (0) {
        // TODO(bassosimone): here we'll probably have flags
      } else {
        std::clog << "fatal: unrecognized flag: " << flag << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    for (auto &param : cmdline.params()) {
      if (param.first == "server-address") {
        mkudns_query_set_server_address(query.get(), param.second.c_str());
      } else {
        std::clog << "fatal: unrecognized param: " << param.first << std::endl;
        usage();
        exit(EXIT_FAILURE);
      }
    }
    auto sz = cmdline.pos_args().size();
    if (sz != 2) {
      usage();
      exit(EXIT_FAILURE);
    }
    mkudns_query_set_name(query.get(), cmdline.pos_args()[1].c_str());
  }
  mkudns_response_uptr response{mkudns_query_perform_nonnull(query.get())};
  summary(response);
  if (!mkudns_response_good(response.get())) {
    std::clog << "FATAL: the query did not succeed" << std::endl;
    exit(EXIT_FAILURE);
  }
}
