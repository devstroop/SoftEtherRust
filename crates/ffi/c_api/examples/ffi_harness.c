#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/softether_c_api.h"

static void on_state(int s, void* u) { fprintf(stderr, "state=%d\n", s); }
static void on_event(int lvl, int code, const char* msg, void* u) { fprintf(stderr, "event[%d/%d]: %s\n", lvl, code, msg?msg:"(null)"); }
static void on_rx(const uint8_t* data, uint32_t len, void* u) { fprintf(stderr, "rx len=%u\n", len); }

int main() {
  const char* json = "{\"server\":\"127.0.0.1\",\"port\":443,\"hub\":\"DEFAULT\",\"username\":\"user\",\"password\":\"pass\",\"use_encrypt\":true,\"use_compress\":false,\"max_connections\":1,\"insecure_skip_verify\":true}";
  softether_client_t* h = softether_client_create(json);
  if (!h) { fprintf(stderr, "create failed\n"); return 1; }
  softether_client_set_state_callback(h, on_state, NULL);
  softether_client_set_event_callback(h, on_event, NULL);
  softether_client_set_rx_callback(h, on_rx, NULL);
  int r = softether_client_connect(h);
  fprintf(stderr, "connect=%d\n", r);
  // Sleep briefly to exercise callbacks (replace with proper wait in a real app)
#ifdef _WIN32
  Sleep(5000);
#else
  usleep(5*1000*1000);
#endif
  softether_client_disconnect(h);
  softether_client_free(h);
  return 0;
}
