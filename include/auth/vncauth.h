#pragma once

struct nvnc;
struct nvnc_client;

void vncauth_set_password(struct nvnc* server, const char* password);
int vncauth_send_challenge(struct nvnc_client* client);
int vncauth_handle_response(struct nvnc_client* client);

