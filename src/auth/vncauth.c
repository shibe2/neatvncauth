#include <nettle/des.h>

#include "auth/auth.h"
#include "auth/vncauth.h"
#include "common.h"

void vncauth_set_password(struct nvnc* server, const char* password)
{
	uint8_t key[8];
	size_t len = strlen(password);
	for (size_t i = 0; i < 8U; ++i) {
		uint8_t b;
		if (i < len) {
			b = password[i];
			b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
			b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
			b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
		} else {
			b = 0;
		}
		key [i] = b;
	}
	des_fix_parity(8, key, key);
	des_set_key(&server->password_sched, key);
	server->has_vnc_password = true;
}

int vncauth_send_challenge(struct nvnc_client* client)
{
	uint8_t challenge[16];
	crypto_random(challenge, 16);
	for (int i = 0; i < 16; i += 8)
		des_encrypt(&client->server->password_sched, 8, client->vncauth_expected_response + i, challenge + i);
	return stream_write(client->net_stream, challenge, 16, NULL, NULL);
}

int vncauth_handle_response(struct nvnc_client* client)
{
	if (client->buffer_len - client->buffer_index < 16)
		return 0;
	if (memcmp(client->msg_buffer + client->buffer_index, client->vncauth_expected_response, 16)) {
		security_handshake_failed(client, NULL, "Invalid VNC password");
		return -1;
	}
	security_handshake_ok(client, NULL);
	client->state = VNC_CLIENT_STATE_WAITING_FOR_INIT;
	return 16;
}
