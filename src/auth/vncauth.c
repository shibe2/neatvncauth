#include "auth/auth.h"
#include "auth/vncauth.h"
#include "common.h"
#include "crypto/d3des.h"

void vncauth_set_password(struct nvnc* server, const char* password)
{
	size_t len = strlen(password);
	unsigned char key[8];
	for (size_t i = 0; i < 8U; ++i)
		key[i] = i < len ? password[i] : 0;
	des_set_key(server->password_sched, key, EN0);
	server->has_vnc_password = true;
}

int vncauth_send_challenge(struct nvnc_client* client)
{
	unsigned char challenge[16];
	crypto_random(challenge, 16);
	for (int i = 0; i < 16; i += 8)
		des_crypt(client->server->password_sched, challenge + i, client->vncauth_expected_response + i);
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
