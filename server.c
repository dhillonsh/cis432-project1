#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netdb.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <errno.h>

#include "duckchat.h"
#include "linkedlist.h"
#include "iterator.h"

#define BUFLEN 1024
int BUFFER_SIZE = 256;
int is_alive = 1;

int server_socket;

/* Data Structures */
//Channel Name: Linked List <sockaddr_in.sin_port>
std::map<std::string, LinkedList*> channels_map; // Map the channel name to its list of users

//sockaddr_in.sin_port: Linked List <Channel names>
std::map<uint16_t, LinkedList*> user_channels_map; // Map the user's sock to their list of active channels

//sockaddr_in.sin_port: username
std::map<uint16_t, std::string> username_map; // Map the user's sock to their username

/* -- Data Structures */


/* Prototypes */
void send_client_error(uint16_t, char *);
void log_message(char *);
void log_error(char *);

void remove_from_channel(char *, uint16_t);

void handle_recv(struct sockaddr_in *, struct request *);
void handle_recv_login(struct sockaddr_in *, struct request_login *);
void handle_recv_logout(struct sockaddr_in *, struct request_logout *);
void handle_recv_join(struct sockaddr_in *, struct request_join *);
void handle_recv_leave(struct sockaddr_in *, struct request_leave *);
void handle_recv_say(struct sockaddr_in *, struct request_say *);
void handle_recv_list(struct sockaddr_in *, struct request_list *);
void handle_recv_who(struct sockaddr_in *, struct request_who *);
/* -- Prototypes -- */

int is_logged_in(uint16_t client_port) {
	return user_channels_map.count(client_port) != 0;
}
const char *get_username(uint16_t client_port) {
	return username_map[client_port].c_str();
}

/* Map Functions */
void login_user(struct sockaddr_in *client_addr, char *username) {
	/*
	Add the client_addr to the `username_map` if it is not in it already.
	Add the client_addr to the `user_channels_map` if it is not in it already.

	*/
	uint16_t client_port = htons(client_addr->sin_port);
	if(username_map.count(client_port) > 0) return;

	username_map[client_port] = strdup(username);

	LinkedList *channel_list_ll = ll_create();
	user_channels_map[client_port] = channel_list_ll;
}



/* -- Map Functions -- */
int server_write(uint16_t client_port, void *packet, int packet_size) {
	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(client_port);

	return sendto(server_socket, packet, packet_size, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in));
}

void send_client_error(uint16_t client_port, char *error_message) {
	struct text_error *packet = (struct text_error *)malloc(sizeof(struct text_error));
	packet->txt_type = htonl(TXT_ERROR);
	strncpy(packet->txt_error, error_message, SAY_MAX);
	server_write(client_port, packet, sizeof(struct text_error));
}

void log_message(char *error_message) {
	printf("server: %s\n", error_message);
}

void log_error(char *error_message) {
	printf("* %s\n", error_message);
}


void remove_from_channel(char *channel_name, uint16_t client_port) {
	if(ll_size(channels_map[channel_name]) == 0) return;

	char error_message[BUFFER_SIZE];
	uint16_t **tmp_client_port = (uint16_t **)calloc(1, sizeof(uint16_t));
	int it_index = 0;

	Iterator *it = ll_it_create(channels_map[channel_name]);

	// Find the user's client_port and remove it from the map
	while(it_hasNext(it)) {
		it_next(it, (void **)tmp_client_port);
		if(**tmp_client_port == client_port) {
			if(ll_size(channels_map[channel_name]) == 1) {
				ll_destroy(channels_map[channel_name], NULL);
				channels_map.erase(channels_map.find(channel_name));

				snprintf(error_message, BUFFER_SIZE, "removing empty channel %s", channel_name);
				log_message(error_message);

			} else ll_remove(channels_map[channel_name], it_index, (void**)tmp_client_port);
			break;
		}
		it_index++;
	}
	it_destroy(it);
	free(tmp_client_port);
}

void handle_recv_login(struct sockaddr_in *client_addr, struct request_login *in_packet) {
	char error_message[BUFFER_SIZE];
	char *username = in_packet->req_username;

	login_user(client_addr, username);
	snprintf(error_message, BUFFER_SIZE, "%s logs in", username);
	log_message(error_message);
}

void handle_recv_logout(struct sockaddr_in *client_addr, struct request_logout *in_packet) {
	char error_message[BUFFER_SIZE];
	char client_error[SAY_MAX];
	uint16_t client_port = htons(client_addr->sin_port);

	if(is_logged_in(client_port) == 0) {
		/*snprintf(error_message, BUFFER_SIZE, "%s tried to send [logout] without being logged in.", get_username(*client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(*client_port, client_error);*/
		return;
	}

	char **tmp_channel = (char**)calloc(1, CHANNEL_MAX);

	/* Update user_channels_map */
	if(ll_size(user_channels_map[client_port]) > 0) {
		Iterator *channel_name_it = ll_it_create(user_channels_map[client_port]);

		while(it_hasNext(channel_name_it)) {
			it_next(channel_name_it, (void **)tmp_channel);

			// For each channel the user belongs to, iterate over the channel's list of users and remove client_port
			remove_from_channel(*tmp_channel, client_port);
		}

		// Destroy the map containing the chats the user belongs to
		ll_destroy(user_channels_map[client_port], NULL);
	}
	user_channels_map.erase(user_channels_map.find(client_port));

	//free(username_map[client_port]);
	username_map.erase(username_map.find(client_port));
}

void handle_recv_join(struct sockaddr_in *client_addr, struct request_join *in_packet) {
	char client_error[SAY_MAX];
	char error_message[BUFFER_SIZE];
	char *channel_name = strdup(in_packet->req_channel);
	uint16_t *client_port = (uint16_t *)calloc(1, sizeof(uint16_t));
	*client_port = htons(client_addr->sin_port);

	if(is_logged_in(*client_port) == 0) {
		/*snprintf(error_message, BUFFER_SIZE, "%s tried to send [join] without being logged in.", get_username(*client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(*client_port, client_error);*/
		return;
	}

	ll_add(user_channels_map[*client_port], strdup(channel_name));

	/* Create channels_map linked list if it doesn't exist already */
	if(channels_map.count(channel_name) == 0) channels_map[channel_name] = ll_create();

	/* Update channels_map linked list */
	if(is_logged_in(*client_port) == 0) {
		printf("User tried to /leave without being logged in.\n");

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(*client_port, client_error);
		return;
	}

	ll_add(channels_map[channel_name], client_port);

	snprintf(error_message, BUFFER_SIZE, "%s joins channnel %s", get_username(*client_port), in_packet->req_channel);
	log_message(error_message);
}

void handle_recv_leave(struct sockaddr_in *client_addr, struct request_leave *in_packet) {
	char error_message[BUFFER_SIZE];
	char client_error[SAY_MAX];
	uint16_t client_port = htons(client_addr->sin_port);

	long it_index;
	char *channel_name = strdup(in_packet->req_channel);
	char **tmp_channel = (char**)calloc(1, CHANNEL_MAX);
	char **tmp_username = (char**)calloc(1, USERNAME_MAX);

	int found_in_map = 0;

	if(is_logged_in(client_port) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s tried to send [leave] without being logged in.", get_username(client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(client_port, client_error);
		return;
	}

	if(channels_map.count(in_packet->req_channel) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s trying to leave non-existent channel %s", get_username(client_port), in_packet->req_channel);
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: No channel by the name %s", in_packet->req_channel);
		send_client_error(client_port, client_error);
		return;
	}

	/* Update user_channels_map */
	if(ll_size(user_channels_map[client_port]) > 0) {
		it_index = 0;
		Iterator *it = ll_it_create(user_channels_map[client_port]);

		// Remove in_packet->req_channel from the user's list of active channels
		while(it_hasNext(it)) {
			it_next(it, (void **)tmp_channel);

			if(strcmp(*tmp_channel, in_packet->req_channel) == 0) {
				ll_remove(user_channels_map[client_port], it_index, (void **)tmp_channel);
				break;
			}
			it_index++;
		}
		it_destroy(it);
		found_in_map = 1;
	}

	if(found_in_map == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s trying to leave channel %s  where he/she is not a member", get_username(client_port), in_packet->req_channel);
		log_message(error_message);

		//FIXME: Send error message to user
		return;
	}

	/* Update channels_map linked list */
	found_in_map = 0;
	uint16_t **tmp_client_port = (uint16_t **)calloc(1, sizeof(uint16_t));

	if(ll_size(channels_map[in_packet->req_channel]) > 0) {
		it_index = 0;
		Iterator *it = ll_it_create(channels_map[in_packet->req_channel]);

		while(it_hasNext(it)) {
			it_next(it, (void **)tmp_client_port);
			if(**tmp_client_port == client_port) {
				if(ll_size(channels_map[in_packet->req_channel]) == 1) {
					ll_destroy(channels_map[in_packet->req_channel], NULL);
					channels_map.erase(channels_map.find(in_packet->req_channel));

					snprintf(error_message, BUFFER_SIZE, "removing empty channel %s", in_packet->req_channel);
					log_message(error_message);

				} else ll_remove(channels_map[in_packet->req_channel], it_index, (void**)tmp_client_port);
				break;
			}
			it_index++;
		}
		it_destroy(it);
	}
	free(tmp_client_port);

	snprintf(error_message, BUFFER_SIZE, "%s leaves channel %s", get_username(client_port), in_packet->req_channel);
	log_message(error_message);
}

void handle_recv_say(struct sockaddr_in *client_addr, struct request_say *in_packet) {
	char client_error[SAY_MAX];
	char error_message[BUFFER_SIZE];
	uint16_t client_port = htons(client_addr->sin_port);
	int found_in_map = 0;

	if(is_logged_in(client_port) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s tried to send [say] without being logged in.", get_username(client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(client_port, client_error);
		return;
	}

	/* Check if user is joined in the channel they are attempting to send [say] from */
	char **tmp_channel = (char**)calloc(1, CHANNEL_MAX);

	if(ll_size(user_channels_map[client_port]) > 0) {
		Iterator *it = ll_it_create(user_channels_map[client_port]);

		while(it_hasNext(it)) {
			it_next(it, (void **)tmp_channel);
			if(strcmp(*tmp_channel, in_packet->req_channel) == 0) {
				found_in_map = 1;
				break;
			}
		}
		it_destroy(it);
	}

	if(found_in_map == 0) {
		printf("User attempted to [say] from a chat they are not joined to.\n");
		return;
	}

	/* Set up the outgoing packet */
	struct text_say *packet = (struct text_say *)malloc(sizeof(struct text_say));
	packet->txt_type = htonl(TXT_SAY);
	strncpy(packet->txt_channel, in_packet->req_channel, CHANNEL_MAX);
	strncpy(packet->txt_username, get_username(client_port), USERNAME_MAX);
	strncpy(packet->txt_text, in_packet->req_text, SAY_MAX);

	/* Send the packet to all users in the channels_map */
	uint16_t **tmp_client_port = (uint16_t **)calloc(1, sizeof(uint16_t));

	if(channels_map.count(in_packet->req_channel) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s trying to [say] in non-existing channel %s", get_username(client_port), in_packet->req_channel);
		log_message(error_message);
		return;
	}

	Iterator *it = ll_it_create(channels_map[in_packet->req_channel]);

	while(it_hasNext(it)) {
		it_next(it, (void **)tmp_client_port);
		server_write(**tmp_client_port, packet, sizeof(struct text_say));
	}
	it_destroy(it);
	free(tmp_client_port);

	snprintf(error_message, BUFFER_SIZE, "%s sends say message in %s", get_username(client_port), in_packet->req_channel);
	log_message(error_message);
}

void handle_recv_list(struct sockaddr_in *client_addr, struct request_list *in_packet) {
	char client_error[SAY_MAX];
	char error_message[BUFFER_SIZE];
	uint16_t client_port = htons(client_addr->sin_port);

	if(is_logged_in(client_port) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s tried to send [list] without being logged in.", get_username(client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(client_port, client_error);
		return;
	}

	/* Set up the outgoing packet */
	struct text_list *packet = (struct text_list *)malloc(sizeof(struct text_list) + (sizeof(struct channel_info) * channels_map.size()));

	packet->txt_type = htonl(TXT_LIST);
	packet->txt_nchannels = channels_map.size();

	int channel_index = 0;
	std::map<std::string, LinkedList*>::iterator channels_it;

	for(channels_it = channels_map.begin(); channels_it != channels_map.end(); channels_it++) {
		strcpy(((packet->txt_channels) + channel_index)->ch_channel, channels_it->first.c_str());
		channel_index++;
	}

	server_write(client_port, packet, sizeof(struct text_list) + (sizeof(struct channel_info) * channels_map.size()));

	snprintf(error_message, BUFFER_SIZE, "%s lists channels", get_username(client_port));
	log_message(error_message);
}

void handle_recv_who(struct sockaddr_in *client_addr, struct request_who *in_packet) {
	char client_error[SAY_MAX];
	char error_message[BUFFER_SIZE];
	uint16_t client_port = htons(client_addr->sin_port);

	if(is_logged_in(client_port) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s tried to send [who] without being logged in.", get_username(client_port));
		log_message(error_message);

		snprintf(client_error, SAY_MAX, "Error: You are not logged in.");
		send_client_error(client_port, client_error);
		return;
	}

	if(channels_map.count(in_packet->req_channel) == 0) {
		snprintf(error_message, BUFFER_SIZE, "%s trying to list users in non-existing channel %s", get_username(client_port), in_packet->req_channel);
		log_message(error_message);

		struct text_error *packet = (struct text_error *)malloc(sizeof(struct text_error));
		packet->txt_type = htonl(TXT_ERROR);
		snprintf(packet->txt_error, SAY_MAX, "Error: No channel by the name %s", in_packet->req_channel);
		server_write(client_port, packet, sizeof(struct text_error));
		return;
	}

	/* Set up the outgoing packet */
	struct text_who *packet = (struct text_who *)malloc(sizeof(struct text_who) + (sizeof(struct user_info) * ll_size(channels_map[in_packet->req_channel])));

	packet->txt_type = htonl(TXT_WHO);
	strncpy(packet->txt_channel, in_packet->req_channel, CHANNEL_MAX);
	packet->txt_nusernames = ll_size(channels_map[in_packet->req_channel]);

	uint16_t **tmp_client_port = (uint16_t **)calloc(1, sizeof(uint16_t));
	Iterator *it = ll_it_create(channels_map[in_packet->req_channel]);
	int username_index = 0;

	while(it_hasNext(it)) {
		it_next(it, (void **)tmp_client_port);
		strcpy(((packet->txt_users) + username_index)->us_username, get_username(**tmp_client_port));
		username_index++;
	}
	it_destroy(it);
	free(tmp_client_port);

	server_write(client_port, packet, sizeof(struct text_who) + (sizeof(struct user_info) * ll_size(channels_map[in_packet->req_channel])));

	snprintf(error_message, BUFFER_SIZE, "%s lists users in channel %s", get_username(client_port), in_packet->req_channel);
	log_message(error_message);
}

void handle_recv(struct sockaddr_in *client_addr, struct request *packet, int packet_size) {
	switch(ntohl(packet->req_type)) {
		case REQ_LOGIN:
			if(sizeof(struct request_login) != packet_size) {
				char error_message[] = "Received invalid request_login packet from client.";
				log_error(error_message);
			} else handle_recv_login(client_addr, (struct request_login *) packet);
			return;
		case REQ_LOGOUT:
			if(sizeof(struct request_logout) != packet_size) {
				char error_message[] = "Received invalid request_logout packet from client.";
				log_error(error_message);
			} else handle_recv_logout(client_addr, (struct request_logout *) packet);
			return;
		case REQ_JOIN:
			if(sizeof(struct request_join) != packet_size) {
				char error_message[] = "Received invalid request_join packet from client.";
				log_error(error_message);
			} else handle_recv_join(client_addr, (struct request_join *) packet);
			return;
		case REQ_LEAVE:
			if(sizeof(struct request_leave) != packet_size) {
				char error_message[] = "Received invalid request_leave packet from client.";
				log_error(error_message);
			} else handle_recv_leave(client_addr, (struct request_leave *) packet);
			return;
		case REQ_SAY:
			if(sizeof(struct request_say) != packet_size) {
				char error_message[] = "Received invalid request_say packet from client.";
				log_error(error_message);
			} else handle_recv_say(client_addr, (struct request_say *) packet);
			return;
		case REQ_LIST:
			if(sizeof(struct request_list) != packet_size) {
				char error_message[] = "Received invalid request_list packet from client.";
				log_error(error_message);
			} else handle_recv_list(client_addr, (struct request_list *) packet);
			return;
		case REQ_WHO:
			if(sizeof(struct request_who) != packet_size) {
				char error_message[] = "Received invalid request_who packet from client.";
				log_error(error_message);
			} else handle_recv_who(client_addr, (struct request_who *) packet);
			return;
		default:
			char error_message[] = "Received unknown packet from client.";
			log_error(error_message);
			return;
	}
}

int main(int argc, char** argv) {
	char buf[BUFLEN];
	char from_buffer[1028];

	if(argc != 4) {
		printf("Usage: ./client server_socket server_port username\n");
		return 1;
	}

	struct sockaddr_in *from_socket = (sockaddr_in *)malloc(sizeof(sockaddr_in));
	socklen_t from_socket_len = sizeof(struct sockaddr_in);

	int packet_size;
	int status =- 1;
	server_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if(server_socket < 0)
		printf("Failed creating socket\n");

	int opt = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(struct sockaddr_in));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(123123);

	if((status = bind(server_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr))) < 0)
		printf("bind error with port %s\n", strerror(errno));

	while(is_alive == 1) {
		if((packet_size = recvfrom(server_socket, from_buffer, sizeof from_buffer, 0, (struct sockaddr *)from_socket, &from_socket_len)) > 0) {
			handle_recv(from_socket, (struct request *)from_buffer, packet_size);
		}
	}

	free(from_socket);

	return 0;
}