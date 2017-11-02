#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <cerrno>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>

#include <assert.h>

#include "duckchat.h"
#include "raw.h"
#include "linkedlist.h"
#include "iterator.h"

/* Prototypes */
void print_prompt();
void restore_prompt();
void clear_prompt();
void log_error(char *);

int server_write(void *, int);
void server_connect(char *, uint16_t);

int handle_send(char *);
int handle_send_login(char *);
int handle_send_logout();
int handle_send_join(char *);
int handle_send_leave(char *);
int handle_send_say(char *, char *);
int handle_send_list();
int handle_send_who(char *);
int handle_send_switch(char *);

void handle_recv(struct text *);
void handle_recv_say(struct text_say *);
void handle_recv_list(struct text_list *);
void handle_recv_who(struct text_who *);
void handle_recv_error(struct text_error *);

char *read_input();
/* -- Prototypes -- */

int BUFFER_SIZE = 256;
int is_alive = 1;

char input_buffer[SAY_MAX + 1];
char *input_buffer_position = input_buffer;

struct sockaddr_in server_addr;
int server_socket;

char prompt_delimeter[10] = ">";
char COMMAND_IDENTIFIER[10] = "/";

LinkedList *joined_channels = NULL;
char active_channel[CHANNEL_MAX] = "Common";

void set_active_channel(char *channel_name) {
	char error_message[BUFFER_SIZE];

	memmove(active_channel, channel_name, CHANNEL_MAX);
	snprintf(error_message, BUFFER_SIZE, "You are now active in the channel: %s", channel_name);
	log_error(error_message);
}

int in_chat(char *channel_name) {
	if(ll_size(joined_channels) == 0) return 0;

	int channel_found = 0;
	char *it_channel;
	Iterator *it = ll_it_create(joined_channels);

	while(it_hasNext(it)) {
		it_next(it, (void **)&it_channel);
		if(strcmp(it_channel, channel_name) == 0) {
			channel_found = 1;
			break;
		}
	}
	it_destroy(it);
	return channel_found;
}

/* Prompt Functions */
void print_prompt() {
	printf("%s", prompt_delimeter);
	fflush(stdout);
}

void restore_prompt_input() {
	int buffer_size = input_buffer_position - input_buffer;
	int i;

	for(i = 0; i < buffer_size; i++) {
		printf("%c", input_buffer[i]);
	}
	fflush(stdout);
}

void clear_prompt() {
	int buffer_size = input_buffer_position - input_buffer + strlen(prompt_delimeter);
	int i;

	for(i = 0; i < buffer_size; i++) {
		printf("\b \b");
	}
	fflush(stdout);
}

void log_error(char *error_message) {
	printf("* %s\n", error_message);
}
/* -- Prompt Functions -- */


/* Socket Handlers */
int server_write(void *packet, int packet_size) {
	int bytes = sendto(server_socket, packet, packet_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if(bytes == -1) {
		char error_message[] = "Unknown command";
		log_error(error_message);
	}
	return bytes;
}

void server_connect(char *server_ip, uint16_t server_port) {
	socklen_t addr_size = sizeof server_addr;

	server_socket = socket(PF_INET, SOCK_DGRAM, 0);

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);

	memset(server_addr.sin_zero, '\0', sizeof server_addr.sin_zero);
	connect(server_socket, (struct sockaddr *) &server_addr, addr_size);
}
/* -- Socket Handlers -- */


/* Client->Server Functions */
int handle_send(char *input) {
	int result = 0;
	char *token;
	char unknown_command[] = "Unknown command";

	if(strncmp(input, COMMAND_IDENTIFIER, strlen(COMMAND_IDENTIFIER)) == 0) {
		input++;

		token = strsep(&input, " ");

		if(strcmp(token, "join") == 0) {
			char *channel_name = strsep(&input, " ");
			if(channel_name == NULL) log_error(unknown_command);
			else handle_send_join(channel_name);
		} else if(strcmp(token, "leave") == 0) {
			char *channel_name = strsep(&input, " ");
			if(channel_name == NULL) log_error(unknown_command);
			else handle_send_leave(channel_name);
		} else if(strcmp(token, "exit") == 0) {
			char *extra_input = strsep(&input, " ");
			if(extra_input != NULL) log_error(unknown_command);
			else handle_send_logout();
		} else if(strcmp(token, "list") == 0) {
			char *extra_input = strsep(&input, " ");
			if(extra_input != NULL) log_error(unknown_command);
			else handle_send_list();
		} else if(strcmp(token, "who") == 0) {
			char *channel_name = strsep(&input, " ");
			if(channel_name == NULL) log_error(unknown_command);
			else handle_send_who(channel_name);
		} else if(strcmp(token, "switch") == 0) {
			char *channel_name = strsep(&input, " ");
			if(channel_name == NULL) log_error(unknown_command);
			else handle_send_switch(channel_name);
		}

	} else handle_send_say(active_channel, input);

	return result;
}

int handle_send_login(char *username) {
	int write_result;
	struct request_login *packet = (struct request_login *)malloc(sizeof(struct request_login));
	memset(packet, 0, sizeof(struct request_login));

	packet->req_type = REQ_LOGIN;
	strncpy(packet->req_username, username, USERNAME_MAX - 1);

	write_result = server_write(packet, sizeof(struct request_login));
	free(packet);
	return write_result;
}

int handle_send_logout() {
	int write_result;
	struct request_logout *packet = (struct request_logout *)malloc(sizeof(struct request_logout));
	memset(packet, 0, sizeof(struct request_logout));

	packet->req_type = REQ_LOGOUT;

	write_result = server_write(packet, sizeof(struct request_logout));
	free(packet);

	char *tmp_channel;
	Iterator *it = ll_it_create(joined_channels);
	while(it_hasNext(it)) {
		it_next(it, (void **)&tmp_channel);
		free(tmp_channel);
	}
	it_destroy(it);
	ll_destroy(joined_channels, NULL);

	is_alive = 0;
	return write_result;
}

int handle_send_join(char *channel_name) {
	int write_result;
	struct request_join *packet = (struct request_join *)malloc(sizeof(struct request_join));
	memset(packet, 0, sizeof(struct request_join));

	packet->req_type = REQ_JOIN;
	strncpy(packet->req_channel, channel_name, CHANNEL_MAX - 1);

	write_result = server_write(packet, sizeof(struct request_join));
	free(packet);

	// Add the channel to the list of joined channels
	if(in_chat(channel_name) == 0) {
		ll_add(joined_channels, strdup(channel_name));

		char error_message[BUFFER_SIZE];
		snprintf(error_message, BUFFER_SIZE, "You have joined the channel: %s", channel_name);
		log_error(error_message);

		set_active_channel(channel_name);
	} else {
		char error_message[] = "You have already joined that channel!";
		log_error(error_message);
	}

	return write_result;
}

int handle_send_leave(char *channel_name) {
	int write_result = 0;

	if(in_chat(channel_name) == 0) {
		return 0;
	}

	struct request_leave *packet = (struct request_leave *)malloc(sizeof(struct request_leave));
	memset(packet, 0, sizeof(struct request_leave));

	packet->req_type = REQ_LEAVE;
	strncpy(packet->req_channel, channel_name, CHANNEL_MAX - 1);
	write_result = server_write(packet, sizeof(struct request_leave));
	free(packet);

	if(ll_size(joined_channels) > 0) {
		int it_index = 0;
		char **tmp_channel = (char**)calloc(1, CHANNEL_MAX);
		Iterator *it = ll_it_create(joined_channels);

		// Remove *channel_name from the user's list of active channels
		while(it_hasNext(it)) {
			it_next(it, (void **)tmp_channel);

			if(strcmp(*tmp_channel, channel_name) == 0) {
				free(*tmp_channel);
				ll_remove(joined_channels, it_index, (void **)tmp_channel);
				break;
			}
			it_index++;
		}
		it_destroy(it);
	}

	return write_result;
}

int handle_send_say(char *channel_name, char *text) {
	int write_result;

	if(in_chat(channel_name) == 0) {
		return 0;
	}

	struct request_say *packet = (struct request_say *)malloc(sizeof(struct request_say));
	memset(packet, 0, sizeof(struct request_say));

	packet->req_type = REQ_SAY;
	strncpy(packet->req_channel, channel_name, CHANNEL_MAX - 1);
	strncpy(packet->req_text, text, SAY_MAX - 1);

	write_result = server_write(packet, sizeof(struct request_say));
	free(packet);
	return write_result;
}

int handle_send_list() {
	int write_result;
	struct request_list *packet = (struct request_list *)malloc(sizeof(struct request_list));
	memset(packet, 0, sizeof(struct request_list));

	packet->req_type = REQ_LIST;

	write_result = server_write(packet, sizeof(struct request_list));
	free(packet);
	return write_result;
}

int handle_send_who(char *channel_name) {
	int write_result;
	struct request_who *packet = (struct request_who *)malloc(sizeof(struct request_who));
	memset(packet, 0, sizeof(struct request_who));

	packet->req_type = REQ_WHO;
	strncpy(packet->req_channel, channel_name, CHANNEL_MAX - 1);

	write_result = server_write(packet, sizeof(struct request_who));
	free(packet);
	return write_result;
}

int handle_send_switch(char *channel_name) {
	if(strcmp(active_channel, channel_name) == 0) {
		char error_message[] = "That is already your active channel!";
		log_error(error_message);
		return 0;
	}
	if(in_chat(channel_name) == 0) {
		char error_message[] = "You have not joined that channel yet!";
		log_error(error_message);
		return 0;
	}
	set_active_channel(channel_name);
	return 1;
}
/* -- Client->Server Functions -- */


/* Server->Client Functions */
void handle_recv(struct text *packet, int packet_size) {
	printf("Packet size: %d\n", packet_size);
	printf("Real size: %d\n", sizeof(struct text_list))
	switch(packet->txt_type) {
		case TXT_SAY:
			if(sizeof(struct text_say) != packet_size) {
				char error_message[] = "Received invalid packet from server.";
				log_error(error_message);
			} else handle_recv_say((struct text_say *) packet);
			return;
		case TXT_LIST:
/*
		struct channel_info {
	char ch_channel[CHANNEL_MAX];
} packed;

struct text_list {
	text_t txt_type;
	int txt_nchannels;
	struct channel_info txt_channels[0];
} packed;
*/
printf("text_list size: %d\n", sizeof(text_list));
printf("channel_info size: %d\n", sizeof(channel_info));
			if(sizeof(struct text_list) != packet_size) {
				char error_message[] = "Received invalid packet from server.";
				log_error(error_message);
			} else handle_recv_list((struct text_list *) packet);
			return;
		case TXT_WHO:
			if(sizeof(struct text_who) != packet_size) {
				char error_message[] = "Received invalid packet from server.";
				log_error(error_message);
			} else handle_recv_who((struct text_who *) packet);
			return;
		case TXT_ERROR:
			if(sizeof(struct text_error) != packet_size) {
				char error_message[] = "Received invalid packet from server.";
				log_error(error_message);
			} else handle_recv_error((struct text_error *) packet);
			return;
		default:
			char error_message[] = "Received unknown packet from server.";
			log_error(error_message);
			return;
	}
}

void handle_recv_say(struct text_say *packet) {
	clear_prompt();
	printf("[%s][%s]: %s\n", packet->txt_channel, packet->txt_username, packet->txt_text);
	print_prompt();
	restore_prompt_input();
}

void handle_recv_list(struct text_list *packet) {
	int i;

	clear_prompt();
	printf("Existing channels:\n");

	for(i = 0; i < packet->txt_nchannels; i++) {
		printf(" %s\n", ((struct channel_info)packet->txt_channels[i]).ch_channel);
	}

	print_prompt();
	restore_prompt_input();
}

void handle_recv_who(struct text_who *packet) {
	int i;

	clear_prompt();
	printf("Users on channel %s:\n", packet->txt_channel);

	for(i = 0; i < packet->txt_nusernames; i++) {
		printf(" %s\n", ((struct user_info)packet->txt_users[i]).us_username);
	}

	print_prompt();
	restore_prompt_input();
}

void handle_recv_error(struct text_error *packet) {
	clear_prompt();
	log_error(packet->txt_error);
	print_prompt();
	restore_prompt_input();
}
/* -- Server->Client Functions -- */


char *read_input() {
	char c = getchar();

	if(c == '\n' || c == EOF) {
		*input_buffer_position = '\0';
		printf("\n");
		//clear_prompt();

		handle_send(input_buffer);
		input_buffer_position = input_buffer;

		fflush(stdout);
		print_prompt();
		return input_buffer;
	} else if((int)c == 127) {
		if(input_buffer_position - input_buffer > 0) {
			*(input_buffer_position--) = '\0';
			printf("\b \b");
			fflush(stdout);
		}
	} else if(input_buffer_position != input_buffer + SAY_MAX) {
		*(input_buffer_position++) = c;
		printf("%c", c);
		fflush(stdout);
	}
	return NULL;
}


int main(int argc, char** argv) {
	char *end;
	int result= 0;

	struct addrinfo *servinfo= NULL;

	if(argc != 4) {
		printf("Usage: ./client server_socket server_port username\n");
		return 1;
	}

	/* Setup the socket and verify connectivity */
	char *server_ip = argv[1];
	uint16_t server_port = (uint16_t)(strtol(argv[2], &end, 10));

	struct addrinfo info;
	memset(&info, 0, sizeof info);
	info.ai_family= AF_INET;
	info.ai_socktype= SOCK_DGRAM;

	if ((result= getaddrinfo(argv[1], argv[2], &info, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
		return false;
	}
	/*    */

	/* Receiving from the server */
	struct sockaddr from_socket;
	char from_buffer[1028];
	socklen_t from_socket_len = sizeof from_socket;

	/*    */

	joined_channels = ll_create();

	/* Connect and Login */
	raw_mode();

	char *username = argv[3];

	server_connect(server_ip, server_port);
	handle_send_login(username);

	handle_send_join(active_channel);
	/*  */

	fd_set *master = (fd_set *)malloc(sizeof(fd_set));
	fd_set *dup_fd_set = (fd_set *)malloc(sizeof(fd_set));

	FD_ZERO(master);
	FD_SET(STDIN_FILENO, master);
	FD_SET(server_socket, master);

	print_prompt();
	int packet_size;

	while(is_alive == 1) {
		fflush(stdin);

		*dup_fd_set = *master;

		if(select(server_socket + 1, dup_fd_set, NULL, NULL, NULL) < 0) {
			perror("select");
			return -1;
		}

		if(FD_ISSET(STDIN_FILENO, dup_fd_set)) read_input();
		else if(FD_ISSET(server_socket, dup_fd_set)) {
			if((packet_size = recvfrom(server_socket, from_buffer, sizeof from_buffer, 0, &from_socket, &from_socket_len)) > 0)
				handle_recv((struct text *)from_buffer, packet_size);
		}
	}

	free(master);
	free(dup_fd_set);
	freeaddrinfo(servinfo);

	cooked_mode();
	return 0;
}
