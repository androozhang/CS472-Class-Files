/**
 * =============================================================================
 * STUDENT ASSIGNMENT: CRYPTO-CLIENT.C
 * =============================================================================
 *
 * ASSIGNMENT OBJECTIVE:
 * Implement a TCP client that communicates with a server using an encrypted
 * protocol. Your focus is on socket programming and network communication.
 * The cryptographic functions are provided for you in crypto-lib.
 *
 * =============================================================================
 * WHAT YOU NEED TO IMPLEMENT:
 * =============================================================================
 *
 * 1. SOCKET CONNECTION (start_client function):
 *    - Create a TCP socket using socket()
 *    - Configure the server address structure (struct sockaddr_in)
 *    - Connect to the server using connect()
 *    - Handle connection errors appropriately
 *    - Call your communication loop function
 *    - Close the socket when done
 *
 * 2. CLIENT COMMUNICATION LOOP:
 *    - Create a function that handles the request/response cycle
 *    - Allocate buffers for sending and receiving data
 *    - Maintain a session key (crypto_key_t) for encryption
 *    - Loop to:
 *      a) Get user command using get_command() (provided below)
 *      b) Build a PDU (Protocol Data Unit) from the command
 *      c) Send the PDU to the server using send()
 *      d) Receive the server's response using recv()
 *      e) Process the response (extract key, decrypt data, etc.)
 *      f) Handle exit commands and connection closures
 *    - Free allocated buffers before returning
 *
 * 3. PDU CONSTRUCTION:
 *    - Consider creating a helper function to build PDUs
 *    - Fill in the PDU header (msg_type, direction, payload_len)
 *    - For MSG_DATA: copy plaintext to payload
 *    - For MSG_ENCRYPTED_DATA: use encrypt_string() to encrypt before copying
 *    - For MSG_KEY_EXCHANGE: no payload needed
 *    - For command messages: no payload needed
 *    - Return the total PDU size (header + payload)
 *
 * =============================================================================
 * ONE APPROACH TO SOLVE THIS PROBLEM:
 * =============================================================================
 *
 * FUNCTION STRUCTURE:
 *
 * void start_client(const char* addr, int port) {
 *     // 1. Create TCP socket
 *     // 2. Configure server address (sockaddr_in)
 *     // 3. Connect to server
 *     // 4. Print connection confirmation
 *     // 5. Call your communication loop function
 *     // 6. Close socket
 *     // 7. Print disconnection message
 * }
 *
 * int client_loop(int socket_fd) {
 *     // 1. Allocate buffers (send, receive, input)
 *     // 2. Initialize session_key to NULL_CRYPTO_KEY
 *     // 3. Loop:
 *     //    a) Call get_command() to get user input
 *     //    b) Build PDU from command (use helper function)
 *     //    c) Send PDU using send()
 *     //    d) If exit command, break after sending
 *     //    e) Receive response using recv()
 *     //    f) Handle recv() return values (0 = closed, <0 = error)
 *     //    g) Process response:
 *     //       - If MSG_KEY_EXCHANGE: extract key from payload
 *     //       - If MSG_ENCRYPTED_DATA: decrypt using decrypt_string()
 *     //       - Print results
 *     //    h) Loop back
 *     // 4. Free buffers
 *     // 5. Return success/error code
 * }
 *
 * int build_packet(const msg_cmd_t *cmd, crypto_msg_t *pdu, crypto_key_t key) {
 *     // 1. Set pdu->header.msg_type = cmd->cmd_id
 *     // 2. Set pdu->header.direction = DIR_REQUEST
 *     // 3. Based on cmd->cmd_id:
 *     //    - MSG_DATA: copy cmd->cmd_line to payload, set length
 *     //    - MSG_ENCRYPTED_DATA: encrypt cmd->cmd_line, set length
 *     //    - MSG_KEY_EXCHANGE: set length to 0
 *     //    - Command messages: set length to 0
 *     // 4. Return sizeof(crypto_pdu_t) + payload_len
 * }
 *
 * =============================================================================
 * IMPORTANT PROTOCOL DETAILS:
 * =============================================================================
 *
 * PDU STRUCTURE:
 *   typedef struct crypto_pdu {
 *       uint8_t  msg_type;      // MSG_DATA, MSG_ENCRYPTED_DATA, etc.
 *       uint8_t  direction;     // DIR_REQUEST or DIR_RESPONSE
 *       uint16_t payload_len;   // Length of payload in bytes
 *   } crypto_pdu_t;
 *
 *   typedef struct crypto_msg {
 *       crypto_pdu_t header;
 *       uint8_t      payload[]; // Flexible array
 *   } crypto_msg_t;
 *
 * MESSAGE TYPES (from protocol.h):
 *   MSG_KEY_EXCHANGE     - Request/send encryption key
 *   MSG_DATA             - Plain text message
 *   MSG_ENCRYPTED_DATA   - Encrypted message (requires session key)
 *   MSG_CMD_CLIENT_STOP  - Client exit command
 *   MSG_CMD_SERVER_STOP  - Server shutdown command
 *
 * TYPICAL MESSAGE FLOW:
 *   1. Client sends MSG_KEY_EXCHANGE request
 *   2. Server responds with MSG_KEY_EXCHANGE + key in payload
 *   3. Client extracts key: memcpy(&session_key, response->payload, sizeof(crypto_key_t))
 *   4. Client can now send MSG_ENCRYPTED_DATA
 *   5. Server responds with MSG_ENCRYPTED_DATA
 *   6. Client decrypts using decrypt_string()
 *
 * =============================================================================
 * CRYPTO LIBRARY FUNCTIONS YOU'LL USE:
 * =============================================================================
 *
 * int encrypt_string(crypto_key_t key, uint8_t *out, uint8_t *in, size_t len)
 *   - Encrypts a string before sending
 *   - Returns number of encrypted bytes or negative on error
 *
 * int decrypt_string(crypto_key_t key, uint8_t *out, uint8_t *in, size_t len)
 *   - Decrypts received data
 *   - Returns number of decrypted chars or negative on error
 *   - NOTE: Output is NOT null-terminated, you must add '\0'
 *
 * void print_msg_info(crypto_msg_t *msg, crypto_key_t key, int mode)
 *   - Prints PDU details for debugging
 *   - Use CLIENT_MODE for the mode parameter
 *   - VERY helpful for debugging your protocol!
 *
 * =============================================================================
 * DEBUGGING TIPS:
 * =============================================================================
 *
 * 1. Use print_msg_info() before sending and after receiving
 * 2. Check return values from ALL socket operations
 * 3. Verify payload_len matches actual data length
 * 4. Remember: recv() may return less bytes than expected
 * 5. Encrypted data requires a valid session key (check for NULL_CRYPTO_KEY)
 * 6. Use printf() liberally to trace program flow
 *
 * =============================================================================
 * TESTING RECOMMENDATIONS:
 * =============================================================================
 *
 * 1. Start simple: Get plain MSG_DATA working first
 * 2. Test key exchange: Send '#' command
 * 3. Test encryption: Send '!message' after key exchange
 * 4. Test exit commands: '-' for client exit, '=' for server shutdown
 * 5. Test error cases: What if server closes unexpectedly?
 *
 * Good luck! Remember: Focus on the socket operations. The crypto is done!
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include "crypto-client.h"
#include "crypto-lib.h"
#include "crypto-echo.h"
#include "protocol.h"

char send_buffer_client[BUFFER_SIZE];
char recv_buffer_client[BUFFER_SIZE];

extern volatile int client_exit_requested;

int build_packet(const msg_cmd_t *cmd, crypto_msg_t *pdu, crypto_key_t key)
{
    pdu->header.msg_type = cmd->cmd_id;
    pdu->header.direction = DIR_REQUEST;
    uint16_t payload_len = 0;

    if (cmd->cmd_id == MSG_DATA && cmd->cmd_line)
    {
        payload_len = strlen(cmd->cmd_line);
        memcpy(pdu->payload, cmd->cmd_line, payload_len);
    }
    else if (cmd->cmd_id == MSG_ENCRYPTED_DATA && cmd->cmd_line)
    {
        if (key == NULL_CRYPTO_KEY)
        {
            printf("[ERROR] No session key established. Cannot send encrypted data.\n");
            return -1;
        }
        payload_len = encrypt_string(key, pdu->payload,
                                     (uint8_t *)cmd->cmd_line,
                                     strlen(cmd->cmd_line));
        if (payload_len < 0)
        {
            printf("[ERROR] Encryption failed.\n");
            return -1;
        }
    }
    else
    {
        payload_len = 0;
    }

    pdu->header.payload_len = payload_len;
    return sizeof(crypto_pdu_t) + payload_len;
}

ssize_t send_all_client(int sockfd, const char *buffer, size_t length)
{
    size_t bytes_sent = 0;
    ssize_t result;

    while (bytes_sent < length)
    {
        result = send(sockfd, buffer + bytes_sent, length - bytes_sent, 0);
        if (result < 0)
        {
            return -1;
        }
        bytes_sent += result;
    }

    return bytes_sent;
}

/* =============================================================================
 * STUDENT TODO: IMPLEMENT THIS FUNCTION
 * =============================================================================
 * This is the main client function. You need to:
 * 1. Create a TCP socket
 * 2. Connect to the server
 * 3. Call your communication loop
 * 4. Clean up and close the socket
 *
 * Parameters:
 *   addr - Server IP address (e.g., "127.0.0.1")
 *   port - Server port number (e.g., 1234)
 */
void start_client(const char *addr, int port)
{
    printf("Student TODO: Implement start_client()\n");
    printf("  - Create TCP socket\n");
    printf("  - Connect to %s:%d\n", addr, port);
    printf("  - Implement communication loop\n");
    printf("  - Close socket when done\n");
    int sockfd;
    struct sockaddr_in server_addr;
    char input_buffer[BUFFER_SIZE];
    char extracted_msg[BUFFER_SIZE];
    ssize_t pdu_len;
    msg_cmd_t command;
    crypto_msg_t *request = malloc(sizeof(crypto_msg_t) + MAX_MSG_DATA_SIZE);
    crypto_msg_t *response = malloc(sizeof(crypto_msg_t) + MAX_MSG_DATA_SIZE);
    crypto_key_t session_key = NULL_CRYPTO_KEY;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Error: Invalid address %s\n", addr);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error connecting to server");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", addr, port);
    printf("Type messages to send to server.\n");
    printf("Type 'exit' to quit, or 'exit server' to shutdown the server.\n");
    printf("Press Ctrl+C to exit at any time.\n\n");

    while (1)
    {
        if (get_command(input_buffer, sizeof(input_buffer), &command) != CMD_EXECUTE)
            continue;

        memset(request, 0, sizeof(crypto_msg_t) + MAX_MSG_DATA_SIZE);
        memset(response, 0, sizeof(crypto_msg_t) + MAX_MSG_DATA_SIZE);

        int packet_len = build_packet(&command, request, session_key);
        if (packet_len < 0)
            continue;

        if (send_all_client(sockfd, (char *)request, packet_len) != packet_len)
        {
            perror("send_all_client");
            break;
        }

        ssize_t hdr_bytes = recv(sockfd, &response->header, sizeof(crypto_pdu_t), MSG_WAITALL);
        if (hdr_bytes <= 0)
        {
            printf("Server closed connection.\n");
            break;
        }

        uint16_t payload_len = response->header.payload_len;
        if (payload_len > MAX_MSG_DATA_SIZE)
        {
            printf("[ERROR] Invalid payload length: %u\n", payload_len);
            break;
        }

        if (payload_len > 0)
        {
            ssize_t recv_bytes = recv(sockfd, response->payload, payload_len, MSG_WAITALL);
            if (recv_bytes <= 0)
                break;
        }

        print_msg_info(response, session_key, CLIENT_MODE);

        if (response->header.msg_type == MSG_KEY_EXCHANGE)
        {
            memcpy(&session_key, response->payload, sizeof(crypto_key_t));
        }
        else if (response->header.msg_type == MSG_ENCRYPTED_DATA)
        {
            char decrypted[BUFFER_SIZE];
            int dec_len = decrypt_string(session_key,
                                         (uint8_t *)decrypted,
                                         response->payload,
                                         payload_len);

            decrypted[dec_len] = '\0';
        }
        if (pdu_len < 0)
        {
            printf("Error receiving response. Server may have disconnected.\n");
            break;
        }
        else if (pdu_len == 0)
        {
            printf("Server closed connection.\n");
            break;
        }

        print_msg_info(response, session_key, CLIENT_MODE);

        if (response->header.msg_type == MSG_KEY_EXCHANGE)
        {
            memcpy(&session_key, response->payload, sizeof(crypto_key_t));
        }
        if (strstr(extracted_msg, "server is exiting") != NULL)
        {
            printf("Server is shutting down.\n");
            break;
        }
    }

    close(sockfd);
    printf("Client disconnected.\n");
}

/* =============================================================================
 * PROVIDED HELPER FUNCTION: get_command()
 * =============================================================================
 * This function is FULLY IMPLEMENTED for you. It handles user input and
 * interprets special command characters.
 *
 * HOW TO USE:
 *   char input_buffer[MAX_MSG_DATA_SIZE];
 *   msg_cmd_t command;
 *   int result = get_command(input_buffer, MAX_MSG_DATA_SIZE, &command);
 *   if (result == CMD_EXECUTE) {
 *       // command.cmd_id contains the message type
 *       // command.cmd_line contains the message text (or NULL)
 *   } else {
 *       // CMD_NO_EXEC means skip this command (like '?' for help)
 *   }
 *
 * COMMAND FORMAT:
 *   Regular text      -> MSG_DATA (plain text message)
 *   !<message>        -> MSG_ENCRYPTED_DATA (encrypt the message)
 *   #                 -> MSG_KEY_EXCHANGE (request encryption key)
 *   -                 -> MSG_CMD_CLIENT_STOP (exit client)
 *   =                 -> MSG_CMD_SERVER_STOP (shutdown server)
 *   ?                 -> Show help (returns CMD_NO_EXEC)
 *
 * RETURN VALUES:
 *   CMD_EXECUTE  - Command should be sent to server (use cmd_id and cmd_line)
 *   CMD_NO_EXEC  - Command was handled locally (like help), don't send
 *
 * IMPORTANT NOTES:
 *   - The returned cmd_line is a pointer into cmd_buff (no need to free)
 *   - For commands without data (like '#'), cmd_line will be NULL
 *   - For '!' commands, cmd_line points to text AFTER the '!' character
 */
int get_command(char *cmd_buff, size_t cmd_buff_sz, msg_cmd_t *msg_cmd)
{
    if ((cmd_buff == NULL) || (cmd_buff_sz == 0))
        return CMD_NO_EXEC;

    printf("> ");
    fflush(stdout);

    // Get input from user
    if (fgets(cmd_buff, cmd_buff_sz, stdin) == NULL)
    {
        printf("[WARNING] Error reading input command.\n\n");
        return CMD_NO_EXEC;
    }

    // Remove trailing newline
    cmd_buff[strcspn(cmd_buff, "\n")] = '\0';

    // Interpret the command based on first character
    switch (cmd_buff[0])
    {
    case '!':
        // Encrypted message - everything after '!' is the message
        msg_cmd->cmd_id = MSG_ENCRYPTED_DATA;
        msg_cmd->cmd_line = cmd_buff + 1; // Skip the '!' character
        return CMD_EXECUTE;

    case '#':
        // Key exchange request - no message data
        msg_cmd->cmd_id = MSG_KEY_EXCHANGE;
        msg_cmd->cmd_line = NULL;
        return CMD_EXECUTE;

    case '$':
        // Digital signature (not implemented in this assignment)
        msg_cmd->cmd_id = MSG_DIG_SIGNATURE;
        msg_cmd->cmd_line = NULL;
        printf("[INFO] Digital signature command not implemented yet.\n\n");
        return CMD_NO_EXEC;

    case '-':
        // Client exit command
        msg_cmd->cmd_id = MSG_CMD_CLIENT_STOP;
        msg_cmd->cmd_line = NULL;
        return CMD_EXECUTE;

    case '=':
        // Server shutdown command
        msg_cmd->cmd_id = MSG_CMD_SERVER_STOP;
        msg_cmd->cmd_line = NULL;
        return CMD_EXECUTE;

    case '?':
        // Help - display available commands
        msg_cmd->cmd_id = MSG_HELP_CMD;
        msg_cmd->cmd_line = NULL;
        printf("Available commands:\n");
        printf("  <message>  : Send plain text message\n");
        printf("  !<message> : Send encrypted message (requires key exchange first)\n");
        printf("  #          : Request key exchange from server\n");
        printf("  ?          : Show this help message\n");
        printf("  -          : Exit the client\n");
        printf("  =          : Exit the client and request server shutdown\n\n");
        return CMD_NO_EXEC;

    default:
        // Regular text message
        msg_cmd->cmd_id = MSG_DATA;
        msg_cmd->cmd_line = cmd_buff;
        return CMD_EXECUTE;
    }

    return CMD_NO_EXEC;
}
