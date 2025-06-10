/**
 * @file server.h
 *
 * @brief
 *
 * @author 2LT Matt Eckert
 *
 * @date 08APR2025
 */

#include <limits.h>
#include <errno.h>
#include <signal.h>

#define MESSAGE_SIZE             2048
#define DEFAULT_PORT             8080
#define DEFAULT_TIMEOUT          120
#define ADMIN_USER               "admin"
#define ADMIN_PASS               "password"
#define ADMIN_TIMEOUT            3600
#define DEFAULT_PATH             "../server_test_dir"

typedef enum opcodes_t
{
    USER_OPCODE = 0x01,
    DELETE_OPCODE = 0x02,
    LIST_OPCODE = 0x03,
    GET_OPCODE = 0x04,
    MKDIR_OPCODE = 0x05,
    PUT_OPCODE = 0x06,
} opcodes_t;

// Session struct

typedef struct sockaddr    SA;
typedef struct sockaddr_in SA_IN;

void * server_handle_connection (void * p_arg);
