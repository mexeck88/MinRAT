/**
 * @file operations.h
 *
 * @brief
 *
 * @author 2LT Matt Eckert
 *
 * @date 10APR2025
 */

#ifndef OPERATIONS_H
#define OPERATIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>

#define MAX_USERS                     30
#define MAX_CONNECTIONS               50
#define MAX_FILE_SIZE                 1016
#define MAX_USER_SIZE                 30
#define MAX_PASS_SIZE                 30

typdef enum user_permissions_t
{
    READ_PERMISSION = 1,
    READ_WRITE_PERMISSION = 2,
    ADMIN_PERMISSION = 3,
} user_permissions_t;

#define USER_SESSIONID_OFFSET         8
#define DEL_SESSIONID_OFFSET          4
#define DEL_FILENAME_OFFSET           2
#define DEL_FILE_OFFSET               8
#define USER_FLAG_OFFSET              1
#define USERNAME_LENGTH_OFFSET        4
#define PASSWORD_LENGTH_OFFSET        6
#define USERPASS_OFFSET               12
#define USER_RETURN_SESSIONID_OFFSET  2
#define GET_SESSIONID_OFFSET          4
#define GET_FILENAME_OFFSET           8
#define GET_FILELEN_OFFSET            2
#define GET_RETURN_FILESIZE_OFFSET    2
#define GET_RETURN_FILE_OFFSET        6
#define LIST_SESSIONID_OFFSET         4
#define LIST_NAMELEN_OFFSET           2
#define LIST_CURPOS_OFFSET            8
#define LIST_DIRNAME_OFFSET           12
#define LIST_RETURN_TOTALBYTES_OFFSET 4
#define LIST_RETURN_MESSAGELEN_OFFSET 8
#define LIST_RETURN_CURPOS_OFFSET     12
#define LIST_RETURN_CONTENT_OFFSET    16
#define MKDIR_DIRNAME_OFFSET          12
#define MKDIR_SESSIONID_OFFSET        4
#define MKDIR_DIRLEN_OFFSET           2
#define PUT_SESSIONID_OFFSET          4
#define PUT_FILENAME_OFFSET           2
#define PUT_OVERWRITE_OFFSET          1
#define PUT_FILESIZE_OFFSET           8
#define PUT_FILE_OFFSET               12

typedef enum user_flags_t
{
    USER_FLAG_LOGIN = 0x00,
    USER_FLAG_CREATE_READ = 0x01,
    USER_FLAG_CREATE_RW = 0x02,
    USER_FLAG_CREATE_ADMIN = 0x03,
    USER_FLAG_DELETE = 0xff,
} user_flags_t;

typedef enum return_codes_t
{
    RET_SUCCESS = 0x01,
    RET_SESSION_ERROR = 0x02,
    RET_PERMISSION_ERROR = 0x03,
    RET_USER_EXISTS = 0x04,
    RET_FILE_EXISTS = 0x05,
    RET_FAILURE = 0xff,
} return_codes_t;

typedef struct session_t
{
    uint32_t session_id; // Session ID
    time_t   start_time; // Start time of the session
    char *   p_username; // Username associated with the session
} session_t;

// User Struct

typedef struct user_t
{
    char *  p_username;  // Username
    char *  p_password;  // Password
    uint8_t permissions; // Permissions (e.g., read/write/execute)
} user_t;

// Thread Args
typedef struct thread_args_t
{
    int               client_socket;
    int               session_timeout;
    int               session_index;
    char *            p_server_directory_path;
    user_t *          p_user_list;
    session_t *       p_session_list;
    pthread_mutex_t * p_mutex;
} thread_args_t;

typedef struct request_header_t
{
    uint8_t  opcode;
    uint32_t session_id;
    uint8_t  reserved;
    uint16_t target_length;
} request_header_t;

typedef struct user_request_t
{
    request_header_t header;
    uint8_t          user_flag;
    uint16_t         username_length;
    uint16_t         password_length;
    char *           p_request_buffer;
} user_request_t;

typedef struct delete_request_t
{
    request_header_t header;
    char *           p_file_name;
} delete_request_t;

typedef struct list_request_t
{
    request_header_t header;
    uint32_t         current_position;
    char *           p_directory_name;
    char *           p_response_buffer; // buffer to hold the response
} list_request_t;

typedef struct get_request_t
{
    request_header_t header;
    char *           p_file_name;
} get_request_t;

typedef struct mkdir_request_t
{
    request_header_t header;
    int              reserved;
    char *           p_directory_name;
} mkdir_request_t;

typedef struct put_request_t
{
    request_header_t header;
    uint8_t          overwrite_flag;
    uint32_t         file_size;
    char *           p_file_content_buffer;
    char *           p_file_name_buffer;
} put_request_t;

typedef struct response_header_t
{
    uint8_t return_code;
} response_header_t;

typedef struct user_response_t
{
    response_header_t header;
    uint8_t           reserved;
    uint32_t          session_id;
} user_response_t;

typedef struct list_response_t
{
    response_header_t header;
    uint8_t           reserved; // 3 of these used
    uint32_t          total_bytes;
    uint32_t          message_length;
    uint32_t          current_position;
    char *            p_response_content; // list of files in the directory
} list_response_t;

typedef struct get_response_t
{
    response_header_t header;
    int               reserved;
    int               file_size;
    char *            p_file_buffer; // contents of the file
} get_response_t;

// Deserialize functions
uint8_t operations_user_request (char *           p_buffer,
                                 user_request_t * p_request,
                                 thread_args_t *  p_conn_args);
uint8_t operations_delete_request (char *             p_buffer,
                                   delete_request_t * p_request,
                                   thread_args_t *    p_conn_args);
uint8_t operations_list_request (char *            p_buffer,
                                 list_request_t *  p_request,
                                 list_response_t * p_response,
                                 thread_args_t *   p_conn_args);
uint8_t operations_get_request (char *           p_buffer,
                                get_request_t *  p_request,
                                get_response_t * p_response,
                                thread_args_t *  p_conn_args);
uint8_t operations_mkdir_request (char *            p_buffer,
                                  mkdir_request_t * p_request,
                                  thread_args_t *   p_conn_args);
uint8_t operations_put_request (char *          p_buffer,
                                put_request_t * p_request,
                                thread_args_t * p_conn_args);
bool    operations_list_read_buffer (char *     p_response_buffer,
                                     uint32_t   request_current_position,
                                     uint32_t   response_total_bytes,
                                     uint32_t * response_message_length,
                                     uint32_t * response_current_position,
                                     char **    p_response_content);

// Serialize functions
bool operations_user_response (char * p_buffer, user_response_t * p_response);
bool operations_list_response (char *            p_buffer,
                               list_response_t * p_response,
                               thread_args_t *   p_conn_args);
bool operations_get_response (char *           p_buffer,
                              get_response_t * p_response,
                              thread_args_t *  p_conn_args);

uint8_t operations_validate_file_path (char *  p_server_directory,
                                       char *  p_requested_file_path,
                                       char ** p_final_file_path);
bool    operations_check_session (char **     p_username,
                                  uint32_t    session_id,
                                  int         session_timeout,
                                  session_t * p_session_list);
uint8_t operations_check_permissions (char * p_username, user_t * p_user_list);

#endif // OPERATIONS_H