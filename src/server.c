/**
 * @file server.c
 *
 * @brief
 *
 * @author 2LT Matt Eckert
 *
 * @date 08APR2025
 */


#include "server.h"
#include "operations.h"
#include <stdatomic.h>

atomic_bool gb_run = true;

/**
 * @brief Signal handler for SIGINT and SIGTERM signals
 *
 * @param signum Signal number
 */
void server_sighandler (int signum)
{
    fprintf(stderr, "Caught signal %d\n", signum);
    atomic_store(&gb_run, false); // Set the global run flag to false to exit the loop
}


/**
 * @brief Handle the connection from the client
 *
 * @param p_arg Pointer to the thread arguments structure
 *
 * @return NULL on success, 1 on failure
 */
void * server_handle_connection (void * p_arg)
{
    thread_args_t * p_conn_args = (thread_args_t *)p_arg;

    // -------------------------------------------------
    int               client_socket        = p_conn_args->client_socket;
    pthread_mutex_t * p_mutex              = p_conn_args->p_mutex;
    char              buffer[MESSAGE_SIZE] = { 0 };
    int               bytes_received       = 0;
    int               bytes_sent           = 0;
    uint8_t           opcode               = 0;
    uint8_t           retcode              = 0;
    //-------------------------------------------------


    // Receive the request from the client
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (0 >= bytes_received)
    {
        printf("SERVER ERROR: recv failed\n");
        goto SEND_FAILURE;
    }

    // Buffer now holds the bytestream from the client. Need to parse it into a
    // struct

    opcode = buffer[0]; // First byte is the opcode
    request_header_t *  p_request_header  = malloc(sizeof(request_header_t));
    response_header_t * p_response_header = malloc(sizeof(response_header_t));

    if ((NULL == p_request_header) || (NULL == p_response_header))
    {
        retcode = RET_FAILURE;
        printf("SERVER ERROR: malloc failed for request/response header\n");
        goto SEND_FAILURE;
    }

    p_request_header->opcode        = opcode;
    p_request_header->session_id    = 0;
    p_request_header->reserved      = 0;
    p_request_header->target_length = 0;

    p_response_header->return_code = 0xff; // Failure by default

    switch (opcode)
    {
        case USER_OPCODE:
            user_request_t * p_user_request = malloc(sizeof(user_request_t));

            if (NULL == p_user_request)
            {
                printf("SERVER ERROR: malloc failed for user request\n");
                free(p_user_request);
                goto SEND_FAILURE;
            }

            p_user_request->header = *p_request_header;

            pthread_mutex_lock(p_mutex);

            retcode
                = operations_user_request(buffer, p_user_request, p_conn_args);
            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_user_request failed\n");
                free(p_user_request);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);

            // Action completed, reuse buffer for response
            memset(buffer, 0, sizeof(buffer));
            user_response_t * p_user_response = malloc(sizeof(user_response_t));

            if (NULL == p_user_response)
            {
                printf("SERVER ERROR: malloc failed for user response\n");
                free(p_user_request);
                free(p_user_response);
                goto SEND_FAILURE;
            }

            p_user_response->header = *p_response_header;
            p_user_response->session_id
                = p_conn_args->p_session_list[p_conn_args->session_index]
                      .session_id;
            p_user_response->reserved           = 0x00;
            p_user_response->header.return_code = retcode;

            pthread_mutex_lock(p_mutex);
            if (false == operations_user_response(buffer, p_user_response))
            {
                printf("SERVER ERROR: operations_user_response failed\n");
                free(p_user_request);
                free(p_user_response);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);
            // Send the response to the client
            free(p_user_request);
            free(p_user_response);
            goto SEND_SUCCESS;

        case DELETE_OPCODE:
            delete_request_t * p_delete_request
                = malloc(sizeof(delete_request_t));

            if (NULL == p_delete_request)
            {
                printf("SERVER ERROR: malloc failed for delete request\n");
                free(p_delete_request);
                goto SEND_FAILURE;
            }

            p_delete_request->header = *p_request_header;
            pthread_mutex_lock(p_mutex);
            retcode = operations_delete_request(
                buffer, p_delete_request, p_conn_args);

            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_delete_request failed\n");
                free(p_delete_request);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);
            // Action completed, reuse buffer for response
            memset(buffer, 0, sizeof(buffer));
            buffer[0] = retcode;
            free(p_delete_request);
            goto SEND_SUCCESS;

        case LIST_OPCODE: // Not finished - need to clarify the response packet
            list_request_t *  p_list_request  = calloc(1, sizeof(list_request_t));
            list_response_t * p_list_response = calloc(1, sizeof(list_response_t));

            p_list_response->p_response_content = NULL;

            if (NULL == p_list_response)
            {
                printf("SERVER ERROR: malloc failed for list response\n");
                goto SEND_FAILURE;
            }

            if (NULL == p_list_request)
            {
                printf("SERVER ERROR: malloc failed for list request\n");
                free(p_list_response);
                goto SEND_FAILURE;
            }

            p_list_request->header = *p_request_header;
            pthread_mutex_lock(p_mutex);
            retcode = operations_list_request(
                buffer, p_list_request, p_list_response, p_conn_args);

            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_list_request failed\n");
                free(p_list_request);
                free(p_list_response);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);

            // Action completed, reuse buffer for response
            memset(buffer, 0, sizeof(buffer));
            buffer[0] = retcode;
            buffer[1] = (uint8_t)0x00;
            buffer[2] = (uint8_t)0x00;
            buffer[3] = (uint8_t)0x00;
            pthread_mutex_lock(p_mutex);

            if (false
                == operations_list_response(
                    buffer, p_list_response, p_conn_args))
            {
                printf("SERVER ERROR: operations_list_response failed\n");
                free(p_list_request);
                free(p_list_response);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);
            free(p_list_request);
            free(p_list_response->p_response_content);
            free(p_list_response);

            goto SEND_SUCCESS;

        case GET_OPCODE:
            get_request_t *  p_get_request  = malloc(sizeof(get_request_t));
            get_response_t * p_get_response = malloc(sizeof(get_response_t));

            if (NULL == p_get_request)
            {
                printf("SERVER ERROR: malloc failed for get request\n");
                free(p_get_request);
                goto SEND_FAILURE;
            }

            p_get_request->header = *p_request_header;
            pthread_mutex_lock(p_mutex);
            retcode = operations_get_request(
                buffer, p_get_request, p_get_response, p_conn_args);
            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_get_request failed\n");
                free(p_get_request);
                free(p_get_response);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }
            pthread_mutex_unlock(p_mutex);

            // Action completed, reuse buffer for response
            memset(buffer, 0, sizeof(buffer));
            buffer[0] = retcode;
            buffer[1] = (uint8_t)0x00; // Reserved

            pthread_mutex_lock(p_mutex);
            if (false
                == operations_get_response(buffer, p_get_response, p_conn_args))
            {
                printf("SERVER ERROR: operations_get_response failed\n");
                free(p_get_request);
                free(p_get_response);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);
            free(p_get_request);
            free(p_get_response);

            goto SEND_SUCCESS;

        case MKDIR_OPCODE:
            mkdir_request_t * p_mkdir_request = malloc(sizeof(mkdir_request_t));

            if (NULL == p_mkdir_request)
            {
                printf("SERVER ERROR: malloc failed for mkdir request\n");
                free(p_mkdir_request);
                goto SEND_FAILURE;
            }

            p_mkdir_request->header = *p_request_header;
            pthread_mutex_lock(p_mutex);
            retcode = operations_mkdir_request(
                buffer, p_mkdir_request, p_conn_args);

            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_mkdir_request failed\n");
                free(p_mkdir_request);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);

            // Action completed, send retcode
            memset(buffer, 0, sizeof(buffer));
            buffer[0] = retcode;
            free(p_mkdir_request);

            goto SEND_SUCCESS;

        case PUT_OPCODE:
            put_request_t * p_put_request = malloc(sizeof(put_request_t));

            if (NULL == p_put_request)
            {
                printf("SERVER ERROR: malloc failed for put request\n");
                free(p_put_request);
                goto SEND_FAILURE;
            }

            p_put_request->header = *p_request_header;
            pthread_mutex_lock(p_mutex);
            retcode
                = operations_put_request(buffer, p_put_request, p_conn_args);

            if (0xff == retcode)
            {
                printf("SERVER ERROR: operations_put_request failed\n");
                free(p_put_request);
                pthread_mutex_unlock(p_mutex);
                goto SEND_FAILURE;
            }

            pthread_mutex_unlock(p_mutex);

            memset(buffer, 0, sizeof(buffer));
            buffer[0] = retcode;

            free(p_put_request);
            goto SEND_SUCCESS;

        default:
            goto SEND_FAILURE;
    }

SEND_SUCCESS:
    // Send the response to the client
    bytes_sent = send(p_conn_args->client_socket, buffer, sizeof(buffer), 0);
    if (0 >= bytes_sent)
    {
        printf("SERVER ERROR: send_success failed\n");
        close(client_socket);
        goto SEND_FAILURE;
    }

    // Close the client socket
    printf("SERVER: Closing Connection\n");
    close(client_socket);
    free(p_conn_args);
    free(p_request_header);
    free(p_response_header);
    return (void *)1;

SEND_FAILURE:
    uint8_t failure_retcode = RET_FAILURE;
    bytes_sent = send(p_conn_args->client_socket,
                      &failure_retcode,
                      sizeof(failure_retcode),
                      0);

    printf("SERVER: Closing Connection\n");
    close(client_socket);
    free(p_conn_args);
    free(p_request_header);
    free(p_response_header);
    return (void *)1;
}

/**
 * @brief Main function for the server
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 *
 * @return 0 on success, -1 on failure
 */
int main (int argc, char * argv[])
{
    struct sigaction sa;
    sa.sa_handler = server_sighandler;
    sa.sa_flags   = 0;
    sigemptyset(&sa.sa_mask);

    if ((-1 == sigaction(SIGINT, &sa, NULL))|| (-1 == sigaction(SIGTERM, &sa, NULL)))
{
    perror("sigaction failed");
    exit(EXIT_FAILURE);
}

    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    // Initialize the server
    int       server_socket, client_socket;
    SA_IN     server_addr, client_addr;
    pthread_t thread_id;

    // Take in 3 Arguements: session timeout length, server folder, and port
    // listening on
    int    opt;
    int    server_port           = DEFAULT_PORT;
    int    session_timeout       = DEFAULT_TIMEOUT;
    char * server_directory_path = DEFAULT_PATH;

    while (-1 != (opt = getopt(argc, argv, "t:p:d:")))
    {
        switch (opt)
        {
            case 't':
                session_timeout = atoi(optarg);
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'd':

                if (NULL != optarg)
                {
                    server_directory_path = optarg;
                }
                else
                {
                    fprintf(stderr, "Error: Missing argument for -d option\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [-t session_timeout] [-p port] [-d "
                        "server_folder]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (NULL == server_directory_path)
    {
        server_directory_path = DEFAULT_PATH;
        printf("INFO: Using default server directory path: %s\n",
               server_directory_path);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        printf("socket failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(server_port);

    // Bind and Listen
    int bind_opt = 1;
    if (0 > setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &bind_opt,
                       sizeof(bind_opt))) //Allows for socket reuse immediately after termination
    {
        printf("SERVER ERROR: setsockopt failed\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (0 > bind(server_socket, (SA *)&server_addr, sizeof(server_addr)))
    {
        printf("SERVER ERROR: bind failed\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (0 > listen(server_socket, MAX_CONNECTIONS))
    {
        printf("SERVER ERROR: listen failed\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Establish the User Array and Session Array

    session_t * p_session_list = malloc(sizeof(session_t) * MAX_CONNECTIONS);
    user_t *    p_user_list    = malloc(sizeof(user_t) * MAX_USERS);

    if ((NULL == p_session_list) || (NULL == p_user_list))
    {
        printf("SERVER ERROR: malloc failed for session/user list\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    memset(p_session_list, 0, sizeof(session_t) * MAX_CONNECTIONS);
    memset(p_user_list, 0, sizeof(user_t) * MAX_USERS);

    // Establish Admin User

    p_user_list[0].p_username = malloc(strlen(ADMIN_USER) + 1);
    p_user_list[0].p_password = malloc(strlen(ADMIN_PASS) + 1);
    
    if ((NULL == p_user_list[0].p_username) || (NULL == p_user_list[0].p_password))
    {
        printf("SERVER ERROR: malloc failed for admin user\n");
        free(p_session_list);
        free(p_user_list);
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    strcpy(p_user_list[0].p_username, ADMIN_USER);
    strcpy(p_user_list[0].p_password, ADMIN_PASS);
    p_user_list[0].permissions = ADMIN_PERMISSION;

    // Wait for connections Loop

    while (gb_run)
    {
        printf("SERVER: Waiting for connections...\n");
        socklen_t addr_size = sizeof(SA_IN);

        if (0 > (client_socket
                 = accept(server_socket, (SA *)&client_addr, &addr_size)))
        {
            if (false == atomic_load(&gb_run))
            {
                break;
            }

            printf("SERVER ERROR: accept failed\n");
            continue; // Continue to the next iteration to accept more
                      // connections
        }

        printf("Connected!\n");
        thread_args_t * p_args = malloc(sizeof(thread_args_t));

        if (p_args == NULL)
        {
            printf("malloc failed for thread arguments\n");
            close(client_socket);
            continue;
        }

        // Populate the thread arguments
        p_args->client_socket           = client_socket;
        p_args->session_timeout         = session_timeout;
        p_args->session_index           = 0;
        p_args->p_server_directory_path = server_directory_path;
        p_args->p_user_list             = p_user_list;
        p_args->p_session_list          = p_session_list;
        p_args->p_mutex                 = &mutex;

        // Check for expired sessions and remove them from the list - This
        // prevents dead sessions from taking up space
        for (int idx = 0; idx < MAX_CONNECTIONS; idx++)
        {
            if (p_session_list[idx].session_id != 0)
            {
                time_t current_time = time(NULL);
                double diff_time
                    = difftime(current_time, p_session_list[idx].start_time);
                if (diff_time > session_timeout)
                {
                    // Remove the session from the list
                    free(p_session_list[idx].p_username);
                    p_session_list[idx].session_id = 0;
                    p_session_list[idx].p_username = NULL;
                }
            }
        }

        if(0 != pthread_create(&thread_id, NULL, server_handle_connection, p_args))
        {
            printf("SERVER ERROR: pthread_create failed\n");
            close(client_socket);
            continue; // Continue to the next iteration to accept more
                      // connections
        }

        pthread_detach(thread_id);
    }

    printf("SERVER: SIGINT Caught, Exiting...\n");
    pthread_mutex_lock(&mutex);

    for (int idx = 0; idx < MAX_USERS; idx++)
    {   
        if (NULL != p_user_list[idx].p_username)
        {
            free(p_user_list[idx].p_username);
        }

        if (NULL != p_user_list[idx].p_password)
        {
            free(p_user_list[idx].p_password);
        }
    }

    for (int idx = 0; idx < MAX_CONNECTIONS; idx++)
    {
        if (NULL != p_session_list[idx].p_username)
        {;
            free(p_session_list[idx].p_username);
        }
    }

    free(p_session_list);
    free(p_user_list);
    pthread_mutex_unlock(&mutex);
    close(server_socket);
    return 0;
}