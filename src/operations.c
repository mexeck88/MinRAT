/**
 * @file operations.c
 *
 * @brief Contains the operations for the server to exeucte. Called by the
 * Handle_connections threaded function.
 *
 * @author 2LT Matt Eckert
 *
 * @date 10APR2025
 */

#include "operations.h"

/**
 * @brief User Request function
 *
 * @param p_buffer Pointer to the buffer containing the request data
 * @param p_request Pointer to the user request structure
 * @param p_conn_args Pointer to the connection arguments structure
 *
 * @return RET_SUCCESS on success, RET_FAILURE on failure
 */
uint8_t operations_user_request (char *           p_buffer,
                                 user_request_t * p_request,
                                 thread_args_t *  p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE; // Failure
    char *  p_session_username = NULL;        // Unknown length

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_user_request\n");
        goto EXIT;
    }

    // Populate the request struct with the buffer data
    p_request->user_flag = p_buffer[USER_FLAG_OFFSET];
    memcpy(&p_request->header.session_id,
           p_buffer + USER_SESSIONID_OFFSET,
           sizeof(uint32_t));
    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->username_length,
           p_buffer + USERNAME_LENGTH_OFFSET,
           sizeof(uint16_t));
    memcpy(&p_request->password_length,
           p_buffer + PASSWORD_LENGTH_OFFSET,
           sizeof(uint16_t));

    p_request->header.session_id = ntohl(p_request->header.session_id);
    p_request->username_length   = ntohs(p_request->username_length);
    p_request->password_length   = ntohs(p_request->password_length);

    p_request->p_request_buffer
        = malloc(p_request->username_length + p_request->password_length + 1);

    if (NULL == p_request->p_request_buffer)
    {
        printf("SERVER ERROR: malloc failed for user request buffer\n");
        goto EXIT;
    }

    memcpy(p_request->p_request_buffer,
           p_buffer + USERPASS_OFFSET,
           p_request->username_length + p_request->password_length);
    p_request->p_request_buffer[p_request->username_length
                                + p_request->password_length]
        = '\0'; // Null terminate
    char * p_username = malloc(p_request->username_length + 1);

    if ((NULL == p_username))
    {
        printf("SERVER ERROR: malloc failed for username buffer\n");
        free(p_request->p_request_buffer);
        goto EXIT;
    }

    char * p_password = malloc(p_request->password_length + 1);
    if ((NULL == p_password))
    {
        printf("SERVER ERROR: malloc failed for password buffer\n");
        free(p_username);
        free(p_request->p_request_buffer);
        goto EXIT;
    }

    memcpy(p_username, p_request->p_request_buffer, p_request->username_length);
    p_username[p_request->username_length] = '\0'; // Null terminate
    memcpy(p_password,
           p_request->p_request_buffer + p_request->username_length,
           p_request->password_length);
    p_password[p_request->password_length] = '\0'; // Null terminate

    // Limit user and pass size to MAX_USER_SIZE and MAX_PASS_SIZE

    if ((MAX_USER_SIZE < p_request->username_length)
        || (MAX_PASS_SIZE < p_request->password_length))
    {
        printf("SERVER ERROR: User or Password too long\n");
        free(p_username);
        free(p_password);
        free(p_request->p_request_buffer);
        goto EXIT;
    }

    switch (p_request->user_flag)
    {
        case USER_FLAG_LOGIN:
            printf("SERVER: User Login Request\n");
            // Perform login action

            // Check password - if password is correct, create a session ID and
            // return it

            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                // Check for NULL Username
                if (NULL == p_conn_args->p_user_list[idx].p_username)
                {
                    continue; // Skip to next iteration
                }

                if (0
                    == strcmp(p_conn_args->p_user_list[idx].p_username,
                              p_username))
                {
                    // Check for NULL Password

                    if (NULL == p_conn_args->p_user_list[idx].p_password)
                    {
                        continue; // Skip to next iteration
                    }

                    if (0
                        == strcmp(p_conn_args->p_user_list[idx].p_password,
                                  p_password))
                    {
                        // User exists in User List, create a Session for the
                        // User
                        for (int idx = 0; idx < MAX_CONNECTIONS; idx++)
                        {
                            if (0
                                == p_conn_args->p_session_list[idx].session_id)
                            {
                                srand((unsigned)time(NULL));

                                p_conn_args->p_session_list[idx].session_id
                                    = (uint32_t)
                                        rand(); // Generate a random session ID,
                                                // This is NOT cryptographically
                                                // secure
                                p_conn_args->p_session_list[idx].start_time
                                    = time(NULL); // set the start time to now

                                p_conn_args->p_session_list[idx].p_username
                                    = malloc(strlen(p_username) + 1);
                                if (NULL
                                    == p_conn_args->p_session_list[idx]
                                           .p_username)
                                {
                                    printf(
                                        "SERVER ERROR: malloc failed for "
                                        "username\n");
                                    free(p_username);
                                    free(p_password);
                                    free(p_request->p_request_buffer);
                                    goto EXIT;
                                }

                                strcpy(
                                    p_conn_args->p_session_list[idx].p_username,
                                    p_username);

                                p_conn_args->session_index
                                    = idx;              // Set the session index
                                ret_code = RET_SUCCESS; // Success

                                free(p_username);
                                free(p_password);
                                free(p_request->p_request_buffer);
                                goto EXIT;
                            }
                        }
                    }
                }
            }

            if (RET_FAILURE == ret_code)
            {
                printf(
                    "SERVER ERROR: User does not exist or password is "
                    "incorrect\n");
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
            }

            goto EXIT;

        case USER_FLAG_CREATE_READ:

            if (false
                == operations_check_session(&p_session_username,
                                            p_request->header.session_id,
                                            p_conn_args->session_timeout,
                                            p_conn_args->p_session_list))
            {
                printf("SERVER ERROR: Session Invalid or timed out\n");
                ret_code = RET_SESSION_ERROR;
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                goto EXIT;
            }

            // Check permissions - Since anyone can make a Read only, just need
            // to verify the username doesnt exist
            // Check existing

            for (int idx = 0; idx < MAX_USERS; idx++)
            {

                // Check for NULL Username
                if (NULL == p_conn_args->p_user_list[idx].p_username)
                {
                    continue; // Skip to next iteration
                }

                if (0
                    == strcmp(p_conn_args->p_user_list[idx].p_username,
                              p_username))
                {
                    printf("SERVER ERROR: User already exists\n");
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    ret_code = RET_USER_EXISTS;
                    goto EXIT;
                }
            }

            // Create the user in the user list
            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                if (0 == p_conn_args->p_user_list[idx].p_username)
                {
                    p_conn_args->p_user_list[idx].p_username
                        = malloc(strlen(p_username) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_username)
                    {
                        printf("SERVER ERROR: malloc failed for username\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    p_conn_args->p_user_list[idx].p_password
                        = malloc(strlen(p_password) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_password)
                    {
                        printf("SERVER ERROR: malloc failed for password\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    strcpy(p_conn_args->p_user_list[idx].p_username,
                           p_username);
                    strcpy(p_conn_args->p_user_list[idx].p_password,
                           p_password);

                    p_conn_args->p_user_list[idx].permissions = READ_PERMISSION;
                    ret_code = RET_SUCCESS; // Success
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    goto EXIT;
                }
            }

            printf(
                "SERVER ERROR: User list is full - cannot create new user\n");
            free(p_username);
            free(p_password);
            free(p_request->p_request_buffer);

            goto EXIT;

        case USER_FLAG_CREATE_RW:

            if (false
                == operations_check_session(&p_session_username,
                                            p_request->header.session_id,
                                            p_conn_args->session_timeout,
                                            p_conn_args->p_session_list))
            {
                printf("SERVER ERROR: Session Invalid or timed out\n");
                ret_code = RET_SESSION_ERROR;
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                goto EXIT;
            }

            // Check permissions

            if (READ_WRITE_PERMISSION > operations_check_permissions(
                    p_session_username, p_conn_args->p_user_list))
            {
                printf(
                    "SERVER ERROR: User does not have permissions to create "
                    "user with Read/Write Privledges\n");
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                ret_code = RET_PERMISSION_ERROR;
                goto EXIT;
            }

            // Check existing

            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                // Check for NULL Username
                if (NULL == p_conn_args->p_user_list[idx].p_username)
                {
                    continue; // Skip to next iteration
                }

                if (0
                    == strcmp(p_conn_args->p_user_list[idx].p_username,
                              p_username))
                {
                    printf("SERVER ERROR: User already exists\n");
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    ret_code = RET_USER_EXISTS;
                    goto EXIT;
                }
            }

            // Create the user in the user list
            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                if (0 == p_conn_args->p_user_list[idx].p_username)
                {

                    p_conn_args->p_user_list[idx].p_username
                        = malloc(strlen(p_username) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_username)
                    {
                        printf("SERVER ERROR: malloc failed for username\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    p_conn_args->p_user_list[idx].p_password
                        = malloc(strlen(p_password) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_password)
                    {
                        printf("SERVER ERROR: malloc failed for password\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    strcpy(p_conn_args->p_user_list[idx].p_username,
                           p_username);
                    strcpy(p_conn_args->p_user_list[idx].p_password,
                           p_password);

                    p_conn_args->p_user_list[idx].permissions
                        = READ_WRITE_PERMISSION;
                    ret_code = RET_SUCCESS; // Success
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    goto EXIT;
                }
            }

            printf(
                "SERVER ERROR: User list is full - cannot create new user\n");
            free(p_username);
            free(p_password);
            free(p_request->p_request_buffer);
            goto EXIT;

        case USER_FLAG_CREATE_ADMIN:
            // Check session ID
            if (false
                == operations_check_session(&p_session_username,
                                            p_request->header.session_id,
                                            p_conn_args->session_timeout,
                                            p_conn_args->p_session_list))
            {
                printf("SERVER ERROR: Session Invalid or timed out\n");
                ret_code = RET_SESSION_ERROR;
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                goto EXIT;
            }

            // Check permissions
            if (ADMIN_PERMISSION > operations_check_permissions(
                    p_session_username, p_conn_args->p_user_list))
            {
                printf(
                    "SERVER ERROR: User does not have permissions to create "
                    "user with Admin Privledges\n");
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                ret_code = RET_PERMISSION_ERROR;
                goto EXIT;
            }

            // Check existing
            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                // Check for NULL Username
                if (NULL == p_conn_args->p_user_list[idx].p_username)
                {
                    continue; // Skip to next iteration
                }

                if (0
                    == strcmp(p_conn_args->p_user_list[idx].p_username,
                              p_username))
                {
                    printf("SERVER ERROR: User already exists\n");
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    ret_code = RET_USER_EXISTS;
                    goto EXIT;
                }
            }

            // Create the user in the user list
            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                if (0 == p_conn_args->p_user_list[idx].p_username)
                {

                    p_conn_args->p_user_list[idx].p_username
                        = malloc(strlen(p_username) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_username)
                    {
                        printf("SERVER ERROR: malloc failed for username\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    p_conn_args->p_user_list[idx].p_password
                        = malloc(strlen(p_password) + 1);
                    if (NULL == p_conn_args->p_user_list[idx].p_password)
                    {
                        printf("SERVER ERROR: malloc failed for password\n");
                        free(p_username);
                        free(p_password);
                        free(p_request->p_request_buffer);
                        goto EXIT;
                    }

                    strcpy(p_conn_args->p_user_list[idx].p_username,
                           p_username);
                    strcpy(p_conn_args->p_user_list[idx].p_password,
                           p_password);

                    p_conn_args->p_user_list[idx].permissions
                        = ADMIN_PERMISSION;
                    ret_code = RET_SUCCESS; // Success
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    goto EXIT;
                }
            }

            printf(
                "SERVER ERROR: User list is full - cannot create new user\n");
            free(p_username);
            free(p_password);
            free(p_request->p_request_buffer);
            goto EXIT;

        case USER_FLAG_DELETE:

            // Check session ID
            if (false
                == operations_check_session(&p_session_username,
                                            p_request->header.session_id,
                                            p_conn_args->session_timeout,
                                            p_conn_args->p_session_list))
            {
                printf("SERVER ERROR: Session Invalid or timed out\n");
                ret_code = RET_SESSION_ERROR;
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                goto EXIT;
            }

            // Check permissions
            if (ADMIN_PERMISSION > operations_check_permissions(
                    p_session_username, p_conn_args->p_user_list))
            {
                printf(
                    "SERVER ERROR: User does not have permissions to delete "
                    "users\n");
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                ret_code = RET_PERMISSION_ERROR;
                goto EXIT;
            }

            // Ensure the user is not deleting themselves

            if (0 == strcmp(p_session_username, p_username))
            {
                printf("SERVER ERROR: User cannot delete themselves\n");
                free(p_username);
                free(p_password);
                free(p_request->p_request_buffer);
                ret_code = RET_FILE_EXISTS; // Using this as a temp code to pass
                                            // to client the error
                goto EXIT;
            }

            // Delete the user in Userlist
            for (int idx = 0; idx < MAX_USERS; idx++)
            {
                // Check for NULL Username
                if (NULL == p_conn_args->p_user_list[idx].p_username)
                {
                    continue; // Skip to next iteration
                }

                if (0
                    == strcmp(p_conn_args->p_user_list[idx].p_username,
                              p_username))
                {
                    free(p_conn_args->p_user_list[idx].p_username);
                    free(p_conn_args->p_user_list[idx].p_password);
                    p_conn_args->p_user_list[idx].p_username = NULL;
                    p_conn_args->p_user_list[idx].p_password = NULL;
                    ret_code = RET_SUCCESS; // Success
                    free(p_username);
                    free(p_password);
                    free(p_request->p_request_buffer);
                    goto EXIT;
                }
            }

            printf("SERVER ERROR: User was not found in User List\n");
            free(p_username);
            free(p_password);
            free(p_request->p_request_buffer);
            goto EXIT;

        default:
            // Invalid user flag
            printf(
                "SERVER ERROR: Invalid user flag in operations_user_request\n");
            free(p_username);
            free(p_password);
            free(p_request->p_request_buffer);
            ret_code = RET_FAILURE;
            goto EXIT;
    }

EXIT:
    return ret_code;
}

/**
 * @brief Delete Request function
 *
 * @param p_buffer Pointer to the buffer containing the request data
 * @param p_request Pointer to the delete request structure
 * @param p_response Pointer to the delete response structure
 * @param p_conn_args Pointer to the connection arguments structure
 *
 * @return RET_SUCCESS on success, RET_FAILURE on failure
 */
uint8_t operations_delete_request (char *             p_buffer,
                                   delete_request_t * p_request,
                                   thread_args_t *    p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE; // Failure
    char *  p_session_username = NULL;        // Unknown length

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_delete_request\n");
        goto EXIT;
    }

    // Populate the request struct with the buffer data
    memcpy(&p_request->header.session_id,
           p_buffer + DEL_SESSIONID_OFFSET,
           sizeof(uint32_t));
    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->header.target_length,
           p_buffer + DEL_FILENAME_OFFSET,
           sizeof(uint16_t));

    // nltohl the session ID and target length

    p_request->header.session_id    = ntohl(p_request->header.session_id);
    p_request->header.target_length = ntohs(p_request->header.target_length);

    // Check Session ID
    if (false
        == operations_check_session(&p_session_username,
                                    p_request->header.session_id,
                                    p_conn_args->session_timeout,
                                    p_conn_args->p_session_list))
    {
        printf("SERVER ERROR: Session Invalid or timed out\n");
        ret_code = RET_SESSION_ERROR;
        goto EXIT;
    }

    p_request->p_file_name
        = malloc(p_request->header.target_length + 1); // +1 for null terminator
    if (NULL == p_request->p_file_name)
    {
        printf("SERVER ERROR: malloc failed for user request buffer\n");
        free(p_request->p_file_name);
        goto EXIT;
    }

    memcpy(p_request->p_file_name,
           p_buffer + DEL_FILE_OFFSET,
           p_request->header.target_length);
    p_request->p_file_name[p_request->header.target_length]
        = '\0'; // Null terminate

    // Check Permissions

    if (READ_WRITE_PERMISSION > operations_check_permissions(
            p_session_username, p_conn_args->p_user_list))
    {
        printf(
            "SERVER ERROR: User does not have permissions to delete files\n");
        free(p_request->p_file_name);
        ret_code = RET_PERMISSION_ERROR;
        goto EXIT;
    }

    // Check if file exists in the directory
    char * p_file_path = NULL;

    // Build File Path

    if (RET_FAILURE
        == operations_validate_file_path(p_conn_args->p_server_directory_path,
                                         p_request->p_file_name,
                                         &p_file_path))
    {
        printf("SERVER ERROR: Failed to build file path\n");
        free(p_file_path);
        free(p_request->p_file_name);
        goto EXIT;
    }

    // Delete the file

    if (0 != remove(p_file_path))
    {
        printf("SERVER ERROR: Failed to delete file\n");
        free(p_file_path);
        free(p_request->p_file_name);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    free(p_file_path);
    free(p_request->p_file_name);
    ret_code = RET_SUCCESS;

EXIT:
    return ret_code;
}

/**
 * @brief List Request function
 *
 * @param p_buffer Pointer to the buffer containing the request data
 * @param p_request Pointer to the list request structure
 * @param p_response Pointer to the list response structure
 * @param p_conn_args Pointer to the connection arguments structure
 *
 * @return RET_SUCCESS on success, RET_FAILURE on failure
 */
uint8_t operations_list_request (char *            p_buffer,
                                 list_request_t *  p_request,
                                 list_response_t * p_response,
                                 thread_args_t *   p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE;
    char *  p_session_username = NULL; // Unknown length

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_list_request\n");
        goto EXIT;
    }

    // Populate the request struct with the buffer data
    memcpy(&p_request->header.session_id,
           p_buffer + LIST_SESSIONID_OFFSET,
           sizeof(uint32_t));
    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->header.target_length,
           p_buffer + LIST_NAMELEN_OFFSET,
           sizeof(uint16_t));
    memcpy(&p_request->current_position,
           p_buffer + LIST_CURPOS_OFFSET,
           sizeof(uint32_t));

    p_request->p_directory_name
        = malloc(p_request->header.target_length + 1); // +1 for null terminator
    if (NULL == p_request->p_directory_name)
    {
        printf("SERVER ERROR: malloc failed for directory name buffer\n");
        goto EXIT;
    }

    memcpy(p_request->p_directory_name,
           p_buffer + LIST_DIRNAME_OFFSET,
           p_request->header.target_length);

    p_request->p_directory_name[p_request->header.target_length]
        = '\0'; // Null terminate

    // Network to host order conversion
    p_request->header.session_id    = ntohl(p_request->header.session_id);
    p_request->header.target_length = ntohs(p_request->header.target_length);
    p_request->current_position     = ntohl(p_request->current_position);

    // Check Session ID

    if (false
        == operations_check_session(&p_session_username,
                                    p_request->header.session_id,
                                    p_conn_args->session_timeout,
                                    p_conn_args->p_session_list))
    {
        printf("SERVER ERROR: Session Invalid or timed out\n");
        ret_code = RET_SESSION_ERROR;
        free(p_request->p_directory_name);
        goto EXIT;
    }

    // char * p_file_path = malloc(strlen(p_conn_args->p_server_directory_path)
    //                             + strlen(p_request->p_directory_name)
    //                             + 2); // +2 for / and null terminator
    // if (NULL == p_file_path)
    // {
    //     printf("SERVER ERROR: malloc failed for file path buffer\n");
    //     free(p_request->p_directory_name);
    //     goto EXIT;
    // }
    char * p_file_path = NULL;

    if (RET_FAILURE
        == operations_validate_file_path(p_conn_args->p_server_directory_path,
                                         p_request->p_directory_name,
                                         &p_file_path))
    {
        printf("SERVER ERROR: Failed to build file path\n");
        free(p_file_path);
        free(p_request->p_directory_name);
        goto EXIT;
    }

    DIR * p_dir = opendir(p_file_path);
    if (NULL == p_dir)
    {
        printf("SERVER ERROR: Failed to open directory for reading\n");
        free(p_file_path);
        free(p_request->p_directory_name);
        goto EXIT;
    }

    // Malloc base buffer
    uint8_t type_ret             = 0x00;
    p_request->p_response_buffer = malloc(1);

    if (NULL == p_request->p_response_buffer)
    {
        printf("SERVER ERROR: malloc failed for response buffer\n");
        free(p_file_path);
        free(p_request->p_directory_name);
        closedir(p_dir);
        goto EXIT;
    }

    p_request->p_response_buffer[0] = '\0';
    int             buff_size       = 1;
    struct dirent * entry;

    while (NULL != (entry = readdir(p_dir)))
    {
        if ((0 == strcmp(entry->d_name, "."))
            || (0 == strcmp(entry->d_name, "..")))
        {
            continue;
        }

        int entry_name_length = strlen(entry->d_name);
        int new_size          = buff_size + entry_name_length
                       + 2; // +2 for the ID byte and NULL Byte
        char * p_new_buffer = realloc(p_request->p_response_buffer, new_size);

        if (NULL == p_new_buffer)
        {
            printf("SERVER ERROR: realloc failed for response buffer\n");
            free(p_request->p_response_buffer);
            free(p_file_path);
            free(p_request->p_directory_name);
            closedir(p_dir);
            goto EXIT;
        }

        if (new_size > buff_size)
        {
            memset(p_new_buffer + buff_size, 0, new_size - buff_size);
        }

        // NEED TO FIGURE OUT FREES FOR P_NEW_BUFFER AND
        // P_REQUEST->P_RESOPNSE_BUFFER
        p_request->p_response_buffer = p_new_buffer;

        // Fill Buffer

        memcpy(p_request->p_response_buffer + buff_size,
               entry->d_name,
               entry_name_length);
        p_request->p_response_buffer[buff_size + entry_name_length] = '\0';

        if (DT_DIR == entry->d_type)
        {
            type_ret = 0x02; // Directory
        }
        else if (DT_REG == entry->d_type)
        {
            type_ret = 0x01; // File
        }
        else
        {
            type_ret = 0x03; // Unknown type
            printf("SERVER ERROR: Unknown file type for %s\n", entry->d_name);
        }

        p_request->p_response_buffer[buff_size - 1] = type_ret;
        buff_size                                   = new_size;
    }
    // Access the two entries for the response buffer and update the CUR POS
    p_response->total_bytes = buff_size;

    if (false
        == operations_list_read_buffer(p_request->p_response_buffer,
                                       p_request->current_position,
                                       p_response->total_bytes,
                                       &p_response->message_length,
                                       &p_response->current_position,
                                       &p_response->p_response_content))
    {
        printf("SERVER ERROR: Failed to read buffer for response content\n");
        free(p_request->p_response_buffer);
        free(p_file_path);
        free(p_request->p_directory_name);
        closedir(p_dir);
        goto EXIT;
    }

    free(p_request->p_response_buffer);
    free(p_file_path);
    free(p_request->p_directory_name);
    closedir(p_dir);
    ret_code = RET_SUCCESS;

EXIT:

    return ret_code;
}

/**
 * @brief Read the buffer and extract the content for the list response.
 *
 * @param p_response_buffer The buffer containing the response data.
 * @param request_current_position The current position in the request buffer.
 * @param response_total_bytes The total bytes in the response buffer.
 * @param response_message_length The length of the message in the response.
 * @param response_current_position The current position in the response buffer.
 * @param p_response_content Pointer to store the extracted content.
 *
 * @return true if successful, false otherwise.
 */
bool operations_list_read_buffer (char *     p_response_buffer,
                                  uint32_t   request_current_position,
                                  uint32_t   response_total_bytes,
                                  uint32_t * response_message_length,
                                  uint32_t * response_current_position,
                                  char **    p_response_content)
{
    char * p_start_pos = p_response_buffer + request_current_position;
    char * p_end_pos   = p_response_buffer + response_total_bytes;

    int    null_count    = 0;
    char * p_current_pos = p_start_pos;

    while (p_current_pos < p_end_pos && null_count < 2)
    {
        if (*p_current_pos == '\0')
        {
            null_count++;
        }
        p_current_pos++;
    }

    size_t content_length = p_current_pos - p_start_pos;

    if (NULL != *p_response_content)
    {
        free(*p_response_content);
        *p_response_content = NULL;
    }

    *p_response_content = malloc(content_length + 1); // +1 for null terminator

    if (NULL == *p_response_content)
    {
        printf("SERVER ERROR: malloc failed for response content buffer\n");
        return false;
    }

    memcpy(*p_response_content, p_start_pos, content_length);
    (*p_response_content)[content_length] = '\0';
    *response_current_position = request_current_position + content_length;
    *response_message_length   = content_length;

    return true;
}

/**
 * @brief Handle the GET request from the client.
 *
 * @param p_buffer Pointer to the buffer containing the request data.
 * @param p_request Pointer to the GET request structure.
 * @param p_response Pointer to the GET response structure.
 * @param p_conn_args Pointer to the connection arguments structure.
 *
 * @return uint8_t Returns RET_SUCCESS on success, RET_FAILURE on failure.
 */
uint8_t operations_get_request (char *           p_buffer,
                                get_request_t *  p_request,
                                get_response_t * p_response,
                                thread_args_t *  p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE;
    char *  p_session_username = NULL; // Unknown length

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_get_request\n");
        goto EXIT;
    }

    // Populate Struct
    memcpy(&p_request->header.session_id,
           p_buffer + GET_SESSIONID_OFFSET,
           sizeof(uint32_t));

    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->header.target_length,
           p_buffer + GET_FILELEN_OFFSET,
           sizeof(uint16_t));

    p_request->header.session_id    = ntohl(p_request->header.session_id);
    p_request->header.target_length = ntohs(p_request->header.target_length);

    p_request->p_file_name = malloc(p_request->header.target_length + 1);
    if (NULL == p_request->p_file_name)
    {
        printf("SERVER ERROR: malloc failed for file name buffer\n");
        goto EXIT;
    }

    memcpy(p_request->p_file_name,
           p_buffer + GET_FILENAME_OFFSET,
           p_request->header.target_length);
    p_request->p_file_name[p_request->header.target_length] = '\0';

    // Check Session ID

    if (false
        == operations_check_session(&p_session_username,
                                    p_request->header.session_id,
                                    p_conn_args->session_timeout,
                                    p_conn_args->p_session_list))
    {
        printf("SERVER ERROR: Session Invalid or timed out\n");
        ret_code = RET_SESSION_ERROR;
        free(p_request->p_file_name);
        goto EXIT;
    }

    // Build File Path
    char * p_file_path = NULL;

    if (RET_FAILURE
        == operations_validate_file_path(p_conn_args->p_server_directory_path,
                                         p_request->p_file_name,
                                         &p_file_path))
    {
        printf("SERVER ERROR: Failed to build file path\n");
        free(p_file_path);
        free(p_request->p_file_name);
        goto EXIT;
    }

    // Get File
    FILE * p_file = fopen(p_file_path, "rb");
    if (NULL == p_file)
    {
        printf("SERVER ERROR: Failed to open file for reading\n");
        free(p_file_path);
        free(p_request->p_file_name);
        goto EXIT;
    }

    fseek(p_file, 0, SEEK_END);
    p_response->file_size = ftell(p_file);
    fseek(p_file, 0, SEEK_SET);
    p_response->p_file_buffer = malloc(p_response->file_size + 1);

    if (NULL == p_response->p_file_buffer)
    {
        printf("SERVER ERROR: malloc failed for file buffer\n");
        fclose(p_file);
        free(p_file_path);
        free(p_request->p_file_name);
        goto EXIT;
    }

    if (MAX_FILE_SIZE < p_response->file_size)
    {
        printf("SERVER ERROR: File size is too large\n");
        fclose(p_file);
        free(p_file_path);
        free(p_request->p_file_name);
        free(p_response->p_file_buffer);
        goto EXIT;
    }

    fread(
        p_response->p_file_buffer, sizeof(char), p_response->file_size, p_file);
    p_response->p_file_buffer[p_response->file_size] = '\0'; // Null terminate
    ret_code                                         = RET_SUCCESS;
    fclose(p_file);
    free(p_file_path);
    free(p_request->p_file_name);

EXIT:
    return ret_code;
}

/**
 * @brief Handle the MKDIR request from the client.
 *
 * @param p_buffer Pointer to the buffer containing the request data.
 * @param p_request Pointer to the MKDIR request structure.
 * @param p_conn_args Pointer to the connection arguments structure.
 *
 * @return uint8_t Returns RET_SUCCESS on success, RET_FAILURE on failure.
 */
uint8_t operations_mkdir_request (char *            p_buffer,
                                  mkdir_request_t * p_request,
                                  thread_args_t *   p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE;
    char *  p_session_username = NULL;

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_mkdir_request\n");
        goto EXIT;
    }

    // Populate Struct
    memcpy(&p_request->header.session_id,
           p_buffer + MKDIR_SESSIONID_OFFSET,
           sizeof(uint32_t));
    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->header.target_length,
           p_buffer + MKDIR_DIRLEN_OFFSET,
           sizeof(uint16_t));
    p_request->reserved             = (uint32_t)0;
    p_request->header.session_id    = ntohl(p_request->header.session_id);
    p_request->header.target_length = ntohs(p_request->header.target_length);
    p_request->p_directory_name = malloc(p_request->header.target_length + 1);

    if (NULL == p_request->p_directory_name)
    {
        printf("SERVER ERROR: malloc failed for directory name buffer\n");
        goto EXIT;
    }

    memcpy(p_request->p_directory_name,
           p_buffer + MKDIR_DIRNAME_OFFSET,
           p_request->header.target_length);
    p_request->p_directory_name[p_request->header.target_length] = '\0';

    if (false
        == operations_check_session(&p_session_username,
                                    p_request->header.session_id,
                                    p_conn_args->session_timeout,
                                    p_conn_args->p_session_list))
    {
        printf("SERVER ERROR: Session Invalid or timed out\n");
        ret_code = RET_SESSION_ERROR;
        free(p_request->p_directory_name);
        goto EXIT;
    }

    // Check Permissions

    if (READ_WRITE_PERMISSION > operations_check_permissions(
            p_session_username, p_conn_args->p_user_list))
    {
        printf(
            "SERVER ERROR: User does not have permissions to create "
            "directories\n");
        free(p_request->p_directory_name);
        ret_code = RET_PERMISSION_ERROR;
        goto EXIT;
    }

    // Build File Path

    if ((NULL == p_conn_args->p_server_directory_path)
        || (NULL == p_request->p_directory_name))
    {
        printf(
            "SERVER ERROR: Server directory path or file name buffer is "
            "NULL\n");
        free(p_request->p_directory_name);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    char * p_temp = malloc(strlen(p_request->p_directory_name) + 2);
    if (NULL == p_temp)
    {
        printf("SERVER ERROR: malloc failed for temp buffer\n");
        free(p_request->p_directory_name);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    char * p_dirname    = NULL;
    char * p_last_slash = strrchr(p_request->p_directory_name, '/');

    if (NULL != p_last_slash)
    {
        p_dirname = p_last_slash + 1; // Get the file name after the last slash
        *p_last_slash = '\0'; // Null terminate the string at the last slash
        strcpy(p_temp, p_request->p_directory_name);
    }
    else
    {
        snprintf(p_temp,
                 strlen(p_request->p_directory_name) + 2,
                 "/%s",
                 p_request->p_directory_name);
        p_last_slash = strrchr(p_temp, '/');

        if (NULL != p_last_slash)
        {
            p_dirname
                = p_last_slash + 1; // Get the file name after the last slash
            *p_last_slash = '\0'; // Null terminate the string at the last slash
        }
    }
    // Add slash to front of the directory name, in the event that the previous
    // if is reached, it will create a double slash which is handled by realpath

    char * p_dir_path = NULL;
    if (RET_FAILURE
        == operations_validate_file_path(
            p_conn_args->p_server_directory_path, p_temp, &p_dir_path))
    {
        printf("SERVER ERROR: Failed to build file path\n");
        free(p_dir_path);
        free(p_request->p_directory_name);
        free(p_temp);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    char * p_full_dir_path = malloc(strlen(p_dir_path) + strlen(p_dirname)
                                    + 2); // +2 for / and null terminator
    if (NULL == p_full_dir_path)
    {
        printf("SERVER ERROR: malloc failed for full file path buffer\n");
        free(p_dir_path);
        free(p_request->p_directory_name);
        free(p_temp);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    snprintf(p_full_dir_path,
             strlen(p_dir_path) + strlen(p_dirname) + 2,
             "%s/%s",
             p_dir_path,
             p_dirname);
    // Check if directory already exists

    if (0 == access(p_full_dir_path, F_OK))
    {
        printf("SERVER ERROR: Directory already exists\n");
        free(p_dir_path);
        free(p_request->p_directory_name);
        free(p_full_dir_path);
        free(p_temp);
        ret_code = RET_FILE_EXISTS;
        goto EXIT;
    }

    // Create Directory

    if (0 != mkdir(p_full_dir_path, 0777))
    {
        printf("SERVER ERROR: Failed to create directory\n");
        free(p_dir_path);
        free(p_request->p_directory_name);
        free(p_full_dir_path);
        free(p_temp);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    ret_code = RET_SUCCESS;
    free(p_dir_path);
    free(p_request->p_directory_name);
    free(p_full_dir_path);
    free(p_temp);

EXIT:
    return ret_code;
}

/**
 * @brief Handle the PUT request from the client.
 *
 * @param p_buffer Pointer to the buffer containing the request data.
 * @param p_request Pointer to the PUT request structure.
 * @param p_conn_args Pointer to the connection arguments structure.
 *
 * @return uint8_t Returns RET_SUCCESS on success, RET_FAILURE on failure.
 */
uint8_t operations_put_request (char *          p_buffer,
                                put_request_t * p_request,
                                thread_args_t * p_conn_args)
{
    uint8_t ret_code           = RET_FAILURE;
    char *  p_session_username = NULL;

    if ((NULL == p_buffer) || (NULL == p_request) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or request or connection args passed to "
            "operations_mkdir_request\n");
        goto EXIT;
    }

    // Populate Struct
    memcpy(&p_request->header.session_id,
           p_buffer + PUT_SESSIONID_OFFSET,
           sizeof(uint32_t));
    memcpy(&p_request->header.target_length,
           p_buffer + PUT_FILENAME_OFFSET,
           sizeof(uint16_t));

    p_request->header.reserved = (uint8_t)0;
    memcpy(&p_request->overwrite_flag,
           p_buffer + PUT_OVERWRITE_OFFSET,
           sizeof(uint8_t));
    memcpy(&p_request->file_size,
           p_buffer + PUT_FILESIZE_OFFSET,
           sizeof(uint32_t));

    p_request->header.session_id    = ntohl(p_request->header.session_id);
    p_request->header.target_length = ntohs(p_request->header.target_length);
    p_request->file_size            = ntohl(p_request->file_size);

    if (MAX_FILE_SIZE < p_request->file_size)
    {
        printf("SERVER ERROR: File size is too large\n");
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    p_request->p_file_content_buffer = malloc(p_request->file_size + 1);
    if (NULL == p_request->p_file_content_buffer)
    {
        printf("SERVER ERROR: malloc failed for file content buffer\n");
        goto EXIT;
    }

    p_request->p_file_name_buffer = malloc(p_request->header.target_length + 1);
    if (NULL == p_request->p_file_name_buffer)
    {
        printf("SERVER ERROR: malloc failed for file name buffer\n");
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    memcpy(p_request->p_file_name_buffer,
           p_buffer + PUT_FILE_OFFSET,
           p_request->header.target_length);
    memcpy(p_request->p_file_content_buffer,
           p_buffer + PUT_FILE_OFFSET + p_request->header.target_length,
           p_request->file_size);
    p_request->p_file_name_buffer[p_request->header.target_length]
        = '\0'; // Null terminate
    p_request->p_file_content_buffer[p_request->file_size]
        = '\0'; // Null terminate

    // Check Session ID

    if (false
        == operations_check_session(&p_session_username,
                                    p_request->header.session_id,
                                    p_conn_args->session_timeout,
                                    p_conn_args->p_session_list))
    {
        printf("SERVER ERROR: Session Invalid or timed out\n");
        ret_code = RET_SESSION_ERROR;
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    // Check Permissions

    if (READ_WRITE_PERMISSION > operations_check_permissions(
            p_session_username, p_conn_args->p_user_list))
    {
        printf(
            "SERVER ERROR: User does not have permissions to create "
            " files\n");
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        ret_code = RET_PERMISSION_ERROR;
        goto EXIT;
    }

    // Build File Path

    // test for NULL pointer

    if ((NULL == p_conn_args->p_server_directory_path)
        || (NULL == p_request->p_file_name_buffer))
    {
        printf(
            "SERVER ERROR: Server directory path or file name buffer is "
            "NULL\n");
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        ret_code = RET_FAILURE;
        goto EXIT;
    }

    // Need to trim p_file_name_buffer to remove the file name from the path to
    // allow for realpath to work
    char * p_filename   = NULL;
    char * p_last_slash = strrchr(p_request->p_file_name_buffer, '/');

    if (NULL != p_last_slash)
    {
        p_filename = p_last_slash + 1; // Get the file name after the last slash
        *p_last_slash = '\0'; // Null terminate the string at the last slash
    }

    char * p_file_path = NULL;
    if (RET_FAILURE
        == operations_validate_file_path(p_conn_args->p_server_directory_path,
                                         p_request->p_file_name_buffer,
                                         &p_file_path))
    {
        printf("SERVER ERROR: Failed to build file path\n");
        free(p_file_path);
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    // Combine p_file_path and p_filename to get the full file path

    char * p_full_file_path = malloc(strlen(p_file_path) + strlen(p_filename)
                                     + 2); // +2 for / and null terminator
    if (NULL == p_full_file_path)
    {
        printf("SERVER ERROR: malloc failed for full file path buffer\n");
        free(p_file_path);
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    snprintf(p_full_file_path,
             strlen(p_file_path) + strlen(p_filename) + 2,
             "%s/%s",
             p_file_path,
             p_filename);

    // Check if file exists and overwrite flag is set
    if (0 == access(p_full_file_path, F_OK))
    {
        if (0 == p_request->overwrite_flag)
        {
            printf(
                "SERVER ERROR: File already exists and overwrite flag is "
                "not set\n");
            free(p_full_file_path);
            free(p_file_path);
            free(p_request->p_file_name_buffer);
            free(p_request->p_file_content_buffer);
            ret_code = RET_FILE_EXISTS;
            goto EXIT;
        }
    }

    // Put File

    FILE * p_file = fopen(p_full_file_path, "w");
    if (NULL == p_file)
    {
        printf("SERVER ERROR: Failed to open file for writing\n");
        free(p_full_file_path);
        free(p_file_path);
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    fwrite(p_request->p_file_content_buffer,
           sizeof(char),
           p_request->file_size,
           p_file);

    if (ferror(p_file))
    {
        printf("SERVER ERROR: Failed to write file\n");
        fclose(p_file);
        free(p_file_path);
        free(p_full_file_path);
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    if (0 != fclose(p_file))
    {
        printf("SERVER ERROR: Failed to close file\n");
        free(p_file_path);
        free(p_full_file_path);
        free(p_request->p_file_name_buffer);
        free(p_request->p_file_content_buffer);
        goto EXIT;
    }

    ret_code = RET_SUCCESS;
    free(p_file_path);
    free(p_full_file_path);
    free(p_request->p_file_name_buffer);
    free(p_request->p_file_content_buffer);

EXIT:
    return ret_code;
}

// Serializaiton Functions

/**
 * * @brief Get the response from the server and populate the buffer.
 *
 * * * @param p_buffer Pointer to the buffer to populate.
 * * * @param p_response Pointer to the response structure.
 *
 * * * @return true if successful, false otherwise.
 */
bool operations_user_response (char * p_buffer, user_response_t * p_response)
{
    bool b_retval = false;
    if ((NULL == p_buffer) || (NULL == p_response))
    {
        printf(
            "SERVER ERROR: NULL buffer or response or connection args passed "
            "to "
            "operations_user_response\n");
        goto EXIT;
    }

    // Populate the response struct with the buffer data

    p_buffer[0]                 = p_response->header.return_code;
    p_buffer[1]                 = p_response->reserved;
    uint32_t network_session_id = htonl(p_response->session_id);
    memcpy(p_buffer + USER_RETURN_SESSIONID_OFFSET,
           &network_session_id,
           sizeof(uint32_t));

    b_retval = true;

EXIT:
    return b_retval;
}

/**
 * * @brief Get the response from the server and populate the buffer.
 *
 * * @param p_buffer Pointer to the buffer to populate.
 * * @param p_response Pointer to the response structure.
 * * @param p_conn_args Pointer to the connection arguments.
 *
 * * @return true if successful, false otherwise.
 */
bool operations_list_response (char *            p_buffer,
                               list_response_t * p_response,
                               thread_args_t *   p_conn_args)
{
    bool b_retval = false;
    if ((NULL == p_buffer) || (NULL == p_response) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or response or connection args passed "
            "to "
            "operations_get_response\n");
        goto EXIT;
    }

    // Build frame, total-bytes, message length, current position and content
    // are populated.

    uint32_t network_content_length = htonl(p_response->total_bytes);
    uint32_t network_message_length = htonl(p_response->message_length);
    uint32_t network_current_pos    = htonl(p_response->current_position);

    memcpy(p_buffer + LIST_RETURN_TOTALBYTES_OFFSET,
           &network_content_length,
           sizeof(uint32_t));
    memcpy(p_buffer + LIST_RETURN_MESSAGELEN_OFFSET,
           &network_message_length,
           sizeof(uint32_t));
    memcpy(p_buffer + LIST_RETURN_CURPOS_OFFSET,
           &network_current_pos,
           sizeof(uint32_t));
    memcpy(p_buffer + LIST_RETURN_CONTENT_OFFSET,
           p_response->p_response_content,
           p_response->message_length);

    free(p_response->p_response_content);
    p_response->p_response_content = NULL;

    b_retval = true;
EXIT:
    return b_retval;
}

/**
 * * @brief Get the response from the server and populate the buffer.
 *
 * * @param p_buffer Pointer to the buffer to populate.
 * * @param p_response Pointer to the response structure.
 * * @param p_conn_args Pointer to the connection arguments.
 *
 * * @return true if successful, false otherwise.
 */
bool operations_get_response (char *           p_buffer,
                              get_response_t * p_response,
                              thread_args_t *  p_conn_args)
{
    bool b_retval = false;
    if ((NULL == p_buffer) || (NULL == p_response) || (NULL == p_conn_args))
    {
        printf(
            "SERVER ERROR: NULL buffer or response or connection args passed "
            "to "
            "operations_get_response\n");
        goto EXIT;
    }

    // Populate the response struct with the buffer data
    uint32_t network_file_size = htonl(p_response->file_size);
    memcpy(p_buffer + GET_RETURN_FILESIZE_OFFSET,
           &network_file_size,
           sizeof(uint32_t));

    memcpy(p_buffer + GET_RETURN_FILE_OFFSET,
           p_response->p_file_buffer,
           p_response->file_size);
    p_buffer[GET_RETURN_FILE_OFFSET + p_response->file_size]
        = '\0'; // Null
                // terminate
    b_retval = true;

    free(p_response->p_file_buffer);

EXIT:
    return b_retval;
}

/**
 * @brief Check if the user has the required permissions
 *
 * @param p_username Pointer to the username to check
 *
 * @return The permissions of the user, or -1 if not found
 */
uint8_t operations_check_permissions (char * p_username, user_t * p_user_list)
{
    uint8_t ret_value = -1;

    if (NULL == p_username)
    {
        printf(
            "SERVER ERROR: NULL username passed to "
            "server_check_permissions\n");
        goto EXIT;
    }

    for (int idx = 0; idx < MAX_USERS; idx++)
    {
        if (0 == strcmp(p_user_list[idx].p_username, p_username))
        {
            ret_value = p_user_list[idx].permissions;
            goto EXIT;
        }
    }

EXIT:
    return ret_value;
}

/**
 * * @brief Check if the session is valid and not timed out
 *
 * * @param p_username Pointer to the username associated with the session
 * * @param session_id The session ID to check
 * * @param session_timeout The timeout duration for the session
 *
 * * @return true if the session is valid and not timed out, false otherwise
 */
bool operations_check_session (char **     p_username,
                               uint32_t    session_id,
                               int         session_timeout,
                               session_t * p_session_list)
{
    bool   b_retval  = false;
    time_t diff_time = 0;
    *p_username      = NULL;

    for (int idx = 0; idx < MAX_CONNECTIONS; idx++)
    {
        if (p_session_list[idx].session_id == session_id)
        {
            // Check if the session is still valid (e.g., not timed out)
            time_t current_time = time(NULL);
            diff_time = difftime(current_time, p_session_list[idx].start_time);
            if (diff_time > session_timeout)
            {
                printf("SERVER: Session has timed out - Exiting\n");

                free(p_session_list[idx].p_username);
                p_session_list[idx].p_username = NULL;
                p_session_list[idx].session_id = 0;
                p_session_list[idx].start_time = 0;

                goto EXIT;
            }
            else
            {
                *p_username = p_session_list[idx].p_username;
                b_retval    = true;
                goto EXIT;
            }
        }
    }

EXIT:
    return b_retval;
}

/**
 * @brief Validate the file path to ensure it is within the server directory
 *
 * @param p_server_directory Pointer to the server directory path
 * @param p_requested_file_path Pointer to the requested file path
 * @param p_final_file_path Pointer to the final file path (output)
 *
 * @return RET_SUCCESS if the file path is valid, RET_FAILURE otherwise
 */
uint8_t operations_validate_file_path (char *  p_server_directory,
                                       char *  p_requested_file_path,
                                       char ** p_final_file_path)
{
    uint8_t ret_value = RET_FAILURE;

    if ((NULL == p_server_directory) || (NULL == p_requested_file_path))
    {
        printf("SERVER ERROR: NULL pointer passed to validate_file_path\n");
        goto EXIT;
    }

    char * file_path
        = malloc(sizeof(char)
                 * (strlen(p_server_directory) + strlen(p_requested_file_path)
                    + 2)); // +2 for '/' and null terminator
    if (NULL == file_path)
    {
        printf("SERVER ERROR: malloc failed for resolved path buffer\n");
        goto EXIT;
    }

    char * server_dir_full_path = realpath(p_server_directory, NULL);
    if (NULL == server_dir_full_path)
    {
        printf("SERVER ERROR: Failed to resolve server directory path\n");
        free(file_path);
        goto EXIT;
    }

    // Construct the full file path
    snprintf(file_path,
             strlen(p_server_directory) + strlen(p_requested_file_path) + 2,
             "%s/%s",
             p_server_directory,
             p_requested_file_path);
    char * resolved_path = realpath(file_path, NULL);

    if (NULL == resolved_path)
    {
        printf("SERVER ERROR: Failed to resolve file path\n");
        free(file_path);
        free(server_dir_full_path);
        goto EXIT;
    }

    if (0
        != strncmp(
            resolved_path, server_dir_full_path, strlen(server_dir_full_path)))
    {
        printf("SERVER ERROR: File path is outside the server directory\n");
        free(file_path);
        free(server_dir_full_path);
        goto EXIT;
    }

    *p_final_file_path = malloc(strlen(resolved_path) + 1);
    if (NULL == *p_final_file_path)
    {
        printf("SERVER ERROR: malloc failed for final file path buffer\n");
        free(file_path);
        free(resolved_path);
        free(server_dir_full_path);
        goto EXIT;
    }

    strcpy(*p_final_file_path, resolved_path);

    free(file_path);
    free(resolved_path);
    free(server_dir_full_path);
    ret_value = RET_SUCCESS;

EXIT:
    return ret_value;
}

/** End of File **/