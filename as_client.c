
#include "as_client.h"
#include <sys/select.h>


static int connect_to_server(int port, const char *hostname)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("connect_to_server");
        return -1;
    }

    struct sockaddr_in addr;

    // Allow sockets across machines.
    addr.sin_family = AF_INET;
    // The port the server will be listening on.
    // htons() converts the port number to network byte order.
    // This is the same as the byte order of the big-endian architecture.
    addr.sin_port = htons(port);
    // Clear this field; sin_zero is used for padding for the struct.
    memset(&(addr.sin_zero), 0, 8);

    // Lookup host IP address.
    struct hostent *hp = gethostbyname(hostname);
    if (hp == NULL)
    {
        ERR_PRINT("Unknown host: %s\n", hostname);
        return -1;
    }

    addr.sin_addr = *((struct in_addr *)hp->h_addr);

    // Request connection to server.
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("connect");
        return -1;
    }

    return sockfd;
}

/*
** Helper for: list_request
** This function reads from the socket until it finds a network newline.
** This is processed as a list response for a single library file,
** of the form:
**                   <index>:<filename>\r\n
**
** returns index on success, -1 on error
** filename is a heap allocated string pointing to the parsed filename
*/
static int get_next_filename(int sockfd, char **filename)
{
    static int bytes_in_buffer = 0;
    static char buf[RESPONSE_BUFFER_SIZE];

    while ((*filename = find_network_newline(buf, &bytes_in_buffer)) == NULL)
    {
        int num = read(sockfd, buf + bytes_in_buffer,
                       RESPONSE_BUFFER_SIZE - bytes_in_buffer);
        if (num < 0)
        {
            perror("list_request");
            return -1;
        }
        bytes_in_buffer += num;
        if (bytes_in_buffer == RESPONSE_BUFFER_SIZE)
        {
            ERR_PRINT("Response buffer filled without finding file\n");
            ERR_PRINT("Bleeding data, this shouldn't happen, but not giving up\n");
            memmove(buf, buf + BUFFER_BLEED_OFF, RESPONSE_BUFFER_SIZE - BUFFER_BLEED_OFF);
        }
    }

    char *parse_ptr = strtok(*filename, ":");
    int index = strtol(parse_ptr, NULL, 10);
    parse_ptr = strtok(NULL, ":");
    // moves the filename to the start of the string (overwriting the index)
    memmove(*filename, parse_ptr, strlen(parse_ptr) + 1);

    return index;
}

// Helper function to send the "LIST\r\n" request
static int send_list_request(int sockfd)
{
    char *listCmd = "LIST\r\n";
    ssize_t numBytes = write(sockfd, listCmd, strlen(listCmd));
    if (numBytes < 0)
    {
        perror("write failed");
        return -1;
    }
    return 0;
}

void add_file_to_library(Library *library, const char *filename)
{

    // Resize the files array to accommodate the new file name
    char **temp = realloc(library->files, (library->num_files + 1) * sizeof(char *));
    if (!temp)
    {
        perror("Failed to realloc library files");
        return;
    }
    library->files = temp;

    // Allocate memory for the new filename and copy it
    library->files[library->num_files] = strdup(filename);
    if (!library->files[library->num_files])
    {
        perror("Failed to duplicate filename");
        return;
    }

    library->num_files++;
}

typedef struct
{
    char *filename;
    int index;
} FileEntry;

int list_request(int sockfd, Library *library)
{
    if (send_list_request(sockfd) == -1)
    {
        return -1; // If sending the LIST request fails
    }

    _free_library(library); // Clear existing library content before populating

    // print filename

    char *filename = NULL;
    int index = 0;
    int highestIndex = -1; // Initialize to -1 to indicate it's unset

    // Get the first filename to determine the highest index
    highestIndex = get_next_filename(sockfd, &filename);

    // fprintf(stderr, "highestIndex: %d\n", highestIndex);
    if (highestIndex == -1)
    {
        fprintf(stderr, "Failed to get the first file index\n");
        return -1; // Error handling if fetching the first filename fails
    }

    FileEntry *entries = malloc(sizeof(FileEntry) * (highestIndex + 1));
    if (!entries)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    entries[highestIndex].filename = strdup(filename);
    entries[highestIndex].index = highestIndex;
    free(filename);

    // Now we know the total number of files based on the highest index
    int file_count = 1;
    while ((highestIndex >= file_count))
    {
        if ((index = get_next_filename(sockfd, &filename)) == -1)
        {
            fprintf(stderr, "Failed to get the next file index\n");
            free(filename);
            return -1;
        }
        if (index == highestIndex)
        { // Skip adding highest index again
            free(filename);
            continue;
        }
        entries[index].filename = strdup(filename);
        entries[index].index = index;
        free(filename);
        file_count++;
    }

    // Add all files to library, highest index last
    for (int i = 0; i <= highestIndex; i++)
    {
        if (entries[i].filename != NULL)
        { // Check if entry is valid
            add_file_to_library(library, entries[i].filename);
            free(entries[i].filename); // Clean up
        }
    }

    free(entries);

    // print the library with index
    for (int i = 0; i < library->num_files; i++)
    {
        printf("%d: %s\n", i, library->files[i]);
    }

    // The loop exits when there are no more filenames to fetch
    return file_count; // Return the count of files listed
}

/*
** Get the permission of the library directory. If the library
** directory does not exist, this function shall create it.
**
** library_dir: the path of the directory storing the audio files
** perpt:       an output parameter for storing the permission of the
**              library directory.
**
** returns 0 on success, -1 on error
*/
static int get_library_dir_permission(const char *library_dir, mode_t *perpt)
{
    struct stat st;

    // Attempt to get the directory's status
    if (stat(library_dir, &st) == -1)
    {
        // If the directory does not exist, create it with 0700 permissions
        if (errno == ENOENT)
        {
            if (mkdir(library_dir, 0700) == -1)
            {
                perror("mkdir failed");
                return -1; // mkdir failed
            }
            // After creation, set *perpt to 0700
            *perpt = 0700;
        }
        else
        {
            perror("stat failed");
            return -1; // stat failed for reasons other than non-existence
        }
    }
    else
    {
        // Directory exists, extract its permissions
        // The permission bits are stored in the st_mode field of the stat struct,
        // masked by S_IRWXU | S_IRWXG | S_IRWXO.
        *perpt = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    }

    return 0; // Success
}

/*
** Creates any directories needed within the library dir so that the file can be
** written to the correct destination. All directories will inherit the permissions
** of the library_dir.
**
** This function is recursive, and will create all directories needed to reach the
** file in destination.
**
** Destination shall be a path without a leading /
**
** library_dir can be an absolute or relative path, and can optionally end with a '/'
**
*/
static void create_missing_directories(const char *destination, const char *library_dir)
{
    char *str_de_tokville = strdup(destination);
    if (str_de_tokville == NULL)
    {
        perror("create_missing_directories");
        return;
    }

    char *before_filename = strrchr(str_de_tokville, '/');
    if (!before_filename)
    {
        goto free_tokville;
    }

    char *path = malloc(strlen(library_dir) + strlen(destination) + 2);
    if (path == NULL)
    {
        goto free_tokville;
    }
    *path = '\0';

    char *dir = strtok(str_de_tokville, "/");
    if (dir == NULL)
    {
        goto free_path;
    }
    strcpy(path, library_dir);
    if (path[strlen(path) - 1] != '/')
    {
        strcat(path, "/");
    }
    strcat(path, dir);

    // get the permissions of the library dir
    mode_t permissions;
    if (get_library_dir_permission(library_dir, &permissions) == -1)
    {
        goto free_path;
    }

    while (dir != NULL && dir != before_filename + 1)
    {
#ifdef DEBUG
        printf("Creating directory %s\n", path);
#endif
        if (mkdir(path, permissions) == -1)
        {
            if (errno != EEXIST)
            {
                perror("create_missing_directories");
                goto free_path;
            }
        }
        dir = strtok(NULL, "/");
        if (dir != NULL)
        {
            strcat(path, "/");
            strcat(path, dir);
        }
    }
free_path:
    free(path);
free_tokville:
    free(str_de_tokville);
}

/*
** Helper for: get_file_request
*/
static int file_index_to_fd(uint32_t file_index, const Library *library)
{
    create_missing_directories(library->files[file_index], library->path);

    char *filepath = _join_path(library->path, library->files[file_index]);
    if (filepath == NULL)
    {
        return -1;
    }

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
#ifdef DEBUG
    printf("Opened file %s\n", filepath);
#endif
    free(filepath);
    if (fd < 0)
    {
        perror("file_index_to_fd");
        return -1;
    }

    return fd;
}

int get_file_request(int sockfd, uint32_t file_index, const Library *library)
{
#ifdef DEBUG
    printf("Getting file %s\n", library->files[file_index]);
#endif

    int file_dest_fd = file_index_to_fd(file_index, library);
    if (file_dest_fd == -1)
    {
        return -1;
    }

    int result = send_and_process_stream_request(sockfd, file_index, -1, file_dest_fd);
    if (result == -1)
    {
        return -1;
    }

    return 0;
}

int start_audio_player_process(int *audio_out_fd)
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        return -1;
    }
    else if (pid == 0)
    {                     // Child process
        close(pipefd[1]); // Close writing end, not needed in child
        if (dup2(pipefd[0], STDIN_FILENO) == -1)
        { // Redirect stdin
            perror("dup2");
            exit(EXIT_FAILURE);
        }
        close(pipefd[0]); // Close original reading end

        // Prepare for execvp
        char *args[] = AUDIO_PLAYER_ARGS;
        execvp(AUDIO_PLAYER, args);

        // execvp only returns if an error occurred
        perror("execvp");
        exit(EXIT_FAILURE);
    }
    else
    {                                   // Parent process
        close(pipefd[0]);               // Close reading end, not needed in parent
        *audio_out_fd = pipefd[1];      // Return writing end of the pipe
        sleep(AUDIO_PLAYER_BOOT_DELAY); // Wait for audio player to initialize
    }

    return pid;
}

static void _wait_on_audio_player(int audio_player_pid)
{
    int status;
    if (waitpid(audio_player_pid, &status, 0) == -1)
    {
        perror("_wait_on_audio_player");
        return;
    }
    if (WIFEXITED(status))
    {
        fprintf(stderr, "Audio player exited with status %d\n", WEXITSTATUS(status));
    }
    else
    {
        printf("Audio player exited abnormally\n");
    }
}

int stream_request(int sockfd, uint32_t file_index)
{
    int audio_out_fd;
    int audio_player_pid = start_audio_player_process(&audio_out_fd);

    int result = send_and_process_stream_request(sockfd, file_index, audio_out_fd, -1);
    if (result == -1)
    {
        ERR_PRINT("stream_request: send_and_process_stream_request failed\n");
        return -1;
    }

    _wait_on_audio_player(audio_player_pid);

    return 0;
}

int stream_and_get_request(int sockfd, uint32_t file_index, const Library *library)
{
    int audio_out_fd;
    int audio_player_pid = start_audio_player_process(&audio_out_fd);

#ifdef DEBUG
    printf("Getting file %s\n", library->files[file_index]);
#endif

    int file_dest_fd = file_index_to_fd(file_index, library);
    if (file_dest_fd == -1)
    {
        ERR_PRINT("stream_and_get_request: file_index_to_fd failed\n");
        return -1;
    }

    int result = send_and_process_stream_request(sockfd, file_index,
                                                 audio_out_fd, file_dest_fd);
    if (result == -1)
    {
        ERR_PRINT("stream_and_get_request: send_and_process_stream_request failed\n");
        return -1;
    }

    _wait_on_audio_player(audio_player_pid);

    return 0;
}

// Function to send stream request
static int send_stream_request(int sockfd, uint32_t file_index)
{
    char request[10] = "STREAM\r\n";                  // STREAM command
    uint32_t index_network_order = htonl(file_index); // Convert to network byte order

    // Send the STREAM command
    if (write(sockfd, request, strlen(request)) < 0)
    {
        perror("Failed to send stream command");
        return -1;
    }

    // Send the file index
    if (write(sockfd, &index_network_order, sizeof(index_network_order)) < 0)
    {
        perror("Failed to send file index");
        return -1;
    }

    return 0; // Success
}

int send_and_process_stream_request(int sockfd, uint32_t file_index,
                                    int audio_out_fd, int file_dest_fd)
{

    if (audio_out_fd == -1 && file_dest_fd == -1)
    {
        fprintf(stderr, "No output destination specified\n");
        return -1;
    }

    char *fixed_buffer = malloc(NETWORK_PRE_DYNAMIC_BUFF_SIZE);

    char *dynamic_buffer = NULL;
    size_t dynamic_buffer_len = 0;

    if (send_stream_request(sockfd, file_index) < 0)
    {
        fprintf(stderr, "Failed to send stream request\n");
        free(fixed_buffer);
        free(dynamic_buffer);
        return -1;
    }

    fd_set read_fds, write_fds;
    struct timeval timeout;
    int max_fd = sockfd > audio_out_fd ? sockfd : audio_out_fd;
    max_fd = max_fd > file_dest_fd ? max_fd : file_dest_fd;

    // Read file size first
    uint32_t file_size_net, file_size;
    if (read(sockfd, &file_size_net, sizeof(file_size_net)) < sizeof(file_size_net))
    {
        perror("Failed to read file size");
        free(fixed_buffer);
        free(dynamic_buffer);
        return -1;
    }
    file_size = ntohl(file_size_net); // Convert from network byte order to host byte order

    // Continue processing until all file data has been read and written
    size_t total_bytes_read = 0;
    size_t total_bytes_written_file = 0;
    size_t total_bytes_written_audio = 0;

    while (total_bytes_read < file_size || dynamic_buffer_len > 0)
    {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        if (total_bytes_read < file_size)
            FD_SET(sockfd, &read_fds);
        if (dynamic_buffer_len > 0)
        {
            if (audio_out_fd != -1)
                FD_SET(audio_out_fd, &write_fds);
            if (file_dest_fd != -1)
                FD_SET(file_dest_fd, &write_fds);
        }

        timeout.tv_sec = SELECT_TIMEOUT_SEC;
        timeout.tv_usec = SELECT_TIMEOUT_USEC;

        if (select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout) < 0)
        {
            perror("Select error");
            break;
        }

        // Handle reading from socket

        if (FD_ISSET(sockfd, &read_fds))
        {
            ssize_t bytes_read = read(sockfd, fixed_buffer, sizeof(fixed_buffer));
            if (bytes_read > 0)
            {
                char *temp_buffer = realloc(dynamic_buffer, dynamic_buffer_len + bytes_read);
                if (!temp_buffer)
                {
                    perror("Failed to resize dynamic buffer");
                    break; // Breaking out of the loop on realloc failure
                }
                dynamic_buffer = temp_buffer;
                memcpy(dynamic_buffer + dynamic_buffer_len, fixed_buffer, bytes_read);
                dynamic_buffer_len += bytes_read;
                total_bytes_read += bytes_read;
            }
            else if (bytes_read == 0)
            {
                // End of data stream
                break;
            }
            else
            {
                perror("Socket read error");
                break;
            }
        }

        // Write to audio_out_fd and file_dest_fd
        if (audio_out_fd != -1 && file_dest_fd != -1 && dynamic_buffer_len > 0)
        {
            if (FD_ISSET(audio_out_fd, &write_fds) && FD_ISSET(file_dest_fd, &write_fds))
            {
                ssize_t bytes_written_audio = write(audio_out_fd, dynamic_buffer, dynamic_buffer_len);
                ssize_t bytes_written_file = write(file_dest_fd, dynamic_buffer, dynamic_buffer_len);

                size_t min_bytes_to_write = bytes_written_audio < bytes_written_file ? bytes_written_audio : bytes_written_file;

                // if (bytes_written_audio < bytes_written_file){
                //     ssize_t min_bits_to_write = bytes_written_audio;
                // }else{
                //     ssize_t min_bits_to_write = bytes_written_file;
                // }

                memmove(dynamic_buffer, dynamic_buffer + min_bytes_to_write, dynamic_buffer_len - min_bytes_to_write);
                dynamic_buffer_len -= min_bytes_to_write;
            }
        }

        // Write to audio_out_fd
        if (audio_out_fd != -1)
        {
            if (FD_ISSET(audio_out_fd, &write_fds) && dynamic_buffer_len > 0)
            {
                ssize_t bytes_written = write(audio_out_fd, dynamic_buffer, dynamic_buffer_len);
                if (bytes_written > 0)
                {
                    memmove(dynamic_buffer, dynamic_buffer + bytes_written, dynamic_buffer_len - bytes_written);
                    dynamic_buffer_len -= bytes_written;
                    total_bytes_written_audio += bytes_written;
                }
            }
        }

        // Write to file_dest_fd
        if (file_dest_fd != -1)
        {
            if (FD_ISSET(file_dest_fd, &write_fds) && dynamic_buffer_len > 0)
            {
                ssize_t bytes_written = write(file_dest_fd, dynamic_buffer, dynamic_buffer_len);
                if (bytes_written > 0)
                {
                    memmove(dynamic_buffer, dynamic_buffer + bytes_written, dynamic_buffer_len - bytes_written);
                    dynamic_buffer_len -= bytes_written;
                    total_bytes_written_file += bytes_written;
                }
            }
        }

        // Debugging print statements
        //  printf("Tpatal bytes read: %zu\n", total_bytes_read);
        //  printf("Total bytes written to audio: %zu\n", total_bytes_written_audio);
        //  printf("Total bytes written to file: %zu\n", total_bytes_written_file);

        // Free up dynamic buffer space if it's empty, to avoid memory waste
        if (dynamic_buffer_len == 0 && dynamic_buffer)
        {
            free(dynamic_buffer);
            dynamic_buffer = NULL;
        }

        // Check if we've read more bytes than expected
        if (total_bytes_read > file_size)
        {
            fprintf(stderr, "Read more bytes than expected\n");
            break;
        }
    }

    // Cleanup and exit
    free(fixed_buffer);
    free(dynamic_buffer);
    close(audio_out_fd);
    close(file_dest_fd);
    return 0;
}

static void _print_shell_help()
{
    printf("Commands:\n");
    printf("  list: List the files in the library\n");
    printf("  get <file_index>: Get a file from the library\n");
    printf("  stream <file_index>: Stream a file from the library (without saving it)\n");
    printf("  stream+ <file_index>: Stream a file from the library\n");
    printf("                        and save it to the local library\n");
    printf("  help: Display this help message\n");
    printf("  quit: Quit the client\n");
}

/*
** Shell to handle the client options
** ----------------------------------
** This function is a mini shell to handle the client options. It prompts the
** user for a command and then calls the appropriate function to handle the
** command. The user can enter the following commands:
** - "list" to list the files in the library
** - "get <file_index>" to get a file from the library
** - "stream <file_index>" to stream a file from the library (without saving it)
** - "stream+ <file_index>" to stream a file from the library and save it to the local library
** - "help" to display the help message
** - "quit" to quit the client
*/
static int client_shell(int sockfd, const char *library_directory)
{
    char buffer[REQUEST_BUFFER_SIZE];
    char *command;
    int file_index;

    Library library = {"client", library_directory, NULL, 0};

    while (1)
    {
        if (library.files == 0)
        {
            printf("Server library is empty or not retrieved yet\n");
        }

        printf("Enter a command: ");
        if (fgets(buffer, REQUEST_BUFFER_SIZE, stdin) == NULL)
        {
            perror("client_shell");
            goto error;
        }

        command = strtok(buffer, " \n");
        if (command == NULL)
        {
            continue;
        }

        // List Request -- list the files in the library
        if (strcmp(command, CMD_LIST) == 0)
        {
            if (list_request(sockfd, &library) == -1)
            {
                goto error;
            }

            // Get Request -- get a file from the library
        }
        else if (strcmp(command, CMD_GET) == 0)
        {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL)
            {
                printf("Usage: get <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files)
            {
                printf("Invalid file index\n");
                continue;
            }

            if (get_file_request(sockfd, file_index, &library) == -1)
            {
                goto error;
            }

            // Stream Request -- stream a file from the library (without saving it)
        }
        else if (strcmp(command, CMD_STREAM) == 0)
        {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL)
            {
                printf("Usage: stream <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files)
            {
                printf("Invalid file index\n");
                continue;
            }

            if (stream_request(sockfd, file_index) == -1)
            {
                goto error;
            }

            // Stream and Get Request -- stream a file from the library and save it to the local library
        }
        else if (strcmp(command, CMD_STREAM_AND_GET) == 0)
        {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL)
            {
                printf("Usage: stream+ <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files)
            {
                printf("Invalid file index\n");
                continue;
            }

            if (stream_and_get_request(sockfd, file_index, &library) == -1)
            {
                goto error;
            }
        }
        else if (strcmp(command, CMD_HELP) == 0)
        {
            _print_shell_help();
        }
        else if (strcmp(command, CMD_QUIT) == 0)
        {
            printf("Quitting shell\n");
            break;
        }
        else
        {
            printf("Invalid command\n");
        }
    }

    _free_library(&library);
    return 0;
error:
    _free_library(&library);
    return -1;
}

static void print_usage()
{
    printf("Usage: as_client [-h] [-a NETWORK_ADDRESS] [-p PORT] [-l LIBRARY_DIRECTORY]\n");
    printf("  -h: Print this help message\n");
    printf("  -a NETWORK_ADDRESS: Connect to server at NETWORK_ADDRESS (default 'localhost')\n");
    printf("  -p  Port to listen on (default: " XSTR(DEFAULT_PORT) ")\n");
    printf("  -l LIBRARY_DIRECTORY: Use LIBRARY_DIRECTORY as the library directory (default 'as-library')\n");
}

int main(int argc, char *const *argv)
{
    int opt;
    int port = DEFAULT_PORT;
    const char *hostname = "localhost";
    const char *library_directory = "saved";

    while ((opt = getopt(argc, argv, "ha:p:l:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_usage();
            return 0;
        case 'a':
            hostname = optarg;
            break;
        case 'p':
            port = strtol(optarg, NULL, 10);
            if (port < 0 || port > 65535)
            {
                ERR_PRINT("Invalid port number %d\n", port);
                return 1;
            }
            break;
        case 'l':
            library_directory = optarg;
            break;
        default:
            print_usage();
            return 1;
        }
    }

    printf("Connecting to server at %s:%d, using library in %s\n",
           hostname, port, library_directory);

    int sockfd = connect_to_server(port, hostname);
    if (sockfd == -1)
    {
        return -1;
    }

    int result = client_shell(sockfd, library_directory);
    if (result == -1)
    {
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}
