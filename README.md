# AudioStreamServer

AudioStreamServer is a simple command-line server application that streams audio files from a designated library directory. It listens on a specified port, forks a new process for every client connection, and handles file listing and streaming requests.

## Features

- **Multi-Client Support:**  
  Each client connection is handled in a separate child process.
  
- **Dynamic Library Scanning:**  
  The server periodically scans a specified directory for supported audio files, keeping its file library up to date.
  
- **File Listing:**  
  Responds to client requests with a list of audio files formatted with an index and file path.
  
- **Audio Streaming:**  
  Streams requested files in chunks. Clients request a file by index and receive the file's size followed by its data.

## Protocol Details

### LIST Request
- **Client Action:**  
  Send the `REQUEST_LIST` command followed by the network newline (`"\r\n"`).
- **Server Response:**  
  Returns a single string listing all files. Each file is sent in reverse order with the format:  
  `<index>:<file_path>\r\n`  
  (e.g., `2:artist/album/file3.wav\r\n1:artist/file2.wav\r\n0:file1.wav\r\n`).

### STREAM Request
- **Client Action:**  
  Send the `REQUEST_STREAM` command followed by `"\r\n"`, then a 32-bit integer (in network byte order) indicating the file index.
- **Server Response:**  
  First sends the file size (as a 32-bit network byte-order integer), then streams the file in chunks of up to `STREAM_CHUNK_SIZE` bytes.

## Installation

### Prerequisites
- A POSIX-compliant operating system (Linux, macOS, etc.)
- A C compiler (e.g., `gcc`)

### Building the Server
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/AudioStreamServer.git
   cd AudioStreamServer
   ```

### Build All Targets:
   ```bash
    make
   ```

### Build in Debug Mode:
   ```bash
    make debug
   ```

### Running the Server

The server can be run with the following command:
```bash
./as_server <port> <library_directory>
```

Client Usage:
```bash
./as_client <server_ip> <port>
```