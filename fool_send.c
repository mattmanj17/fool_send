
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#pragma comment(lib, "ws2_32.lib")



// Macros

#define DEFAULT_PORT "42069"

#define ERROR_EXIT(src, err) _error_exit_impl(src, err, __LINE__, __FILE__)



// Globals

static bool s_hasStartedWinsock = false;

static SOCKET s_listenSocket = INVALID_SOCKET;

static struct addrinfo * s_ai = NULL;
static SOCKET s_connectSocket = INVALID_SOCKET;



// Procedures

void _error_exit_impl(const char * src, int errorCode, int line, const char * file)
{
	printf("At file %s, line %d, %s failed with ", file, line, src);

	LPVOID errorMsgBuffer;
	DWORD result = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		errorCode,
		0,
		(LPSTR)&errorMsgBuffer,
		0,
		NULL);

	if (result == 0)
	{
		printf("Unknown error %d\n", errorCode);
	}
	else
	{
		printf("Error %d: %s\n", errorCode, (LPSTR)errorMsgBuffer);
		LocalFree(errorMsgBuffer); // does this matter since we just exit?
	}

	exit(1);
}

void init_winsock(void)
{
	assert(!s_hasStartedWinsock);

	WSADATA wsaData;
	int errorCode = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (errorCode)
		ERROR_EXIT("WSAStartup", errorCode);

	s_hasStartedWinsock = true;
}

void cleanup_winsock(void)
{
	if (!s_hasStartedWinsock)
		return;

	WSACleanup();

	s_hasStartedWinsock = false;
}

enum WANTPASSIVE
{
	WANTPASSIVE_False,
	WANTPASSIVE_True
};

void resolve_host_port(const char * host, const char * port, enum WANTPASSIVE wantpassive, struct addrinfo ** pAi)
{
	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (wantpassive == WANTPASSIVE_True)
		hints.ai_flags = AI_PASSIVE;

	int getaddrinfo_error = getaddrinfo(host, port, &hints, pAi);
	if (getaddrinfo_error)
		ERROR_EXIT("getaddrinfo", getaddrinfo_error);
}

void socket_send_bytes(
	SOCKET s,
	const char * buf,
	int len)
{
	if (send(s, buf, len, 0) == SOCKET_ERROR)
		ERROR_EXIT("send", WSAGetLastError());
}

int socket_receive_bytes(
	SOCKET s,
	char * buf,
	int len)
{
	int result = recv(s, buf, len, 0);
	if (result == SOCKET_ERROR)
		ERROR_EXIT("recv", WSAGetLastError());

	return result;
}

void start_listening(void)
{
	struct addrinfo * ai = NULL;
	resolve_host_port(NULL, DEFAULT_PORT, WANTPASSIVE_True, &ai);

	assert(ai);

	s_listenSocket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if (s_listenSocket == INVALID_SOCKET)
		ERROR_EXIT("socket", WSAGetLastError());

	if (bind(s_listenSocket, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR)
		ERROR_EXIT("bind", WSAGetLastError());

	if (listen(s_listenSocket, SOMAXCONN) == SOCKET_ERROR)
		ERROR_EXIT("listen", WSAGetLastError());

	assert(ai);
	freeaddrinfo(ai);
}

SOCKET accept_connection(void)
{
	SOCKET clientSocket = accept(s_listenSocket, NULL, NULL);
	if (clientSocket == INVALID_SOCKET)
		ERROR_EXIT("accept", WSAGetLastError());

	return clientSocket;
}

int scoped_fwrite(const char * fileName, const char * fileBuffer, size_t fileLength)
{
	FILE * file = fopen(fileName, "wb");
	if (!file)
		return 1;

	if (fwrite(fileBuffer, 1, fileLength, file) != fileLength)
		return 1;

	if (fclose(file) != 0)
		return 1;

	return 0;
}

void start_server(void)
{
	start_listening();

	printf("listening\n");

	SOCKET clientSocket = INVALID_SOCKET;

	while (1)
	{
		if (clientSocket != INVALID_SOCKET)
		{
			closesocket(clientSocket);
			clientSocket = INVALID_SOCKET;
		}

		clientSocket = accept_connection();

		printf("accepted connection\n");

		// call socket_receive_bytes to get the header (file name + file legnth)

		char headerBuffer[256 + 8 + 1];
		int headerSize = socket_receive_bytes(clientSocket, headerBuffer, sizeof(headerBuffer) - 1);
		if (headerSize < 9)
			continue;

		headerBuffer[headerSize] = '\0';
		size_t fileLength = *((size_t *)headerBuffer);
		const char * fileName = headerBuffer + 8;

		char * fileBuffer = (char *)malloc(fileLength);
		if (!fileBuffer)
			continue;
		
		// call socket_send_bytes to send back an acknowledgement

		socket_send_bytes(clientSocket, "ACK", 3);

		// call socket_receive_bytes to get all the file bytes

		int fileBytesReceived = socket_receive_bytes(clientSocket, fileBuffer, (int)fileLength);
		if (fileBytesReceived != fileLength)
			continue;

		// write out file bytes to file in working dir

		int result = scoped_fwrite(fileName, fileBuffer, fileLength);
		free(fileBuffer);

		if (result != 0)
			continue;

		// call socket_send_bytes to send 2nd acknowledgement

		socket_send_bytes(clientSocket, "ACK", 3);
	}
}

void make_connection(void)
{
	assert(s_ai);
	assert(!s_ai->ai_next);

	s_connectSocket = socket(s_ai->ai_family, s_ai->ai_socktype, s_ai->ai_protocol);
	if (s_connectSocket == INVALID_SOCKET)
		ERROR_EXIT("socket", WSAGetLastError());

	if (connect(s_connectSocket, s_ai->ai_addr, (int)s_ai->ai_addrlen) == SOCKET_ERROR)
		ERROR_EXIT("connect", WSAGetLastError());
}

const char * extract_file_name(const char * path) 
{
	assert(path);

	const char * lastFslash = strrchr(path, '/');
	const char * lastBslash = strrchr(path, '\\');
	const char * lastColon = strrchr(path, ':');

	const char * fileName = path;
	if (lastFslash && lastFslash >= fileName)
		fileName = lastFslash + 1;
	if (lastBslash && lastBslash >= fileName)
		fileName = lastBslash + 1;
	if (lastColon && lastColon >= fileName)
		fileName = lastColon + 1;

	return fileName;
}

void start_client(const char * hostname, const char * path)
{
	// Get file name, open file, read bytes

	const char * fileName = extract_file_name(path);
	size_t len_name = strlen(fileName);
	if (len_name > 256)
	{
		printf("file name too long");
		return;
	}

	size_t file_length;
	char * file_bytes;
	{
		FILE * file = fopen(path, "rb");
		if (!file)
		{
			printf("Failed to open file");
			return;
		}

		// get file length 
		//  (seek to end, ftell, seek back to start)

		if (fseek(file, 0, SEEK_END))
		{
			printf("fseek SEEK_END failed.\n");
			return;
		}

		long signed_file_length = ftell(file);
		if (signed_file_length < 0)
		{
			printf("ftell failed.\n");
			return;
		}

		file_length = (size_t)signed_file_length;

		if (fseek(file, 0, SEEK_SET))
		{
			printf("fseek SEEK_SET failed.\n");
			return;
		}

		// Allocate space to read file

		file_bytes = (char *)malloc(file_length);
		if (!file_bytes)
		{
			printf("failed to allocate bytes to read file.\n");
			return;
		}

		// Actually read

		size_t bytes_read = fread(
			file_bytes,
			1,
			file_length,
			file);

		if (bytes_read != file_length)
		{
			printf("failed to read bytes from file");
			return;
		}

		// close file

		// BUG (matthewd) ignoring return value?

		fclose(file);
	}

	// Connect to server on host

	resolve_host_port(hostname, DEFAULT_PORT, WANTPASSIVE_False, &s_ai);
	make_connection();

	// TODO finish function

	// call socket_send_bytes to send file name and file length

	char headerBuffer[256 + 8];
	
	*((size_t *)headerBuffer) = file_length;
	for (size_t i = 0; i < len_name; ++i)
	{
		headerBuffer[i + 8] = fileName[i];
	}

	socket_send_bytes(s_connectSocket, headerBuffer, (int)(len_name + 8));
	
	// call socket_receive_bytes to get back acknoledgement from server

	char ackBuffer[3];
	int bytesReceived = socket_receive_bytes(s_connectSocket, ackBuffer, 3);
	if (bytesReceived != 3 || ackBuffer[0] != 'A' || ackBuffer[1] != 'C' || ackBuffer[2] != 'K')
	{
		printf("Failed to receive 1st acknowledgement from server");
		return;
	}

	// call socket_send_bytes to send all the file bytes

	socket_send_bytes(s_connectSocket, file_bytes, (int)file_length);
	free(file_bytes);

	// call socket_receive_bytes to get back 2nd acknoledgement from server

	bytesReceived = socket_receive_bytes(s_connectSocket, ackBuffer, 3);
	if (bytesReceived != 3 || ackBuffer[0] != 'A' || ackBuffer[1] != 'C' || ackBuffer[2] != 'K')
	{
		printf("Failed to receive 2nd acknowledgement from server");
		return;
	}

	// hooray, we did it, say something about it

	printf("File sent!");
}

void my_atexit(void)
{
	if (s_ai)
		freeaddrinfo(s_ai);

	if (s_listenSocket != INVALID_SOCKET)
		closesocket(s_listenSocket);

	if (s_connectSocket != INVALID_SOCKET)
		closesocket(s_connectSocket);

	cleanup_winsock();
}

int main(int argc, const char * argv[])
{
	atexit(my_atexit);
	init_winsock();

	if (argc == 1)
	{
		start_server();
	}
	else if (argc == 3)
	{
		start_client(argv[1], argv[2]);
	}
	else
	{
		printf(
			"Incorect number of arguments. Expected either:\n"
			"%s (to start as server)\n"
			"%s <hostname> <path> (to send file at <path> to the computer named <hostname>)",
			argv[0],
			argv[0]);
	}
}