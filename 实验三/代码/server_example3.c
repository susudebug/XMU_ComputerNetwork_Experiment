#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <error.h>
#include <stdlib.h>

void handle_client(int client_socket) {
	char recv_msg[255];
	char send_msg[255];


	while (1) {
		memset(recv_msg, 0, sizeof(recv_msg)); //接收数组置零
		recv(client_socket, recv_msg, sizeof(recv_msg), 0);
		printf("client: %s", recv_msg);

		if (strcmp(recv_msg, "bye\n") == 0) {//若接受到bye则退出服务器
			close(client_socket);
			exit(EXIT_SUCCESS);
		}

		char line[256];
		char *StudentID;
		int courseID = 0;

		char *token2 = strtok(recv_msg, ",");
		if (token2 != NULL) {
			StudentID = token2;
			token2 = strtok(NULL, ",");
			if (token2 != NULL) {
				courseID = atoi(token2);
			}
		}
		//printf("StudentID: %s,courseID: %d\n", StudentID, courseID);


		FILE *file = fopen("课程表_utf8.txt", "r");

		if (file == NULL) {
			printf("Error opening file.\n");
			close(client_socket);
			exit(EXIT_FAILURE);
		}
		

		while (fgets(line, sizeof(line), file)) {
			memset(send_msg, 0, sizeof(send_msg)); //接收数组置零

			char *token = strtok(line, " ");
			//printf("StudentID: %d,token: %d\n", atoi(StudentID), atoi(token));
			if (atoi(token) == atoi(StudentID)) {
				if (courseID == 0) {
					printf("server: ");
					while (token != NULL) {
						printf("%s ", token);
						strcat(send_msg, token);
						strcat(send_msg, " ");
						token = strtok(NULL, " ");
					}
					printf("\n");
					strcat(send_msg, "\n");
					if (send(client_socket, send_msg, strlen(send_msg), 0) == -1) {
						perror("send");
						break;
					}
					break;
				} else {
					token = strtok(NULL, " ");
					char *StudentName = token;

					for (int i = 0; i < courseID && token != NULL; i++)
						token = strtok(NULL, " ");
					if (token == NULL) {
						printf("server: 不存在!\n");
						strcat(send_msg, "不存在!\n");
					} else {
						char *courseName = token;
						printf("server: %s %s %s\n", StudentID, StudentName, courseName);
						strcat(send_msg, StudentID);
						strcat(send_msg, " ");
						strcat(send_msg, StudentName);
						strcat(send_msg, " ");
						strcat(send_msg, courseName);
						strcat(send_msg, "\n");
					}
					if (send(client_socket, send_msg, strlen(send_msg), 0) == -1) {
						perror("send");
						break;
					}
					break;
				}
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int server_sock_listen, client_socket;
	struct sockaddr_in server_addr;

	/* 创建socket */
	server_sock_listen = socket(AF_INET, SOCK_STREAM, 0);

	/* 指定服务器地址 */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(12345);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY); //INADDR_ANY表示本机所有IP地址
	memset(&server_addr.sin_zero, 0, sizeof(server_addr.sin_zero)); //零填充

	/* 绑定socket与地址 */
	bind(server_sock_listen, (struct sockaddr *)&server_addr, sizeof(server_addr));
	/* 监听socket */
	listen(server_sock_listen, 5);


	while (1) {
		/* 接受客户端连接 */
		client_socket = accept(server_sock_listen, NULL, NULL);
		if (client_socket == -1) {
			perror("accept");
			continue;
		}

		printf("Client connected\n");

		/* 创建子进程处理客户端连接 */
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			close(client_socket);
			continue;
		} else if (pid == 0) {
			// 子进程处理客户端连接
			close(server_sock_listen); // 关闭在子进程中不需要的套接字
			handle_client(client_socket);
		} else {
			// 父进程继续监听下一个连接
			close(client_socket); // 父进程不需要处理该连接，关闭套接字
		}
	}

	/* 关闭监听socket（在实际应用中通常不会执行到这里）*/
	close(server_sock_listen);
	return 0;
}
