#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Usage: %s <server_ip> <port>\n", argv[0]);
		return 1;
	}
	int client_sock;
	struct sockaddr_in server_addr;
	char send_msg[255];//自定义
	char recv_msg[255];

	/* 创建socket */
	if ((client_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket"); //错误处理代码
		return  1;
	}

	if (strcmp(argv[1], "localhost") == 0) {
		strcpy(argv[1], "127.0.0.1");
	}

	/* 指定服务器地址 */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[2]));
	if (inet_aton(argv[1], &server_addr.sin_addr) == 0) {
		perror("inet_aton");
		return 1;
	}

	memset(server_addr.sin_zero, 0, sizeof(server_addr.sin_zero)); //零填充


	/* 连接服务器 */
	if (connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		perror("connect");
		return 1;
	}

	while (1) {
		//printf("请输入学生ID 课程编号\n");
		memset(send_msg, 0, sizeof(send_msg)); //发送数组置零
		fgets(send_msg, sizeof(send_msg), stdin);


		/* 发送消息 */
		printf("client: %s", send_msg);

		if (send(client_sock, send_msg, strlen(send_msg), 0) == -1) {
			perror("send");
			break;
		}
		if (strcmp(send_msg, "bye\n") == 0)
			break;

		/* 接收并显示消息 */
		memset(recv_msg, 0, sizeof(recv_msg)); //接收数组置零
		if (recv(client_sock, recv_msg, sizeof(recv_msg), 0) == -1) {
			perror("recv");
			break;
		}


		/* 发送消息 */
		printf("server: %s", recv_msg);
//		FILE *file = fopen("课程表_utf8.txt", "r");
//		if (file == NULL) {
//			printf("Error opening file.\n");
//			return 1;
//		}
//
//
//
//		char line[256];
//		char *StudentID;
//		int courseID = 0;
//
//		char *token2 = strtok(recv_msg, ",");
//		if (token2 != NULL) {
//			StudentID = token2;
//			token2 = strtok(NULL, ",");
//			if (token2 != NULL) {
//				courseID = atoi(token2);
//			}
//		}
//		//printf("StudentID:%s courseID:%d\n", StudentID, courseID);
//
//		while (fgets(line, sizeof(line), file)) {
//			char *token = strtok(line, " ");//获取学号
//			//printf("token:%d StudentID:%d\n",atoi(token),atoi(StudentID));
//			if (atoi(token) == atoi(StudentID)) {
//				if (courseID == 0) {
//					printf("server: ");
//					while (token != NULL) {
//						printf("%s ", token);
//						token = strtok(NULL, " ");
//					}
//					printf("\n");
//					break;
//				} else {
//					token = strtok(NULL, " ");
//					char *StudentName = token;
//
//					for (int i = 0; i < courseID && token != NULL; i++)
//						token = strtok(NULL, " ");
//					if (token == NULL) {
//						printf("server: 不存在!\n");
//					} else {
//						char *courseName = token;
//
//						printf("server: %s %s %s\n", StudentID, StudentName, courseName);
//					}
//					break;
//				}
//			}
//		}
//		fclose(file);
	}
	/* 关闭socket */
	close(client_sock);

	return 0;
}
