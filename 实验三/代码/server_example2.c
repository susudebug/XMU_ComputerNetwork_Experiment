#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <error.h>

int main(int argc, char *argv[]) {
	int server_sock_listen, server_sock_data;
	struct sockaddr_in server_addr;
	char recv_msg[255];
	char send_msg[255];
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
	listen(server_sock_listen, 0);

	server_sock_data = accept(server_sock_listen, NULL, NULL);
	//不断接受客户机发送来的信息，直到接受到bye
	while (1) {
		printf("Server is listening....\n");

		/* 接收并显示消息 */
		memset(recv_msg, 0, sizeof(recv_msg)); //接收数组置零
		recv(server_sock_data, recv_msg, sizeof(recv_msg), 0);
		printf("client: %s", recv_msg);

		if (strcmp(recv_msg, "bye\n") == 0)//若接收到bye则退出服务器
			break;


		FILE *file = fopen("课程表_utf8.txt", "r");
		if (file == NULL) {
			printf("Error opening file.\n");
			return 1;
		}


		char line[256];
		char *StudentID;
		int courseID = 0;

		//使用逗号分隔接收到的字符串
		char *token2 = strtok(recv_msg, ",");
		if (token2 != NULL) {
			StudentID = token2;
			token2 = strtok(NULL, ",");
			if (token2 != NULL) {
				courseID = atoi(token2);
			}
		}
		//printf("StudentID:%s courseID:%d\n", StudentID, courseID);

		//按行读取txt文件
		while (fgets(line, sizeof(line), file)) {

			memset(send_msg, 0, sizeof(send_msg)); //接收数组置零

			char *token = strtok(line, " ");//获取学号

			
			//若txt中某行学号与客户机输入的一致
			if (atoi(token) == atoi(StudentID)) {
				//若没有输入课程编号--整行输出
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
				} else {//若有输入课程编号--定位到对应位置
					token = strtok(NULL, " ");
					char *StudentName = token;

					for (int i = 0; i < courseID && token != NULL; i++)
						token = strtok(NULL, " ");
						
					//若token查找不到，则不存在
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
				}
				//		/* 向客户机发送消息 */
				printf("%s", send_msg);
				if (send(server_sock_data, send_msg, strlen(send_msg), 0) == -1) {
					printf("send");
					break;
				}
				break;
			}

		}
		fclose(file);

	}
	/* 关闭数据socket */
	close(server_sock_data);
	/* 关闭监听socket */
	close(server_sock_listen);
	return 0;
}
