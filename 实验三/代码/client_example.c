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
	
	if (strcmp(argv[1],"localhost")==0){
		strcpy(argv[1],"127.0.0.1");
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
		printf("Enter message('bye' to quit)\n");
		memset(send_msg, 0, sizeof(send_msg)); //发送数组置零
		fgets(send_msg, sizeof(send_msg), stdin);
		
		
		/* 发送消息 */
		printf("Send: %s", send_msg);
		
		if(send(client_sock, send_msg, strlen(send_msg), 0)==-1){
			perror("send");
			break;
		}

		/* 接收并显示消息 */
		memset(recv_msg, 0, sizeof(recv_msg)); //接收数组置零
		if(recv(client_sock, recv_msg, sizeof(recv_msg), 0)==-1){
			perror("recv");
			break;
		}
		printf("Recv: %s", recv_msg);
		
		if(strcmp(recv_msg,"bye\n")==0){
			printf("quit---\n");
			break;
		}
	}

	/* 关闭socket */
	close(client_sock);
	return 0;
}
