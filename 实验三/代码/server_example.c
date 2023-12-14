#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <error.h>

int main(int argc, char *argv[])
{
	int server_sock_listen, server_sock_data;
	struct sockaddr_in server_addr;
	char recv_msg[255];

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

	while(1){

	/* 接收并显示消息 */
	memset(recv_msg, 0, sizeof(recv_msg)); //接收数组置零
	recv(server_sock_data, recv_msg, sizeof(recv_msg), 0);
	printf("Recv: %s", recv_msg);

	/* 发送消息 */
	printf("Send: %s", recv_msg);
	if(send(server_sock_data, recv_msg, strlen(recv_msg), 0)==-1){
		perror("send");
		break;
	}

	if(strcmp(recv_msg,"bye\n")==0)
		break;
		


	}
	/* 关闭数据socket */
	close(server_sock_data);
	/* 关闭监听socket */
	close(server_sock_listen);
	return 0;
}
