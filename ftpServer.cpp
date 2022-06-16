#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <errno.h>
#include <sys/wait.h>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <sys/stat.h>
#include <dirent.h>
#include <sstream>
using namespace std;

char* FTP_SERVER_CPORT;//控制端口
char* FTP_SERVER_DPORT;//数据端口

string remember;

//函数声明
int sendInfo(int socketfd,const void* buffer,size_t length);
void doftp(int client_Cfd);
int recvsingleline(int serverfd,string& info);
int parseIpPort(string& ipport,string& ipstr,string& portstr);
int bindsocket(const char *port);
int make_client_connection_with_sockfd (int sock_fd,const char *host, const char *port);
string execute(const char* cmd);
int sendDataBinary(int serverfd, FILE* fd,int size);
int recvDataBinary(int serverfd, FILE* fd);
int server_listen(const char *port);
int accept_connection(int server_fd);
void *get_in_addr (struct sockaddr *sa);
//


// 处理命令中的空白符
static inline std::string &ltrim(std::string &s) 
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}


static inline std::string &rtrim(std::string &s) 
{
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

static inline std::string &trim(std::string &s) 
{
    return ltrim(rtrim(s));
}



int main(int argc,char** argv)
{
    if(argc == 3)
    {
		FTP_SERVER_CPORT = argv[1];
		FTP_SERVER_DPORT = argv[2];
    }
	else
	{
		cout<<"命令格式应为: ./ftpServer <control port> <data port>"<<endl;
		exit(0);
	}

    // 绑定并监听控制端口
	int server_fd;
	if((server_fd = server_listen(FTP_SERVER_CPORT)) < 0)
    {
		fprintf(stderr, "%s\n", "Error given port");
		return 0;
	}
    cout<<"FTPServer listening at "<<FTP_SERVER_CPORT<<endl;

	// 阻塞等待连接
	while(1)
    {
		int client_Cfd;
		if((client_Cfd = accept_connection(server_fd)) < 0)
        {
			fprintf(stderr, "%s\n", "Accepting Connections Error");
		}
        else
        {
			int pid = fork();
			if(pid==0)
            {
				//子进程
				doftp(client_Cfd);
				close(client_Cfd);
				return 0;
			}
		}
	}
    return 0;
}

//阻塞等待客户端连接
int accept_connection(int server_fd)
{
	struct sockaddr_storage their_addr; // 连接的地址信息
	char s[INET6_ADDRSTRLEN];
	socklen_t sin_size = sizeof their_addr;

	// 接受连接
	int client_fd = accept(server_fd, (struct sockaddr *)&their_addr, &sin_size);
	if (client_fd == -1)
	{
	  perror("accept");
	  return -1;
	}

	// 打印 ip 地址
	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
	printf("server: got connection from %s\n", s);

	// 设置有效期
	struct timeval tv;
	tv.tv_sec = 120;  
	tv.tv_usec = 0;
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
	return client_fd;
}


//绑定控制端口并监听
int server_listen(const char *port)
{
	// 创建地址结构
	struct addrinfo hints, *res;
	int sock_fd;
	// 配置地址属性
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int addr_status = getaddrinfo(NULL, port, &hints, &res);
	if (addr_status != 0)
	{
	  fprintf(stderr, "Cannot get info\n");
	  return -1;
	}

	// 遍历结果，连通一个即可
	struct addrinfo *p;
	for (p = res; p != NULL; p = p->ai_next)
	{
	  sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	  if (sock_fd < 0)
	  {
	    perror("server: cannot open socket");
	    continue;
	  }

	  int yes = 1;
	  int opt_status = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	  if (opt_status == -1)
	  {
	    perror("server: setsockopt");
	    exit(1);
	  }

	  int bind_status = bind(sock_fd, p->ai_addr, p->ai_addrlen);
	  if (bind_status != 0)
	  {
	    close(sock_fd);
	    perror("server: Cannot bind socket");
	    continue;
	  }

	  break;
	}

	//无法绑定 
	if (p == NULL)
	{
	  fprintf(stderr, "server: failed to bind\n");
	  return -2;
	}

	freeaddrinfo(res);

	//开始监听
	if (listen(sock_fd, 100) == -1) 
	{
	  perror("listen");
	  exit(1);
	}

	return sock_fd;
}

//FTP功能
void doftp(int client_Cfd)
{
	string aloha = "220 FTPServer1.0 is ok\r\n";
	sendInfo(client_Cfd,aloha.c_str(),aloha.size());

	//身份验证
	string username;
	recvsingleline(client_Cfd,username);
	if(username.compare(0,strlen("slownorth"),"slownorth") == 0)
	{
		//
		string res = "331 Please specify password\r\n";
		sendInfo(client_Cfd,res.c_str(),res.size());
		string password;
		recvsingleline(client_Cfd,password);
		res = "230 Login Successfully\r\n";
		sendInfo(client_Cfd,res.c_str(),res.size());
	}
	else
	{
		string res = "430 Invalid Username\r\n";
		sendInfo(client_Cfd,res.c_str(),res.size());
		exit(0);
	}

	int clientDatafd=0,datasocket=0; // clientDatafd 连接客户端数据端口, datasocket 绑定服务器数据端口
	int binarymode = 0; // 二进制模式
	while(1)
	{
		string command;
		recvsingleline(client_Cfd,command);
		if(command.compare(0,strlen("SYST"),"SYST") == 0)
		{
			string res = "215 UNIX Type: L8\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());
		}
		else if(command.compare(0,strlen("PORT"),"PORT") == 0)
		{
			string ipport = command.substr(4); // 获得socket串 ip+port
			ipport = trim(ipport);
			string ip,port;
			parseIpPort(ipport,ip,port); // 将ipport拆成ip和port

			datasocket = bindsocket(FTP_SERVER_DPORT); // 绑定服务器端数据端口
			clientDatafd = make_client_connection_with_sockfd(datasocket,ip.c_str(),port.c_str());
			
			string res = "200 PORT command successful\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());

		}
		else if(command.compare(0,strlen("LIST"),"LIST") == 0)
		{
			if(clientDatafd > 0)
			{
				string res = "150 Here comes the directory listing.\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
				res = execute("ls -l");
				sendInfo(client_Cfd,res.c_str(),res.size());
				close(clientDatafd);
				close(datasocket);
				clientDatafd = 0;
				datasocket  = 0;
				res = "226 Directory send OK.\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
			}
			else
			{
				string res = "425 Use PORT\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
			}
		}
		else if(command.compare(0,strlen("PWD"),"PWD") == 0)
		{
			char cwd[1024];
	      	getcwd(cwd, sizeof(cwd)) ;
	      	string res(cwd);
	      	res = "257 "+res+"\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());	        
		}
		else if(command.compare(0,strlen("CWD"),"CWD") == 0)
		{
			string path = command.substr(3);
			path = trim(path);
			int stat = chdir(path.c_str());
			if(stat==0)
			{
				string res = "250 Directory successfully changed.\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
			}
			else
			{
				string res = "550 Failed to change directory.\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
			}

		}
		else if(command.compare(0,strlen("TYPE I"),"TYPE I") == 0)
		{
			string res = "200 Switching to Binary mode.\r\n";
			binarymode = 1;
			sendInfo(client_Cfd,res.c_str(),res.size());
		}
		else if(command.compare(0,strlen("RETR"),"RETR") == 0)
		{
			if(clientDatafd<=0)
			{
				string res = "425 Use PORT first\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
				continue;
			}

			string path = command.substr(4);
			path = trim(path);

			// 获取文件大小
			struct stat st;
			int statcode = stat(path.c_str(), &st);
			int size = st.st_size;
			if(statcode == -1)
			{
				close(clientDatafd);
				close(datasocket);
				clientDatafd = 0;
				datasocket  = 0;
				string res = "550 "+string(strerror(errno))+"\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
				binarymode=0;
				continue;
			}

			string res = "150 Opening BINARY mode data connection for "+path+"\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());

			FILE* filer;
			filer=fopen(path.c_str(),"rb");
			int len = sendDataBinary(clientDatafd,filer,size);
			cout<<"Bytes Sent : "<<size<<endl;
			fclose(filer);
			close(clientDatafd);
			close(datasocket);
			clientDatafd = 0;
			datasocket  = 0;
			res = "226 Transfer complete.\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());
			binarymode=0;
		}
		else if(command.compare(0,strlen("STOR"),"STOR") == 0)
		{
			if(clientDatafd <= 0)
			{
				string res = "425 Use PORT first\r\n";
				sendInfo(client_Cfd,res.c_str(),res.size());
				continue;
			}

			string path = command.substr(4);
			path = trim(path);

			string res = "150 Ok to send data.\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());

			FILE* filew;

			filew=fopen(path.c_str(),"wb");
			int len = recvDataBinary(clientDatafd,filew);
			cout<<"Bytes Received : "<<len<<endl;
			fclose(filew);

			close(clientDatafd);
			close(datasocket);
			clientDatafd = 0;
			datasocket  = 0;
			res = "226 Transfer complete.\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());
			binarymode=0;
		}
		else if(command.compare(0,strlen("QUIT"),"QUIT") == 0)
		{
			string res = "221 Goodbye.\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());
			close(clientDatafd);
			close(datasocket);
			close(client_Cfd);
			return;
		}
		else
		{
			string res = "500 Unknown command.\r\n";
			sendInfo(client_Cfd,res.c_str(),res.size());
		}
	}
}

//支持ipv4和ipv6
void *get_in_addr (struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) 
	{
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//以二进制格式从缓冲区接收文件，再存放到服务器
int recvDataBinary(int serverfd, FILE* fd)
{
	unsigned char buf[10001];
	int bytesRead=0;
	int len=0;
	while((bytesRead = recv(serverfd,buf,10000,0)) > 0)
	{
		len+=bytesRead;
		fwrite(buf,1,bytesRead,fd);
	}

	if(bytesRead < 0)
	{
		cerr<<"Error Occurred";
		return -1;
	}
	else
	{
		return len;
	}
}

//以二进制格式发送指定文件到缓冲区，再发送客户端
int sendDataBinary(int serverfd, FILE* fd,int size)
{
	unsigned char buf[100001];
	int bytesSent=0;
	while(size > 0)
	{
		int bytesRead = fread(buf,1,100000,fd);
		int stat = sendInfo(serverfd,buf,bytesRead);
		if(stat != 0 )
		{
			cout<<"ERROR IN SENDING"<<endl;
			return -1;
		}
		size = size - bytesRead;
	}
	return 0;	
}

//执行命令，返回结果
string execute(const char* cmd) 
{
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[256];
    std::string result = "";
    while(!feof(pipe)) 
	{
    	if(fgets(buffer, 256, pipe) != NULL)
    		result += buffer;
    }
    pclose(pipe);
    return result;
}


//与客户端建立连接
int make_client_connection_with_sockfd (int sock_fd,const char *host, const char *port)
{
	struct addrinfo hints, *res;

	// 配置地址属性

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo(host, port, &hints, &res);

	// 连接
	int stat = connect(sock_fd, res->ai_addr, res->ai_addrlen);
	if(stat==-1)
	{
		cout<<"Connect Error "<<strerror(errno)<<endl;
		return -1;
	}
  
  return sock_fd;
}


//绑定提供的端口
int bindsocket(const char *port)
{
	//创建地址结构
	struct addrinfo hints, *res;
	int sock_fd;
	//配置地址属性
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int addr_status = getaddrinfo(NULL, port, &hints, &res);
	if (addr_status != 0)
	{
	  fprintf(stderr, "Cannot get info\n");
	  return -1;
	}

	// 循环直到找到第一个能连接的
	struct addrinfo *p;
	for (p = res; p != NULL; p = p->ai_next)
	{
	  // 创建socket
	  sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	  if (sock_fd < 0)
	  {
	    perror("server: cannot open socket");
	    continue;
	  }

	  // 设置socket选项
	  int yes = 1;
	  int opt_status = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	  if (opt_status == -1)
	  {
	    perror("server: setsockopt");
	    exit(1);
	  }

	  // socket与port绑定
	  int bind_status = bind(sock_fd, p->ai_addr, p->ai_addrlen);
	  if (bind_status != 0)
	  {
	    close(sock_fd);
	    perror("server: Cannot bind socket");
	    continue;
	  }
	  break;
	}

	//无法绑定
	if (p == NULL)
	{
	  fprintf(stderr, "server: failed to bind\n");
	  return -2;
	}

	freeaddrinfo(res);

	return sock_fd;
}


//解析ipport,拆成ip和port
int parseIpPort(string& ipport,string& ipstr,string& portstr)
{
	int cnt=0,pos;
	string ip = ipport;
	for (int i = 0; i < ipport.size(); i++)
	{
		if(ip[i]==',')
		{
			ip[i] = '.';
			cnt++;
			if(cnt==4)
			{
				pos = i;
				break;
			}
		}
	}
	
	if(cnt!=4) return -1;
	ipstr = ip.substr(0,pos);
	string port = ip.substr(pos+1);
	int val=0;
	int i=0;

	while(i<port.size())
	{
		if(port[i] == ',') break;
		val = 10*val +  (port[i] - '0');
		i++;
	}
	val = 256*val;
	int portval = val;
	val = 0;
	i++;
	while(i<port.size())
	{
		val = 10*val + (port[i] - '0');
		i++;
	}
	portval = portval + val;

	stringstream ss;
	ss<<portval;
	portstr = ss.str();

	return 0;
}

//发送消息
int sendInfo(int socketfd,const void* buffer,size_t length)
{
	size_t i = 0;
	while(i < length)
	{
		int byteSent = send(socketfd,buffer,length - i,MSG_NOSIGNAL);
		if(byteSent == -1)
		{
			return errno;
		}
		else
		{
			i += byteSent;
		}
	}
	return 0;
} 

//读一行
int recvsingleline(int serverfd,string& info)
{
	char buffer[501];
	info = remember;
	int byteRead = recv(serverfd,buffer,500,0);
	while(byteRead > 0)
	{
		info += string(buffer,buffer+byteRead);
		int pos = info.find("\r\n");
		if(pos!=string::npos)
		{
			//一行结束
			remember = info.substr(pos+2);
			info = info.substr(0,pos+2);
			break;
		}
		byteRead = recv(serverfd,buffer,500,0);
	}
	if(byteRead < 0)
	{
		cerr<<"Error Occurred";
		return -1;
	}
	else
	{
		return 0;
	}
}