/*
 * Solution to Assignment 4
 *
 * Thread Pooling & Managment, Concurrency and Synchronization, Replication.
 */

#include <limits.h>
#include <fcntl.h>
#include "shfd.h"

#define verbose			1
#define LOG_FILE                "/var/log/assign4.log"

struct g_stat g_stat;
int t_incr; //from command line
int t_max; //from command line
int repl_port; //from command line
pthread_mutex_t logging_lock; //mutex for looging file

unsigned int g_count;

unsigned int g_txn_id;

struct repl_peer *repl_peers_list_first;
struct repl_peer *repl_peers_list_last;

struct repl_req_hdr {
	int command;
           #define CMD_FOPEN 		1
           #define CMD_FWRITE		2
           #define CMD_FSEEK 		3
           #define CMD_FREAD 		4
	int type;
           #define TYPE_REQ  		0
           #define TYPE_RES  		1
	char ts[32];
	int txn_id;
};

struct repl_req_fopen {
	struct repl_req_hdr hdr;
	char filename[256];
};

struct repl_req_fwrite {
	struct repl_req_hdr hdr;
	char filename[256];
	char bytes[256];
};

struct repl_req_fseek {
	struct repl_req_hdr hdr;
	char filename[256];
	int offset;
};

struct repl_req_fread {
        struct repl_req_hdr hdr;
        char filename[256];
        int length;
};

struct repl_resp_fread {
        struct repl_req_hdr hdr;
        int result;
};

void file_client_fopen(struct repl_req_fopen *req);
void file_client_fwrite(struct repl_req_fwrite *req);
void file_client_fseek(struct repl_req_fseek *req);

void log_print(char *msg)
{
        FILE* log_fp;

        if(verbose)
        {
       		 pthread_mutex_lock(&logging_lock);
                 if((log_fp = fopen(LOG_FILE, "a")) == NULL)
                 {
                   printf("Cannot open file: %s\n", LOG_FILE);
       		   pthread_mutex_unlock(&logging_lock);
                   return;
                 }
                 fprintf(log_fp, msg);
                 fclose(log_fp);
       		 pthread_mutex_unlock(&logging_lock);
        }

}

void log_print_init()
{
        FILE* log_fp;

        if(verbose)
        {
                 pthread_mutex_lock(&logging_lock);
                 if((log_fp = fopen(LOG_FILE, "w")) == NULL)
                 {
                   printf("Cannot open file: %s\n", LOG_FILE);
                   pthread_mutex_unlock(&logging_lock);
                   return;
                 }
                 fprintf(log_fp, "******************************************************************************************\n");
                 fprintf(log_fp, "*                      Started File Server and Sh server                                 *\n");
                 fprintf(log_fp, "*                                  Welcome                                               *\n");
                 fprintf(log_fp, "******************************************************************************************\n");
                 fclose(log_fp);
                 pthread_mutex_unlock(&logging_lock);
        }

}

void dump_in_assign_logfile(char *msg)
{
	log_print(msg);
}

void set_defaults()
{
	t_incr = 4;
	t_max = 10;
	repl_port = 7878;
	g_count = 0;
	g_txn_id = 1;
	repl_peers_list_first = NULL;
	repl_peers_list_last = NULL;
	g_stat.total_thread_count = 0;
	g_stat.active_thread_count = 0;
	g_stat.num_thread_to_del = 0;
}

void set_t_incr(int value)
{
	t_incr = value;
}	

void set_t_max(int value)
{
	char msg[MAX_LEN];  // log_print string
	t_max = value;
	snprintf(msg, MAX_LEN, "%s: t_max: %d\n", __FILE__, value);
	log_print(msg);
}	

void set_repl_port(int port)
{
	repl_port = port;
}	

char * get_filename_from_fd(int idx)
{
	char filePath[1024];
	//if (fcntl(idx, F_GETPATH, filePath) != -1)
	{
		printf("file: %s\n", filePath);
	}
}

/*************************************************************************/
/*  Point 1. a. sh server to accept connection from local machine only.  */
/*              Change INADDR_ANY to INADDR_LOOPBACK                     */
/*              tcp-utils.cc line 108                                    */
/*           b. sequential execution of request.                         */
/*              Use pthread_join after processing request.               */
/*************************************************************************/


/*************************************************************************/
/*  Point 2. Concurrency management                                      */
/*           a. create thread pool of t_incr threads in bunch unless     */
/*              t_max.                                                   */
/*           b. periodical cleanup if (total_thread_count) > t_incr and  */
/*              (total_thread_count -t_incr - 1) < active_thread_count   */
/*************************************************************************/
int create_t_pool()
{
   	pthread_t tt;
	pthread_attr_t ta;
	pthread_attr_init(&ta);
	pthread_attr_setdetachstate(&ta,PTHREAD_CREATE_DETACHED);
	struct t_pool *t_info;
	int ii, ii_temp;
	char msg[MAX_LEN];  // log_print string

        pthread_mutex_lock(&(g_stat.lock));
	snprintf(msg, MAX_LEN, "%s: Current stat:\t t_incr: %d\t t_max: %d\t Total: %d\t Active: %d\n", __FILE__, t_incr, t_max, g_stat.total_thread_count, g_stat.active_thread_count);
	log_print(msg);

	if(t_incr <= t_max - g_stat.total_thread_count)
	{
		ii = t_incr;
	}	    
	else 
	{
		ii = t_max - g_stat.total_thread_count;
	}	    
        pthread_mutex_unlock(&(g_stat.lock));

	if(ii == 0)
	{
		snprintf(msg, MAX_LEN, "%s: t_max limit: %d reached\n", __FILE__, t_max);
		log_print(msg);
	}

	ii_temp = ii; //required to logging
	snprintf(msg, MAX_LEN, "%s: Creating %d thread\n", __FILE__, ii);
	log_print(msg);

	while(ii) 
	{
		t_info = alloc_t_info_node();

		if(t_info == NULL)
		{
			snprintf(msg, MAX_LEN, "%s: Memory Alloc failure:%s\n", __FILE__, strerror(errno));
			log_print(msg);
		}


		if ( pthread_create(&tt, &ta, (void* (*) (void*))work_function, t_info) != 0 ) 
		{
			snprintf(msg, MAX_LEN, "%s: pthread_create failed: %s\n", __FILE__, strerror(errno));
			log_print(msg);
			return 1;
		}

		t_info->tt = tt;

        	pthread_mutex_lock(&(g_stat.lock));
		g_stat.total_thread_count++;
		add_to_t_pool(t_info);
        	pthread_mutex_unlock(&(g_stat.lock));
	
		ii--;
	}

	if(g_stat.total_thread_count > t_incr + t_max)
	{
		snprintf(msg, MAX_LEN, "%s: thread_count-consistency check failed:%s\n", __FILE__, strerror(errno));
		log_print(msg);
	}

	snprintf(msg, MAX_LEN, "%s: Added %d Threads to Pool(Total: %d): \n", __FILE__, ii_temp, g_stat.total_thread_count);
	log_print(msg);

	return 0;
}

struct t_pool* alloc_t_info_node()
{
        struct t_pool *tmp = NULL;;
        char msg[MAX_LEN];  // log_print string

        tmp = (struct t_pool*)malloc(sizeof(struct t_pool));
        if(tmp == NULL)
        {
                snprintf(msg, MAX_LEN, "%s: malloc failed: %s\n", __FILE__, strerror(errno));
                log_print(msg);
		return NULL;
        }
	memset(tmp, 0, sizeof(struct t_pool));
	g_count++;
	tmp->id = g_count;
	tmp->next = NULL;
        return tmp;
}

int add_to_t_pool(struct t_pool *tmp)
{
        tmp->flag = 0;
        tmp->clnt = NULL;
        tmp->stop = 0;

	if(g_stat.t_pool_first == NULL)
	{
		g_stat.t_pool_first = tmp;
		g_stat.t_pool_last = tmp;
	}
	else
	{
		g_stat.t_pool_last->next = tmp;
	        g_stat.t_pool_last = tmp;

	}

        return 0;
}

int del_from_t_pool(struct t_pool *thread)
{
        struct t_pool *prev = NULL;
        struct t_pool *tmp = g_stat.t_pool_first;
        char msg[MAX_LEN];  // log_print string

        snprintf(msg, MAX_LEN, "%s: Node to delete: %lu (first: %lu)\n", __FILE__, thread->tt, tmp->tt);
        log_print(msg);

        /* if it is head */
        if((tmp != NULL ) && (tmp->tt == thread->tt))
        {
                g_stat.t_pool_first = tmp->next;
                free(tmp);
        	g_stat.total_thread_count--;
                return 0;
        }
        else
        {
                while(tmp != NULL && tmp->tt != thread->tt)
                {
                        prev = tmp;
                        tmp = tmp->next;
                }
        }

        if(tmp == NULL)
        {
                snprintf(msg, MAX_LEN, "%s: Node not found %s\n", __FILE__, strerror(errno));
                log_print(msg);
                return 1;
        }

        prev->next = tmp->next;
        g_stat.total_thread_count--;

        free(tmp);
        return 0;
}

struct t_pool* get_idle_thread_from_t_pool()
{
        struct t_pool *tmp = NULL;
        char msg[MAX_LEN];  // log_print string

        /*scan list and find first with flag ==0 */

       	pthread_mutex_lock(&(g_stat.lock));
	tmp = g_stat.t_pool_first;
        while(tmp)
        {
                snprintf(msg, MAX_LEN, "%s: Checking Node: %lu (%d): %d\n", __FILE__, tmp->tt, tmp->id, tmp->flag);
                log_print(msg);
                if(tmp->flag == 0)
                {
			tmp->flag = 1;
                        break;
                }

                tmp = tmp->next;
        }

       	pthread_mutex_unlock(&(g_stat.lock));

	if(tmp != NULL)
	{
		snprintf(msg, MAX_LEN, "%s: Return Node: %lu\n", __FILE__, tmp->tt);
		log_print(msg);
	}
	else
	{
		snprintf(msg, MAX_LEN, "%s: No more threads\n", __FILE__);
		log_print(msg);
	}
        return tmp;
}

int cleanup_thread_pool(struct t_pool *t_info)
{
    if((g_stat.total_thread_count > t_incr) && (g_stat.active_thread_count < g_stat.total_thread_count - t_incr - 1))
    {
        g_stat.total_thread_count--;

	t_info->stop = 1;

    }

    return 0;
}

void* work_function(struct t_pool *t_info)
{
	char msg[MAX_LEN];  // log_print string
	struct timespec time;
	timespec_get(&time, TIME_UTC);
	time.tv_sec += 5;


	while (1) 
	{
                snprintf(msg, MAX_LEN, "%s: Thread %lu (%d)\n", __FILE__, t_info->tt, t_info->id);
                log_print(msg);

        	pthread_mutex_lock(&(t_info->lock));
		while (t_info->clnt == NULL && !t_info->stop) {
			//pthread_cond_wait(&(t_info->cond), &(t_info->lock));
			pthread_cond_timedwait(&(t_info->cond), &(t_info->lock), &time);
			time.tv_sec += 5;
                	snprintf(msg, MAX_LEN, "Timedwait over\n");
	                log_print(msg);

	        	pthread_mutex_lock(&(g_stat.lock));
			cleanup_thread_pool(t_info);
                	snprintf(msg, MAX_LEN, "%s: Total: %d: Active %d\n", __FILE__, g_stat.total_thread_count, g_stat.active_thread_count);
	                log_print(msg);
        		pthread_mutex_unlock(&(g_stat.lock));

		}

               	snprintf(msg, MAX_LEN, "KiilAfter: Timedwait over\n");
                log_print(msg);

		
        	pthread_mutex_lock(&(g_stat.lock));
		//cleanup_thread_pool(t_info);
		if (t_info->stop)
		{
        	        snprintf(msg, MAX_LEN, "%s: Thread %lu is stopped now\n", __FILE__, t_info->tt);
	                log_print(msg);
        		del_from_t_pool(t_info);
        		pthread_mutex_unlock(&(g_stat.lock));
			break;
		}

		if(t_info->clnt == NULL)
		{
        		pthread_mutex_unlock(&(g_stat.lock));
			continue;
		}

        	pthread_mutex_unlock(&(g_stat.lock));

                snprintf(msg, MAX_LEN, "%s: Thread %lu (%d) is Active now\n", __FILE__, t_info->tt, t_info->id);
                log_print(msg);

		g_stat.active_thread_count++;
        	pthread_mutex_unlock(&(t_info->lock));

		file_client(t_info->clnt);

        	pthread_mutex_lock(&(g_stat.lock));
		t_info->clnt = NULL;
		t_info->flag = 0;
		g_stat.active_thread_count--;
        	pthread_mutex_unlock(&(g_stat.lock));

                snprintf(msg, MAX_LEN, "%s: Thread %lu is Idle now\n", __FILE__, t_info->tt);
                log_print(msg);

	}		

	return NULL;
}

void activate_thread(t_pool *t_info)
{
        pthread_mutex_lock(&(t_info->lock));
	pthread_cond_signal(&(t_info->cond));
        pthread_mutex_unlock(&(t_info->lock));
}

/*************************************************************************/
/*  Point 3. Dynamic reconfiguration                                     */
/*           a. SIGQUIT: gracefull_shutdown                              */
/*           b. SIGHUP: dynamic_reconfiguration                          */
/*************************************************************************/
void system_cleanup()
{
        struct t_pool *tmp = g_stat.t_pool_first;
	char msg[MAX_LEN];  // log_print string

	snprintf(msg, MAX_LEN, "%s: System cleanup\n", __FILE__);
	log_print(msg);

       	pthread_mutex_lock(&(g_stat.lock));

        while(tmp)
        {
                tmp->stop = 1;
		
		if(tmp->flag == 0) //stop all idle threads
		{
			activate_thread(tmp); //wakeup so that it comes out of wait
		}
		else // stop active thread
		{
			tmp->clnt->stop = 1; //will be checked from inside file_client
		}

                tmp = tmp->next;
        }

       	pthread_mutex_unlock(&(g_stat.lock));
	sleep(3);
	
	//while(g_stat.total_thread_count != 0) {
	//	;
	//}

       	pthread_mutex_lock(&(g_stat.lock));
	g_stat.total_thread_count = 0;
	g_stat.active_thread_count = 0;
	g_stat.t_pool_first = NULL;
	g_stat.t_pool_last = NULL;
       	pthread_mutex_unlock(&(g_stat.lock));
}	

void graceful_shutdown(int sig)
{
	char msg[MAX_LEN];  // log_print string

	snprintf(msg, MAX_LEN, "%s: Shuting down gracefully...\n", __FILE__);
	log_print(msg);

	system_cleanup();
	
	exit(0);
}

void dynamic_reconfiguration(int sig)
{
	char msg[MAX_LEN];  // log_print string

	snprintf(msg, MAX_LEN, "%s: Dynamic Reconfiguration\n", __FILE__);
	log_print(msg);

	system_cleanup();

	//preallocate t_incr threads
	create_t_pool();
}	


/*************************************************************************/
/*  Point 4. Replication                                                 */
/*           a. A Replication server to listen request from others       */
/*           b. To replicate the request to other peers                  */
/*                                                                       */
/*  Application Protocol for Replication based on one Phase Commit       */
/*  Protocol:                                                            */
/*                                                                       */
/*  Replication request/response will have following structure:          */
/*                                                                       */
/*  HEADER {Command-Code[int], Type[Boolean], Txn-Id, Ts} {DATA}         */
/*                                                                       */
/*-----------------------------------------------------------------------*/
/*  HEADER OF REQUEST AND RESPONSE MESSAGES                              */
/*-----------------------------------------------------------------------*/
/*  Command-Code: One of the following command:                          */
/*           #define CMD_FOPEN 		1                                */
/*           #define CMD_FSEEK 		2                                */
/*           #define CMD_FREAD 		3                                */
/*           #define CMD_FWRITE		4                                */
/*                                                                       */
/*  Type: It used to identify a request or response                      */
/*           #define TYPE_REQ  		0                                */
/*           #define TYPE_RES  		1                                */
/*                                                                       */
/*  Txn-Id: Transaction Id to uniquely identify a request-response       */
/*          transaction.                                                 */
/*                                                                       */
/*  Ts: Timestamp                                                        */
/*                                                                       */
/*  Based on the command-code and type request or response will have     */
/*  will have data as follows:                                           */
/*                                                                       */
/*-----------------------------------------------------------------------*/
/* PAYLOAD FOR REQUEST                                                   */
/*-----------------------------------------------------------------------*/
/*   1. FWRITE: Id[int], Bytes[int]                                      */
/*   2. FSEEK: Id[int], Offset[int]                                      */
/*   3. FREAD: Id[int], Length[int]                                      */
/*                                                                       */
/*-----------------------------------------------------------------------*/
/* PAYLOAD FOR RESPONSE                                                  */
/*-----------------------------------------------------------------------*/
/*   1. FWRITE: Result-Code[int]                                         */
/*   2. FSEEK: Result-Code[int]                                          */
/*   3. FREAD: Result-Code[int]                                          */
/*                                                                       */
/*   Result-Code will have following values:                             */
/*           #define RESULT_SYNC_FAIL           1	                 */
/*           #define RESULT_SYNC_SUCC           2	                 */
/*                                                                       */
/*                                                                       */
/*                                                                       */
/*************************************************************************/
void* start_repl_server(long int replsock)
{
    int ssock;                      // slave sockets
    struct sockaddr_in client_addr; // the address of the client...
    socklen_t client_addr_len = sizeof(client_addr); // ... and its length
    // Setting up the thread creation:
    pthread_t tt;
    pthread_attr_t ta;
    pthread_attr_init(&ta);
    pthread_attr_setdetachstate(&ta,PTHREAD_CREATE_DETACHED);

    char msg[MAX_LEN];  // logger string

    printf("File Replication server up and listening on port %d\n", repl_port);
    while (1) {
        // Accept connection:
        ssock = accept(replsock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (ssock < 0) {
            if (errno == EINTR) continue;
            snprintf(msg, MAX_LEN, "%s: file server accept: %s\n", __FILE__, strerror(errno));
            logger(msg);
            snprintf(msg, MAX_LEN, "%s: the file server died.\n", __FILE__);
            logger(msg);
            return 0;
        }

        // assemble client coordinates (communication socket + IP)
        client_t* clnt = new client_t;
        clnt -> sd = ssock;
        ip_to_dotted(client_addr.sin_addr.s_addr, clnt -> ip);

        // create a new thread for the incoming client:
        if ( pthread_create(&tt, &ta, (void* (*) (void*))replication_server, (void*)clnt) != 0 ) {
            snprintf(msg, MAX_LEN, "%s: file server pthread_create: %s\n", __FILE__, strerror(errno));
            logger(msg);
            snprintf(msg, MAX_LEN, "%s: the file replication server died.\n", __FILE__);
            logger(msg);
            return 0;
        }
        // go back and block on accept.
    }
    return 0;   // will never reach this anyway...
}

void* replication_server(void* client)
{  
	char buff[1024];
	int n;
	struct repl_req_hdr *hdr;
	struct client_t *clnt = (struct client_t *)client;
	int sd = clnt->sd;

	printf("Connected to Replication peer at: %s\n", clnt->ip);

	while( (n = recv(sd, buff, 1024, 0)) > 0)
	{

		hdr = (struct repl_req_hdr *)buff;

		printf("Request Received(%d): command: %d type: %d ts: %s txn-id: %d\n", n, hdr->command, hdr->type, hdr->ts, hdr->txn_id);

		switch(hdr->command)
		{
			case CMD_FOPEN:
				printf("FOPEN request\n");
				struct repl_req_fopen *req1;
				req1 = (struct repl_req_fopen *)buff;
				file_client_fopen(req1);
				break;
			case CMD_FWRITE:
				printf("FWRITE request\n");
				struct repl_req_fwrite *req2;
				req2 = (struct repl_req_fwrite *)buff;
				file_client_fwrite(req2);
				break;
			case CMD_FSEEK:
				printf("FSEEK request\n");
				struct repl_req_fseek *req3;
				req3 = (struct repl_req_fseek *)buff;
				file_client_fseek(req3);
				break;
			case CMD_FREAD:
                                printf("FREAD request\n");
                                struct repl_req_fread *req4;
                                req4 = (struct repl_req_fread *)buff;
                                int read_bytes = file_client_fread(req4);

                                char buf[128];
                                struct repl_resp_fread *resp = (struct repl_resp_fread *)buff;
                                resp->result = read_bytes;
                                send(sd, buf, sizeof(struct repl_resp_fread), 0);
                                break;
		}
	}
}

void get_timestamp(char *ts)
{
	time_t ltime;
	struct tm result;

	ltime = time(NULL);
	localtime_r(&ltime, &result);
	asctime_r(&result, ts);
}

void add_to_repl_peer_list(struct repl_peer *peer)
{
	if(repl_peers_list_first == NULL)
	{
		printf("Add repl peer\n");
		repl_peers_list_first = peer;
		repl_peers_list_last = peer;
	}
	else
	{
		repl_peers_list_last->next = peer;
		repl_peers_list_last = peer;
	}
}

void send_repl_req(int cmd, char *filename, int offlen, char *bytes)
{
	char buf[1024];
	int buf_len = 256;
	char ts[32];
	void *ptr = (void *)&buf;
	struct repl_req_fopen *req1 = (struct repl_req_fopen *)buf;	
	struct repl_req_fwrite *req2 = (struct repl_req_fwrite *)buf;	
	struct repl_req_fseek *req3 = (struct repl_req_fseek *)buf;	
	struct repl_req_fread *req4 = (struct repl_req_fread *)buf;	
	struct repl_req_hdr *hdr = (struct repl_req_hdr *)buf;
	
	memset(buf, 0, 1024);

	switch(cmd) 
	{
		case CMD_FOPEN:
			printf("Build peer request:FOPEN-> filename: %s\n", filename);
			strcpy(req1->filename, filename);
			buf_len = sizeof(struct repl_req_fopen);
			break;
		case CMD_FWRITE:
			printf("Build peer request:FWRITE-> filename: %s; bytes: %s\n", filename, bytes);
			strcpy(req2->filename, filename);
			strcpy(req2->bytes, bytes);
			buf_len = sizeof(struct repl_req_fwrite);
			break;
		case CMD_FSEEK:
			printf("Build peer request:FSEEK-> filename: %s; offset: %d\n", filename, offlen);
			strcpy(req3->filename, filename);
			req3->offset = offlen;
			buf_len = sizeof(struct repl_req_fseek);
			break;
		case CMD_FREAD:
			printf("Build peer request:FREAD-> filename: %s; length: %d\n", filename, offlen);
			strcpy(req4->filename, filename);
			req4->length = offlen;
			buf_len = sizeof(struct repl_req_fread);
			break;
	}

	get_timestamp(ts);

	hdr->command = cmd;
	hdr->type = 1;
	strncpy(hdr->ts, ts, 24);
	hdr->ts[24] = '\0';
	hdr->txn_id = g_txn_id++;


	struct repl_peer *peer = repl_peers_list_first;
	if(peer == NULL)
		printf("No replication peer to send\n");
		
	while(peer)
	{
		int n = send(peer->sd, buf, buf_len, 0);
		printf("Sent %d bytes(should be %d) to peer %s:%d\n", n, buf_len, peer->ip, peer->port);
		
		if(cmd == CMD_FREAD) {
                        char resp[128];
                        int len = 128;
                        int nn = 0;

                        if((nn = recv(peer->sd, resp, len, 0)) > 0)
                        {
                                struct repl_resp_fread *resp1 = (struct repl_resp_fread *)resp;
                                peer->reply = resp1->result;
				printf("Peer: Recv %d bytes from peer %s:%d\n", peer->reply, peer->ip, peer->port);
                        }
                }
		peer = peer->next;
	}
}

void file_client_fopen(struct repl_req_fopen *req)
{
	int n;
	bool* opened_fds = new bool[flocks_size];
    	char msg[MAX_LEN];  // logger string

	printf("FOPEN: File: %s\n", req->filename);

	for (size_t i = 0; i < flocks_size; i++)
        	opened_fds[i] = false;

	// open the file to obtain its inode:
	int fd = open(req->filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

	// Note: we do not react to errors at this time since we will handle any
	// possible error when opening the file for real

	int inode = -1;
	struct stat fs;
	int ret = fstat (fd, &fs);
	if (ret >= 0)
		inode = fs.st_ino;
	close(fd);

        // Look for a file with the same inode in flocks[]:
	fd = -1;
	for (size_t i = 0; i < flocks_size; i++) {
		if (flocks[i] != 0 && (int)flocks[i] -> inode == inode) {
	        	fd = i;
			pthread_mutex_lock(&flocks[fd] -> mutex);
			if (! opened_fds[fd])  // file already opened by the same client?
				flocks[fd] -> owners ++;
			pthread_mutex_unlock(&flocks[fd] -> mutex);
			opened_fds[fd] = true;
			break;
		}
	}

	if (fd >= 0) { // already opened
		snprintf(msg, MAX_LEN,
                             "ERR %d file already opened, please use the supplied identifier", fd);
	}
   	else { // we open the file anew
 		fd = file_init(req->filename);
		if (fd < 0)
			snprintf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
		else {
			snprintf(msg, MAX_LEN, "OK %d file opened, please use supplied identifier", fd);
                        opened_fds[fd] = true;
        	}
	}
}

void file_client_fwrite(struct repl_req_fwrite *req)
{
    	char msg[MAX_LEN];  // logger string

	printf("FWRITE: File: %s; bytes: %s\n", req->filename, req->bytes);

	int fd = file_init(req->filename);
	if (fd < 0)
		printf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
	else {
		printf(msg, MAX_LEN, "OK %d file opened, please use supplied identifier", fd);
	}
	      	
	int result = write_excl(fd, req->bytes, strlen(req->bytes));
        if (result == err_nofile)
		snprintf(msg, MAX_LEN, "FAIL %d bad file descriptor", EBADF);
	else if (result < 0) {
		snprintf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
	}
	else {
		snprintf(msg, MAX_LEN, "OK 0 wrote %d bytes", result);
	}

}

void file_client_fseek(struct repl_req_fseek *req)
{
    	char msg[MAX_LEN];  // logger string

	printf("FWRITE: File: %s; Offset: %d\n", req->filename, req->offset);

	int fd = file_init(req->filename);
	if (fd < 0)
		printf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
	else {
		printf(msg, MAX_LEN, "OK %d file opened, please use supplied identifier", fd);
	}
	      	
	int result = seek_excl(fd, req->offset);
	if (result == err_nofile)
		snprintf(msg, MAX_LEN, "FAIL %d bad file descriptor", EBADF);
	else if (result < 0) {
		snprintf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
	}
	else {
		snprintf(msg, MAX_LEN, "OK 0 offset is now %d", result);
	}

}	

int file_client_fread(struct repl_req_fread *req)
{
        int n;
        char msg[MAX_LEN];  // logger string

	printf("FREAD: File: %s; Offset: %d\n", req->filename, req->length);

	int fd = file_init(req->filename);
	if (fd < 0) {
		snprintf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
		return -1;
	}
	else {
		snprintf(msg, MAX_LEN, "OK %d file opened, please use supplied identifier", fd);

		char read_buff[req->length + 1];
		int result = read_excl(fd, read_buff, req->length);
		// ASSUMPTION: we never read null bytes from the file.
		if (result == err_nofile) {
			snprintf(msg, MAX_LEN, "FAIL %d bad file descriptor", EBADF);
			return 0;
		}
		else if (result < 0) {
			snprintf(msg, MAX_LEN, "FAIL %d %s", errno, strerror(errno));
			return -1;
		}
		else {
			read_buff[result] = '\0';
			// we may need to allocate a larger buffer
			// besides the message, we give 40 characters to OK + number of bytes read.
			snprintf(msg, MAX_LEN, "OK %d %s", result, read_buff);
			return result;
		}

	}
}

void* peer_connect(void* data)
{  

	struct repl_peer *peer = NULL;
	while(1)
	{
		peer = repl_peers_list_first;
        	if(peer == NULL)
                	printf("No replication peer to send\n");

	        while(peer)
        	{
			if(peer->sd < 0)
			{	
				peer->sd = connectbyportint(peer->ip, peer->port);
				printf("Connected %s:%d(%d)\n", peer->ip, peer->port, peer->sd);
			}
			peer = peer->next;
		}
		sleep(4);
	}
}
