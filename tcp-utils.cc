#include "tcp-utils.h"
#include "stdio.h"

int connectbyport(const char* host, const char* port) {
    return connectbyportint(host,(unsigned short)atoi(port));
} 

int connectbyservice(const char* host, const char* service){
    struct servent* sinfo = getservbyname(service,"tcp");  // service info
    if (sinfo == NULL)
        return err_proto;
    return connectbyportint(host,(unsigned short)sinfo->s_port);
}

int connectbyportint(const char* host, unsigned short port) {
    struct hostent *hinfo;         // host information
    struct sockaddr_in sin;        // address to connect to
    int	sd;                      // socket description to be returned
    const int type = SOCK_STREAM;  // TCP connection

    memset(&sin, 0, sizeof(sin));  // needed for correct padding... (?)
    sin.sin_family = AF_INET;

    // host name to IP address
    hinfo = gethostbyname(host);
    if (hinfo == NULL)
        return err_host;
    memcpy(&sin.sin_addr, hinfo->h_addr, hinfo->h_length);

    sin.sin_port = (unsigned short)htons(port);

    // allocate socket:
    sd = socket(PF_INET, type, 0);
    if ( sd < 0 )
        return err_sock;

    // connect socket:
    int rc = connect(sd, (struct sockaddr *)&sin, sizeof(sin));
    if (rc < 0) {
        close(sd);
        printf("connect returned: %d\n", rc);
        return err_connect;
    }
        printf("connect returned: %d\n", rc);

    // done!
    return sd;
}

int passivesocketstr(const char* port, int backlog) {
    return passivesocket((unsigned short)atoi(port), backlog);
}

int passivesocketserv(const char* service, int backlog) {
    struct servent* sinfo = getservbyname(service,"tcp");  // service info
    if (sinfo == NULL)
        return err_proto;
    return passivesocket((unsigned short)sinfo->s_port, backlog);
}

/*
 * Helper function, contains the common code for passivesocket and
 * controlsocket (which are identical except for the IP address they
 * bind to).
 */
int passivesockaux(unsigned short port, int backlog, unsigned long int ip_addr) {
    struct sockaddr_in sin;        // address to connect to
    int	sd;                        // socket description to be returned
    const int type = SOCK_STREAM;  // TCP connection

    memset(&sin, 0, sizeof(sin));  // needed for correct padding... (?)
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(ip_addr);

    sin.sin_port = (unsigned short)htons(port);

    // allocate socket:
    sd = socket(PF_INET, type, 0);
    if ( sd < 0 )
        return err_sock;

    // reusable socket
    int reuse = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // bind socket:
    if ( bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ) {
        close(sd);
        return err_bind;
    }
    // socket is listening:
    if ( listen(sd, backlog) < 0 ) {
        close(sd);
        return err_listen;
    }

    // done!
    return sd;
}

int passivesocket_lcl(unsigned short port, int backlog) {
    return passivesockaux(port, backlog, INADDR_LOOPBACK);
}
int passivesocket(unsigned short port, int backlog) {
    return passivesockaux(port, backlog, INADDR_ANY);
}

int controlsocket(unsigned short port, int backlog) {
    return passivesockaux(port, backlog, INADDR_LOOPBACK);
}

int recv_nonblock (int sd, char* buf, size_t max, int timeout) {
    struct pollfd pollrec;
    pollrec.fd = sd;
    pollrec.events = POLLIN;
  
    int polled = poll(&pollrec,1,timeout);

    if (polled == 0)
        return recv_nodata;
    if (polled == -1)
        return -1;

    return recv(sd,buf,max,0);
}

int readline(const int fd, char* buf, const size_t max) {
    size_t i;
    int begin = 1;

    for (i = 0; i < max; i++) {
        char tmp;
        int what = read(fd,&tmp,1);
        if (what == -1)
            return -1;
        if (begin) {
            if (what == 0)
                return recv_nodata;
            begin = 0;
        }
        if (what == 0 || tmp == '\n') {
            buf[i] = '\0';
            return i;
        }
        buf[i] = tmp;
    }
    buf[i] = '\0';
    return i;
}
