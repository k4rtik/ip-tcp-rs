#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "parselinks.h"
#include "list.h"

int parse_double(FILE *f, char phys_host[HOST_MAX_LENGTH], uint16_t *phys_port)
{
    char phys_host_in[256];
    int phys_port_in;
    int i;

    int ret = fscanf(f, "%255[^:]:%d", phys_host_in, &phys_port_in);
    if (ret != 2) {
        return -1;
    }

    (void)strcpy(phys_host, phys_host_in);

    if (phys_port_in < 0x0000 || phys_port_in > 0xffff) {
        return -1;
    }
    *phys_port = phys_port_in;
    return 0;
}

int parse_quad(FILE *f, char phys_host[HOST_MAX_LENGTH], uint16_t *phys_port,
                 struct in_addr *loc_virt_ip, struct in_addr *rem_virt_ip)
{
    char phys_host_in[256];
    int phys_port_in;
    int loc_virt_ip_in[4];
    int rem_virt_ip_in[4];
    int i;

    int ret = fscanf(f, "%255[^:]:%d %d.%d.%d.%d %d.%d.%d.%d", phys_host_in, &phys_port_in,
                     loc_virt_ip_in, loc_virt_ip_in+1, loc_virt_ip_in+2, loc_virt_ip_in+3,
                     rem_virt_ip_in, rem_virt_ip_in+1, rem_virt_ip_in+2, rem_virt_ip_in+3);
    if (ret != 10) {
        return -1;
    }

    (void)strcpy(phys_host, phys_host_in);

    if (phys_port_in < 0x0000 || phys_port_in > 0xffff) {
        return -1;
    }
    *phys_port = phys_port_in;

    loc_virt_ip->s_addr = 0;
    for (i=0; i<4; i++){
        if (loc_virt_ip_in[i] < 0 || loc_virt_ip_in[i] > 255) {
            return -1;
        }
        loc_virt_ip->s_addr |= loc_virt_ip_in[i] << (24-i*8);
    }

    rem_virt_ip->s_addr = 0;
    for (i=0; i<4; i++){
        if (rem_virt_ip_in[i] < 0 || rem_virt_ip_in[i] > 255) {
            return -1;
        }
        rem_virt_ip->s_addr |= rem_virt_ip_in[i] << (24-i*8);
    }
    return 0;
}

int parse_line(FILE *f, link_t *link)
{
    return parse_quad(f, link->remote_phys_host, &link->remote_phys_port,
                        &link->local_virt_ip, &link->remote_virt_ip);
}

lnx_t *parse_links(char *filename)
{
    FILE *f;
    lnx_t lnx;
    link_t *line;
    f = fopen(filename,"r");
  
    if (f == NULL){
        return NULL;
    }

    // Initialize the list of links.
    list_init(&lnx.links);

    if (feof(f)) {
        return NULL;
    }

    if (parse_double(f, lnx.local_phys_host, &lnx.local_phys_port)) {
        return NULL;
    }

    while (!feof(f)) {
        line = (link_t *)malloc(sizeof(link_t));
        if (line == NULL) {
            fprintf(stderr, "parse_links: out of memory\n");
            exit(1);
        }
	
        if (parse_line(f, line) == -1) {
            free(line);
            lnx_t *ret = malloc(sizeof(lnx_t));
            if (ret == NULL) {
                fprintf(stderr, "parse_links: out of memory\n");
                exit(1);
            }
            *ret = lnx;
            return ret;
        }
        list_append(lnx.links, (void *)(line));
    }

    fclose(f);
    lnx_t *ret = malloc(sizeof(lnx_t));
    if (ret == NULL) {
        fprintf(stderr, "parse_links: out of memory\n");
        exit(1);
    }
    *ret = lnx;
    return ret;
}

void free_links(list_t *links)
{
    node_t *curr;
	for (curr = links->head; curr != NULL; curr = curr->next) {
		free (curr->data);
	}
	list_free(&links);
}
