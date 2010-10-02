/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: list-queue.h,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 

/* Specialized version of list (using pointers to the head and the tail) (faster for queues) */
/* thread-safe version... */


#ifndef _LISTQUEUE_H
#define _LISTQUEUE_H
 
#include <pthread.h>


struct list_node {
	struct list_node *next;
	void *data;
};

struct list_descriptor {
	struct list_node *head;
	struct list_node *tail;
	
	int list_len;
	
	// Variables for notify the arrival of the next packet..
	pthread_mutex_t list_lock;
	pthread_cond_t list_newnode;
};

#define DECLARE_LIST(LISTNAME) struct list_descriptor LISTNAME;

void list_init(struct list_descriptor *list);
void *list_head(struct list_descriptor *list);
void list_append(struct list_descriptor *list, void *data);
void *list_find(struct list_descriptor *list, int (compare)(void*, void *), void *comparedata);
void *list_find_del(struct list_descriptor *list, int (compare)(void*, void *), void *comparedata);


#define queue_out	list_head
#define queue_in	list_append 

#endif   /* _LISTQUEUE_H */
