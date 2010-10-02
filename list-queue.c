/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: list-queue.c,v 1.1.1.1 2004/02/06 11:57:52 flagz Exp $
 */ 

/* Specialized version of list (using pointers to the head and the tail) (faster for queues) */
/* thread-safe version...*/
 
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "list-queue.h"


void list_init(struct list_descriptor *list) {
	
	list->head = list->tail = NULL;
	
	list->list_len = 0;
	
	pthread_mutex_init(&(list->list_lock),NULL);
	pthread_cond_init(&(list->list_newnode),NULL);
}


// Return the first packet on the queue..
void *list_head(struct list_descriptor *list) {
	void *ret;
	struct list_node *nextnode;
	
	pthread_mutex_lock(&(list->list_lock));
	
	if (list->head == NULL) { //if the queue is empty, wait that the condition come true..
		pthread_cond_wait(&(list->list_newnode),&(list->list_lock));
	}
	
	ret = list->head->data;
	nextnode = list->head->next;
	free(list->head);
	
	
	list->head = nextnode;
	list->list_len--;
	
	pthread_mutex_unlock(&(list->list_lock));
	
	return ret;
}

// Append packet in the queue
void list_append(struct list_descriptor *list, void *data) {
	struct list_node *node;
	
	node = (struct list_node *)malloc(sizeof(struct list_node));
	node->next = NULL;
	node->data = data;
	
	pthread_mutex_lock(&(list->list_lock));
	
	if (list->head == NULL) {
		list->head = list->tail = node;
	}
	else {
		list->tail->next = node;
		list->tail = list->tail->next;
	}
	
	list->list_len++;
	
	pthread_mutex_unlock(&(list->list_lock));
	pthread_cond_signal(&(list->list_newnode));
}



void *list_find(struct list_descriptor *list, int (*compare)(void*, void *), void *comparedata) {
	struct list_node *current;
	void *ret;
	
	pthread_mutex_lock(&(list->list_lock));
	
	current = list->head;
	ret = NULL;
	
	while (current != NULL) {
		if (compare(current->data,comparedata)) {
			ret = current->data;
			break;
		}
		current = current->next;
	}
	
	pthread_mutex_unlock(&(list->list_lock));
	
	return ret;
}

void *list_find_del(struct list_descriptor *list, int (*compare)(void*, void *), void *comparedata) {
	struct list_node *current, *back;
	void *ret;
	
	pthread_mutex_lock(&(list->list_lock));
	
	current = list->head;
	ret = NULL;
	
	if (current)
		if (compare(current->data,comparedata))
			ret = list_head(list);
		else
			while (1) {
				back = current;
				current = current->next;
				if (!current)
					break;
				if (compare(current->data,comparedata)) {
					ret = current->data;
					back->next = current->next;
					free(current);
					break;
				}
			}
	
	pthread_mutex_unlock(&(list->list_lock));
	
	return ret;
}

