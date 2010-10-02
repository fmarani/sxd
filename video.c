/* sxd -- SXD Xfer Dump
 * Copyright (C) 2003 Federico Marani <flagz@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * $Id: video.c,v 1.1.1.1 2004/02/06 11:57:51 flagz Exp $
 */ 



#include <ncurses.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include "tcp-netbios.h"

#define VIDEO_LOCK	pthread_mutex_lock(&video_lock)
#define VIDEO_TRYLOCK	pthread_mutex_trylock(&video_lock)
#define VIDEO_UNLOCK	pthread_mutex_unlock(&video_lock)

#define DIALOG_LOCK	
#define DIALOG_UNLOCK	


WINDOW  *xferwin, *statwin, *pktwin, *dialog;

pthread_mutex_t video_lock = PTHREAD_MUTEX_INITIALIZER;

enum { NCURSES, NORMAL } termmode = NORMAL;

void pktwin_append(char *s) {
	if (termmode == NCURSES) {
		if (VIDEO_TRYLOCK == EBUSY)
			return;
		waddstr(pktwin,s);
		wrefresh(pktwin);
		VIDEO_UNLOCK;
	}
	else 
		printf(s);
}

int pktprintf(char *fmt, ...) {
  va_list ap;
  int ret;
  char s[255];

  va_start (ap, fmt);
  ret = vsprintf (s, fmt, ap);
  va_end (ap);

  pktwin_append(s);
  
  return ret;
}


int yesno(char *s) {
	int slen;
	char res;
	
	//add signal(SIGALRM... X IL TIMEOUT...
	slen = strlen(s);
	VIDEO_LOCK;
	DIALOG_LOCK;
	
	dialog = newwin(7,30,7,25);
	box(dialog,'|','-');
	if (slen > 30) slen=30;
	mvwaddstr(dialog,2,15-slen/2,s);
	mvwaddstr(dialog,4,8,"(Y)es or (N)o ?");
	wrefresh(dialog);
	
	do
	 res = tolower(wgetch(dialog));
	while (res != 'y' && res != 'n');
	
	delwin(dialog);
	wrefresh(xferwin);
	wrefresh(pktwin);
	DIALOG_UNLOCK;
	VIDEO_UNLOCK;
	
	return res == 'y';
}


void makewindows() {
	int maxy,maxx;

	getmaxyx(stdscr,maxy,maxx);
	
	xferwin = newwin(maxy/3,maxx-18,0,0);
	statwin = newwin(maxy/3,18,0,maxx-18);
	pktwin = newwin(maxy/3*2,maxx,maxy/3,0);
	scrollok(pktwin,TRUE);
	wsetscrreg(pktwin,maxy/3,maxy/3*2);
	box(xferwin,'|','-');
	box(statwin,'|','-');
	
	mvwaddstr(xferwin,0,5,"| SXD V.0.01  by BlueCRAsH |");
	wrefresh(xferwin);
	VIDEO_UNLOCK;
}

void updateloop() {
	char tmp[20];
	
	VIDEO_LOCK;
	LIST_LOCK;
	
	//FIXME...
	mvwaddstr(xferwin,1,2,"TCPConn: 192.168.0.252:1322->192.168.0.9:139 (STATUS_OK)");
	mvwaddstr(xferwin,2,2,"SMBXfer: BLUECRASH->DIODE (file=\\unwise.exe) 55% of 256000");
	wrefresh(xferwin);
	
	mvwaddstr(statwin,1,4,"Statistics");
	snprintf(tmp,20,"Conns    :%4d",conn);
	mvwaddstr(statwin,2,2,tmp);
	snprintf(tmp,20,"Xfers    :%4d",xfers);
	mvwaddstr(statwin,3,2,tmp);
	snprintf(tmp,20,"pkt_queue:%4d",pkt);
	mvwaddstr(statwin,4,2,tmp);
	
	mvwaddstr(statwin,6,2,"   UPTIME   ");
	mvwaddstr(statwin,7,2,"1 - 00:01:23");

	wrefresh(statwin);
	
	
	VIDEO_UNLOCK;
}



void print_stats() {
}



void delwindows() {
	VIDEO_LOCK;
	delwin(xferwin);
	delwin(statwin);
	delwin(pktwin);
}

void quit() {
	if (termmode == NCURSES) {
		delwindows();
		endwin();
	}
	printf("Stop snffing...\n");
}

int initcurses() {
	termmode = NCURSES;
	initscr();
	curs_set(2);
	noecho();
	cbreak();
	nonl();
	makewindows();
}

 
int video_start(int curses) {
	termmode = NORMAL;
	pthread_mutex_init(&video_lock,NULL);
	if (curses == 1)
		initcurses();
	
	signal(SIGINT,quit);
	if (termmode == NCURSES) {
		pthread_t p;
		pthread_create(p, NULL, updateloop, NULL);
	}
	
}
