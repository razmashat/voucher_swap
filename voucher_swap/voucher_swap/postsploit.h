//
//  postsploit.h
//  voucher_swap
//
//  Created by Yaniv Mashat on 1/30/19.
//  Copyright © 2019 Brandon Azad. All rights reserved.
//

#ifndef postsploit_h
#define postsploit_h

#include <stdio.h>
#include <mach/mach.h>
#include <stdbool.h>
int getroot(mach_port_t tfp0);
void setcsflags(pid_t pid);
bool unsandbox(pid_t pid);
#endif /* postsploit_h */
