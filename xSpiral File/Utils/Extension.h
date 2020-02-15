//
//  Extension.h
//  rootKit
//
//  Created by Lakr Sakura on 2019/2/1.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#ifndef Extension_h
#define Extension_h


#endif /* Extension_h */

NSArray *catchContentUnderPath(NSString *thisPath);
int countItemInThePath(NSString *thisPath);
bool isThisDirectory(NSString *thisPath);
NSString *dropLastContentOfSplash(NSString *what);
void setUserLandHome(NSString *home);
NSString *readUserlandHome(void);
void rootCheckOrCheckIn(void);
bool isRootNow(void);
void setOutPutString(NSString *s);
NSString *readOutPutString(void);
