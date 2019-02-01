//
//  Extension.m
//  rootKit
//
//  Created by Lakr Sakura on 2019/2/1.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#import <Foundation/Foundation.h>

NSString *userlandHome;
NSString *outputString;
bool isRoot = false;

void rootCheckOrCheckIn() {
    isRoot = true;
}

bool isRootNow() {
    return isRoot;
}

void setOutPutString(NSString *s) {
    outputString = s;
}

NSString *readOutPutString() {
    return outputString;
}

void setUserLandHome(NSString *home) {
    userlandHome = home;
}

NSString *readUserlandHome() {
    return userlandHome;
}

NSArray *catchContentUnderPath(NSString *thisPath) {
    
    NSError *error;
    
    NSArray *contentFolder =[[NSFileManager defaultManager] contentsOfDirectoryAtPath:thisPath error:&error];
    if (error != nil) {
        NSLog(@"Something wrong.");
    }
    NSLog(@"%@",contentFolder);
    //
    //    NSArray *contentFile = [[NSFileManager defaultManager] subpathsOfDirectoryAtPath:thisPath error:&error];
    //    if (error != nil) {
    //        NSLog(@"Something wrong.");
    //    }
    //    NSLog(@"%@",contentFile);
    //
    //    NSArray *allFiles = [NSArray alloc] init
    
    NSStringCompareOptions comparisonOptions = NSCaseInsensitiveSearch|NSNumericSearch|
    NSWidthInsensitiveSearch|NSForcedOrderingSearch;
    NSComparator sort = ^(NSString *obj1,NSString *obj2){
        NSRange range = NSMakeRange(0,obj1.length);
        return [obj1 compare:obj2 options:comparisonOptions range:range];
    };
    NSArray *resultArray = [contentFolder sortedArrayUsingComparator:sort];

    return resultArray;
}

int countItemInThePath(NSString *thisPath) {
    NSError *error;
    NSArray *contentFolder =[[NSFileManager defaultManager] contentsOfDirectoryAtPath:thisPath error:&error];
    if (error != nil) {
        NSLog(@"Something wrong.");
    }
    NSLog(@"%@",contentFolder);
    return contentFolder.count;
}

bool isThisDirectory(NSString *thisPath) {
    BOOL isDirectory;
    if ([thisPath hasSuffix:@".plist"]) {
        return false;
    }
    BOOL fileExistsAtPath = [[NSFileManager defaultManager] fileExistsAtPath:thisPath isDirectory:&isDirectory];
    if (fileExistsAtPath && isDirectory) {
        return YES;
    }
    return NO;
}

NSString *dropLastContentOfSplash(NSString *what) {
    NSArray *listItems = [what componentsSeparatedByString:@"/"];
    NSString *p = @"";
    for (int i = 0; i < listItems.count - 1; i ++) {
        p = [p stringByAppendingString:listItems[i]];
        if (i < listItems.count - 2) {
            p = [p stringByAppendingString:@"/"];
        }
    }
    if ([p isEqualToString:@""]) {
        p = @"/";
    }
    return p;
}
