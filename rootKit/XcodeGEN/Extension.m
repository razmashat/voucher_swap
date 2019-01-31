//
//  Extension.m
//  rootKit
//
//  Created by Lakr Sakura on 2019/2/1.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#import <Foundation/Foundation.h>

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
    
    return contentFolder;
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
