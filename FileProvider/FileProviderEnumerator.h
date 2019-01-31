//
//  FileProviderEnumerator.h
//  FileProvider
//
//  Created by Lakr Sakura on 2019/1/31.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#import <FileProvider/FileProvider.h>

@interface FileProviderEnumerator : NSObject <NSFileProviderEnumerator>

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithEnumeratedItemIdentifier:(NSFileProviderItemIdentifier)enumeratedItemIdentifier;

@property (nonatomic, readonly, strong) NSFileProviderItemIdentifier enumeratedItemIdentifier;

@end
