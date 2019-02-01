//
//  ViewController.m
//  rootKit
//
//  Created by Lakr Sakura on 2019/1/31.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#import "ViewController.h"

#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>


#include <mach/mach.h>

#include "../PostExploit/ExploitBridger.h"
#include "../PostExploit/offsets.h"
#include "../RootUnit/noncereboot.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextView *outPutWindow;
@property (weak, nonatomic) IBOutlet UIButton *runButton;
@property (weak, nonatomic) IBOutlet UIButton *openFileManager;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    if (isRootNow()) {
        _outPutWindow.text = readOutPutString();
        [_runButton setEnabled:NO];
        return;
    }
    // Do any additional setup after loading the view, typically from a nib.
    if (offsets_init() != 0) {
        _outPutWindow.text = @"Offsets init may be failed.\n";
    }
    struct utsname u = {};
    uname(&u);
//    struct    utsname {
//        char    sysname[_SYS_NAMELEN];    /* [XSI] Name of OS */
//        char    nodename[_SYS_NAMELEN];    /* [XSI] Name of this network node */
//        char    release[_SYS_NAMELEN];    /* [XSI] Release level */
//        char    version[_SYS_NAMELEN];    /* [XSI] Version level */
//        char    machine[_SYS_NAMELEN];    /* [XSI] Hardware type */
//    };
    NSString *deviceInfo = [[NSString alloc] initWithFormat:@"\n          %s\n          %s  %s", u.version, u.nodename, u.machine];
    _outPutWindow.text = [[_outPutWindow text] stringByAppendingString: deviceInfo];
    setUserLandHome([NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,    NSUserDomainMask, YES)objectAtIndex:0]);
//    [NSFileManager defaultManager]
}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch * touch = [touches anyObject];
    if(touch.phase == UITouchPhaseBegan) {
        [_outPutWindow resignFirstResponder];
    }
}

- (IBAction)postExploit:(id)sender {
    
    _outPutWindow.text = [[_outPutWindow text] stringByAppendingString: @"\n\n---\nStarting Exploiting... using voucher_swap method."];
    [_runButton setEnabled:NO];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        // Exploit here.
        mach_port_t tfp0 = MACH_PORT_NULL;
        kern_return_t kErr = host_get_special_port(mach_host_self(), 0, 4, &tfp0);
        if (kErr != KERN_SUCCESS && !MACH_PORT_VALID(tfp0)) {
            tfp0 = grab_this_tfp0();
        }
        if (MACH_PORT_VALID(tfp0)) {
            NSString * output = [[NSString alloc] initWithFormat:@"\nSuccessfully find our tfp0 at:0x%x", tfp0];
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString:output];
                self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nTrying to gain our root."];
                setOutPutString(self->_outPutWindow.text);
            });
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
                if (start_noncereboot(tfp0) == 0) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nGot root and UID 0.\nDone."];
                        [self->_openFileManager setHidden:NO];
                        setOutPutString(self->_outPutWindow.text);
                        rootCheckOrCheckIn();
                    });
                }else{
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nSomething wrong happens."];
                        setOutPutString(self->_outPutWindow.text);
                    });
                }
            });
        }
    });
}

@end

@interface FileManagerViewController () <UITableViewDelegate,UITableViewDataSource> {
    
    NSString *currentPath;
    NSString *copyFilePath;
    NSString *copyFileName;
    NSArray *currentFileList;
}

@property (weak, nonatomic) IBOutlet FileListTableView *tableView;
@property (weak, nonatomic) IBOutlet UITextField *URLText;
@property (weak, nonatomic) IBOutlet UILabel *errorLabel;


@end


@implementation FileManagerViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    currentPath = @"/";
    currentFileList = catchContentUnderPath(@"/");
    UILongPressGestureRecognizer *lpgr = [[UILongPressGestureRecognizer alloc]
                                          initWithTarget:self action:@selector(handleLongPress:)];
    lpgr.minimumPressDuration = 1.0; //seconds
    lpgr.delegate = self;
    [self.tableView addGestureRecognizer:lpgr];

}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch * touch = [touches anyObject];
    if(touch.phase == UITouchPhaseBegan) {
        [_URLText resignFirstResponder];
    }
}

-(void)handleLongPress:(UILongPressGestureRecognizer *)gestureRecognizer
{
    CGPoint p = [gestureRecognizer locationInView:self.tableView];
    
    NSIndexPath *indexPath = [self.tableView indexPathForRowAtPoint:p];
    if (indexPath == nil) {
        NSLog(@"long press on table view but not on a row");
    } else if (gestureRecognizer.state == UIGestureRecognizerStateBegan) {
        NSLog(@"long press on table view at row %ld", indexPath.row);
        NSString *thisFileName = currentFileList[indexPath.row];
        NSString *thisFilePath;
        if ([currentPath isEqualToString:@"/"]) {
            thisFilePath = [[NSString alloc] initWithFormat:@"%@%@", currentPath, currentFileList[indexPath.row]];
        }else{
            thisFilePath = [[NSString alloc] initWithFormat:@"%@/%@", currentPath, currentFileList[indexPath.row]];
        }
        
        
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Command?"
                                                                       message:@"This is an alert."
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* copyAction = [UIAlertAction actionWithTitle:@"Copy it!" style:UIAlertActionStyleDefault
                                                              handler:^(UIAlertAction * action) {
                                                                  self->_errorLabel.text = @"Touched to clip board.";
                                                                  self->copyFileName = thisFileName;
                                                                  self->copyFilePath = thisFilePath;
                                                              }];
        UIAlertAction* renameAction = [UIAlertAction actionWithTitle:@"Rename it!" style:UIAlertActionStyleDefault
                                                             handler:^(UIAlertAction * action) {
                                                                 UIAlertController * alertController = [UIAlertController alertControllerWithTitle: @"Name?"
                                                                                                                                           message: nil
                                                                                                                                    preferredStyle:UIAlertControllerStyleAlert];
                                                                 [alertController addTextFieldWithConfigurationHandler:^(UITextField *textField) {
                                                                     textField.placeholder = @"name";
                                                                     textField.textColor = [UIColor blueColor];
                                                                     textField.clearButtonMode = UITextFieldViewModeWhileEditing;
                                                                     textField.borderStyle = UITextBorderStyleRoundedRect;
                                                                 }];
                                                                 [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                                                                     NSArray * textfields = alertController.textFields;
                                                                     UITextField * namefield = textfields[0];
                                                                     if ([namefield.text isEqualToString:@""]) {
                                                                         return;
                                                                     }
                                                                     NSString *destFilePath = [[dropLastContentOfSplash(thisFilePath) stringByAppendingString:@"/"] stringByAppendingString:thisFileName];
                                                                     NSError *errrrr;
                                                                     [[NSFileManager defaultManager] moveItemAtPath:thisFilePath toPath:destFilePath error:&errrrr];
                                                                     if (errrrr != nil) {
                                                                         printf("Soemthing wrong!\n");
                                                                         NSLog(@"%@", errrrr);
                                                                         self->_errorLabel.text = @"Failed to rename!";
                                                                     }
                                                                 }]];
                                                                 [alertController addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {NSLog(@"Canceled");}]];
                                                                 [self presentViewController:alertController animated:YES completion:nil];
                                                             }];
        UIAlertAction* cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault
                                                             handler:nil];
        
        [alert addAction:copyAction];
        [alert addAction:renameAction];
        [alert addAction:cancelAction];
        [self presentViewController:alert animated:YES completion:nil];
        
    } else {
        NSLog(@"gestureRecognizer.state = %ld", gestureRecognizer.state);
    }
}
- (IBAction)goBack:(id)sender {
    if ([currentPath  isEqual: @"/"]) {
        _URLText.text = currentPath;
        return;
    }
    currentPath = dropLastContentOfSplash(currentPath);
    currentFileList = catchContentUnderPath(currentPath);
    _tableView.reloadData;
    _URLText.text = currentPath;
}

- (IBAction)refreshList:(id)sender {
    if (![[NSFileManager defaultManager] fileExistsAtPath:_URLText.text]) {
        _errorLabel.text = @"No such file or direct.";
        return;
    }
    currentPath = _URLText.text;
    if (isThisDirectory(currentPath)) {
        currentFileList = catchContentUnderPath(currentPath);
        _tableView.reloadData;
    }else{
        currentPath = dropLastContentOfSplash(currentPath);
        currentFileList = catchContentUnderPath(currentPath);
        _tableView.reloadData;
    }
}

- (IBAction)wentToHome:(id)sender {
    currentPath = dropLastContentOfSplash(readUserlandHome());
    currentFileList = catchContentUnderPath(currentPath);
    _tableView.reloadData;
    _URLText.text = currentPath;
}

- (IBAction)pasteFile:(id)sender {
    if ([copyFileName isEqualToString:@""] || copyFileName == nil) {
        _errorLabel.text = @"Nothing to copy!";
        return;
    }
    NSString *dest;
    if ([currentPath isEqualToString:@"/"]) {
        dest = [[NSString alloc] initWithFormat:@"%@%@", currentPath, copyFileName];
    }else{
        dest = [[NSString alloc] initWithFormat:@"%@/%@", currentPath, copyFileName];
    }
    while ([[NSFileManager defaultManager] fileExistsAtPath:dest]) {
        dest = [dest stringByAppendingString:@".copy"];
    }
    NSError *err;
    [[NSFileManager defaultManager] copyItemAtPath:copyFilePath toPath:dest error:&err];
    if (err != nil) {
        NSLog(@"Copy file failed!");
        _errorLabel.text = @"Unable to copy.";
    }
    currentFileList = catchContentUnderPath(currentPath);
    _tableView.reloadData;
}

- (IBAction)createFolder:(id)sender {
    _errorLabel.text = @"Last error: nil";
    UIAlertController * alertController = [UIAlertController alertControllerWithTitle: @"Name?"
                                                                              message: @"Input the folder's name or cancel."
                                                                       preferredStyle:UIAlertControllerStyleAlert];
    [alertController addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"name";
        textField.textColor = [UIColor blueColor];
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
        textField.borderStyle = UITextBorderStyleRoundedRect;
    }];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSArray * textfields = alertController.textFields;
        UITextField * namefield = textfields[0];
        if ([namefield.text isEqualToString:@""]) {
            return;
        }
        NSLog(@"Creating file as:%@",namefield.text);
        NSError *err;
        NSString *fullPath;
        if ([currentPath isEqualToString:@"/"]) {
            fullPath = [[NSString alloc] initWithFormat:@"%@%@", self->currentPath, namefield.text];
        }else{
            fullPath = [[NSString alloc] initWithFormat:@"%@/%@", self->currentPath, namefield.text];
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:fullPath withIntermediateDirectories:NO attributes:nil error:&err];
        if (err != nil) {
            NSLog(err);
            self->_errorLabel.text = @"Failed to create folder.";
        }
        self->currentFileList = catchContentUnderPath(self->currentPath);
        self->_tableView.reloadData;
    }]];
    [alertController addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {NSLog(@"Canceled");}]];
    [self presentViewController:alertController animated:YES completion:nil];
}


- (nonnull UITableViewCell *)tableView:(nonnull UITableView *)tableView cellForRowAtIndexPath:(nonnull NSIndexPath *)indexPath {
    static NSString *cellID = @"cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellID];
    cell.textLabel.text = [@"  " stringByAppendingString: currentFileList[indexPath.row]];
    NSString *fullPathForThisFile;
    if ([currentPath isEqualToString:@"/"]){
        fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@%@", currentPath, currentFileList[indexPath.row]];
    }else{
        fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@/%@", currentPath, currentFileList[indexPath.row]];
    }
    if (isThisDirectory(fullPathForThisFile)) {
        int itemCount = countItemInThePath(fullPathForThisFile);
        NSString *details = [[NSString alloc] initWithFormat:@"%d item(s)", itemCount];
        cell.detailTextLabel.text = details;
    }else{
        cell.detailTextLabel.text = @"";
    }
    
    return cell;
}

- (NSInteger)tableView:(nonnull UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return currentFileList.count;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    NSString *fullPathForThisFile;
    if ([currentPath  isEqual: @"/"]) {
        fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@%@", currentPath, currentFileList[indexPath.row]];
    }else{
        fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@/%@", currentPath, currentFileList[indexPath.row]];
    }
    if (isThisDirectory(fullPathForThisFile)) {
        currentPath = fullPathForThisFile;
        currentFileList = catchContentUnderPath(currentPath);
        tableView.reloadData;
        _URLText.text = currentPath;
    }else{
        NSString *filePath = [readUserlandHome() stringByAppendingPathComponent:currentFileList[indexPath.row]];
        if (isRootNow()) {
            self->_errorLabel.text = @"We can't share file as root.\nBut we copied it to home.";
            NSString *destPath = [@"/var/mobile/Media/" stringByAppendingPathComponent:currentFileList[indexPath.row]];
            [[NSFileManager defaultManager] copyItemAtPath:filePath toPath:destPath error:nil];
            NSError *err;
            NSDictionary *attr=[NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedLong:0777U] forKey:NSFilePosixPermissions];
            [[NSFileManager defaultManager] setAttributes:attr ofItemAtPath:destPath error:&err];
        }else{
            // Let's copy file to our doc direct.
            [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:fullPathForThisFile toPath:filePath error:nil];
            NSError *err;
            NSDictionary *attr=[NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedLong:0777U] forKey:NSFilePosixPermissions];
            [[NSFileManager defaultManager] setAttributes:attr ofItemAtPath:filePath error:&err];
            NSLog(@"%@", err);
            
            NSURL *fileUrl     = [NSURL fileURLWithPath:filePath isDirectory:NO];
            NSArray *activityItems = @[fileUrl];
            UIActivityViewController *activityController = [[UIActivityViewController alloc] initWithActivityItems:activityItems applicationActivities:nil];
            //if iPhone
            if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
                [self presentViewController:activityController animated:YES completion:nil];
            }
            //if iPad
            else {
                // Change Rect to position Popover
                UIPopoverController *popup = [[UIPopoverController alloc] initWithContentViewController:activityController];
                [popup presentPopoverFromRect:CGRectMake(self.view.frame.size.width/2, self.view.frame.size.height/4, 0, 0)inView:self.view permittedArrowDirections:UIPopoverArrowDirectionAny animated:YES];
            }
        }
        
    }
    
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(nonnull NSIndexPath *)indexPath {
    _errorLabel.text = @"Last error: nil";
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        NSString *fullPathForThisFile;
        if ([currentPath  isEqual: @"/"]) {
            fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@%@", currentPath, currentFileList[indexPath.row]];
        }else{
            fullPathForThisFile = [[NSString alloc] initWithFormat:@"%@/%@", currentPath, currentFileList[indexPath.row]];
        }
        NSError *err;
        [[NSFileManager defaultManager] removeItemAtPath:fullPathForThisFile error:&err];
        if (err != nil) {
            NSLog(@"%@", err);
            _errorLabel.text = @"Failed to delete file.";
        }
        currentFileList = catchContentUnderPath(currentPath);
        tableView.reloadData;
    }
}


@end

