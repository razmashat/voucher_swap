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

#include "../PostExploit/ExploitBridger.h"
#include "../PostExploit/offsets.h"
#include "../RootUnit/noncereboot.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextView *outPutWindow;
@property (weak, nonatomic) IBOutlet UIButton *runButton;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
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
    NSString *deviceInfo = [[NSString alloc]initWithFormat:@"\n          %s\n          %s  %s", u.version, u.nodename, u.machine];
    _outPutWindow.text = [[_outPutWindow text] stringByAppendingString: deviceInfo];

}

- (IBAction)postExploit:(id)sender {
    
    _outPutWindow.text = [[_outPutWindow text] stringByAppendingString: @"\n\n---\nStarting Exploiting... using voucher_swap method."];
    [_runButton setEnabled:NO];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        // Exploit here.
        mach_port_t tfp0 = grab_this_tfp0();
        if (MACH_PORT_VALID(tfp0)) {
            NSString * output = [[NSString alloc] initWithFormat:@"\nSuccessfully find our tfp0 at:0x%x", tfp0];
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString:output];
                self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nTrying to gain our root."];
            });
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
                if (start_noncereboot(tfp0) == 0) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nGot root and UID 0.\nDoen."];
                    });
                }else{
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self->_outPutWindow.text = [[self->_outPutWindow text] stringByAppendingString: @"\nSomething wrong happens."];
                    });
                }
            });
        }
    });
}

@end
