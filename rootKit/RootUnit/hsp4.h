//
//  hsp4.h
//  rootKit
//
//  Created by Lakr Sakura on 2019/2/1.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#ifndef hsp4_h
#define hsp4_h

#include <stdio.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

#include "../PostExploit/Headers/mach_vm.h"
#include "../PostExploit/offsets.h"
#include "../RootUnit/noncereboot.h"
#include "../RootUnit/QiLin.h"


void init_tfp0_at_hsp4(mach_port_t p);
mach_port_t fake_host_priv(void);

int remap_tfp0_set_hsp4(mach_port_t *port, uint64_t zone_map_ref);

//FuckTheGetAddressOfPortMethod!



#endif /* hsp4_h */
