//
//  sha-256.h
//  MyIPFilter
//
//  Created by Bob on 14/10/2018.
//  Copyright © 2018 Xymos Software. All rights reserved.
//

#ifndef sha_256_h
#define sha_256_h


void calc_sha_256(uint8_t hash[32], const void *input, size_t len);

#endif /* sha_256_h */
