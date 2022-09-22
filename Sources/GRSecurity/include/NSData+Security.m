/*
 * @(#) $$CVSHeader: $$
 *
 * Copyright (C) 2012 by Netcetera AG.
 * All rights reserved.
 *
 * The copyright to the computer program(s) herein is the property of
 * Netcetera AG, Switzerland.  The program(s) may be used and/or copied
 * only with the written permission of Netcetera AG or in accordance
 * with the terms and conditions stipulated in the agreement/contract
 * under which the program(s) have been supplied.
 *
 * @(#) $$Id: NSData+Security.m 718 2012-12-24 13:48:11Z zkuvendz $$
 */

#import "NSData+Security.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

@implementation NSData (Security)

- (NSString *)bytesToHex:(const uint8_t*)input size:(NSUInteger)length
{
    if (length == 0) {
        NSLog(@"Converting empty data to hex !!!");
        return @"";
    }
    
    size_t strLength = length << 1;
    uint8_t *cstr = malloc(strLength);
    for (NSUInteger i=0, j=0; i < length; i++, j+=2) {
        cstr[j]     = (input[i] >> 4)  & 0x0f;
        cstr[j+1]   = input[i]         & 0x0f;
        
        cstr[j]     += cstr[j]  < 0x0a ? '0' : 'a' - 10;
        cstr[j+1]   += cstr[j+1]< 0x0a ? '0' : 'a' - 10;
    }
    
    NSString *res = [[NSString alloc] initWithBytes:cstr 
                                             length:strLength
                                           encoding:NSASCIIStringEncoding];
    free(cstr);
    return res;
}

- (NSString *)toHexString
{
    return [self bytesToHex:[self bytes] size:[self length]];
}

#pragma mark - CERTIFICATES
- (SecCertificateRef)toCertificateRef
{
    SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, 
                                                             (__bridge CFDataRef) self);
    
    if (!certRef) {
        [NSException raise:NSInvalidArgumentException
                    format:@"The data is not a valid certificate"];
    }
    
    return certRef;    
}

- (NSArray *)toKeystoreArrayUsingPassword:(NSString *)pass;
{
    CFArrayRef keyref = NULL;
    OSStatus sanityChesk = SecPKCS12Import((__bridge CFDataRef)self, 
                                           (__bridge CFDictionaryRef)[NSDictionary 
                                                                      dictionaryWithObject:pass 
                                                                      forKey:(__bridge id)kSecImportExportPassphrase], 
                                           &keyref);
    
    if (sanityChesk != noErr) {
        NSLog(@"Error while importing pkcs12 [%d]", sanityChesk);
        return nil;
    }
    
    NSArray *keystores = (__bridge_transfer NSArray *)keyref;
    return keystores;
}

- (NSInteger)numberOfLengthBytes:(uint8_t)firstOctet
{
    uint8_t maskedFirstBit = firstOctet & 0x80; // get the firt most significant bit with mask  1000 0000
    uint8_t maskedBits     = firstOctet & 0x7F; // get the rest 7 remaining bits with mask 0111 1111
    NSInteger result = 1;
    
    if (maskedFirstBit == 0x00) { // length is represented with one octet (byte)
        return result;
    } else { 
        result = maskedBits; //the remaining 7 bits indicate how many bytes down the byte array will represent the length of the sequence
        result ++;            //move the index, pass tha length bits
    }
    return result;
}

- (NSInteger)contentLength:(uint8_t *)lengthBytes size:(NSInteger)size
{
    NSInteger sum = 0;
    NSInteger start = 0;
    
    if ((lengthBytes[0] & 0x80) != 0x00) {
        start ++;
    }
    
    for (NSInteger i = start; i < size; i++) {
        sum *= 256;
        sum += lengthBytes[i];
    }
    
    return  sum;
}

- (NSInteger)headerLength:(uint8_t *)data forTag:(uint8_t)tag
{
    NSInteger index = 0;
    if (data[0] != tag) { // expecting a sequence - deterimned by the tag byte
        NSLog(@"Certificate's DER representation might not be valid. Expected tag %@ not found",
              [self bytesToHex:&tag size:1]);
        return index;
    }
    
    // skip the tag byte
    index ++;
    
    // skip the length bytes
    index += [self numberOfLengthBytes:data[index]]; 
    
    //return the offset 
    return index;
}

- (NSInteger)tagLength:(uint8_t *)data forTag:(uint8_t)tag
{
    NSInteger index = 0;
    if (data[0] != tag) { // expecting a sequence - deterimned by the tag byte
        NSLog(@"Certificate's DER representation might not be valid. Expected tag %@ not found",
              [self bytesToHex:&tag size:1]);
        return index;
    }
    
    // skip the tag bytes
    index ++;
    
    // get the content length
    NSInteger numberOfLengthBytes = [self numberOfLengthBytes:data[index]]; 
    NSInteger contentLength = [self contentLength:(data + index) 
                                             size:numberOfLengthBytes];
    
    // skip the length  bytes
    index += numberOfLengthBytes;  
    
    // skip the content bytes
    index += contentLength;
    
    return index;
}

- (NSData *)issuerForDERCertificate;
{
    uint8_t *certificateBytes = (uint8_t *)self.bytes;
    NSInteger index = 0;
    
    index += [self headerLength:(certificateBytes + index) forTag:0x30];  // enter the first sequence
    index += [self headerLength:(certificateBytes + index) forTag:0x30];  // enter the TBSCertificate sequence
    index += [self tagLength:(certificateBytes + index) forTag:0xa0];     // skip the content of the version tag (possibly missing)
    index += [self tagLength:(certificateBytes + index) forTag:0x02];     // skip the content of the serial number
    index += [self tagLength:(certificateBytes + index) forTag:0x30];     // skip the content of the algorithm id
    
    /* ************************************** */
    /*             ISSUER SEQUENCE            */
    /* ************************************** */
    NSInteger tagLength = [self tagLength:(certificateBytes + index) forTag:0x30];
    NSData *issuerData = [NSData dataWithBytes:(certificateBytes + index)
                                        length:tagLength];
    return issuerData;
}

typedef unsigned char * (*hash_func)(const void *data, CC_LONG len, unsigned char *md);

- (NSData *)hashWithAlgorithm:(hash_func)func length:(NSUInteger)length
{
    // allocate buffer for the hash
    uint8_t *hashBytes = NULL;
    NSData *hash = nil;
    
    hashBytes = malloc(length);
    if (!hashBytes) { 
        return nil;
    }
    
    // zerro-out the buffer
    memset((void *)hashBytes, 0x0, length);
    
    // compute the hash
    (*func)([self bytes], [self length], hashBytes);
    hash = [NSData dataWithBytes:(const void *)hashBytes length:length];
    
    free(hashBytes);
    return hash;
}

- (NSData *)md2 {
    return [self hashWithAlgorithm:&CC_MD2 length:CC_MD2_DIGEST_LENGTH];
}

- (NSData *)md4 {
    return [self hashWithAlgorithm:&CC_MD4 length:CC_MD4_DIGEST_LENGTH];
}

- (NSData *)md5 {
    return [self hashWithAlgorithm:&CC_MD5 length:CC_MD5_DIGEST_LENGTH];
}

- (NSData *)sha1 {
    return [self hashWithAlgorithm:&CC_SHA1 length:CC_SHA1_DIGEST_LENGTH];
}

- (NSData *)sha224 {
    return [self hashWithAlgorithm:&CC_SHA224 length:CC_SHA224_DIGEST_LENGTH];
}

- (NSData *)sha256 {
    return [self hashWithAlgorithm:&CC_SHA256 length:CC_SHA256_DIGEST_LENGTH];
}

- (NSData *)sha384 {
    return [self hashWithAlgorithm:&CC_SHA384 length:CC_SHA384_DIGEST_LENGTH];
}

- (NSData *)sha512 {
    return [self hashWithAlgorithm:&CC_SHA512 length:CC_SHA512_DIGEST_LENGTH];
}

@end
