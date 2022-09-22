
#import "SSLCredentials.h"
#import "NSData+Security.h"

@implementation SSLCredentials

- (nullable NSArray *)anchors
{
    return anchors;
}

+ (SecCertificateRef)anchorFromData:(NSData *)data
{
    return [data toCertificateRef];
}

+ (NSArray *)keystoresFromData:(NSData *)pkcs12Data password:(NSString *)pass
{
    return [pkcs12Data toKeystoreArrayUsingPassword:pass];
}

- (id)initWithAnchors:(NSArray *)ancs clientKeyStores:(NSArray *)keys
{
    self = [super init];
    if (self) {
        anchors = ancs;
        keystores = keys;
    }
    
    return self;
}

- (id)initWithCA:(SecCertificateRef)ca identity:(SecIdentityRef)idn
{
    SecCertificateRef clientCert = NULL;
    if (SecIdentityCopyCertificate(idn, &clientCert) != errSecSuccess) {
        NSLog(@"Error initializing the SSLCredentials");
        return nil;
    }
    
    return [self initWithAnchors:@[(__bridge id) ca]
                 clientKeyStores:@[@{(__bridge id)idn : (__bridge id)kSecImportItemIdentity,
                                   @[(__bridge id)clientCert] : (__bridge id)kSecImportItemCertChain}]];
}

- (BOOL)canAuthenticateForAuthenticationMethod:(NSString *)authMethod
{
    if ((anchors && [authMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        || (keystores && [authMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])) {
        return YES;
    }
    
    return NO;
}

- (BOOL)isCertificate:(SecCertificateRef)certRef issuedBy:(NSData *)issuerData
{
    NSData *certData = (__bridge_transfer NSData *)SecCertificateCopyData(certRef);
    NSData *certIssuerData = [certData issuerForDERCertificate];
    
    return [certIssuerData isEqualToData:issuerData];
}

- (BOOL)validateResult:(SecTrustResultType)res
{
    if ((res == kSecTrustResultProceed)                 // trusted certificate
        || ((res == kSecTrustResultConfirm)             // valid but user should be asked for confirmation
            || (res == kSecTrustResultUnspecified)      // valid but user have not specified wheter to trust
            || (res == kSecTrustResultDeny)             // valid but user does not trusts this certificate
            )
        )
    {
        return YES;
    } 
    
    return NO;
}

- (NSURLCredential *)credentialsForChallenge:(NSURLAuthenticationChallenge *)challenge
{
    if ([challenge previousFailureCount] > 0) {
        NSLog(@"Authentication already failed %d times", [challenge previousFailureCount]);
        return nil;
    }
    
    NSURLCredential *newCredential = nil;
    NSURLProtectionSpace *protectionSpace = [challenge protectionSpace];
    
    // server authentication - NSURLAuthenticationMethodServerTrust
    if ([protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        SecTrustRef trust = [protectionSpace serverTrust];
        SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)anchors);
        SecTrustSetAnchorCertificatesOnly(trust, YES);
        
        SecTrustResultType res = kSecTrustResultInvalid;
        OSStatus sanityChesk = SecTrustEvaluate(trust, &res);
        
        if ((sanityChesk == noErr)
            && [self validateResult:res]) {
            
            newCredential = [NSURLCredential credentialForTrust:trust];
            //[[challenge sender] useCredential:newCredential forAuthenticationChallenge:challenge];
            
            return newCredential;
        }
        
        NSLog(@"Server certificate validation failed");
        return nil;
    }
    
    // client authentication - NSURLAuthenticationMethodClientCertificate
    if ([protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
        
        // find the first identity signed by one of the expected issuers
        NSDictionary *matchingKeyStore = nil;
        NSArray *acceptedIssuers = [protectionSpace distinguishedNames];
        for (NSData *issuerData in acceptedIssuers) {
            for (NSDictionary *keyStore in keystores) {
                NSArray *clientCertificates = [keyStore objectForKey:(__bridge id)kSecImportItemCertChain];
                
                for (id certRef in clientCertificates) {
                    if ([self isCertificate:(__bridge SecCertificateRef)certRef issuedBy:issuerData]) {
                        matchingKeyStore = keyStore;
                        break;
                    }
                }
                
                if (matchingKeyStore) {
                    break;
                }
            }
        }
        
        if (!matchingKeyStore) {
            NSLog(@"Can not find appropriate client certificate for SSL authentication");
            return nil;
        }
        
        SecIdentityRef identity = (__bridge SecIdentityRef)[matchingKeyStore objectForKey:(__bridge id)kSecImportItemIdentity];
        NSArray *certs = [matchingKeyStore objectForKey:(__bridge id)kSecImportItemCertChain];
        
        if (identity && certs) {
            newCredential = [NSURLCredential credentialWithIdentity:identity
                                                       certificates:certs
                                                        persistence:NSURLCredentialPersistenceNone];
            //[[challenge sender] useCredential:newCredential forAuthenticationChallenge:challenge];
            
            return newCredential;
        }
        
        NSLog(@"Can not authenticate the client");
        return nil;
    }
    
    [NSException raise:@"Authentication method not supported" format:@"%@ not supported.", [protectionSpace authenticationMethod]];
    return nil;
}

@end
