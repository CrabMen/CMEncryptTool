//
//  CMEncryptionTools.m
//
//  Created by CrabMan on 2017/2/10.
//  Copyright © 2017年 CrabMan. All rights reserved.
//
//

#import "CMEncryptionTools.h"

@interface CMEncryptionTools()
@property (nonatomic, assign) int keySize;
@property (nonatomic, assign) int blockSize;
@end

@implementation CMEncryptionTools

+ (instancetype)sharedEncryptionTools {
    static CMEncryptionTools *instance;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
        instance.algorithm = kCCAlgorithmAES;
    });
    
    return instance;
}

- (void)setAlgorithm:(uint32_t)algorithm {
    _algorithm = algorithm;
    switch (algorithm) {
        case kCCAlgorithmAES:
            self.keySize = kCCKeySizeAES128;
            self.blockSize = kCCBlockSizeAES128;
            break;
        case kCCAlgorithmDES:
            self.keySize = kCCKeySizeDES;
            self.blockSize = kCCBlockSizeDES;
            break;
        default:
            break;
    }
}

- (NSString *)cm_encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {
    
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[self.keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:self.keySize];
    
    // 设置iv
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    int option = 0;
    /**
     kCCOptionPKCS7Padding     CBC加密
     kCCOptionPKCS7Padding | kCCOptionECBMode     ECB加密
     */
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [data length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    // 开始加密
    size_t encryptedSize = 0;
    /**
     *  @param kCCEncrypt     加密/解密
     *  @param self.algorithm 加密算法
     *  @param option         CBC/ECB
     *  @param cKey           加密密钥
     *  @param self.keySize   密钥长度
     *  @param cIv            iv初始化向量
     *  @param bytes]         加密的数据
     *  @param length]        加密的数据长度
     *  @param buffer         密文的缓冲区
     *  @param bufferSize     缓冲区的大小
     *  @param encryptedSize  加密结果的大小
     */
    
    
    //在C语言里面,一般上一个参数传指针!下一个参数大部分都是这个指针所指向数据的长度!!
    
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {    
        free(buffer);
        NSLog(@"[错误] 加密失败|状态编码: %d", cryptStatus);
    }
    
    return [result base64EncodedStringWithOptions:0];
}

- (NSString *)cm_decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv {
    
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[self.keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:self.keySize];
    
    // 设置iv
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    
    /**
     kCCOptionPKCS7Padding     CBC加密
     kCCOptionPKCS7Padding | kCCOptionECBMode     ECB加密
     */
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
    size_t bufferSize = [data length] + self.blockSize;/**根据加密方式设置缓存区的结构*/
    void *buffer = malloc(bufferSize);
    
    // 开始解密
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 解密失败|状态编码: %d", cryptStatus);
    }
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

@end
