# sm3-
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// SM3常量定义
#define SM3_BLOCK_SIZE 64
#define SM3_HASH_SIZE 32
#define SM3_HASH_STRING_SIZE 65

// 初始IV值（大端序）
static const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 常量T_j
static const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 循环左移函数
static uint32_t left_rotate(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// P0置换函数
static uint32_t P0(uint32_t x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

// P1置换函数
static uint32_t P1(uint32_t x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

// FF函数（第1-16轮）
static uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

// GG函数（第1-16轮）
static uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

// FF函数（第17-64轮）
static uint32_t FF2(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

// GG函数（第17-64轮）
static uint32_t GG2(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | ((~x) & z);
}

/**
 * 消息填充函数
 */
unsigned char* sm3_pad(const unsigned char* input, size_t input_len, size_t* padded_len) {
    uint64_t bit_len = (uint64_t)input_len * 8;
    size_t k = (448 - (bit_len + 1) % 512 + 512) % 512;
    if (k == 512) k = 0;
    
    *padded_len = input_len + 1 + k/8 + 8;
    unsigned char* padded = (unsigned char*)malloc(*padded_len);
    if (!padded) return NULL;
    
    memcpy(padded, input, input_len);
    padded[input_len] = 0x80;
    memset(padded + input_len + 1, 0, k/8);
    
    // 修正：使用大端序存储长度
    for (int i = 0; i < 8; i++) {
        padded[*padded_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }
    
    return padded;
}
/**
 * 消息分组扩展函数
 */
void sm3_expand(const unsigned char block[64], uint32_t W[68], uint32_t W1[64]) {
    int i;
    
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    
    for (i = 16; i < 68; i++) {
        uint32_t temp = W[i-16] ^ W[i-9] ^ left_rotate(W[i-3], 15);
        W[i] = P1(temp) ^ left_rotate(W[i-13], 7) ^ W[i-6];
    }
    
    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }
}

/**
 * 压缩函数
 */
void sm3_compress(const unsigned char block[64], uint32_t V[8]) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;
    
    sm3_expand(block, W, W1);
    
    A = V[0]; B = V[1]; C = V[2]; D = V[3];
    E = V[4]; F = V[5]; G = V[6]; H = V[7];
    
    for (j = 0; j < 64; j++) {
        SS1 = left_rotate(left_rotate(A, 12) + E + left_rotate(T[j], j), 7);
        SS2 = SS1 ^ left_rotate(A, 12);
        
        if (j < 16) {
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF2(A, B, C) + D + SS2 + W1[j];
            TT2 = GG2(E, F, G) + H + SS1 + W[j];
        }
        
        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

/**
 * SM3哈希计算主函数
 */
void sm3_hash(const unsigned char* input, size_t input_len, unsigned char output[32]) {
    size_t padded_len;
    unsigned char* padded_msg;
    uint32_t V[8];
    int i, num_blocks;
    
    memcpy(V, SM3_IV, sizeof(SM3_IV));
    padded_msg = sm3_pad(input, input_len, &padded_len);
    if (!padded_msg) {
        printf("内存分配失败\n");
        return;
    }
    
    num_blocks = padded_len / SM3_BLOCK_SIZE;
    for (i = 0; i < num_blocks; i++) {
        sm3_compress(padded_msg + i * SM3_BLOCK_SIZE, V);
    }
    
    for (i = 0; i < 8; i++) {
        output[i*4] = (V[i] >> 24) & 0xFF;
        output[i*4+1] = (V[i] >> 16) & 0xFF;
        output[i*4+2] = (V[i] >> 8) & 0xFF;
        output[i*4+3] = V[i] & 0xFF;
    }
    
    free(padded_msg);
}

/**
 * 将哈希值转换为十六进制字符串
 */
void sm3_hash_to_string(const unsigned char hash[32], char output[65]) {
    static const char* hex_digits = "0123456789abcdef";
    int i;
    
    for (i = 0; i < 32; i++) {
        output[i*2] = hex_digits[(hash[i] >> 4) & 0xF];
        output[i*2+1] = hex_digits[hash[i] & 0xF];
    }
    output[64] = '\0';
}

/**
 * 文件哈希计算
 */
int sm3_file_hash(const char* filename, unsigned char output[32]) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("无法打开文件: %s\n", filename);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char* file_data = (unsigned char*)malloc(file_size);
    if (!file_data) {
        fclose(file);
        printf("内存分配失败\n");
        return -1;
    }
    
    fread(file_data, 1, file_size, file);
    fclose(file);
    
    sm3_hash(file_data, file_size, output);
    free(file_data);
    return 0;
}

/**
 * 性能测试函数
 */
void performance_test() {
    const size_t test_sizes[] = {16, 1024, 10240, 102400, 1048576, 10485760};
    const int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    const int iterations = 5;
    
    printf("性能测试结果:\n");
    printf("输入长度(字节)\t平均耗时(ms)\t吞吐量(MB/s)\n");
    
    for (int i = 0; i < num_tests; i++) {
        size_t size = test_sizes[i];
        unsigned char* test_data = (unsigned char*)malloc(size);
        unsigned char hash[32];
        
        for (size_t j = 0; j < size; j++) {
            test_data[j] = rand() % 256;
        }
        
        clock_t total_time = 0;
        
        for (int j = 0; j < iterations; j++) {
            clock_t start = clock();
            sm3_hash(test_data, size, hash);
            clock_t end = clock();
            total_time += (end - start);
        }
        
        double avg_time_ms = ((double)total_time / iterations / CLOCKS_PER_SEC) * 1000;
        double throughput = (size / (1024.0 * 1024.0)) / (avg_time_ms / 1000.0);
        
        printf("%12zu\t%12.3f\t%12.2f\n", size, avg_time_ms, throughput);
        free(test_data);
    }
}

/**
 * 标准测试用例验证
 */
void standard_test_cases() {
    struct test_case {
        const char* input;
        const char* expected;
    };
    
 
struct test_case test_cases[] = {
    {"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
    {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
    {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 
     "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"}
};
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    int passed = 0;
    
    printf("标准测试用例验证:\n");
    printf("========================================\n");
    
    for (int i = 0; i < num_cases; i++) {
        unsigned char hash[32];
        char hash_str[65];
        
        sm3_hash((const unsigned char*)test_cases[i].input, 
                 strlen(test_cases[i].input), hash);
        sm3_hash_to_string(hash, hash_str);
        
        int result = strcmp(hash_str, test_cases[i].expected);
        
        printf("测试用例 %d:\n", i + 1);
        printf("  输入: \"%s\"\n", test_cases[i].input);
        printf("  预期: %s\n", test_cases[i].expected);
        printf("  实际: %s\n", hash_str);
        printf("  结果: %s\n", result == 0 ? "通过" : "失败");
        printf("----------------------------------------\n");
        
        if (result == 0) passed++;
    }
    
    printf("总结: %d/%d 测试用例通过\n", passed, num_cases);
    printf("========================================\n\n");
}

/**
 * 边界测试用例
 */
void boundary_test_cases() {
    printf("边界测试用例验证:\n");
    printf("========================================\n");
    
    // 测试用例1: 空文件
    printf("1. 空文件测试:\n");
    FILE* empty_file = fopen("empty_test.txt", "wb");
    if (empty_file) {
        fclose(empty_file);
        unsigned char hash[32];
        char hash_str[65];
        
        if (sm3_file_hash("empty_test.txt", hash) == 0) {
            sm3_hash_to_string(hash, hash_str);
            printf("   空文件哈希: %s\n", hash_str);
        }
        remove("empty_test.txt");
    }
    
    // 测试用例2: 1字节输入
    printf("2. 1字节输入测试:\n");
    unsigned char hash[32];
    char hash_str[65];
    sm3_hash((const unsigned char*)"a", 1, hash);
    sm3_hash_to_string(hash, hash_str);
    printf("   输入 'a' 的哈希: %s\n", hash_str);
    
    // 测试用例3: 448bit边界
    printf("3. 448bit边界测试:\n");
    char test_448[56]; // 448bit = 56字节
    memset(test_448, 'a', 56);
    sm3_hash((const unsigned char*)test_448, 56, hash);
    sm3_hash_to_string(hash, hash_str);
    printf("   56个'a'的哈希: %s\n", hash_str);
    
    printf("========================================\n\n");
}

/**
 * 命令行工具使用说明
 */
void print_usage() {
    printf("SM3哈希算法工具 - Dev-C++版本\n");
    printf("========================================\n");
    printf("用法:\n");
    printf("  直接运行程序进行标准测试\n");
    printf("  或修改main函数中的测试代码\n");
    printf("========================================\n");
}

int main() {
    printf("SM3密码杂凑算法实现 - Dev-C++环境\n");
    printf("作者: 李斌\n");
    printf("学号: 24405090319\n");
    printf("========================================\n\n");
    
    // 执行标准测试用例
    standard_test_cases();
    
    // 执行边界测试用例
    boundary_test_cases();
    
    // 性能测试（可选，可能需要较长时间）
    printf("是否执行性能测试? (y/n): ");
    char choice = getchar();
    if (choice == 'y' || choice == 'Y') {
        printf("\n开始性能测试...\n");
        performance_test();
    }
    
    printf("\n程序执行完毕。按任意键退出...");
    getchar(); // 清除之前的回车
    getchar(); // 等待按键
    
    return 0;
}
