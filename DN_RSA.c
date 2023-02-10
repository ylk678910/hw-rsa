#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct Bitset_t Bitset_t;
typedef uint32_t BitData_t;

typedef enum
{
    MSB = 0,
    LSB
} BitsetMode_t;

typedef enum
{
    UINT8_T = 0,
    UINT32_T,
    UINT64_T,
    INT8_T,
    INT32_T,
    INT64_T,
    FLOAT,
    DOUBLE
} InRangeType_t;

typedef enum
{
    CYCLE = 0,
    RANGE,
    NORMAL
} Bitset_Bitmap_t;

struct Bitset_t
{
    char neg;
    uint32_t bit_num;
    uint32_t array_num;
    BitsetMode_t mode;
    BitData_t *bit_data;
};

#define BitsetData(bitset, ptr) ((bitset)->bit_data[ptr])

Bitset_t *Karatsuba(Bitset_t *num1, Bitset_t *num2);

int NewBitset(Bitset_t **bitset, uint32_t bit_num, BitsetMode_t mode);
int DelBitset(Bitset_t **bitset);

int SetBitset(Bitset_t *bitset, uint32_t bit, uint8_t set);
int SetBitset_CountingCpy(Bitset_t *bitset_o, Bitset_t *bitset_i);
int SetBitset_4Byte(Bitset_t *bitset, int bit, uint32_t set, uint8_t set_num);
int SetBitset_Bitset(Bitset_t *bitset, int bit, Bitset_t *bitset_in, uint32_t bitset_in_first_bit, uint32_t bitset_in_last_bit, Bitset_Bitmap_t mode);
int SetBitset_String(Bitset_t *bitset, int bit, char *str);
int SetBitset_HexString(Bitset_t *bitset, int bit, char *str);
int SetBitset_CountingHexString(Bitset_t *bitset, char *str);
int SetBitset_CountingUint32(Bitset_t *bitset, uint32_t data);
int SetBitset_CountingDecString(Bitset_t *bitset, char *str);

uint32_t GetBitset(Bitset_t *bitset, uint32_t bit);
uint32_t GetBitset_4Byte(Bitset_t *bitset, int bit, uint8_t get_num);
int GetBitset_DivideByUint32(uint32_t *data_o, uint32_t *start_bit_o, uint32_t *bit_num_o, Bitset_t *bitset, uint32_t array_ptr, uint32_t first_bit, uint32_t last_bit);
uint32_t Bitset_DivideByUint32_ArrayNum(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit);
int GetBitset_Bitset(Bitset_t *bitset_get, int bit, Bitset_t *bitset_in, uint32_t bitset_in_first_bit, uint32_t bitset_in_last_bit, Bitset_Bitmap_t mode);

int InsertBitsetBits_uint32(Bitset_t *bitset, uint32_t start_bit, uint32_t data, uint8_t data_num);
int DelBitsetBits(Bitset_t *bitset, uint32_t start_bit, uint32_t del_num);

int LeftShiftBitset(Bitset_t *bitset, int offset, Bitset_Bitmap_t mode);
int LeftShiftBitset_Range(Bitset_t *bitset, int offset, uint32_t first_bit, uint32_t last_bit, Bitset_Bitmap_t mode);

int BitsetToString(char *str_o, Bitset_t *bitset, int start_bit, uint32_t bit_num);
int BitsetToHexString(char *str_o, Bitset_t *bitset, int start_bit, uint32_t bit_num);

int BitsetClear(Bitset_t *bitset);
int BitsetCmpWithNeg(Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetCmpWithoutNeg(Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetCmpWithoutNegUint32(Bitset_t *bitset_cmp, uint32_t uint32_in);
int BitsetAdd(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetSub(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetMul(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetDiv(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetMod(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetGCD(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
int BitsetInverseMod(Bitset_t *bitset_o, Bitset_t *bitset_base, Bitset_t *bitset_mod);
int BitsetRandom(Bitset_t *bitset_o, Bitset_t *bitset_range);

int BitsetSquareAndMultiply_Mod(Bitset_t *bitset_o, Bitset_t *bitset_base, Bitset_t *bitset_pow, Bitset_t *bitset_mod);
int BitsetMillerRabinTest(Bitset_t *bitset, uint32_t times);
int BitsetFermatTest(Bitset_t *bitset, uint32_t times);

uint32_t BitsetPtr(Bitset_t *bitset, uint32_t bit);
uint32_t BitsetArrayNum(Bitset_t *bitset);

static void gcd(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2);
static void LeftShiftBitset_s(Bitset_t *bitset);
static void LeftShiftBitset_Range_s(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit);
static void RightShiftBitset_s(Bitset_t *bitset);
static void RightShiftBitset_Range_s(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit);
static int InRange(void *in, void *max, void *min, InRangeType_t type);
static int CharToHex(char ch);
static void DebugPrintf(char *name, Bitset_t *bitset);
static int GetBitset_MaxBitPtr(Bitset_t *bitset);

char *StrInverse(char str[]);
int StrSub(char str_o[], char str_i[], char str_s[]);
int SetBitset_CountingDecString(Bitset_t *bitset, char str[]);

int RSA_Encode(Bitset_t *c, Bitset_t *m, Bitset_t *e, Bitset_t *n);
int RSA_Decode(Bitset_t *m, Bitset_t *c, Bitset_t *p, Bitset_t *q, Bitset_t *q_inv, Bitset_t *d_p, Bitset_t *d_q);

uint32_t one_data[] = {1};
Bitset_t one_bitset = {
    .neg = 0,
    .bit_num = 1,
    .array_num = 1,
    .mode = MSB,
    .bit_data = one_data};
Bitset_t *one = &one_bitset;

uint32_t two_data[] = {2};
Bitset_t two_bitset = {
    .neg = 0,
    .bit_num = 2,
    .array_num = 1,
    .mode = MSB,
    .bit_data = two_data};
Bitset_t *two = &two_bitset;

char p_buf[2048], q_buf[2048];
char input_data[4097];
char p_def[] = "7e4d91bb86a2cff868e987bbc90ae690d70be7b4fa93211c1128c59381d302a418f03149eb06edf1b5de35b7af9472233f4d54104f9e50e656cdb24667a1d54b";
char q_def[] = "8765eaf70929749012cbbf702e32d8902743b2a4bacdf894dcdb24966393775e6e2395f47c864be32bdcc42ff3ede7932275affadefc7f2b0c283e9eca501edd";

int main(int argc, char *argv[])
{
    char *p_str, *q_str;
    int times, bit_num = 1024;
    Bitset_t *p, *q, *n, *phi, *e, *d, *d_p, *d_q, *q_inv;
    Bitset_t *tmp1, *tmp2, *tmp3;

    char input;
    printf("0: Use default p, q.(p, q: 512 bits, n: 1024 bits)\n1:Use p.txt, q.txt(Decimal).\n2:Use p.txt, q.txt(Hexadecimal)\n3:Auto generate p and q.(Very slow.)\n");
    scanf("%c", &input);
    FILE *f;
    int tmp = 0, bit_num_tmp;
    switch (input)
    {
    case '0':
        NewBitset(&p, 512, MSB);
        NewBitset(&q, 512, MSB);
        NewBitset(&n, 1024, MSB);
        NewBitset(&phi, 1024, MSB);
        NewBitset(&e, 1024, MSB);
        NewBitset(&d, 1024, MSB);
        NewBitset(&d_p, 512, MSB);
        NewBitset(&d_q, 512, MSB);
        NewBitset(&q_inv, 512, MSB);

        p_str = p_def;
        q_str = q_def;
        SetBitset_HexString(p, p->bit_num - 1 - (512 - strlen(p_str) * 4), p_str);
        SetBitset_HexString(q, q->bit_num - 1 - (512 - strlen(q_str) * 4), q_str);
        break;
    case '1':
        printf("How many bits of n do you want?\n");
        printf("At least 64 bits or 2^k (k is positive integer).\n");
        scanf("%d", &bit_num);
        if (bit_num < 64)
        {
            printf("Wrong input.\n");
            return -1;
        }

        bit_num_tmp = bit_num;
        for (int ptr = 0; ptr < 32; ptr++)
        {
            if (bit_num_tmp & 0x1 == 1)
            {
                if (tmp == 0)
                {
                    tmp = 1;
                }
                else
                {
                    printf("Wrong input.\n");
                    return -1;
                }
            }
            bit_num_tmp >>= 1;
        }

        NewBitset(&p, bit_num >> 1, MSB);
        NewBitset(&q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&n, bit_num, MSB);
        NewBitset(&phi, bit_num, MSB);
        NewBitset(&e, bit_num, MSB);
        NewBitset(&d, bit_num, MSB);
        NewBitset(&d_p, bit_num >> 1, MSB);
        NewBitset(&d_q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&q_inv, bit_num - (bit_num >> 1), MSB);

        p_str = p_buf;
        q_str = q_buf;
        f = fopen("p.txt", "r");
        if (NULL == f)
        {
            fprintf(stderr, "Failed to open p.txt.\n");
            return -1;
        }
        else
        {
            fread(p_buf, 1, sizeof(p_buf), f);
        }
        fclose(f);

        f = fopen("q.txt", "r");
        if (NULL == f)
        {
            fprintf(stderr, "Failed to open q.txt.\n");
            return -1;
        }
        else
        {
            fread(q_buf, 1, sizeof(q_buf), f);
        }
        fclose(f);
        printf("Transfer p string to uint32_t.\n");
        SetBitset_CountingDecString(p, p_str);
        printf("Transfer q string to uint32_t.\n");
        SetBitset_CountingDecString(q, q_str);
        break;
    case '2':
        printf("How many bits of n do you want?\n");
        printf("At least 64 bits.\n");
        scanf("%d", &bit_num);
        if (bit_num < 64)
        {
            printf("Wrong input.\n");
            return -1;
        }

        bit_num_tmp = bit_num;
        for (int ptr = 0; ptr < 32; ptr++)
        {
            if (bit_num_tmp & 0x1 == 1)
            {
                if (tmp == 0)
                {
                    tmp = 1;
                }
                else
                {
                    printf("Wrong input.\n");
                    return -1;
                }
            }
            bit_num_tmp >>= 1;
        }

        NewBitset(&p, bit_num >> 1, MSB);
        NewBitset(&q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&n, bit_num, MSB);
        NewBitset(&phi, bit_num, MSB);
        NewBitset(&e, bit_num, MSB);
        NewBitset(&d, bit_num, MSB);
        NewBitset(&d_p, bit_num >> 1, MSB);
        NewBitset(&d_q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&q_inv, bit_num - (bit_num >> 1), MSB);

        p_str = p_buf;
        q_str = q_buf;
        f = fopen("p.txt", "r");
        if (NULL == f)
        {
            fprintf(stderr, "Failed to open p.txt.\n");
            return -1;
        }
        else
        {
            fread(p_buf, 1, sizeof(p_buf), f);
        }
        fclose(f);

        f = fopen("q.txt", "r");
        if (NULL == f)
        {
            fprintf(stderr, "Failed to open q.txt.\n");
            return -1;
        }
        else
        {
            fread(q_buf, 1, sizeof(q_buf), f);
        }
        fclose(f);
        SetBitset_CountingHexString(q, q_str);
        SetBitset_CountingHexString(p, p_str);
        break;
    case '3':
        printf("How many bits of n do you want?\n");
        printf("At least 64 bits.\n");
        printf("In this mode, I recommend the number of n not larger than 128 bits.\n");
        scanf("%d", &bit_num);
        if (bit_num < 64)
        {
            printf("Wrong input.\n");
            return -1;
        }

        bit_num_tmp = bit_num;
        for (int ptr = 0; ptr < 32; ptr++)
        {
            if (bit_num_tmp & 0x1 == 1)
            {
                if (tmp == 0)
                {
                    tmp = 1;
                }
                else
                {
                    printf("Wrong input.\n");
                    return -1;
                }
            }
            bit_num_tmp >>= 1;
        }

        NewBitset(&p, bit_num >> 1, MSB);
        NewBitset(&q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&n, bit_num, MSB);
        NewBitset(&phi, bit_num, MSB);
        NewBitset(&e, bit_num, MSB);
        NewBitset(&d, bit_num, MSB);
        NewBitset(&d_p, bit_num >> 1, MSB);
        NewBitset(&d_q, bit_num - (bit_num >> 1), MSB);
        NewBitset(&q_inv, bit_num - (bit_num >> 1), MSB);
        printf("Generate p.\n");

        times = 1;
        for (;;)
        {
            BitsetRandom(p, NULL);
            if (BitsetFermatTest(p, 5) == 1)
                if (BitsetMillerRabinTest(p, 1) == 1)
                    break;
        }
        printf("Generate q.\n");
        for (;;)
        {
            BitsetRandom(q, NULL);
            if (BitsetCmpWithoutNeg(p, q) == 0)
                continue;
            if (BitsetFermatTest(q, 5) == 1)
                if (BitsetMillerRabinTest(q, 1) == 1)
                    break;
        }
        break;
    default:
        printf("Wrong input.\n");
        return -1;
    }

    DebugPrintf("p", p);
    DebugPrintf("q", q);

    BitsetMul(n, p, q); // n = p * q
    DebugPrintf("n", n);

    SetBitset(p, 0, 0);   // p => p-1
    SetBitset(q, 0, 0);   // q => q-1
    BitsetMul(phi, p, q); // phi = (p-1) * (q-1)
    SetBitset(p, 0, 1);   // p-1 => p
    SetBitset(q, 0, 1);   // q-1 => q
    DebugPrintf("phi", phi);

    NewBitset(&tmp1, phi->bit_num, MSB);
    NewBitset(&tmp2, phi->bit_num << 2, MSB);
    BitsetSub(tmp1, phi, two); // tmp1 = phi - 2

    printf("\nGenerating e:\n");
    {
        int times = 0;
        for (;;)
        {
            times++;
            printf("Times: %d", times);
            fflush(stdout);
            BitsetRandom(e, tmp1);                       // e = 0 ~ ((phi - 2) - 1)
            BitsetAdd(e, e, two);                        // e = 2 ~ (phi-1)
            BitsetGCD(tmp2, e, phi);                     // tmp2 = gcd(e,phi)
            if (BitsetCmpWithoutNegUint32(tmp2, 1) == 0) // if(gcd(e,phi) == 1)
            {
                printf("\r                \r", times);
                break;
            }
            printf("\r");
        }
        DebugPrintf("e", e);
    }

    DelBitset(&tmp1);
    DelBitset(&tmp2);

    printf("\nGenerating d:\n");
    BitsetInverseMod(d, e, phi); // Use Extended Euclidean algorithm
    DebugPrintf("d", d);

    printf("\nGenerating :\n");

    NewBitset(&d_p, p->bit_num, MSB);
    NewBitset(&d_q, q->bit_num, MSB);
    SetBitset(p, 0, 0);   // p => p-1
    SetBitset(q, 0, 0);   // q => q-1
    BitsetMod(d_p, d, p); // d_p = d (mod (p-1))
    BitsetMod(d_q, d, q); // d_q = d (mod (q-1))
    SetBitset(p, 0, 1);   // p-1 => p
    SetBitset(q, 0, 1);   // q-1 => q

    NewBitset(&q_inv, p->bit_num, MSB);
    BitsetInverseMod(q_inv, q, p); // q_inv = q^-1 (mod p)

    DebugPrintf("q_inv", q_inv);
    DebugPrintf("d_p", d_p);
    DebugPrintf("d_q", d_q);

    // Encode and Decode
    Bitset_t *InputData, *m, *c, *m_tmp, *c_tmp;
    NewBitset(&m_tmp, n->bit_num / 2, MSB);
    NewBitset(&c_tmp, n->bit_num, MSB);
    for (;;)
    {
        char exit_flg = 0;
        for (;;)
        {
            char finish = 1;
            printf("\nPlease input what you want to encode.\nCan only be hex type.(0~9, a~f or A~F)\n");
            printf("If you want to exit, please enter \"exit\". : \n");
            scanf("%s", &input_data);
            if (strcmp(input_data, "exit") == 0)
            {
                exit_flg = 1;
                break;
            }
            else
            {
                for (int i = 0; i < strlen(input_data); ++i)
                {
                    if (!(input_data[i] >= '0' && input_data[i] <= '9'))
                        if (!(input_data[i] >= 'a' && input_data[i] <= 'f'))
                            if (!(input_data[i] >= 'A' && input_data[i] <= 'F'))
                            {
                                finish = 0;
                                break;
                            }
                }
                if (finish)
                    break;
                printf("ERROR: Input must be hex type(0~9, a~f or A~F).\n");
            }
        }
        if (exit_flg)
            break;
        printf(input_data);

        int size = strlen(input_data) << 2;
        NewBitset(&InputData, size, MSB);
        NewBitset(&m, size, MSB);
        int encode_size = n->array_num >> 1;
        int encode_bit_num = n->bit_num >> 1;
        int max = InputData->array_num / encode_size + (InputData->array_num % encode_size != 0);
        int first_bit_num = (InputData->bit_num % encode_bit_num != 0) ? InputData->bit_num % encode_bit_num : encode_bit_num;
        NewBitset(&c, max * n->bit_num, MSB);

        SetBitset_CountingHexString(InputData, input_data);
        DebugPrintf("InputData", InputData);

        printf("\nEncoding:\n"); // Encode: c = m^e mod n
        for (int times = 0; times < max; times++)
        {
            BitsetClear(m_tmp);

            if (times == 0)
                GetBitset_Bitset(m_tmp, first_bit_num - 1, InputData, InputData->bit_num - 1, (max - 1) * encode_bit_num, RANGE);
            else
                GetBitset_Bitset(m_tmp, m_tmp->bit_num - 1, InputData, (max - times) * encode_bit_num - 1, (max - 1 - times) * encode_bit_num, RANGE);

            printf("Encoding %d/%d\n", times + 1, max);
            RSA_Encode(c_tmp, m_tmp, e, n);

            for (int ptr = 0; ptr < c_tmp->array_num; ptr++)
            {
                BitsetData(c, ptr + times * n->array_num) = BitsetData(c_tmp, ptr);
            }
        }
        DebugPrintf("c", c);

        printf("\nDecoding:\n"); // Decode: (Use Chinese Remainder Theorem)
        // RSA_Decode(m, c,   p, q, q_inv, d_p, d_q);
        for (int times = 0; times < max; times++)
        {
            BitsetClear(c_tmp);

            GetBitset_Bitset(c_tmp, c_tmp->bit_num - 1, c, (max - times) * n->bit_num - 1, (max - 1 - times) * n->bit_num, RANGE);

            printf("Decoding %d/%d\n", times + 1, max);
            RSA_Decode(m_tmp, c_tmp, p, q, q_inv, d_p, d_q);

            if (times == 0)
            {
                GetBitset_Bitset(m, m->bit_num - 1, m_tmp, first_bit_num - 1, 0, RANGE);
            }
            else
            {
                GetBitset_Bitset(m, (max - times) * encode_bit_num - 1, m_tmp, m_tmp->bit_num - 1, 0, RANGE);
            }
        }
        DebugPrintf("m", m);

        DelBitset(&m);
        DelBitset(&InputData);
        printf("\n\n");
    }

    DelBitset(&m_tmp);
    DelBitset(&c_tmp);
    DelBitset(&p);
    DelBitset(&q);
    DelBitset(&c);
    DelBitset(&n);
    DelBitset(&phi);
    DelBitset(&e);
    DelBitset(&d);
    DelBitset(&d_p);
    DelBitset(&d_q);
    DelBitset(&q_inv);
    // system("pause");
    return 0;
}

int RSA_Encode(Bitset_t *c, Bitset_t *m, Bitset_t *e, Bitset_t *n)
{
    BitsetSquareAndMultiply_Mod(c, m, e, n); // c = m^e mod n
    return 0;
}

int RSA_Decode(Bitset_t *m, Bitset_t *c, Bitset_t *p, Bitset_t *q, Bitset_t *q_inv, Bitset_t *d_p, Bitset_t *d_q)
{
    // Use Chinese Remainder Theorem
    Bitset_t *tmp1;
    Bitset_t *m1, *m2, *h;
    NewBitset(&m1, p->bit_num, MSB);
    NewBitset(&m2, q->bit_num, MSB);
    NewBitset(&h, p->bit_num + q->bit_num, MSB);

    BitsetSquareAndMultiply_Mod(m1, c, d_p, p); // m1 = c^d_p mod p
    BitsetSquareAndMultiply_Mod(m2, c, d_q, q); // m2 = c^d_q mod q
    NewBitset(&tmp1, p->bit_num + q->bit_num, MSB);
    BitsetSub(tmp1, m1, m2);      // tmp1 = m1 - m2
    BitsetMul(tmp1, q_inv, tmp1); // tmp1 = q_inv * (m1 - m2)
    BitsetMod(h, tmp1, p);        // h = q_inv * (m1 - m2) (mod p)
    DelBitset(&tmp1);
    BitsetMul(h, h, q);  // h = h * q
    BitsetAdd(m, m2, h); // m = m2 * h

    DelBitset(&h);
    DelBitset(&m1);
    DelBitset(&m2);
    return 0;
}

char *StrInverse(char str[])
{
    int len = strlen(str);
    char *tmp = malloc(len + 1);

    tmp[0] = '\0';
    for (int ptr = len; ptr != -1, ptr--;)
    {
        sprintf(tmp, "%s%c", tmp, str[ptr]);
    }
    return tmp;
}

static void DebugPrintf(char *name, Bitset_t *bitset)
{
    // char str[9];
    // sprintf(str, "%8x", BitsetData(bitset, 0));

    printf("%s", name);
    int ptr, t;

    for (ptr = 16; ptr > strlen(name); ptr--)
    {
        printf(" ");
    }

    for (ptr = 0; ptr < 8; ptr++)
    {
        for (t = 0; t < 4; t++)
        {
            if (GetBitset(bitset, (bitset->array_num << 5) - (ptr << 2) - t - 1) == 0)
            {
                if (t == 3)
                {
                    printf(" ");
                }
                continue;
            }
            else
            {
                t = 5;
                break;
            }
        }
        if (t == 5)
        {
            printf("%x", BitsetData(bitset, 0));
            break;
        }
    }

    for (int ptr1 = 1; ptr1 < bitset->array_num; ptr1++)
    {
        for (ptr = 0; ptr < 8; ptr++)
        {
            for (t = 0; t < 4; t++)
            {
                if (GetBitset(bitset, ((bitset->array_num - ptr1) << 5) - (ptr << 2) - t - 1) == 0)
                {
                    if (t == 3)
                    {
                        printf("0");
                    }
                    continue;
                }
                else
                {
                    t = 5;
                    break;
                }
            }
            if (t == 5)
            {
                printf("%x", BitsetData(bitset, ptr1));
                break;
            }
        }
    }
    printf("\n");
}

int NewBitset(Bitset_t **bitset, uint32_t bit_num, BitsetMode_t mode)
{
    uint8_t last_array_bits = bit_num & 0x1f;
    uint32_t array_num = (bit_num >> 5) + (last_array_bits > 0);

    *bitset = calloc(1, sizeof(Bitset_t));

    if (*bitset == NULL)
    {
        fprintf(stderr, "Failed to new.\n");
        return -1;
    }

    (*bitset)->bit_data = NULL;
    (*bitset)->bit_data = calloc(array_num, sizeof(BitData_t));

    if ((*bitset)->bit_data != NULL)
    {
        (*bitset)->bit_num = bit_num;
        (*bitset)->mode = mode;
        (*bitset)->array_num = array_num;
        return 0;
    }
    else
    {
        fprintf(stderr, "Failed to new.\n");
        return -1;
    }
}

int DelBitset(Bitset_t **bitset)
{
    free((*bitset)->bit_data);
    free((*bitset));
    *bitset = NULL;
    return 0;
}

int SetBitset(Bitset_t *bitset, uint32_t bit, uint8_t set)
{
    if (bitset == NULL)
    {
        return -1;
    }
    if (bitset->bit_num <= bit)
    {
        return -2;
    }

    uint32_t tmp = 0x1;

    if (bitset->mode == MSB)
    {
        tmp = tmp << (bit & 0x1f);
        if (set)
        {
            BitsetData(bitset, bitset->array_num - (bit >> 5) - 1) |= tmp;
        }
        else
        {
            BitsetData(bitset, bitset->array_num - (bit >> 5) - 1) &= ~tmp;
        }
    }
    else
    {
        tmp = tmp << (31 - (bit & 0x1f));
        if (set)
        {
            BitsetData(bitset, bit >> 5) |= tmp;
        }
        else
        {
            BitsetData(bitset, bit >> 5) &= ~tmp;
        }
    }

    return 0;
}

int SetBitset_CountingCpy(Bitset_t *bitset_o, Bitset_t *bitset_i)
{
    BitsetClear(bitset_o);
    bitset_o->neg = bitset_i->neg;
    return SetBitset_Bitset(bitset_o, bitset_i->bit_num - 1, bitset_i, bitset_i->bit_num - 1, 0, RANGE);
}

int SetBitset_4Byte(Bitset_t *bitset, int start_bit, uint32_t set, uint8_t set_num)
{
    if (bitset == NULL)
    {
        return -1;
    }
    if (set_num > 32)
    {
        return -2;
    }

    uint32_t tmp;

    for (int ptr = 0; ptr < set_num; ptr++)
    {
        tmp = set;
        tmp <<= 32 - set_num + ptr;
        tmp >>= 31;

        if (bitset->mode == MSB)
        {
            if (start_bit - ptr >= 0)
                SetBitset(bitset, start_bit - ptr, tmp);
        }
        else
        {
            if (start_bit + ptr >= 0)
                SetBitset(bitset, start_bit + ptr, tmp);
        }
    }

    return 0;
}

int SetBitset_Bitset(Bitset_t *bitset, int start_bit, Bitset_t *bitset_in, uint32_t bitset_in_first_bit, uint32_t bitset_in_last_bit, Bitset_Bitmap_t mode)
{
    uint32_t tmp;
    uint32_t ptr;

    if (bitset == NULL)
    {
        return -1;
    }
    if (bitset_in == NULL)
    {
        return -2;
    }
    if (bitset_in_first_bit >= bitset_in->bit_num)
    {
        return -3;
    }
    if (bitset_in_last_bit >= bitset_in->bit_num)
    {
        return -4;
    }

    ptr = bitset_in_first_bit;
    uint32_t times = 0;
    while (1)
    {
        tmp = GetBitset(bitset_in, ptr);
        if (bitset->mode == MSB)
        {
            if (start_bit - times >= 0)
                SetBitset(bitset, start_bit - times, tmp);
        }
        else
        {
            if (start_bit + times >= 0)
                SetBitset(bitset, start_bit + times, tmp);
        }

        times++;
        if (ptr == bitset_in_last_bit)
            break;
        else
        {
            switch (mode)
            {
            case CYCLE:
                if (ptr == bitset_in->bit_num - 1)
                    ptr = 0;
                else
                    ptr++;
                break;
            case RANGE:
                if (bitset_in_first_bit > bitset_in_last_bit)
                    ptr--;
                else
                    ptr++;
                break;
            default:
                return -5; // Mode error
                break;
            }
        }
    }

    return 0;
}

int SetBitset_String(Bitset_t *bitset, int start_bit, char *str)
{
    if (bitset == NULL)
    {
        return -1;
    }

    for (int ptr = 0; ptr < strlen(str); ptr++)
    {
        if (bitset->mode == MSB)
        {
            if (start_bit - ptr >= 0)
                SetBitset_4Byte(bitset, start_bit - (ptr << 3), str[ptr], 8);
        }
        else
        {
            if (start_bit + ptr >= 0)
                SetBitset_4Byte(bitset, start_bit + (ptr << 3), str[ptr], 8);
        }
    }

    return 0;
}

int SetBitset_HexString(Bitset_t *bitset, int start_bit, char *str)
{
    if (bitset == NULL)
    {
        return -1;
    }

    int tmp;
    int len = strlen(str);
    for (int ptr = 0; ptr < len; ptr++)
    {
        printf("%3.2f%% \r", (float)ptr / (float)len * 100);
        tmp = CharToHex(str[ptr]);
        if (tmp >= 0)
        {
            if (bitset->mode == MSB)
            {
                if (start_bit - ptr >= 0)
                    SetBitset_4Byte(bitset, start_bit - (ptr << 2), tmp, 4);
            }
            else
            {
                if (start_bit + ptr >= 0)
                    SetBitset_4Byte(bitset, start_bit + (ptr << 2), tmp, 4);
            }
        }
        else
        {
            return -2; // Not in range
        }
    }
    printf("                 \r");
    fflush(stdout);

    return 0;
}

int SetBitset_CountingHexString(Bitset_t *bitset, char *str)
{
    if (bitset == NULL)
    {
        return -1;
    }

    BitsetClear(bitset);

    return SetBitset_HexString(bitset, (strlen(str) << 2) - 1, str);
}

int SetBitset_CountingUint32(Bitset_t *bitset, uint32_t data)
{
    if (bitset == NULL)
    {
        return -1;
    }

    BitsetClear(bitset);

    return SetBitset_4Byte(bitset, 31, data, 32);
}

int SetBitset_CountingDecString(Bitset_t *bitset, char str[])
{
    BitsetClear(bitset);
    char *str_tmp = StrInverse(str);

    Bitset_t *tmp, *ten;
    NewBitset(&tmp, bitset->bit_num, MSB);
    NewBitset(&ten, 4, MSB); //= 10
    BitsetData(ten, 0) = 10;

    int len = strlen(str);
    fflush(stdout);
    for (int str_ptr = 0; str_ptr < len; str_ptr++)
    {
        printf("%3.2f%% \r", (float)str_ptr / (float)len * 100);
        BitsetClear(tmp);
        BitsetData(tmp, tmp->array_num - 1) = str_tmp[str_ptr] - '0';
        for (int times = 0; times < str_ptr; times++)
        {
            BitsetMul(tmp, tmp, ten);
        }
        BitsetAdd(bitset, bitset, tmp);
    }
    printf("                 \r");
    fflush(stdout);

    free(str_tmp);
    DelBitset(&tmp);
    DelBitset(&ten);
    return 0;
}

uint32_t GetBitset(Bitset_t *bitset, uint32_t bit)
{
    uint32_t tmp0 = 0x1;
    uint32_t tmp1;

    if (bit >= bitset->bit_num)
        return 0;

    if (bitset->mode == MSB)
    {
        tmp0 = tmp0 << (bit & 0x1f);
        tmp1 = BitsetData(bitset, bitset->array_num - (bit >> 5) - 1);
        tmp1 = tmp1 & tmp0;
        tmp1 >>= (bit & 0x1f);
    }
    else
    {
        tmp0 = tmp0 << (31 - (bit & 0x1f));
        tmp1 = BitsetData(bitset, bit >> 5);
        tmp1 = tmp1 & tmp0;
        tmp1 >>= (31 - (bit & 0x1f));
    }

    return tmp1;
}

uint32_t GetBitset_4Byte(Bitset_t *bitset, int start_bit, uint8_t get_num)
{
    uint32_t tmp = 0;

    for (int ptr = 0; ptr < get_num; ptr++)
    {
        if (bitset->mode == MSB)
        {
            if (start_bit - ptr >= 0)
            {
                tmp <<= 1;
                tmp |= GetBitset(bitset, start_bit - ptr);
            }
        }
        else
        {
            if (start_bit + ptr >= 0)
            {
                tmp <<= 1;
                tmp |= GetBitset(bitset, start_bit + ptr);
            }
        }
    }

    return tmp;
}

uint32_t Bitset_DivideByUint32_ArrayNum(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit)
{
    uint32_t array_num = bitset->array_num;
    uint32_t first_ptr = BitsetPtr(bitset, first_bit);
    uint32_t last_ptr = BitsetPtr(bitset, last_bit);

    if (first_ptr > last_ptr)
    {
        last_ptr += array_num;
        return last_ptr - first_ptr + 1;
    }
    else if (first_ptr == last_ptr)
    {
        if (bitset->mode == MSB)
        {
            if (first_bit < last_bit)
            {
                last_ptr += array_num;
                return last_ptr - first_ptr + 1;
            }
            else
                return last_ptr - first_ptr + 1;
        }
        else
        {
            if (first_bit > last_bit)
            {
                last_ptr += array_num;
                return last_ptr - first_ptr + 1;
            }
            else
                return last_ptr - first_ptr + 1;
        }
    }
    else
    {
        return last_ptr - first_ptr + 1;
    }
}

int GetBitset_DivideByUint32(uint32_t *data_o, uint32_t *start_bit_o, uint32_t *bit_num_o, Bitset_t *bitset, uint32_t uint_array_ptr, uint32_t first_bit, uint32_t last_bit)
{
    if (bitset == NULL)
    {
        return -1;
    }

    uint32_t uint_array_num = Bitset_DivideByUint32_ArrayNum(bitset, first_bit, last_bit);
    uint32_t array_num = bitset->array_num;

    if (uint_array_ptr >= uint_array_num)
    {
        return -2;
    }
    if (first_bit >= bitset->bit_num)
    {
        return -3;
    }
    if (last_bit >= bitset->bit_num)
    {
        return -4;
    }

    uint32_t start_bit, bit_num, array_ptr, tmp;
    uint32_t first_ptr = BitsetPtr(bitset, first_bit);
    uint32_t last_ptr = BitsetPtr(bitset, last_bit);

    array_ptr = uint_array_ptr;
    array_ptr = (array_ptr + first_ptr);
    while (array_ptr >= array_num)
    {
        array_ptr -= array_num;
    }

    if (uint_array_ptr == 0)
    {
        start_bit = first_bit;

        if (bitset->mode == MSB)
        {
            if (uint_array_num == 1)
            {
                bit_num = start_bit - last_bit + 1;
            }
            else
            {
                tmp = array_num - array_ptr - 1;
                tmp <<= 5;
                bit_num = start_bit - tmp + 1;
            }
        }
        else
        {
            if (uint_array_num == 1)
            {
                bit_num = last_bit - start_bit + 1;
            }
            else
            {
                if (array_ptr == array_num - 1)
                {
                    bit_num = bitset->bit_num - start_bit;
                }
                else
                {
                    tmp = array_ptr + 1;
                    tmp <<= 5;
                    bit_num = tmp - start_bit;
                }
            }
        }
    }
    else if (uint_array_ptr == uint_array_num - 1)
    {
        if (bitset->mode == MSB)
        {
            if (array_ptr == 0)
            {
                start_bit = bitset->bit_num - 1;
            }
            else
            {
                tmp = array_num - array_ptr;
                tmp <<= 5;
                start_bit = tmp - 1;
            }
            bit_num = start_bit - last_bit + 1;
        }
        else
        {
            tmp = array_ptr;
            tmp <<= 5;
            start_bit = tmp;
            bit_num = last_bit - start_bit + 1;
        }
    }
    else
    {
        if (last_ptr <= first_ptr)
        {
            if (bitset->mode == MSB)
            {
                if (first_bit < last_bit)
                {
                    tmp = last_ptr + array_num;
                }
                else
                {
                    tmp = last_ptr;
                }
            }
            else
            {
                if (first_bit > last_bit)
                {
                    tmp = last_ptr + array_num;
                }
                else
                {
                    tmp = last_ptr;
                }
            }
        }
        else
        {
            tmp = last_ptr;
        }

        if (bitset->mode == MSB)
        {
            if ((array_ptr > first_ptr && array_ptr < tmp) || (last_bit > first_bit && array_ptr < last_ptr))
            {
                if (array_ptr == 0)
                {
                    start_bit = bitset->bit_num - 1;
                }
                else
                {
                    tmp = array_num - array_ptr;
                    tmp <<= 5;
                    start_bit = tmp - 1;
                }

                tmp = array_num - array_ptr - 1;
                tmp <<= 5;
                bit_num = start_bit - tmp + 1;
            }
            else
            {
                start_bit = 0;
                bit_num = 0;
            }
        }
        else
        {
            if ((array_ptr > first_ptr && array_ptr < tmp) || (last_bit < first_bit && array_ptr < last_ptr))
            {
                tmp = array_ptr;
                tmp <<= 5;
                start_bit = tmp;

                if (array_ptr == array_num - 1)
                {
                    bit_num = bitset->bit_num - start_bit;
                }
                else
                {
                    bit_num = 32;
                }
            }
            else
            {
                start_bit = 0;
                bit_num = 0;
            }
        }
    }

    if (data_o != NULL)
        *data_o = GetBitset_4Byte(bitset, start_bit, bit_num);
    if (start_bit_o != NULL)
        *start_bit_o = start_bit;
    if (bit_num_o != NULL)
        *bit_num_o = bit_num;

    return 0;
}

int GetBitset_Bitset(Bitset_t *bitset_get, int start_bit, Bitset_t *bitset_in, uint32_t bitset_in_first_bit, uint32_t bitset_in_last_bit, Bitset_Bitmap_t mode)
{
    uint32_t tmp;

    if (bitset_get == NULL)
    {
        return -1;
    }
    if (bitset_in == NULL)
    {
        return -2;
    }
    if (bitset_in_first_bit >= bitset_in->bit_num)
    {
        return -3;
    }
    if (bitset_in_last_bit >= bitset_in->bit_num)
    {
        return -4;
    }

    int ptr = bitset_in_first_bit;
    int times = 0;
    while (1)
    {
        if (bitset_get->mode == MSB)
        {
            if (start_bit - times >= 0)
            {
                tmp = GetBitset(bitset_in, ptr);
                SetBitset(bitset_get, start_bit - times, tmp);
            }
        }
        else
        {
            if (start_bit + times >= 0)
            {
                tmp = GetBitset(bitset_in, ptr);
                SetBitset(bitset_get, start_bit + times, tmp);
            }
        }

        times++;
        if (ptr == bitset_in_last_bit)
            break;
        else
        {
            switch (mode)
            {
            case CYCLE:
                if (ptr == bitset_in->bit_num - 1)
                    ptr = 0;
                else
                    ptr++;
                break;
            case RANGE:
                if (bitset_in_first_bit > bitset_in_last_bit)
                    ptr--;
                else
                    ptr++;
                break;
            default:
                return -5; // Mode error
                break;
            }
        }
    }

    return 0;
}

int BitsetToString(char *str_o, Bitset_t *bitset, int start_bit, uint32_t bit_num)
{
    if (bitset == NULL)
    {
        return -1;
    }
    if (str_o == NULL)
    {
        return -2;
    }

    uint32_t str_times = bit_num;
    str_times >>= 3;
    str_times += (bit_num & 0xf) > 0;

    uint32_t tmp;
    uint32_t ptr;
    for (ptr = 0; ptr < str_times; ptr++)
    {
        tmp = ptr;
        tmp <<= 3;

        if (bitset->mode == MSB)
        {
            if (start_bit - tmp < 0)
                break;
            str_o[ptr] = GetBitset_4Byte(bitset, start_bit - tmp, 8);
        }
        else
        {
            if (start_bit + tmp >= bitset->bit_num)
                break;
            str_o[ptr] = GetBitset_4Byte(bitset, start_bit + tmp, 8);
        }
    }
    str_o[ptr] = '\0';

    return 0;
}

int BitsetToHexString(char *str_o, Bitset_t *bitset, int start_bit, uint32_t bit_num)
{
    if (bitset == NULL)
    {
        return -1;
    }
    if (str_o == NULL)
    {
        return -2;
    }

    uint32_t str_times = bit_num;
    str_times >>= 2;
    str_times += (bit_num & 0x3) > 0;

    uint32_t tmp;
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t ptr;
    for (ptr = 0; ptr < str_times; ptr++)
    {
        tmp = ptr;
        tmp <<= 2;

        if (bitset->mode == MSB)
        {
            if (start_bit - tmp < 0)
                break;
            tmp = GetBitset_4Byte(bitset, start_bit - tmp, 4);
        }
        else
        {
            if (start_bit + tmp >= bitset->bit_num)
                break;
            tmp = GetBitset_4Byte(bitset, start_bit + tmp, 4);
        }

        tmp1 = 9;
        tmp2 = 0;
        if (InRange(&tmp, &tmp1, &tmp2, UINT32_T) == 0)
        {
            tmp += '0';
        }

        tmp1 = 15;
        tmp2 = 10;
        if (InRange(&tmp, &tmp1, &tmp2, UINT32_T) == 0)
        {
            tmp += 'a' - 10;
        }

        str_o[ptr] = tmp;
    }

    str_o[ptr] = '\0';
    return 0;
}

int LeftShiftBitset(Bitset_t *bitset, int offset, Bitset_Bitmap_t mode)
{
    uint32_t tmp;

    if (bitset == NULL)
    {
        return -1;
    }

    switch ((int)mode)
    {
    case CYCLE:         // First bit is set to last
        if (offset > 0) // left shift
        {
            while (offset-- > 0)
            {
                if (bitset->mode == MSB)
                {
                    tmp = GetBitset(bitset, bitset->bit_num - 1);
                }
                else
                {
                    tmp = GetBitset(bitset, 0);
                }

                LeftShiftBitset_s(bitset);

                if (bitset->mode == MSB)
                {
                    tmp = SetBitset(bitset, 0, tmp);
                }
                else
                {
                    tmp = SetBitset(bitset, bitset->bit_num - 1, tmp);
                }
            }
        }
        else if (offset < 0) // right shift
        {
            while (offset++ < 0)
            {
                if (bitset->mode == MSB)
                {
                    tmp = GetBitset(bitset, 0);
                }
                else
                {
                    tmp = GetBitset(bitset, bitset->bit_num - 1);
                }

                RightShiftBitset_s(bitset);

                if (bitset->mode == MSB)
                {
                    tmp = SetBitset(bitset, bitset->bit_num - 1, tmp);
                }
                else
                {
                    tmp = SetBitset(bitset, 0, tmp);
                }
            }
        }
        break;
    case NORMAL:
        if (offset > 0)
        {
            while (offset-- > 0)
            {
                LeftShiftBitset_s(bitset);
            }
        }
        else
        {
            while (offset++ < 0)
            {
                RightShiftBitset_s(bitset);
            }
        }
        break;
    default:
        return -2;
        break;
    }

    return 0;
}

int LeftShiftBitset_Range(Bitset_t *bitset, int offset, uint32_t first_bit, uint32_t last_bit, Bitset_Bitmap_t mode)
{
    uint32_t tmp;

    if (bitset == NULL)
    {
        return -1;
    }
    if (first_bit >= bitset->bit_num)
    {
        return -2; // Larger than range
    }
    if (last_bit >= bitset->bit_num)
    {
        return -3; // Larger than range
    }

    switch ((int)mode)
    {
    case CYCLE:
        if (offset > 0)
        {
            while (offset-- > 0)
            {
                tmp = GetBitset(bitset, first_bit);
                LeftShiftBitset_Range_s(bitset, first_bit, last_bit);
                SetBitset(bitset, last_bit, tmp);
            }
        }
        else
        {
            while (offset++ < 0)
            {
                tmp = GetBitset(bitset, last_bit);
                RightShiftBitset_Range_s(bitset, first_bit, last_bit);
                SetBitset(bitset, first_bit, tmp);
            }
        }
        break;
    case NORMAL:
        if (offset > 0)
        {
            while (offset-- > 0)
            {
                LeftShiftBitset_Range_s(bitset, first_bit, last_bit);
            }
        }
        else
        {
            while (offset++ < 0)
            {
                RightShiftBitset_Range_s(bitset, first_bit, last_bit);
            }
        }
        break;
    default:
        return -4;
        break;
    }

    return 0;
}

int InsertBitsetBits_uint32(Bitset_t *bitset, uint32_t start_bit, uint32_t data, uint8_t data_num)
{
    if (bitset == NULL)
    {
        return -1;
    }

    uint32_t data_num_tmp = data_num;

    while (data_num_tmp-- > 0)
    {
        if (bitset->mode == MSB)
        {
            LeftShiftBitset_Range(bitset, 1, bitset->bit_num - 1, start_bit, NORMAL);
            SetBitset_4Byte(bitset, start_bit + data_num - 1, data, data_num);
        }
        else
        {
            LeftShiftBitset_Range(bitset, -1, start_bit, bitset->bit_num - 1, NORMAL);
            SetBitset_4Byte(bitset, start_bit, data, data_num);
        }
    }

    return 0;
}

int DelBitsetBits(Bitset_t *bitset, uint32_t start_bit, uint32_t del_num)
{
    if (bitset == NULL)
    {
        return -1;
    }

    while (del_num-- > 0)
    {
        if (bitset->mode == MSB)
        {
            LeftShiftBitset_Range(bitset, -1, bitset->bit_num - 1, start_bit, NORMAL);
        }
        else
        {
            LeftShiftBitset_Range(bitset, 1, start_bit, bitset->bit_num - 1, NORMAL);
        }
    }

    return 0;
}

int BitsetCmpWithNeg(Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    if (bitset_1->neg > bitset_2->neg)
        return -1;
    if (bitset_1->neg < bitset_2->neg)
        return 1;

    // Must be MSB
    //  -1: 1  < 2
    //   0: 1 == 2
    //   1: 1  > 2
    int flg_1num_bigger_2num = (bitset_1->array_num > bitset_2->array_num);
    int num = (flg_1num_bigger_2num) ? bitset_1->array_num : bitset_2->array_num;
    int bitset_1_ptr = (flg_1num_bigger_2num) ? 0 : bitset_1->array_num - bitset_2->array_num;
    int bitset_2_ptr = (flg_1num_bigger_2num) ? bitset_2->array_num - bitset_1->array_num : 0;

    uint32_t cmp1, cmp2;
    while (1)
    {
        cmp1 = (bitset_1_ptr >= 0) ? BitsetData(bitset_1, bitset_1_ptr) : 0;
        cmp2 = (bitset_2_ptr >= 0) ? BitsetData(bitset_2, bitset_2_ptr) : 0;

        if (cmp1 < cmp2)
        {
            if (bitset_1->neg == 1)
            {
                return 1;
            }
            return -1;
        }
        else if (cmp1 > cmp2)
        {
            if (bitset_1->neg == 1)
            {
                return -1;
            }
            return 1;
        }

        bitset_1_ptr++;
        bitset_2_ptr++;
        if (bitset_1_ptr == bitset_1->array_num)
            break;
        if (bitset_2_ptr == bitset_2->array_num)
            break;
    }
    return 0;
}

int BitsetCmpWithoutNeg(Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    // Must be MSB
    //  -1: 1  < 2
    //   0: 1 == 2
    //   1: 1  > 2
    int flg_1num_bigger_2num = (bitset_1->array_num > bitset_2->array_num);
    int num = (flg_1num_bigger_2num) ? bitset_1->array_num : bitset_2->array_num;
    int bitset_1_ptr = (flg_1num_bigger_2num) ? 0 : bitset_1->array_num - bitset_2->array_num;
    int bitset_2_ptr = (flg_1num_bigger_2num) ? bitset_2->array_num - bitset_1->array_num : 0;

    uint32_t cmp1, cmp2;
    while (1)
    {
        cmp1 = (bitset_1_ptr >= 0) ? BitsetData(bitset_1, bitset_1_ptr) : 0;
        cmp2 = (bitset_2_ptr >= 0) ? BitsetData(bitset_2, bitset_2_ptr) : 0;

        if (cmp1 < cmp2)
        {
            return -1;
        }
        else if (cmp1 > cmp2)
        {
            return 1;
        }

        bitset_1_ptr++;
        bitset_2_ptr++;
        if (bitset_1_ptr == bitset_1->array_num)
            break;
        if (bitset_2_ptr == bitset_2->array_num)
            break;
    }
    return 0;
}
int BitsetCmpWithoutNegUint32(Bitset_t *bitset_cmp, uint32_t uint32_in)
{
    // Must be MSB
    //  -1: 1  < 2
    //   0: 1 == 2
    //   1: 1  > 2

    int ptr;

    for (ptr = 0; ptr != bitset_cmp->array_num - 1; ptr++)
    {
        if (BitsetData(bitset_cmp, ptr) != 0)
            break;
    }

    if (ptr == bitset_cmp->array_num - 1)
    {
        if (BitsetData(bitset_cmp, ptr) == uint32_in)
            return 0;
        else if (BitsetData(bitset_cmp, ptr) > uint32_in)
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return 1;
    }
}

int BitsetClear(Bitset_t *bitset)
{
    for (int ptr = 0; ptr < bitset->array_num; ptr++)
    {
        BitsetData(bitset, ptr) = 0;
    }
    bitset->neg = 0;
    return 0;
}

int BitsetAdd(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    if (bitset_1->neg > bitset_2->neg)
    {
        bitset_1->neg = 0;
        BitsetSub(bitset_o, bitset_2, bitset_1);
        bitset_1->neg = 1;

        bitset_o->neg = (bitset_o->neg == 1) ? 0 : 1;
        return 0;
    }
    if (bitset_1->neg < bitset_2->neg)
    {
        BitsetSub(bitset_o, bitset_1, bitset_2);
        return 0;
    }
    // All bit num % 32 must == 0
    // Must be MSB

    Bitset_t *bitset_tmp;
    int num = (bitset_1->bit_num > bitset_2->bit_num) ? bitset_1->bit_num : bitset_2->bit_num;
    NewBitset(&bitset_tmp, num + 32, MSB);

    SetBitset_CountingCpy(bitset_tmp, bitset_1);

    int bitset_tmp_ptr, bitset_2_ptr = bitset_2->array_num - 1;
    uint32_t bitset_tmp_data, bitset_2_data;
    uint64_t sum_tmp;
    uint32_t c = 0;
    for (bitset_tmp_ptr = bitset_tmp->array_num - 1; bitset_tmp_ptr >= 0; bitset_tmp_ptr--)
    {
        bitset_tmp_data = BitsetData(bitset_tmp, bitset_tmp_ptr);
        if (bitset_2_ptr >= 0)
        {
            bitset_2_data = BitsetData(bitset_2, bitset_2_ptr);
            bitset_2_ptr--;
        }
        else
        {
            bitset_2_data = 0;
        }

        sum_tmp = (uint64_t)bitset_tmp_data + (uint64_t)bitset_2_data + (uint64_t)c;
        BitsetData(bitset_tmp, bitset_tmp_ptr) = (uint32_t)(sum_tmp & 0xffffffff);
        c = (uint32_t)(sum_tmp >> 32);
    }

    SetBitset_CountingCpy(bitset_o, bitset_tmp);

    if (bitset_1->neg == 1)
        bitset_o->neg = 1;
    DelBitset(&bitset_tmp);
    return 0;
}
int BitsetSub(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    if (bitset_1->neg > bitset_2->neg)
    {
        bitset_2->neg = 1;
        BitsetAdd(bitset_o, bitset_1, bitset_2);
        bitset_2->neg = 0;
        return 0;
    }
    if (bitset_1->neg < bitset_2->neg)
    {
        bitset_2->neg = 0;
        BitsetAdd(bitset_o, bitset_1, bitset_2);
        bitset_2->neg = 1;
        return 0;
    }

    // return 1 = negtive
    // All bit num % 32 must == 0
    // Must be MSB

    Bitset_t *bitset_tmp;
    int cmp_flg = BitsetCmpWithoutNeg(bitset_1, bitset_2);
    if (cmp_flg == 0) // same
    {
        BitsetClear(bitset_o);
        return 0;
    }
    else if (cmp_flg == -1) // 1 less than 2
    {
        bitset_tmp = bitset_1;
        bitset_1 = bitset_2;
        bitset_2 = bitset_tmp;
    }

    int num = (bitset_1->bit_num > bitset_2->bit_num) ? bitset_1->bit_num : bitset_2->bit_num;
    NewBitset(&bitset_tmp, num, MSB);

    SetBitset_CountingCpy(bitset_tmp, bitset_1);

    int bitset_tmp_ptr, bitset_2_ptr = bitset_2->array_num - 1;
    uint32_t bitset_tmp_data, bitset_2_data;
    uint32_t c = 0;
    for (bitset_tmp_ptr = bitset_tmp->array_num - 1; bitset_tmp_ptr >= 0; bitset_tmp_ptr--)
    {
        bitset_tmp_data = BitsetData(bitset_tmp, bitset_tmp_ptr);
        if (bitset_2_ptr >= 0)
        {
            bitset_2_data = BitsetData(bitset_2, bitset_2_ptr);
            bitset_2_ptr--;
        }
        else
        {
            bitset_2_data = 0;
        }

        BitsetData(bitset_tmp, bitset_tmp_ptr) = bitset_tmp_data - bitset_2_data - c;
        if (bitset_tmp_data < bitset_2_data)
        {
            c = 1;
        }
        else
        {
            if (bitset_tmp_data == bitset_2_data && c)
                c = 1;
            else
                c = 0;
        }
    }
    SetBitset_CountingCpy(bitset_o, bitset_tmp);

    DelBitset(&bitset_tmp);

    if (bitset_1->neg == 1) //(-a) - (-b)
    {
        if (cmp_flg == -1) // 1 is bigger than 2
        {
            bitset_o->neg = 0;
        }
        else // 1 is smaller than 2
        {
            bitset_o->neg = 1;
        }
    }
    else
    {
        if (cmp_flg == -1) // 1 is smaller than 2
        {
            bitset_o->neg = 1;
        }
        else // 1 is bigger than 2
        {
            bitset_o->neg = 0;
        }
    }
    return 0;
}

Bitset_t *Karatsuba(Bitset_t *num1, Bitset_t *num2) // array num of num1 & num2 must be the same
{
    Bitset_t *res;
    NewBitset(&res, (num1->array_num << 1) << 5, MSB);

    {
        int ptr;

        for (ptr = 0; ptr != num1->array_num - 1; ptr++)
        {
            if (BitsetData(num1, ptr) != 0)
                break;
        }

        if (ptr == num1->array_num - 1)
        {
            if (BitsetData(num1, ptr) == 0)
            {
                return res;
            }
            else if (BitsetData(num1, ptr) == 1)
            {
                SetBitset_CountingCpy(res, num2);
                return res;
            }
        }

        for (ptr = 0; ptr != num2->array_num - 1; ptr++)
        {
            if (BitsetData(num2, ptr) != 0)
                break;
        }

        if (ptr == num2->array_num - 1)
        {
            if (BitsetData(num2, ptr) == 0)
            {
                return res;
            }
            else if (BitsetData(num2, ptr) == 1)
            {
                SetBitset_CountingCpy(res, num1);
                return res;
            }
        }
    }

    // 1*1
    if (num1->array_num == 1)
    {
        uint64_t tmp;
        tmp = (uint64_t)num1->bit_data[0] * (uint64_t)num2->bit_data[0];
        res->bit_data[0] = tmp >> 32;
        res->bit_data[1] = tmp & 0xffffffff;
        return res;
    }

    // 2*2
    if (num1->array_num == 2)
    {
        uint64_t m[2][2];
        uint64_t tmp;
        m[0][0] = (uint64_t)num1->bit_data[0] * (uint64_t)num2->bit_data[0];
        m[0][1] = (uint64_t)num1->bit_data[0] * (uint64_t)num2->bit_data[1];
        m[1][0] = (uint64_t)num1->bit_data[1] * (uint64_t)num2->bit_data[0];
        m[1][1] = (uint64_t)num1->bit_data[1] * (uint64_t)num2->bit_data[1];

        res->bit_data[3] = m[1][1] & 0xffffffff;
        tmp = (m[1][0] & 0xffffffff) + (m[0][1] & 0xffffffff) + (m[1][1] >> 32);
        res->bit_data[2] = tmp & 0xffffffff;
        tmp >>= 32;
        tmp = (m[0][1] >> 32) + (m[1][0] >> 32) + m[0][0] + tmp;
        res->bit_data[1] = tmp & 0xffffffff;
        res->bit_data[0] = tmp >> 32;

        return res;
    }

    // 2*2
    if ((num1->array_num == 3 && num1->bit_data[0] == 0 && num2->bit_data[0] == 0))
    {
        uint64_t m[2][2];
        uint64_t tmp;
        m[0][0] = (uint64_t)num1->bit_data[1] * (uint64_t)num2->bit_data[1];
        m[0][1] = (uint64_t)num1->bit_data[1] * (uint64_t)num2->bit_data[2];
        m[1][0] = (uint64_t)num1->bit_data[2] * (uint64_t)num2->bit_data[1];
        m[1][1] = (uint64_t)num1->bit_data[2] * (uint64_t)num2->bit_data[2];

        res->bit_data[5] = m[1][1] & 0xffffffff;
        tmp = (m[1][0] & 0xffffffff) + (m[0][1] & 0xffffffff) + (m[1][1] >> 32);
        res->bit_data[4] = tmp & 0xffffffff;
        tmp >>= 32;
        tmp = (m[0][1] >> 32) + (m[1][0] >> 32) + m[0][0] + tmp;
        res->bit_data[3] = tmp & 0xffffffff;
        res->bit_data[2] = tmp >> 32;

        return res;
    }

    int mid = num1->array_num >> 1;
    uint32_t size;

    Bitset_t *x1;
    size = num1->array_num - mid;
    NewBitset(&x1, size << 5, MSB);
    for (int ptr = 0; ptr != size; ptr++)
    {
        BitsetData(x1, ptr) = BitsetData(num1, ptr);
    }

    Bitset_t *x0;
    size = mid;
    NewBitset(&x0, size << 5, MSB);
    for (int ptr = 0; ptr != size; ptr++)
    {
        BitsetData(x0, ptr) = BitsetData(num1, num1->array_num - mid + ptr);
    }

    Bitset_t *y1;
    size = num2->array_num - mid;
    NewBitset(&y1, size << 5, MSB);
    for (int ptr = 0; ptr != size; ptr++)
    {
        BitsetData(y1, ptr) = BitsetData(num2, ptr);
    }

    Bitset_t *y0;
    size = mid;
    NewBitset(&y0, size << 5, MSB);
    for (int ptr = 0; ptr != size; ptr++)
    {
        BitsetData(y0, ptr) = BitsetData(num2, num1->array_num - mid + ptr);
    }

    Bitset_t *x1_add_x0;
    size = x1->array_num + 1;
    NewBitset(&x1_add_x0, size << 5, MSB);
    BitsetAdd(x1_add_x0, x1, x0);

    Bitset_t *y1_add_y0;
    size = y1->array_num + 1;
    NewBitset(&y1_add_y0, size << 5, MSB);
    BitsetAdd(y1_add_y0, y1, y0);

    Bitset_t *z0 = Karatsuba(x0, y0);
    Bitset_t *z1 = Karatsuba(x1_add_x0, y1_add_y0);
    Bitset_t *z2 = Karatsuba(x1, y1);

    DelBitset(&x1);
    DelBitset(&x0);
    DelBitset(&y1);
    DelBitset(&y0);
    DelBitset(&x1_add_x0);
    DelBitset(&y1_add_y0);

    BitsetSub(z1, z1, z2);
    BitsetSub(z1, z1, z0);

    int max;
    Bitset_t *r1;
    size = res->array_num;
    NewBitset(&r1, size << 5, MSB);
    max = (int)r1->array_num - mid;
    for (int ptr = 1; ptr <= max && ptr <= (int)z1->array_num; ptr++)
    {
        BitsetData(r1, max - ptr) = BitsetData(z1, (int)z1->array_num - ptr);
    }
    DelBitset(&z1);

    Bitset_t *r2;
    size = res->array_num;
    NewBitset(&r2, size << 5, MSB);
    max = (int)r2->array_num - (mid << 1);
    for (int ptr = 1; ptr <= max; ptr++)
    {
        BitsetData(r2, max - ptr) = BitsetData(z2, (int)z2->array_num - ptr);
    }
    DelBitset(&z2);

    BitsetAdd(res, r1, r2);
    DelBitset(&r1);
    DelBitset(&r2);

    BitsetAdd(res, res, z0);
    DelBitset(&z0);

    return res;
}

int BitsetMul(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{

    uint32_t array_num1, array_num2;
    Bitset_t *bitset_mul1, *bitset_mul2;

    for (array_num1 = bitset_1->array_num; array_num1 != 1; array_num1--)
    {
        if (BitsetData(bitset_1, bitset_1->array_num - array_num1) != 0)
            break;
    }
    if (array_num1 == 1)
    {
        if (BitsetData(bitset_1, bitset_1->array_num - 1) == 0)
        {
            BitsetClear(bitset_o);
            return 0;
        }
        else if (BitsetData(bitset_1, bitset_1->array_num - 1) == 1)
        {
            NewBitset(&bitset_mul1, bitset_2->bit_num, MSB);
            SetBitset_CountingCpy(bitset_mul1, bitset_2);

            BitsetClear(bitset_o);
            SetBitset_CountingCpy(bitset_o, bitset_mul1);
            DelBitset(&bitset_mul1);
            if (bitset_1->neg != bitset_2->neg)
                bitset_o->neg = 1;
            return 0;
        }
    }

    for (array_num2 = bitset_2->array_num; array_num2 != 1; array_num2--)
    {
        if (BitsetData(bitset_2, bitset_2->array_num - array_num2) != 0)
            break;
    }
    if (array_num2 == 1)
    {
        if (BitsetData(bitset_2, bitset_2->array_num - 1) == 0)
        {
            BitsetClear(bitset_o);
            return 0;
        }
        else if (BitsetData(bitset_2, bitset_2->array_num - 1) == 1)
        {
            NewBitset(&bitset_mul1, bitset_1->bit_num, MSB);
            SetBitset_CountingCpy(bitset_mul1, bitset_1);

            BitsetClear(bitset_o);
            SetBitset_CountingCpy(bitset_o, bitset_mul1);
            DelBitset(&bitset_mul1);
            if (bitset_1->neg != bitset_2->neg)
                bitset_o->neg = 1;
            return 0;
        }
    }

    array_num1 = (array_num1 > array_num2) ? array_num1 << 1 : array_num2 << 1;

    NewBitset(&bitset_mul1, array_num1 << 5, MSB);
    NewBitset(&bitset_mul2, array_num1 << 5, MSB);
    SetBitset_CountingCpy(bitset_mul1, bitset_1);
    SetBitset_CountingCpy(bitset_mul2, bitset_2);

    Bitset_t *res = Karatsuba(bitset_mul1, bitset_mul2);

    DelBitset(&bitset_mul1);
    DelBitset(&bitset_mul2);

    if (bitset_1->neg != bitset_2->neg)
        res->neg = 1;
    SetBitset_CountingCpy(bitset_o, res);
    DelBitset(&res);

    return 0;
}
int BitsetDiv(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    if (BitsetCmpWithoutNegUint32(bitset_2, 0) == 0)
    {
        BitsetClear(bitset_o);
        return -1;
    }

    Bitset_t *bitset_o_tmp, *bitset_tmp, *bitset_tmp2;
    int cmp_flg;

    int num = (bitset_1->bit_num > bitset_2->bit_num) ? bitset_1->bit_num : bitset_2->bit_num;
    NewBitset(&bitset_o_tmp, num, MSB);
    NewBitset(&bitset_tmp, num, MSB);
    NewBitset(&bitset_tmp2, num, MSB);
    num = bitset_tmp->array_num;

    SetBitset_CountingCpy(bitset_o_tmp, bitset_1);

    uint32_t max_bit_ptr1, max_bit_ptr2;
    max_bit_ptr2 = GetBitset_MaxBitPtr(bitset_2);

    BitsetClear(bitset_o);

    while (1)
    {
        SetBitset_CountingCpy(bitset_tmp, bitset_2);
        max_bit_ptr1 = GetBitset_MaxBitPtr(bitset_o_tmp);

        if (max_bit_ptr1 < max_bit_ptr2)
        {
            break;
        }
        else if (max_bit_ptr1 == max_bit_ptr2)
        {
            cmp_flg = BitsetCmpWithoutNeg(bitset_o_tmp, bitset_tmp);
            if (cmp_flg >= 0)
            {
                SetBitset(bitset_o, 0, 1);
            }
            break;
        }
        else
        {
            SetBitset_CountingCpy(bitset_tmp2, one);
            LeftShiftBitset(bitset_tmp, max_bit_ptr1 - max_bit_ptr2, NORMAL);
            LeftShiftBitset(bitset_tmp2, max_bit_ptr1 - max_bit_ptr2, NORMAL);
            cmp_flg = BitsetCmpWithoutNeg(bitset_o_tmp, bitset_tmp);
            if (cmp_flg == -1)
            {
                LeftShiftBitset(bitset_tmp, -1, NORMAL);
                LeftShiftBitset(bitset_tmp2, -1, NORMAL);
            }
            BitsetSub(bitset_o_tmp, bitset_o_tmp, bitset_tmp);

            BitsetAdd(bitset_o, bitset_o, bitset_tmp2);
        }
    }

    DelBitset(&bitset_tmp2);
    DelBitset(&bitset_o_tmp);
    DelBitset(&bitset_tmp);
    return 0;
}
int BitsetMod(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    if (BitsetCmpWithoutNegUint32(bitset_2, 0) == 0)
    {
        BitsetClear(bitset_o);
        return -1;
    }

    Bitset_t *bitset_o_tmp, *bitset_tmp;

    int num = (bitset_1->bit_num > bitset_2->bit_num) ? bitset_1->bit_num : bitset_2->bit_num;
    NewBitset(&bitset_o_tmp, num, MSB);
    NewBitset(&bitset_tmp, num, MSB);
    num = bitset_tmp->array_num;

    SetBitset_CountingCpy(bitset_o_tmp, bitset_1);
    int neg = 0;
    if (bitset_o_tmp->neg == 1)
    {
        bitset_o_tmp->neg = 0;
        neg = 1;
    }
    int max_bit_ptr1, max_bit_ptr2, minus_max_bit, cmp_flg;
    uint32_t data1, data2;
    max_bit_ptr2 = GetBitset_MaxBitPtr(bitset_2);
    max_bit_ptr1 = GetBitset_MaxBitPtr(bitset_o_tmp);

    SetBitset_CountingCpy(bitset_tmp, bitset_2);
    LeftShiftBitset(bitset_tmp, max_bit_ptr1 - max_bit_ptr2, NORMAL);
    minus_max_bit = max_bit_ptr1;
    while (1)
    {
        if (max_bit_ptr1 <= max_bit_ptr2)
        {
            if (max_bit_ptr1 == max_bit_ptr2)
            {
                RightShiftBitset_s(bitset_tmp);
                cmp_flg = BitsetCmpWithoutNeg(bitset_o_tmp, bitset_2);
                if (cmp_flg == 1)
                    BitsetSub(bitset_o_tmp, bitset_o_tmp, bitset_2);
                else if (cmp_flg == 0)
                {
                    BitsetClear(bitset_o);
                    break;
                }
            }

            if (neg == 1)
            {
                BitsetSub(bitset_o_tmp, bitset_2, bitset_o_tmp);
            }

            BitsetClear(bitset_o);
            SetBitset_CountingCpy(bitset_o, bitset_o_tmp);
            break;
        }
        else
        {
            LeftShiftBitset(bitset_tmp, max_bit_ptr1 - minus_max_bit, NORMAL);
            minus_max_bit = max_bit_ptr1;
            for (cmp_flg = (max_bit_ptr1 >> 5) + 1; cmp_flg != -1; cmp_flg--)
            {
                data1 = BitsetData(bitset_o_tmp, (bitset_o_tmp->array_num - cmp_flg));
                data2 = BitsetData(bitset_tmp, (bitset_tmp->array_num - cmp_flg));
                if (data1 < data2)
                {
                    // bitset_o_tmp < bitset_tmp
                    RightShiftBitset_s(bitset_tmp);
                    minus_max_bit--;
                    break;
                }
                if ((data1 > data2))
                {
                    break;
                }
            }
            BitsetSub(bitset_o_tmp, bitset_o_tmp, bitset_tmp);
        }

        max_bit_ptr1 = GetBitset_MaxBitPtr(bitset_o_tmp);
    }

    DelBitset(&bitset_o_tmp);
    DelBitset(&bitset_tmp);
    return 0;
}
int BitsetGCD(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    Bitset_t *bitset_1_tmp, *bitset_2_tmp;
    int num = (bitset_1->bit_num > bitset_2->bit_num) ? bitset_1->bit_num : bitset_2->bit_num;
    NewBitset(&bitset_1_tmp, num, MSB);
    NewBitset(&bitset_2_tmp, num, MSB);
    SetBitset_CountingCpy(bitset_1_tmp, bitset_1);
    SetBitset_CountingCpy(bitset_2_tmp, bitset_2);
    gcd(bitset_o, bitset_1_tmp, bitset_2_tmp);

    DelBitset(&bitset_1_tmp);
    DelBitset(&bitset_2_tmp);
    return 0;
}
int BitsetInverseMod(Bitset_t *bitset_o, Bitset_t *bitset_base, Bitset_t *bitset_mod)
{
    int num = (bitset_base->array_num > bitset_mod->array_num) ? bitset_base->array_num : bitset_mod->array_num;

    if (BitsetCmpWithoutNegUint32(bitset_mod, 1) == 0)
    {
        SetBitset_CountingCpy(bitset_o, one);
        return 0;
    }

    Bitset_t *Data1, *Data2, *tmp, *mul_tmp, *Div, *x, *y;

    NewBitset(&Data1, num << 5, MSB);
    NewBitset(&Data2, num << 5, MSB);
    NewBitset(&tmp, num << 5, MSB);
    NewBitset(&Div, num << 5, MSB);
    NewBitset(&x, num << 6, MSB);
    NewBitset(&y, num << 6, MSB);
    NewBitset(&mul_tmp, num << 6, MSB);

    SetBitset_CountingCpy(Data1, bitset_base);
    SetBitset_CountingCpy(Data2, bitset_mod);
    SetBitset_CountingCpy(y, one);

    int times = 0;
    while (BitsetCmpWithoutNegUint32(Data1, 1) == 1)
    {
        times++;
        printf("Times: %d", times);
        fflush(stdout);

        BitsetDiv(Div, Data1, Data2);
        SetBitset_CountingCpy(tmp, Data2);
        BitsetMod(Data2, Data1, Data2);
        SetBitset_CountingCpy(Data1, tmp);
        SetBitset_CountingCpy(tmp, x);
        BitsetMul(mul_tmp, Div, x);
        BitsetSub(x, y, mul_tmp);
        SetBitset_CountingCpy(y, tmp);

        printf("\r");
    }
    printf("\r                  \r");

    if (y->neg == 1)
    {
        BitsetAdd(y, y, bitset_mod);
    }
    SetBitset_CountingCpy(bitset_o, y);

    DelBitset(&Data1);
    DelBitset(&Data2);
    DelBitset(&tmp);
    DelBitset(&mul_tmp);
    DelBitset(&Div);
    DelBitset(&x);
    DelBitset(&y);

    return 0;
}

int BitsetRandom(Bitset_t *bitset_o, Bitset_t *bitset_range)
{
    srand(time(NULL));

    if (bitset_range == NULL)
    {
        BitsetClear(bitset_o);
        for (int ptr = 0; ptr != bitset_o->array_num; ptr++)
        {
            BitsetData(bitset_o, ptr) = 0;
            for (int times = 0; times < 3; times++)
            {
                BitsetData(bitset_o, ptr) |= rand() << 15 * times;
            }
        }
        return 0;
    }

    Bitset_t *bitset_o_tmp;
    if (NewBitset(&bitset_o_tmp, bitset_range->bit_num, MSB))
    {
        fprintf(stderr, "Cannot New a Bitset!!!!\n");
        return -1;
    }

    for (int ptr = bitset_range->array_num - 1; ptr != -1; ptr--)
    {
        for (int times = 0; times < 3; times++)
        {
            BitsetData(bitset_o_tmp, ptr) |= rand() << 15 * times;
        }
    }
    BitsetMod(bitset_o_tmp, bitset_o_tmp, bitset_range);

    SetBitset_CountingCpy(bitset_o, bitset_o_tmp);
    DelBitset(&bitset_o_tmp);
    return 0;
}

int BitsetSquareAndMultiply_Mod(Bitset_t *bitset_o, Bitset_t *bitset_base, Bitset_t *bitset_pow, Bitset_t *bitset_mod)
{
    Bitset_t *bitset_o_tmp;
    if (NewBitset(&bitset_o_tmp, ((bitset_base->bit_num << 1) > (bitset_mod->bit_num << 1)) ? (bitset_base->bit_num << 1) : (bitset_mod->bit_num << 1), MSB) != 0)
    {
        fprintf(stderr, "Cannot New a Bitset!!!!\n");
        return -1;
    }

    SetBitset_CountingCpy(bitset_o_tmp, bitset_base);

    int t = GetBitset_MaxBitPtr(bitset_pow);

    for (int i = t - 1; i >= 0; i--)
    {
        printf("%3.2f%%\r", (float)(t - i) / (float)t * 100);
        // y = y^2 mod n
        BitsetMul(bitset_o_tmp, bitset_o_tmp, bitset_o_tmp);
        BitsetMod(bitset_o_tmp, bitset_o_tmp, bitset_mod);

        if (GetBitset(bitset_pow, i) == 1)
        {
            // y = y*x mod n
            BitsetMul(bitset_o_tmp, bitset_o_tmp, bitset_base);
            BitsetMod(bitset_o_tmp, bitset_o_tmp, bitset_mod);
        }
    }
    printf("                    \r");
    fflush(stdout);

    SetBitset_CountingCpy(bitset_o, bitset_o_tmp);

    DelBitset(&bitset_o_tmp);
    return 0;
}

int BitsetFermatTest(Bitset_t *bitset, uint32_t times)
{
    // 0: not prime
    // 1: may be prime

    // if bitset == 2 or == 3 => prime
    if (BitsetCmpWithoutNegUint32(bitset, 2) == 0)
        return 1;
    if (BitsetCmpWithoutNegUint32(bitset, 3) == 0)
        return 1;

    // if bitset % 2 == 0 => not prime
    if (GetBitset(bitset, 0) == 0)
    {
        return 0;
    }

    Bitset_t *a, *p_minus1;
    NewBitset(&a, bitset->bit_num, MSB);
    NewBitset(&p_minus1, bitset->bit_num, MSB);

    BitsetSub(p_minus1, bitset, one);

    for (uint32_t i = 0; i < times; i++)
    {
        BitsetRandom(a, p_minus1);                 // a = 0 ~ (p-1)-1
        if (BitsetCmpWithoutNegUint32(a, 2) == -1) // a < 2
        {
            continue;
        }

        BitsetSquareAndMultiply_Mod(a, a, p_minus1, bitset);
        if (BitsetCmpWithoutNegUint32(a, 1) != 0) // a^(p-1) mod p != 1
        {
            return 0;
        }
    }

    DelBitset(&a);
    DelBitset(&p_minus1);
    return 1;
}

int BitsetMillerRabinTest(Bitset_t *bitset, uint32_t times)
{
    // 0: not prime
    // 1: may be prime

    // if bitset == 2 or == 3 => prime
    if (BitsetCmpWithoutNegUint32(bitset, 2) == 0)
        return 1;
    if (BitsetCmpWithoutNegUint32(bitset, 3) == 0)
        return 1;

    // if bitset % 2 == 0 => not prime
    if (GetBitset(bitset, 0) == 0)
    {
        return 0;
    }

    Bitset_t *n_tmp, *tmp;
    NewBitset(&n_tmp, bitset->bit_num, MSB);
    NewBitset(&tmp, bitset->bit_num, MSB);

    SetBitset_CountingCpy(n_tmp, bitset);

    Bitset_t *d, *n;
    uint32_t s = 1;
    n = bitset;
    NewBitset(&d, bitset->bit_num, MSB);

    // start Miller test
    //  n-1 = 2^s * d
    for (int ptr = 1; ptr < bitset->bit_num; ptr++)
    {
        if (GetBitset(bitset, ptr) == 0)
            s++;
        else
        {
            SetBitset_Bitset(d, d->bit_num - s - 1, bitset, bitset->bit_num - 1, s, RANGE);
            break;
        }
    }

    uint32_t r;
    SetBitset(n_tmp, 0, 0); // n => n-1
    for (int counter = 0; counter != times; counter++)
    {
        BitsetSub(n_tmp, n_tmp, two); // n-1 => n-3
        BitsetRandom(tmp, n_tmp);     // Generate random  0 <= tmp < n-3
        BitsetAdd(tmp, tmp, two);     // 2 <= tmp <= n-2
        BitsetAdd(n_tmp, n_tmp, two); // n-3 => n-1

        BitsetSquareAndMultiply_Mod(tmp, tmp, d, n); // tmp = tmp^d mod n

        if (BitsetCmpWithoutNeg(tmp, n_tmp) == 0) // tmp == n-1
            continue;
        if (BitsetCmpWithoutNegUint32(tmp, 1) == 0) // tmp == 1
            continue;

        for (r = 0; r != s; r++)
        {
            if (BitsetCmpWithoutNeg(tmp, n_tmp) == 0) // tmp == n-1
            {
                break;
            }

            BitsetSquareAndMultiply_Mod(tmp, tmp, two, n); // tmp = tmp^2 mod n
        }

        if (r == s)
        {
            DelBitset(&tmp);
            DelBitset(&n_tmp);
            DelBitset(&d);
            return 0;
        }
    }

    DelBitset(&tmp);
    DelBitset(&n_tmp);
    DelBitset(&d);
    return 1;
}

static void gcd(Bitset_t *bitset_o, Bitset_t *bitset_1, Bitset_t *bitset_2)
{
    {
        int ptr;
        for (ptr = 0; ptr != bitset_1->array_num; ptr++)
        {
            if (BitsetData(bitset_1, ptr) != 0)
                break;
        }
        if (ptr == bitset_1->array_num)
        {
            SetBitset_CountingCpy(bitset_o, bitset_2);
            return;
        }
    }
    BitsetMod(bitset_2, bitset_2, bitset_1);
    gcd(bitset_o, bitset_2, bitset_1);
}

static int GetBitset_MaxBitPtr(Bitset_t *bitset)
{
    uint32_t max_bit_ptr;

    uint32_t tmp_ptr;
    for (tmp_ptr = 0; tmp_ptr < bitset->array_num; tmp_ptr++)
    {
        if (BitsetData(bitset, tmp_ptr) != 0)
            break;
    }

    if (tmp_ptr != bitset->array_num)
    {

        for (max_bit_ptr = 0; max_bit_ptr < 32; max_bit_ptr++)
        {
            if (GetBitset(bitset, ((bitset->array_num - tmp_ptr) << 5) - max_bit_ptr - 1) != 0)
                break;
        }
        max_bit_ptr = ((bitset->array_num - tmp_ptr) << 5) - max_bit_ptr - 1;
    }
    else
    {
        max_bit_ptr = 0;
    }

    return max_bit_ptr;
}

uint32_t BitsetPtr(Bitset_t *bitset, uint32_t bit)
{
    if (bitset->mode == MSB)
    {
        return (uint32_t)bitset->array_num - (bit >> 5) - 1;
    }
    else
    {
        return (uint32_t)(bit >> 5);
    }
}

uint32_t BitsetArrayNum(Bitset_t *bitset)
{
    return (bitset->bit_num >> 5) + ((bitset->bit_num & 0x1f) > 0);
}

static void LeftShiftBitset_s(Bitset_t *bitset)
{
    uint32_t tmp;
    for (int ptr = 0; ptr < bitset->array_num; ptr++)
    {
        if (ptr == 0)
        {
            BitsetData(bitset, ptr) <<= 1;
            if (bitset->mode == MSB)
            {
                if (((bitset->bit_num) & 0x1f) != 0)
                {
                    tmp = 0x1 << ((bitset->bit_num) & 0x1f);
                    BitsetData(bitset, ptr) &= ~tmp;
                }
            }
        }
        else
        {
            tmp = BitsetData(bitset, ptr) >> 31;
            BitsetData(bitset, ptr - 1) |= tmp;
            BitsetData(bitset, ptr) <<= 1;
        }
    }
}

static void LeftShiftBitset_Range_s(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit)
{
    uint32_t data, start_bit, bit_num, tmp = 0;
    uint32_t uint32_array_num = Bitset_DivideByUint32_ArrayNum(bitset, first_bit, last_bit);

    uint32_t uint32_array_ptr;

    for (uint32_array_ptr = 0; uint32_array_ptr < uint32_array_num; uint32_array_ptr++)
    {
        if (0 != GetBitset_DivideByUint32(&data, &start_bit, &bit_num, bitset, uint32_array_num - 1 - uint32_array_ptr, first_bit, last_bit))
            return;

        data = (data << 1) | tmp;

        tmp = GetBitset(bitset, start_bit);

        SetBitset_4Byte(bitset, start_bit, data, bit_num);
    }
}

static void RightShiftBitset_s(Bitset_t *bitset)
{
    uint32_t tmp;
    for (int ptr = bitset->array_num - 1; ptr >= 0; ptr--)
    {
        if (ptr == bitset->array_num - 1)
        {
            BitsetData(bitset, ptr) >>= 1;
            if (bitset->mode == LSB)
            {
                if (((bitset->bit_num) & 0x1f) != 0)
                {
                    tmp = 0x1 << (31 - ((bitset->bit_num) & 0x1f));
                    BitsetData(bitset, ptr) &= ~tmp;
                }
            }
        }
        else
        {
            tmp = BitsetData(bitset, ptr) & 0x1;
            BitsetData(bitset, ptr + 1) |= tmp << 31;
            BitsetData(bitset, ptr) >>= 1;
        }
    }
}

static void RightShiftBitset_Range_s(Bitset_t *bitset, uint32_t first_bit, uint32_t last_bit)
{
    uint32_t data, start_bit, bit_num, tmp = 0, tmp1 = 0;
    uint32_t uint32_array_num = Bitset_DivideByUint32_ArrayNum(bitset, first_bit, last_bit);

    uint32_t uint32_array_ptr;

    for (uint32_array_ptr = 0; uint32_array_ptr < uint32_array_num; uint32_array_ptr++)
    {
        if (0 != GetBitset_DivideByUint32(&data, &start_bit, &bit_num, bitset, uint32_array_ptr, first_bit, last_bit))
            return;

        data >>= 1;
        tmp1 = tmp;

        if (bitset->mode == MSB)
        {
            tmp = GetBitset(bitset, start_bit - (bit_num - 1));
        }
        else
        {
            tmp = GetBitset(bitset, start_bit + (bit_num - 1));
        }

        SetBitset_4Byte(bitset, start_bit, data, bit_num);
        SetBitset(bitset, start_bit, tmp1);
    }
}

static int InRange(void *in, void *max, void *min, InRangeType_t type)
{
    switch (type)
    {
    case UINT8_T:
        if (*(uint8_t *)min > *(uint8_t *)in)
        {
            return 1; // Less then
        }
        else if (*(uint8_t *)in > *(uint8_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case UINT32_T:
        if (*(uint32_t *)min > *(uint32_t *)in)
        {
            return 1; // Less then
        }
        else if (*(uint32_t *)in > *(uint32_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case UINT64_T:
        if (*(uint64_t *)min > *(uint64_t *)in)
        {
            return 1; // Less then
        }
        else if (*(uint64_t *)in > *(uint64_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case INT8_T:
        if (*(int8_t *)min > *(int8_t *)in)
        {
            return 1; // Less then
        }
        else if (*(int8_t *)in > *(int8_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case INT32_T:
        if (*(int32_t *)min > *(int32_t *)in)
        {
            return 1; // Less then
        }
        else if (*(int32_t *)in > *(int32_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case INT64_T:
        if (*(int64_t *)min > *(int64_t *)in)
        {
            return 1; // Less then
        }
        else if (*(int64_t *)in > *(int64_t *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case FLOAT:
        if (*(float *)min > *(float *)in)
        {
            return 1; // Less then
        }
        else if (*(float *)in > *(float *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;
    case DOUBLE:
        if (*(double *)min > *(double *)in)
        {
            return 1; // Less then
        }
        else if (*(double *)in > *(double *)max)
        {
            return 2; // Larger then
        }
        else
        {
            return 0; // In range
        }
        break;

    default:
        return -1;
        break;
    }

    return 0;
}

static int CharToHex(char ch)
{
    char tmp, max, min;

    max = '9';
    min = '0';
    if (InRange(&ch, &max, &min, UINT8_T) == 0)
    {
        tmp = ch - min;
        goto OK;
    }
    max = 'f';
    min = 'a';
    if (InRange(&ch, &max, &min, UINT8_T) == 0)
    {
        tmp = ch - min + 10;
        goto OK;
    }
    max = 'F';
    min = 'A';
    if (InRange(&ch, &max, &min, UINT8_T) == 0)
    {
        tmp = ch - min + 10;
        goto OK;
    }
    return -1; // Not In range
OK:
    return (char)tmp;
}
