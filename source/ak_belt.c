#include <libakrypt-internal.h>
#include <libakrypt.h>


typedef ak_uint32 ak_belt_keys[56];

// матрица для преобразования H 
const static linear_matrix matrix_h = {
 { 0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4 },
 { 0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D },
 { 0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B },
 { 0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99 },
 { 0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1 },
 { 0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F },
 { 0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31 },
 { 0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93 },
 { 0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47 },
 { 0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6 },
 { 0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2 },
 { 0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11 },
 { 0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1 },
 { 0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A },
 { 0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21 },
 { 0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет число размером одним байт на другой байт с помощью matrix_h                                                 */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 ak_belt_change_with_matrix_h(ak_uint8 par1){
    int j = par1 & 15;
    int i = (par1 >> 4) & 15 ;
    return matrix_h[i][j];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую раундовыми ключами                                                 */
/* ----------------------------------------------------------------------------------------------- */
static int ak_belt_delete_keys(ak_skey skey){
    int error = ak_error_ok;

     /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                     __func__ , "using a null pointer to secret key" );
    if( skey->data != NULL ) {
         /* теперь очистка и освобождение памяти */
        if(( error = ak_ptr_wipe( skey->data, sizeof( ak_belt_keys ),
                                                                   &skey->generator )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect wiping an internal data" );
        memset( skey->data, 0, sizeof( ak_belt_keys ));
        }
        free( skey->data );
        skey->data = NULL;
    }
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает новое число, преобразуя его согласно алгоритму с помощью matrix_h                                              */
/* ----------------------------------------------------------------------------------------------- */
ak_uint32 ak_new_number(ak_uint32 number){
    ak_uint8 part1 = (number >> 24) & 255;
    ak_uint8 part2 = (number >> 16) & 255;
    ak_uint8 part3 = (number >> 8) & 255;
    ak_uint8 part4 = number & 255;
    part1 = ak_belt_change_with_matrix_h(part1);
    part2 = ak_belt_change_with_matrix_h(part2);
    part3 = ak_belt_change_with_matrix_h(part3);
    part4 = ak_belt_change_with_matrix_h(part4);
    return (part1 << 24) | (part2 << 16) | (part3 << 8) | part4;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Циклический сдвиг влево                                                        */
/* ----------------------------------------------------------------------------------------------- */
ak_uint32 ak_rot_hi(ak_uint32 number, ak_uint32 r) {
    return (((number) << (r)) | ((number) >> (32 - (r))));
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Реализация преобразования G из алгоритма                                                           */
/* ----------------------------------------------------------------------------------------------- */
ak_uint32 ak_g_r_belt(ak_uint32 number, ak_uint32 r){
    return ak_rot_hi(ak_new_number(number), r);
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание числа типа ak_uint32 из 4 байт в той последовательности, в которой они указаны в функции*/
/* ----------------------------------------------------------------------------------------------- */
ak_uint32 ak_create_number_from_bytes(ak_uint8 * p1, ak_uint8 * p2, ak_uint8 * p3, ak_uint8 * p4){
    return (*p1 << 24) + (*p2 << 16) + (*p3 << 8) + *p4;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования                                                            */
/* ----------------------------------------------------------------------------------------------- */
static void ak_belt_encrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint8 * temp = (ak_uint8 *)  in;
    ak_uint32 temp1;
    ak_uint32 a = ak_create_number_from_bytes(temp + 3, temp + 2, temp + 1, temp);
    ak_uint32 b = ak_create_number_from_bytes(temp + 7, temp + 6, temp + 5, temp + 4);
    ak_uint32 c = ak_create_number_from_bytes(temp + 11, temp + 10, temp + 9, temp + 8);
    ak_uint32 d = ak_create_number_from_bytes(temp + 15, temp + 14, temp + 13, temp + 12);
    ak_uint32 e;
    ak_uint32 * k =  (ak_uint32 * ) skey->data;
    for (int i = 1; i < 9; i++){
        b = b ^ ak_g_r_belt(a + *(k + 7 * i - 6 - 1), 5);
        c = c ^ ak_g_r_belt(d + *(k + 7 * i - 5 - 1), 21);
        a = a - ak_g_r_belt(b + *(k + 7 * i - 4 - 1), 13);
        e = ak_g_r_belt(b + c + *(k + 7 * i - 3 - 1), 21) ^ (ak_uint32) i;
        b = b + e;
        c = c - e;
        d = d + ak_g_r_belt(c + *(k + 7 * i - 2 - 1), 13);
        b = b ^ ak_g_r_belt(a + *(k + 7 * i - 1 - 1), 21);
        c = c ^ ak_g_r_belt(d + * (k + 7 * i - 1),5);
        temp1 = a;
        a = b;
        b = temp1;

        temp1 = c;
        c = d;
        d = temp1;

        temp1 = b;
        b = c;
        c = temp1;
    }
    ak_uint32 * y = (ak_uint32 *) out;
    *y = b;
    *(y + 1) = d;
    *(y + 2) = a;
    *(y + 3) = c;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция дешифрования                                                             */
/* ----------------------------------------------------------------------------------------------- */
static void ak_belt_decrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint8 * temp = (ak_uint8 *)  in;
    ak_uint32 temp1;
    ak_uint32 a = ak_create_number_from_bytes(temp + 3, temp + 2, temp + 1, temp);
    ak_uint32 b = ak_create_number_from_bytes(temp + 7, temp + 6, temp + 5, temp + 4);
    ak_uint32 c = ak_create_number_from_bytes(temp + 11, temp + 10, temp + 9, temp + 8);
    ak_uint32 d = ak_create_number_from_bytes(temp + 15, temp + 14, temp + 13, temp + 12);
    ak_uint32 e;
    ak_uint32 * k =  (ak_uint32 * ) skey->data;
    for (int i = 8; i > 0; i--){
        b = b ^ ak_g_r_belt(a + *(k + 7 * i - 1), 5);

        c = c ^ ak_g_r_belt(d + *(k + 7 * i - 1 - 1), 21);

        a = a - ak_g_r_belt(b + *(k + 7 * i - 2 - 1), 13);

        e = ak_g_r_belt(b + c + *(k + 7 * i - 3 - 1), 21) ^ (ak_uint32) i;

        b = b + e;
        c = c - e;

        d = d + ak_g_r_belt(c + *(k + 7 * i - 4 - 1), 13);

        b = b ^ ak_g_r_belt(a + *(k + 7 * i - 5 - 1), 21);

        c = c ^ ak_g_r_belt(d + *(k + 7 * i - 6 - 1), 5);

        temp1 = a;
        a = b;
        b = temp1;

        temp1 = c;
        c = d;
        d = temp1;

        temp1 = a;
        a = d;
        d = temp1;
    }
    ak_uint32 * y = (ak_uint32 *) out;
    *y = c;
    *(y + 1) = a;
    *(y + 2) = d;
    *(y + 3) = b;
}
/* ----------------------------------------------------------------------------------------------- */
/*! \brief специальная функция маскирования, которая ничего не делает, так как в belt не нужно 
 *  маскирование всегда возвращает OK                                                              */
/* ----------------------------------------------------------------------------------------------- */
int ak_skey_set_special_belt_mask(ak_skey skey){
    if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        skey->flags |= ak_key_flag_set_mask;
    }
    return ak_error_ok;
}
/* ----------------------------------------------------------------------------------------------- */
/*! \brief специальная функкция демаскирования, которая ничего не делает, так как в belt не нужно 
 *  демаскирование, всегда возвращает ОК                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_skey_set_special_belt_unmask(ak_skey skey){
    if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        return ak_error_ok;
    }
    skey->flags ^= ak_key_flag_set_mask;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция развертки ключей                                                                */
/* ----------------------------------------------------------------------------------------------- */
static int ak_belt_schedule_keys(ak_skey skey){
    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
    if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "unsupported length of secret key" );
    /* проверяем целостность ключа */
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
    /* удаляем былое */
    if( skey->data != NULL ) ak_belt_delete_keys( skey );
    
    /* далее, по-возможности, выделяем выравненную память */
    if(( skey->data = ak_aligned_malloc( sizeof( ak_belt_keys ))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
    ak_uint32 * teta = (ak_uint32 *) skey->data;
    *teta = ak_create_number_from_bytes(skey->key + 3, skey->key + 2, skey->key + 1, skey->key);
    *(teta + 1) = ak_create_number_from_bytes(skey->key + 7, skey->key + 6, skey->key + 5, skey->key + 4);
    *(teta + 2) = ak_create_number_from_bytes(skey->key + 11, skey->key + 10, skey->key + 9, skey->key + 8);
    *(teta + 3) = ak_create_number_from_bytes(skey->key + 15, skey->key + 14, skey->key + 13, skey->key + 12);
    *(teta + 4) = ak_create_number_from_bytes(skey->key + 19, skey->key + 18, skey->key + 17, skey->key + 16);
    *(teta + 5) = ak_create_number_from_bytes(skey->key + 23, skey->key + 22, skey->key + 21, skey->key + 20);
    *(teta + 6) = ak_create_number_from_bytes(skey->key + 27, skey->key + 26, skey->key + 25, skey->key + 24);
    *(teta + 7) = ak_create_number_from_bytes(skey->key + 31, skey->key + 30, skey->key + 29, skey->key + 28);
    for (int i = 1; i < 7; i++){
        memcpy(teta + 8 * i, teta,32);
    }
    return ak_error_ok;
    
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации struct bckey для BELT                                             */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_belt( ak_bckey bkey){
    int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );
    
     if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );
    /* создаем ключ алгоритма шифрования и определяем его методы */
    if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );
    
    bkey->schedule_keys = ak_belt_schedule_keys;
    bkey->delete_keys = ak_belt_delete_keys;
    bkey->encrypt = ak_belt_encrypt;
    bkey->decrypt = ak_belt_decrypt;
    
    // установим свои специальные функции маскирования и демаскирования
    bkey->key.set_mask = ak_skey_set_special_belt_mask;
    bkey->key.unmask = ak_skey_set_special_belt_unmask;
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция тестирования, это продублировано в test-belt.c                                  */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_libakrypt_test_belt(void){
    
    ak_uint8 for_enc[16] ={
        0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,
        0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4,
    };
    ak_uint8 key_enc[32] =
    {
        0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,
        0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
        0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,
        0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6,
    };

    ak_uint8 out_enc[16];

    ak_uint8 for_dec[16] = {
        0xE1,0x2B,0xDC,0x1A,
        0xE2,0x82,0x57,0xEC,
        0x70,0x3F,0xCC,0xF0,
        0x95,0xEE,0x8D,0xF1
    };

    ak_uint8 key_dec[32] = {
        0x92,0xBD,0x9B,0x1C,0xE5,0xD1,0x41,0x01,
        0x54,0x45,0xFB,0xC9,0x5E,0x4D,0x0E,0xF2,
        0x68,0x20,0x80,0xAA,0x22,0x7D,0x64,0x2F,
        0x26,0x87,0xF9,0x34,0x90,0x40,0x55,0x11
    };

    ak_uint8 out_dec[16];

    struct bckey key;
    if (ak_bckey_create_belt(&key) != ak_error_ok) {
        printf("Проблема в ak_bckey_create_belt\n");
        return -1;
    }

    if (ak_bckey_set_key(&key, key_enc, 32) != ak_error_ok){
        printf("Проблема в ak_bckey_set_key\n");
        return -1;
    }
    if (ak_bckey_encrypt_ecb(&key, for_enc, out_enc, 16 ) != ak_error_ok) {
        printf("Проблема в ak_bckey_encrypt_ecb\n");
        return -1;
    }
    printf("Шифрование\nКлюч: ");
    for (int i = 0; i < 32; i++){
        printf("%X ", key_enc[i]);
    }
    printf("\nЧто шифруем: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", for_enc[i]);
    }
    printf("\nРезультат: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", out_enc[i]);
    }


    if (ak_bckey_set_key(&key, key_dec, 32) != ak_error_ok){
        printf("Проблема в ak_bckey_set_key\n");
        return -1;
    }
    if (ak_bckey_decrypt_ecb(&key, for_dec, out_dec, 16 ) != ak_error_ok) {
        ("Проблема в ak_bckey_decrypt_ecb\n");
        return -1;
    }
    printf("\n\nРасшифрование\nКлюч: ");
    for (int i = 0; i < 32; i++){
        printf("%X ", key_dec[i]);
    }
    printf("\nЧто расшифровываем: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", for_dec[i]);
    }
    printf("\nРезультат: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", out_dec[i]);
    }
    printf("\n");
    return ak_true;
}
