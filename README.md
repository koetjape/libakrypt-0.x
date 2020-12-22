Фомин Адрей, СКБ 172. Встраивание алгоритма шифрования BELT.

Белорусский стандарт шифра: http://apmi.bsu.by/assets/files/std/belt-spec27.pdf

В библиотеку был добавлен файл #### /source/ak_belt.c #### с реализацией алгоритма шифрования BELT;

Функции, определенные в #### ak_belt.c #### : 

    ak_uint8 ak_belt_change_with_matrix_h(ak_uint8 par1)
    
    static int ak_belt_delete_keys(ak_skey skey)
    
    ak_uint32 ak_new_number(ak_uint32 number)
    
    ak_uint32 ak_rot_hi(ak_uint32 number, ak_uint32 r)
    
    ak_uint32 ak_g_r_belt(ak_uint32 number, ak_uint32 r)
    
    ak_uint32 ak_create_number_from_bytes(ak_uint8 * p1, ak_uint8 * p2, ak_uint8 * p3, ak_uint8 * p4)
    
    static void ak_belt_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
    static void ak_belt_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
    int ak_skey_set_special_belt_mask(ak_skey skey)
    
    int ak_skey_set_special_belt_unmask(ak_skey skey)
    
    static int ak_belt_schedule_keys(ak_skey skey)
    
    int ak_bckey_create_belt( ak_bckey bkey)
    
    bool_t ak_libakrypt_test_belt(void)
    
Добавлено описание следующих функций в #### libakrypt_internal.h ####
    ak_uint8 ak_belt_change_with_matrix_h(ak_uint8)         на строке 58
    
    ak_uint32 ak_new_number(ak_uint32)                      на строке 60
    
    ak_uint32 ak_rot_hi(ak_uint32, ak_uint32)               на строке 62
    
    ak_uint32 ak_g_r_belt(ak_uint32 number, ak_uint32 r)    на строке 64
    
    ak_uint32 ak_create_number_from_bytes(ak_uint8 * par1, ak_uint8 * par2, ak_uint8 * par3, ak_uint8 * par4)   на строке 66
    
Добавлено описание следующих функций в #### libakrypt.h ####

    bool_t ak_libakrypt_test_belt( void )       на строке 174
    
    int ak_bckey_create_belt( ak_bckey )        на строке 685

Добавлен пример в виде файла #### /example/test-belt.c ####. Реализуется пример шифрования и дешифрования данных, указанных
в государственном белорусском стандарте.
