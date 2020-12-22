/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл libakrypt-internal.h                                                                      */
/*   - содержит заголовки неэкспортируемых функций                                                 */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_INTERNAL_H__
#define    __LIBAKRYPT_INTERNAL_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac-doc
 @{ */
 extern const ak_uint64 streebog_Areverse_expand_with_pi[8][256];
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-doc Cекретные ключи криптографических механизмов
 @{ */
/*! \brief Указатель на функцию чтения пароля */
 extern ak_function_password_read *ak_function_default_password_read;
/*! \brief Формирование имени файла, в который будет помещаться секретный или открытый ключ. */
 int ak_skey_generate_file_name_from_buffer( ak_uint8 * , const size_t ,
                                                         char * , const size_t , export_format_t );
/*! \brief Инициализация секретного ключа алгоритма блочного шифрования. */
 int ak_bckey_create( ak_bckey , size_t , size_t );
/*! \brief Инициализация ключа алгоритма блочного шифрования значением другого ключа */
 int ak_bckey_create_and_set_bckey( ak_bckey , ak_bckey );
/*! \brief Процедура вычисления производного ключа в соответствии с алгоритмом ACPKM
    из рекомендаций Р 1323565.1.012-2018. */
 int ak_bckey_next_acpkm_key( ak_bckey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает пару ключей алгоритма блочного шифрования из заданного
   пользователем пароля. */
 int ak_bckey_create_key_pair_from_password( ak_bckey , ak_bckey , ak_oid ,
                            const char * , const size_t , ak_uint8 *, const size_t, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выработка матрицы, соответствующей 16 тактам работы линейного региста сдвига. */
 void ak_bckey_kuznechik_generate_matrix( const linear_register , linear_matrix );
/*! \brief Обращение сопровождающей матрицы. */
 void ak_bckey_kuznechik_invert_matrix( linear_matrix , linear_matrix );
/*! \brief Обращение таблицы нелинейного преобразования. */
 void ak_bckey_kuznechik_invert_permutation( const sbox , sbox );
/*! \brief Инициализация внутренних структур данных, используемых при реализации алгоритма
    блочного шифрования Кузнечик (ГОСТ Р 34.12-2015). */
 int ak_bckey_kuznechik_init_tables( const linear_register ,
                                                                const sbox , ak_kuznechik_params );
/*! \brief Инициализация внутренних переменных значениями, регламентируемыми ГОСТ Р 34.12-2015. */
 int ak_bckey_kuznechik_init_gost_tables( void );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательное преобразование из ak_uint8 в ak_uint8 с помощью матрицы H согласно алгоритму*/
 ak_uint8 ak_belt_change_with_matrix_h(ak_uint8);
/*! \brief Вспомогательное преобразование из ak_uint32 в ak_uint32 с помощью матрицы H согласно алгоритму*/
 ak_uint32 ak_new_number(ak_uint32);
/*! \brief Циклический сдвиг влево*/
 ak_uint32 ak_rot_hi(ak_uint32, ak_uint32);
/*! \brief Реализация преобразования G из алгоритма */
 ak_uint32 ak_g_r_belt(ak_uint32 number, ak_uint32 r);
/*! \brief Создание числа типа ak_uint32 из 4 байт в той последовательности, в которой они указаны в функции*/
 ak_uint32 ak_create_number_from_bytes(ak_uint8 * par1, ak_uint8 * par2, ak_uint8 * par3, ak_uint8 * par4);
 
/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac-doc Вычисление кодов целостности (хеширование и имитозащита)
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации контекста начальными значениями. */
 int ak_mac_create( ak_mac , const size_t , ak_pointer ,
                             ak_function_clean * , ak_function_update * , ak_function_finalize * );
/*! \brief Функция удаления контекста. */
 int ak_mac_destroy( ak_mac );
/*! \brief Очистка контекста сжимающего отображения. */
 int ak_mac_clean( ak_mac );
/*! \brief Обновление состояния контекста сжимающего отображения. */
 int ak_mac_update( ak_mac , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения сжимающего отображения. */
 int ak_mac_finalize( ak_mac , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданной области памяти. */
 int ak_mac_ptr( ak_mac , ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданному файлу. */
 int ak_mac_file( ak_mac , const char* , ak_pointer , const size_t );
/** @} */

/** \addtogroup aead-doc
 @{ */
 #define ak_aead_assosiated_data_bit  (0x1)
 #define ak_aead_encrypted_data_bit   (0x2)

 #define ak_aead_set_bit( x, n ) ( (x) = ((x)&(0xFFFFFFFF^(n)))^(n) )
/** @} */

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                            libakrypt-internal.h */
/* ----------------------------------------------------------------------------------------------- */
