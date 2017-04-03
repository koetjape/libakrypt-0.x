/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_skey.h                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_SKEY_H__
#define __AK_SKEY_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_random.h>
 #include <ak_buffer.h>

/* ----------------------------------------------------------------------------------------------- */
/* Предварительные описания ключевых структур */
 struct skey;
 struct block_cipher_key;
 struct hmac_key;
 struct cmac_key;
 struct sign_key;
 struct hybrid_cipher_key;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на структуру секретного ключа */
 typedef struct skey *ak_skey;
/*! \brief Указатель на структуру ключа блочного алгоритма шифрования */
 typedef struct block_cipher_key *ak_block_cipher_key;
/*! \brief Указатель на структуру ключа алгоритма выработки имитовставки HMAC */
 typedef struct hmac_key *ak_hmac_key;
/*! \brief Указатель на структуру ключа алгоритма ГОСТ Р 34.13-2015 выработки имитовставки */
 typedef struct omac_key *ak_omac_key;
/*! \brief Указатель на структуру секретного ключа алгоритма выработки электронной подписи */
 typedef struct sign_key *ak_sign_key;
/*! \brief Указатель на структуру секретного ключа алгоритма гибридного шифрования */
 typedef struct hybrid_key *ak_hybrid_key;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом */
 typedef int ( ak_function_skey )( ak_skey );
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом */
 typedef ak_bool ( ak_function_skey_check )( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения интервала времени использования ключа */
 typedef struct {
 /*! \brief время, до которого ключ недействителен */
  time_t not_before;
  /*! \brief время, после которого клю недействителен */
  time_t not_after;
 } ak_time_interval;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения ресурса ключа */
 typedef union {
  /*! \brief счетчик числа использований, например, зашифрованных/расшифрованных блоков */
   ak_uint64 counter;
  /*! \brief временной интервал использования ключа */
   ak_time_interval time;
 } ak_resource;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура секретного ключа -- базовый набор данных и методов контроля */
 struct skey {
  /*! \brief ключ */
   struct buffer key;
  /*! \brief маска ключа */
   struct buffer mask;
  /*! \brief контрольная сумма ключа */
   struct buffer icode;
  /*! \brief уникальный номер ключа */
   struct buffer number;
  /*! \brief указатель на внутренние данные ключа */
   ak_pointer data;
  /*! \brief генератор случайных масок ключа */
   ak_random generator;
  /*! \brief OID алгоритма для которого предназначен секретный ключ */
   ak_oid oid;
  /*! \brief ресурс использования ключа */
   ak_resource resource;

  /*! \brief указатель на функцию маскирования ключа */
   ak_function_skey *set_mask;
  /*! \brief указатель на функцию изменения маски ключа (перемаскирования) */
   ak_function_skey *remask;
  /*! \brief указатель на функцию вычисления контрольной суммы */
   ak_function_skey *set_icode;
  /*! \brief указатель на функцию проверки контрольной суммы */
   ak_function_skey_check *check_icode;

  /* где же функции чтения/изменения ресурса, получения/установки номера ?
     блокировки доступа к ключу,
     выработка (параметрическая, непараметрическая) следующего в последовательности ключей */
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация структуры секретного ключа */
 int ak_skey_create( ak_skey , size_t );
/*! \brief Очистка структуры секретного ключа */
 int ak_skey_destroy( ak_skey );
/*! \brief Присвоение секретному ключу уникального номера */
 int ak_skey_assign_unique_number( ak_skey );
/*! \brief Присвоение секретному ключу константного значения */
 int ak_skey_assign_ptr( ak_skey , const ak_pointer , const ak_bool );
/*! \brief Присвоение секретному ключу случайного значения */
 int ak_skey_assign_random( ak_skey , ak_random );
/*! \brief Присвоение секретному ключу значения, выработанного из пароля */
 int ak_skey_assign_password( ak_skey , const ak_pointer , const size_t );

/*! \brief Наложение аддитивной (в кольце \f$ \mathbb Z_{2^{32}}\f$ ) маски на ключ */
 int ak_skey_set_mask_additive( ak_skey );
/*! \brief Смена значения аддитивной (в кольце \f$ \mathbb Z_{2^{32}}\f$ ) маски ключа */
 int ak_skey_remask_additive( ak_skey );
/*! \brief Вычисление значения контрольной суммы ключа */
 int ak_skey_set_icode_additive( ak_skey );
/*! \brief Проверка значения контрольной суммы ключа */
 ak_bool ak_skey_check_icode_additive( ak_skey );

// int ak_skey_set_mask_xor( ak_skey );
// int ak_skey_remask_xor( ak_skey );
// int ak_skey_set_icode_xor( ak_skey );
// ak_bool ak_skey_check_icode_xor( ak_skey );


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования/расширования одного блока информации */
  typedef void ( ak_function_block_cipher_key )( ak_skey, ak_pointer, ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ блочного алгоритма шифрования */
 struct block_cipher_key {
  /*! \brief Указатель на секретный ключ */
   struct skey key;
  /*! \brief Длина блока обрабатываемых данных в байтах */
   size_t block_size;

  /*! \brief Функция заширования одного блока информации */
   ak_function_block_cipher_key *encrypt;
  /*! \brief Функция расширования одного блока информации */
   ak_function_block_cipher_key *decrypt;
  /*! \brief Функция развертки ключа */
   ak_function_skey *shedule_keys;
  /*! \brief Функция уничтожения развернутых ключей */
   ak_function_skey *delete_keys;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация ключа алгоритма блочного шифрования */
 int ak_block_cipher_key_create( ak_block_cipher_key , size_t , size_t );
/*! \brief Создание контекста ключа алгоритма блочного шифрования */
 ak_block_cipher_key ak_block_cipher_key_new( size_t , size_t );
/*! \brief Очистка ключа алгоритма блочного шифрования */
 int ak_block_cipher_key_destroy( ak_block_cipher_key );
/*! \brief Удаление ключа алгоритма блочного шифрования */
 ak_pointer ak_block_cipher_key_delete( ak_pointer );

/*! Создание контекста ключа алгоритма Магма с заданным значением */
 ak_block_cipher_key ak_block_cipher_key_new_magma_ptr( const ak_pointer , const ak_bool );
/*! Создание контекста ключа алгоритма Магма с новым, случайным значением */
 ak_block_cipher_key ak_block_cipher_key_new_magma_random( ak_random );
/*! Выработка контекста ключа алгоритма Магма из пароля */
 ak_block_cipher_key ak_block_cipher_key_new_magma_password( const ak_pointer , const size_t );

/*! \brief Зашифрование данных в режиме простой замены */
 int ak_block_cipher_key_encrypt_ecb( ak_block_cipher_key , ak_pointer , ak_pointer , size_t );
/*! \brief Расшифрование данных в режиме простой замены */
 int ak_block_cipher_key_decrypt_ecb( ak_block_cipher_key , ak_pointer , ak_pointer , size_t );
/*! \brief Зашифрование/расшифрование данных в режиме гаммирования (режим счетчика из ГОСТ Р 34.13-2015) */
 int ak_block_cipher_key_encrypt_ctr( ak_block_cipher_key , ak_pointer , ak_pointer ,
                                                                         size_t , ak_pointer );

/*! \brief Функция выполняет тестирование алгоритма Магма в соответствии с ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015 */
 ak_bool ak_block_cipher_key_test_magma( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ алгоритма выработки имитовставки HMAC */
/*!  Алгоритм HMAC описывается рекомендациями IETF RFC 2104 и
     стандартизован отечественными рекомендациями по стандартизации Р 50.1.113-2016.
     Алгоритм предназначен, в основном, для выработки имитовставки и
     преобразования ключевой информации.

     В нашей реализации алгоритм может быть использован совместно с любой функцией хеширования,
     реализованной в библиотеке. Отметим, что согласно Р 50.1.113-2016 алгоритм может
     использоваться только совместно с функцией хеширования Стрибог
     (с длиной хеш кода как 256 бит, так и 512 бит).                                              */
/* ----------------------------------------------------------------------------------------------- */
 struct hmac_key {
 /*! \brief контекст секретного ключа */
  struct skey key;
 /*! \brief контекст функции хеширования */
  struct hash ctx;
};


/* ----------------------------------------------------------------------------------------------- */

/*
   ключи шифрования
    сверху общие методы (режимы шифрования)
    внутри (в структуре) только детализация (блочные преобразования/развертки)

   для маков:
    у хмака - все как у функций хеширования (то есть mac_data, mac_file а также update и finalize
    => общим является только контекст хеширования, который может быть помещен в key->data

    struct hmac_key {
     ak_skey key; // здесь данные
     ak_hash ctx; // здесь методы
     mac_size = ctx->bsize
    }
    механизм update() + finalize() проходит идеально
    с готовой реализацией из


    у омака (он же гост) блочное шифрование/то есть наследование
    методов от ключа блочного шифрования)

    struct omac_key {
      ak_block_cipher_key key;
      ak_buffer промежуточные данные
      + выработка производных ключей в конце
      + промежуточный буффер,
      mac_size = key->block_size
    }
    механизм update() + finalize()  в принципе проходит,
    поскольку алгоритм это позволяет
    (update реализуется блоками по 64/128 бит путем шифрования накопленного в буффере материала)
    (
       нужна отдельная реализация буфера, аналогично ak_hash
       либо делается отдельный класс ak_update с методами update, finalize и данными bsize, tempdata, templen )
       если это будет сделано для функции хеширования, то может быть использовано и здесь
       нужна тестовая реализация поскольку видятся проблемы с передачей обрабатываемых данных
       (update( void *) с уникальной реализацией)
    )


    у аеад => использование ключа для блочного шифрования +
    хранение промежуточных значений (как в хмаке)

    При этом - общая функциональность

     - обработка файлов и данных, как плоских (одним куском),
       так и фрагментарная, в стиле хеш-функции
     - параллельная обработка фрагментов данных (?)

    struct unictr_key {
      ak_block_cipher_key key; // исходный ключ
      ak_skey iteration_key; // промежуточные значения (k1, k2), вырабатываемые для выработки
      ak_buffer промежуточные данные

      mac_size = ( key->block_size << 1 );

    на выход должны подаваться зашифрованные данные.
    Если исопльзовать режим гаммирования, то в принципе можно устроить буффер для хранения
    промежуточной информации (в том числе и ключевой!!!! )
    это потребует возни с хранием этих значений в памяти
    (с другой стороны это все равно придется делать, поскольку секретные значения могут фонить)
    (но здесь придется хранить еще и гамму шифрования)

    либо полностью отказаться от шифрования информации фрагментами,
    отличными от длины блока (двух блоков)

    (в ядре линукса есть стейт, то есть значение синхропосылки используемое на следующем блоке )
    это используется для разрывов при шифровании, то есть полный аналог того
    что мы имеем для хеширования
    при этом, для каждого режима стейт может определяться своим образом и быть секретным :(

    В параллельной реализации обязательно нужно реализовывать update()
    + конечный finalize() правда на уровне стейта, а не данных ключа

    Разрывность при шифровании потребует очень быстрого
    поиска ключа по его хендлу на пользовательском уровне (хеш таблица с широким разлетом плеч)
*/

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.h  */
/* ----------------------------------------------------------------------------------------------- */
