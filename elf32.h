/*
 * =====================================================================================
 *
 *       Filename:  elf32.h
 *
 *    Description:  Struct Defination of ELF_32Bit_FILF_HEADER
 *
 *        Version:  1.0
 *        Created:  2015年08月10日 22时19分13秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ExiaHan
 *   Organization:  CELESTIALBEING
 *
 * =====================================================================================
 */

#ifndef _ELF32_H_
#define _ELF32_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define EI_NIDENT 16

typedef u_int8_t u1;
typedef u_int16_t u2;
typedef u_int32_t u4;

typedef int8_t i1;
typedef int16_t i2;
typedef int32_t i4;

typedef struct {
    u1 e_ident[EI_NIDENT];
    u2 e_type;
    u2 e_machine;
    u4 e_version;
    u4 e_entry;
    u4 e_phoff;
    u4 e_shoff;
    u4 e_flags;
    u2 e_ehsize;
    u2 e_phentsize;
    u2 e_phnum;
    u2 e_shentsize;
    u2 e_shnum;
    u2 e_shstrndx;
}elf32_Header, *pElf32_Header;

#endif
