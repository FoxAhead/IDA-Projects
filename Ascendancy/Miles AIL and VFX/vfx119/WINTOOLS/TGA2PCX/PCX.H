//****************************************************************************
//*                                                                          *
//* PCX.H: PCX file reader/writer                                            *
//*                                                                          *
//* 32-bit protected-mode source compatible with MSVC 10.2                   *
//*                                                                          *
//* Version 1.00 of 28-Jan-97: Initial                                       *
//*                                                                          *
//* Author: Billy Zelsnack                                                   *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//* Copyright (C) 1997 Miles Design, Inc.                                    *
//*                                                                          *
//****************************************************************************

#ifndef PCX_HEADER
#define PCX_HEADER

#ifdef __cplusplus
extern "C"
{
#endif

unsigned char *PCX_load_palette (char *filename);
                                
unsigned char *PCX_load         (char *filename,
                                 int  *wide, 
                                 int  *tall);
                                
int            PCX_save         (char          *filename,
                                 int            wide, 
                                 int            tall, 
                                 unsigned char *data, 
                                 unsigned char *pal);

#ifdef __cplusplus
}
#endif

#endif
