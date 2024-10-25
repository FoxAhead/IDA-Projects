
/* WATCOM100A.H 1 */
/* .\WATCOM100A-FIXES.h 1 */ extern int main ( int argc , char * argv [ ] ) ;
/* .\WATCOM100A-FIXES.h 2 */
/* .\WATCOM100A-FIXES.h 3 */ extern void __fastcall Q_CobCfgLoad_sub_1C3C4 ( P_SomeStruct2 a1
Error .\WATCOM100A-FIXES.h:3: Syntax error near: P_SomeStruct2

  included from WATCOM100A.H:1
 a1 ) ;
/* WATCOM100A.H 2 */
/* WATCOM100A.H 3 */
/* .\H\malloc.h 1 */
/* .\H\malloc.h 2 */
/* .\H\malloc.h 3 */
/* .\H\malloc.h 4 */
/* .\H\malloc.h 5 */
/* .\H\malloc.h 6 */
/* .\H\malloc.h 7 */
/* .\H\malloc.h 8 */
/* .\H\malloc.h 9 */
/* .\H\malloc.h 10 */
/* .\H\malloc.h 11 */
/* .\H\malloc.h 12 */
/* .\H\malloc.h 13 */
/* .\H\malloc.h 14 */ typedef unsigned size_t ;
/* .\H\malloc.h 15 */
/* .\H\malloc.h 16 */
/* .\H\malloc.h 17 */
/* .\H\malloc.h 18 */
/* .\H\malloc.h 19 */
/* .\H\malloc.h 20 */
/* .\H\malloc.h 21 */
/* .\H\malloc.h 22 */
/* .\H\malloc.h 23 */
/* .\H\malloc.h 24 */
/* .\H\malloc.h 25 */
/* .\H\malloc.h 26 */ extern void * alloca ( @type size_t __size ) ;
/* .\H\malloc.h 27 */ extern void * __doalloca ( @type size_t __size ) ;
/* .\H\malloc.h 28 */ extern unsigned stackavail ( void ) ;
/* .\H\malloc.h 29 */
/* .\H\malloc.h 30 */
/* .\H\malloc.h 31 */
/* .\H\malloc.h 32 */
/* .\H\malloc.h 33 */
/* .\H\malloc.h 34 */
/* .\H\malloc.h 35 */
/* .\H\malloc.h 36 */
/* .\H\malloc.h 37 */
/* .\H\malloc.h 40 */
/* .\H\malloc.h 41 */
/* .\H\malloc.h 44 */
/* .\H\malloc.h 45 */
/* .\H\malloc.h 50 */
/* .\H\malloc.h 51 */
/* .\H\malloc.h 52 */
/* .\H\malloc.h 53 */
/* .\H\malloc.h 54 */
/* .\H\malloc.h 55 */
/* .\H\malloc.h 56 */
/* .\H\malloc.h 57 */
/* .\H\malloc.h 58 */
/* .\H\malloc.h 59 */
/* .\H\malloc.h 60 */
/* .\H\malloc.h 61 */
/* .\H\malloc.h 62 */
/* .\H\malloc.h 63 */ typedef struct _heapinfo {
/* .\H\malloc.h 64 */ void __far * _pentry ;
/* .\H\malloc.h 65 */ @type size_t _size ;
/* .\H\malloc.h 66 */ int _useflag ;
/* .\H\malloc.h 67 */ } _HEAPINFO ;
/* .\H\malloc.h 68 */
/* .\H\malloc.h 69 */ extern int _heapenable ( int __enabled ) ;
/* .\H\malloc.h 70 */ extern int _heapchk ( void ) ;
/* .\H\malloc.h 71 */ extern int _nheapchk ( void ) ;
/* .\H\malloc.h 72 */ extern int _fheapchk ( void ) ;
/* .\H\malloc.h 73 */ extern int _heapset ( unsigned int __fill ) ;
/* .\H\malloc.h 74 */ extern int _nheapset ( unsigned int __fill ) ;
/* .\H\malloc.h 75 */ extern int _fheapset ( unsigned int __fill ) ;
/* .\H\malloc.h 76 */ extern int _heapwalk ( struct _heapinfo * __entry ) ;
/* .\H\malloc.h 77 */ extern int _nheapwalk ( struct _heapinfo * __entry ) ;
/* .\H\malloc.h 78 */ extern int _fheapwalk ( struct _heapinfo * __entry ) ;
/* .\H\malloc.h 79 */
/* .\H\malloc.h 80 */ extern void _heapgrow ( void ) ;
/* .\H\malloc.h 81 */ extern void _nheapgrow ( void ) ;
/* .\H\malloc.h 82 */ extern void _fheapgrow ( void ) ;
/* .\H\malloc.h 83 */ extern int _heapmin ( void ) ;
/* .\H\malloc.h 84 */ extern int _nheapmin ( void ) ;
/* .\H\malloc.h 85 */ extern int _fheapmin ( void ) ;
/* .\H\malloc.h 86 */ extern int _heapshrink ( void ) ;
/* .\H\malloc.h 87 */ extern int _nheapshrink ( void ) ;
/* .\H\malloc.h 88 */ extern int _fheapshrink ( void ) ;
/* .\H\malloc.h 89 */
/* .\H\malloc.h 90 */ extern int __nmemneed ( @type size_t ) ;
/* .\H\malloc.h 91 */ extern int __fmemneed ( @type size_t ) ;
/* .\H\malloc.h 92 */ extern void __far * _fcalloc ( @type size_t __n , @type size_t __size ) ;
/* .\H\malloc.h 93 */ extern void __near * _ncalloc ( @type size_t __n , @type size_t __size ) ;
/* .\H\malloc.h 94 */ extern void * _expand ( void * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 95 */ extern void __far * _fexpand ( void __far * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 96 */ extern void __near * _nexpand ( void __near * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 97 */ extern void _ffree ( void __far * __ptr ) ;
/* .\H\malloc.h 98 */ extern void __far * _fmalloc ( @type size_t __size ) ;
/* .\H\malloc.h 99 */ extern unsigned int _freect ( @type size_t __size ) ;
/* .\H\malloc.h 100 */ extern void __huge * halloc ( long __n , @type size_t __size ) ;
/* .\H\malloc.h 101 */ extern void hfree ( void __huge * ) ;
/* .\H\malloc.h 102 */ extern void _nfree ( void __near * __ptr ) ;
/* .\H\malloc.h 103 */ extern void __near * _nmalloc ( @type size_t __size ) ;
/* .\H\malloc.h 104 */ extern void __near * _nrealloc ( void __near * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 105 */ extern void __far * _frealloc ( void __far * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 106 */ extern @type size_t _msize ( void * __ptr ) ;
/* .\H\malloc.h 107 */ extern @type size_t _nmsize ( void __near * __ptr ) ;
/* .\H\malloc.h 108 */ extern @type size_t _fmsize ( void __far * __ptr ) ;
/* .\H\malloc.h 109 */ extern @type size_t _memavl ( void ) ;
/* .\H\malloc.h 110 */ extern @type size_t _memmax ( void ) ;
/* .\H\malloc.h 111 */ extern void * calloc ( @type size_t __n , @type size_t __size ) ;
/* .\H\malloc.h 112 */ extern void free ( void * __ptr ) ;
/* .\H\malloc.h 113 */ extern void * malloc ( @type size_t __size ) ;
/* .\H\malloc.h 114 */ extern void * realloc ( void * __ptr , @type size_t __size ) ;
/* .\H\malloc.h 115 */
/* .\H\malloc.h 116 */
/* .\H\malloc.h 117 */
/* .\H\malloc.h 118 */
/* .\H\malloc.h 119 */
/* .\H\malloc.h 120 */
/* .\H\malloc.h 121 */
/* .\H\malloc.h 122 */
/* .\H\malloc.h 123 */
/* .\H\malloc.h 124 */
/* .\H\malloc.h 125 */
/* .\H\malloc.h 126 */
/* .\H\malloc.h 127 */
/* .\H\malloc.h 128 */
/* .\H\malloc.h 129 */
/* .\H\malloc.h 130 */
/* .\H\malloc.h 131 */
/* .\H\malloc.h 132 */
/* .\H\malloc.h 133 */
/* .\H\malloc.h 134 */
/* .\H\malloc.h 135 */
/* .\H\malloc.h 136 */
/* .\H\malloc.h 137 */
/* .\H\malloc.h 138 */
/* .\H\malloc.h 139 */
/* .\H\malloc.h 140 */
/* .\H\malloc.h 141 */
/* .\H\malloc.h 142 */
/* .\H\malloc.h 143 */
/* WATCOM100A.H 4 */
/* WATCOM100A.H 5 */
/* WATCOM100A.H 6 */
/* WATCOM100A.H 7 */
/* WATCOM100A.H 8 */
/* WATCOM100A.H 9 */
/* WATCOM100A.H 10 */
/* .\H\dos.h 1 */
/* .\H\dos.h 2 */
/* .\H\dos.h 3 */
/* .\H\dos.h 4 */
/* .\H\dos.h 5 */
/* .\H\dos.h 6 */
/* .\H\dos.h 7 */
/* .\H\dos.h 8 */
/* .\H\dos.h 9 */
/* .\H\dos.h 10 */ extern "C" {
/* .\H\dos.h 11 */
/* .\H\dos.h 12 */
/* .\H\dos.h 13 */
/* .\H\i86.h 1 */
/* .\H\i86.h 2 */
/* .\H\i86.h 3 */
/* .\H\i86.h 4 */
/* .\H\i86.h 5 */
/* .\H\i86.h 6 */
/* .\H\i86.h 7 */
/* .\H\i86.h 8 */
/* .\H\i86.h 9 */
/* .\H\i86.h 10 */ extern "C" {
/* .\H\i86.h 11 */
/* .\H\i86.h 12 */
/* .\H\i86.h 13 */
/* .\H\i86.h 14 */
/* .\H\i86.h 15 */
/* .\H\i86.h 16 */
/* .\H\i86.h 17 */
/* .\H\i86.h 18 */ struct DWORDREGS {
/* .\H\i86.h 19 */ unsigned int eax ;
/* .\H\i86.h 20 */ unsigned int ebx ;
/* .\H\i86.h 21 */ unsigned int ecx ;
/* .\H\i86.h 22 */ unsigned int edx ;
/* .\H\i86.h 23 */ unsigned int esi ;
/* .\H\i86.h 24 */ unsigned int edi ;
/* .\H\i86.h 25 */ unsigned int cflag ;
/* .\H\i86.h 26 */ } ;
/* .\H\i86.h 27 */
/* .\H\i86.h 28 */
/* .\H\i86.h 29 */
/* .\H\i86.h 30 */
/* .\H\i86.h 31 */
/* .\H\i86.h 32 */
/* .\H\i86.h 33 */
/* .\H\i86.h 34 */ struct WORDREGS {
/* .\H\i86.h 35 */ unsigned short ax ; unsigned short _1 ;
/* .\H\i86.h 36 */ unsigned short bx ; unsigned short _2 ;
/* .\H\i86.h 37 */ unsigned short cx ; unsigned short _3 ;
/* .\H\i86.h 38 */ unsigned short dx ; unsigned short _4 ;
/* .\H\i86.h 39 */ unsigned short si ; unsigned short _5 ;
/* .\H\i86.h 40 */ unsigned short di ; unsigned short _6 ;
/* .\H\i86.h 41 */
/* .\H\i86.h 42 */
/* .\H\i86.h 43 */
/* .\H\i86.h 44 */ unsigned int cflag ;
/* .\H\i86.h 45 */
/* .\H\i86.h 46 */ } ;
/* .\H\i86.h 47 */
/* .\H\i86.h 48 */
/* .\H\i86.h 49 */
/* .\H\i86.h 50 */ struct BYTEREGS {
/* .\H\i86.h 51 */ unsigned char al , ah ; unsigned short _1 ;
/* .\H\i86.h 52 */ unsigned char bl , bh ; unsigned short _2 ;
/* .\H\i86.h 53 */ unsigned char cl , ch ; unsigned short _3 ;
/* .\H\i86.h 54 */ unsigned char dl , dh ; unsigned short _4 ;
/* .\H\i86.h 55 */ } ;
/* .\H\i86.h 56 */
/* .\H\i86.h 57 */
/* .\H\i86.h 58 */
/* .\H\i86.h 59 */
/* .\H\i86.h 60 */
/* .\H\i86.h 61 */ union REGS {
/* .\H\i86.h 62 */
/* .\H\i86.h 63 */ struct DWORDREGS x ;
/* .\H\i86.h 64 */
/* .\H\i86.h 65 */
/* .\H\i86.h 66 */
/* .\H\i86.h 67 */ struct WORDREGS w ;
/* .\H\i86.h 68 */ struct BYTEREGS h ;
/* .\H\i86.h 69 */ } ;
/* .\H\i86.h 70 */
/* .\H\i86.h 71 */
/* .\H\i86.h 72 */
/* .\H\i86.h 73 */
/* .\H\i86.h 74 */ struct SREGS {
/* .\H\i86.h 75 */ unsigned short es , cs , ss , ds ;
/* .\H\i86.h 76 */
/* .\H\i86.h 77 */ unsigned short fs , gs ;
/* .\H\i86.h 78 */
/* .\H\i86.h 79 */ } ;
/* .\H\i86.h 80 */
/* .\H\i86.h 81 */
/* .\H\i86.h 82 */
/* .\H\i86.h 83 */
/* .\H\i86.h 84 */
/* .\H\i86.h 85 */ struct REGPACKB {
/* .\H\i86.h 86 */ unsigned char al , ah ; unsigned short _1 ;
/* .\H\i86.h 87 */ unsigned char bl , bh ; unsigned short _2 ;
/* .\H\i86.h 88 */ unsigned char cl , ch ; unsigned short _3 ;
/* .\H\i86.h 89 */ unsigned char dl , dh ; unsigned short _4 ;
/* .\H\i86.h 90 */ } ;
/* .\H\i86.h 91 */
/* .\H\i86.h 92 */ struct REGPACKW {
/* .\H\i86.h 93 */ unsigned short ax ; unsigned short _1 ;
/* .\H\i86.h 94 */ unsigned short bx ; unsigned short _2 ;
/* .\H\i86.h 95 */ unsigned short cx ; unsigned short _3 ;
/* .\H\i86.h 96 */ unsigned short dx ; unsigned short _4 ;
/* .\H\i86.h 97 */ unsigned short bp ; unsigned short _5 ;
/* .\H\i86.h 98 */ unsigned short si ; unsigned short _6 ;
/* .\H\i86.h 99 */ unsigned short di ; unsigned short _7 ;
/* .\H\i86.h 100 */ unsigned short ds ;
/* .\H\i86.h 101 */ unsigned short es ;
/* .\H\i86.h 102 */
/* .\H\i86.h 103 */ unsigned short fs ;
/* .\H\i86.h 104 */ unsigned short gs ;
/* .\H\i86.h 105 */
/* .\H\i86.h 106 */
/* .\H\i86.h 107 */
/* .\H\i86.h 108 */
/* .\H\i86.h 109 */ unsigned int flags ;
/* .\H\i86.h 110 */
/* .\H\i86.h 111 */ } ;
/* .\H\i86.h 112 */
/* .\H\i86.h 113 */ struct REGPACKX {
/* .\H\i86.h 114 */ unsigned int eax , ebx , ecx , edx , ebp , esi , edi ;
/* .\H\i86.h 115 */ unsigned short ds , es , fs , gs ;
/* .\H\i86.h 116 */ unsigned int flags ;
/* .\H\i86.h 117 */ } ;
/* .\H\i86.h 118 */
/* .\H\i86.h 119 */ union REGPACK {
/* .\H\i86.h 120 */ struct REGPACKB h ;
/* .\H\i86.h 121 */ struct REGPACKW w ;
/* .\H\i86.h 122 */
/* .\H\i86.h 123 */ struct REGPACKX x ;
/* .\H\i86.h 124 */
/* .\H\i86.h 125 */
/* .\H\i86.h 126 */
/* .\H\i86.h 127 */ } ;
/* .\H\i86.h 128 */
/* .\H\i86.h 129 */
/* .\H\i86.h 130 */
/* .\H\i86.h 131 */
/* .\H\i86.h 132 */ struct INTPACKX {
/* .\H\i86.h 133 */ unsigned gs , fs , es , ds , edi , esi , ebp , esp , ebx , edx , ecx , eax , eip , cs , flags ;
/* .\H\i86.h 134 */ } ;
/* .\H\i86.h 135 */
/* .\H\i86.h 136 */
/* .\H\i86.h 137 */
/* .\H\i86.h 138 */
/* .\H\i86.h 139 */ struct INTPACKW {
/* .\H\i86.h 140 */ unsigned short gs ; unsigned short _1 ;
/* .\H\i86.h 141 */ unsigned short fs ; unsigned short _2 ;
/* .\H\i86.h 142 */ unsigned short es ; unsigned short _3 ;
/* .\H\i86.h 143 */ unsigned short ds ; unsigned short _4 ;
/* .\H\i86.h 144 */ unsigned short di ; unsigned short _5 ;
/* .\H\i86.h 145 */ unsigned short si ; unsigned short _6 ;
/* .\H\i86.h 146 */ unsigned short bp ; unsigned short _7 ;
/* .\H\i86.h 147 */ unsigned short sp ; unsigned short _8 ;
/* .\H\i86.h 148 */ unsigned short bx ; unsigned short _9 ;
/* .\H\i86.h 149 */ unsigned short dx ; unsigned short _a ;
/* .\H\i86.h 150 */ unsigned short cx ; unsigned short _b ;
/* .\H\i86.h 151 */ unsigned short ax ; unsigned short _c ;
/* .\H\i86.h 152 */ unsigned short ip ; unsigned short _d ;
/* .\H\i86.h 153 */ unsigned short cs ; unsigned short _e ;
/* .\H\i86.h 154 */ unsigned flags ;
/* .\H\i86.h 155 */ } ;
/* .\H\i86.h 156 */ struct INTPACKB {
/* .\H\i86.h 157 */
/* .\H\i86.h 158 */ unsigned : 0x20 , : 0x20 ,
/* .\H\i86.h 159 */ : 0x20 , : 0x20 ,
/* .\H\i86.h 160 */ : 0x20 , : 0x20 ,
/* .\H\i86.h 161 */ : 0x20 , : 0x20 ;
/* .\H\i86.h 162 */
/* .\H\i86.h 163 */
/* .\H\i86.h 164 */
/* .\H\i86.h 165 */
/* .\H\i86.h 166 */
/* .\H\i86.h 167 */
/* .\H\i86.h 168 */ unsigned char bl , bh ; unsigned short _1 ;
/* .\H\i86.h 169 */ unsigned char dl , dh ; unsigned short _2 ;
/* .\H\i86.h 170 */ unsigned char cl , ch ; unsigned short _3 ;
/* .\H\i86.h 171 */ unsigned char al , ah ; unsigned short _4 ;
/* .\H\i86.h 172 */ } ;
/* .\H\i86.h 173 */ union INTPACK {
/* .\H\i86.h 174 */ struct INTPACKB h ;
/* .\H\i86.h 175 */ struct INTPACKW w ;
/* .\H\i86.h 176 */
/* .\H\i86.h 177 */ struct INTPACKX x ;
/* .\H\i86.h 178 */
/* .\H\i86.h 179 */
/* .\H\i86.h 180 */
/* .\H\i86.h 181 */ } ;
/* .\H\i86.h 182 */
/* .\H\i86.h 183 */
/* .\H\i86.h 184 */
/* .\H\i86.h 185 */ enum {
/* .\H\i86.h 186 */ INTR_CF = 0x1 ,
/* .\H\i86.h 187 */ INTR_PF = 0x4 ,
/* .\H\i86.h 188 */ INTR_AF = 0x10 ,
/* .\H\i86.h 189 */ INTR_ZF = 0x40 ,
/* .\H\i86.h 190 */ INTR_SF = 0x80 ,
/* .\H\i86.h 191 */ INTR_TF = 0x100 ,
/* .\H\i86.h 192 */ INTR_IF = 0x200 ,
/* .\H\i86.h 193 */ INTR_DF = 0x400 ,
/* .\H\i86.h 194 */ INTR_OF = 0x800
/* .\H\i86.h 195 */ } ;
/* .\H\i86.h 196 */
/* .\H\i86.h 197 */ extern void _disable ( void ) ;
/* .\H\i86.h 198 */ extern void _enable ( void ) ;
/* .\H\i86.h 199 */
/* .\H\i86.h 200 */
/* .\H\i86.h 201 */
/* .\H\i86.h 202 */
/* .\H\i86.h 203 */
/* .\H\i86.h 204 */ extern void delay ( unsigned int __milliseconds ) ;
/* .\H\i86.h 205 */
/* .\H\i86.h 206 */ extern int int386 ( int , union REGS * , union REGS * ) ;
/* .\H\i86.h 207 */ extern int int386x ( int , union REGS * , union REGS * , struct SREGS * ) ;
/* .\H\i86.h 208 */
/* .\H\i86.h 209 */
/* .\H\i86.h 210 */
/* .\H\i86.h 211 */
/* .\H\i86.h 212 */ extern void intr ( int , union REGPACK * ) ;
/* .\H\i86.h 213 */ extern void nosound ( void ) ;
/* .\H\i86.h 214 */ extern void segread ( struct SREGS * ) ;
/* .\H\i86.h 215 */ extern void sound ( unsigned __frequency ) ;
/* .\H\i86.h 216 */
/* .\H\i86.h 217 */
/* .\H\i86.h 218 */
/* .\H\i86.h 219 */
/* .\H\i86.h 220 */
/* .\H\i86.h 221 */
/* .\H\i86.h 222 */
/* .\H\i86.h 223 */ unsigned short FP_SEG ( void __far * ) ;
/* .\H\i86.h 224 */
/* .\H\i86.h 225 */
/* .\H\i86.h 226 */
/* .\H\i86.h 227 */
/* .\H\i86.h 228 */
/* .\H\i86.h 229 */
/* .\H\i86.h 230 */
/* .\H\i86.h 231 */
/* .\H\i86.h 232 */
/* .\H\i86.h 233 */
/* .\H\i86.h 234 */
/* .\H\i86.h 235 */
/* .\H\i86.h 236 */
/* .\H\i86.h 237 */ } ;
/* .\H\i86.h 238 */
/* .\H\i86.h 239 */
/* .\H\dos.h 14 */
/* .\H\dos.h 15 */
/* .\H\dos.h 16 */
/* .\H\dos.h 17 */
/* .\H\dos.h 18 */
/* .\H\dos.h 19 */
/* .\H\dos.h 20 */
/* .\H\dos.h 21 */
/* .\H\dos.h 22 */ struct _DOSERROR {
/* .\H\dos.h 23 */ int exterror ;
/* .\H\dos.h 24 */ char errclass ;
/* .\H\dos.h 25 */ char action ;
/* .\H\dos.h 26 */ char locus ;
/* .\H\dos.h 27 */ } ;
/* .\H\dos.h 28 */
/* .\H\dos.h 29 */
/* .\H\dos.h 30 */
/* .\H\dos.h 31 */
/* .\H\dos.h 32 */
/* .\H\dos.h 33 */
/* .\H\dos.h 34 */
/* .\H\dos.h 35 */
/* .\H\dos.h 36 */
/* .\H\dos.h 37 */ struct dosdate_t {
/* .\H\dos.h 38 */ unsigned char day ;
/* .\H\dos.h 39 */ unsigned char month ;
/* .\H\dos.h 40 */ unsigned short year ;
/* .\H\dos.h 41 */ unsigned char dayofweek ;
/* .\H\dos.h 42 */ } ;
/* .\H\dos.h 43 */
/* .\H\dos.h 44 */
/* .\H\dos.h 45 */ struct dostime_t {
/* .\H\dos.h 46 */ unsigned char hour ;
/* .\H\dos.h 47 */ unsigned char minute ;
/* .\H\dos.h 48 */ unsigned char second ;
/* .\H\dos.h 49 */ unsigned char hsecond ;
/* .\H\dos.h 50 */ } ;
/* .\H\dos.h 51 */
/* .\H\dos.h 52 */
/* .\H\dos.h 53 */ struct find_t {
/* .\H\dos.h 54 */ char reserved [ 0x15 ] ;
/* .\H\dos.h 55 */ char attrib ;
/* .\H\dos.h 56 */ unsigned short wr_time ;
/* .\H\dos.h 57 */ unsigned short wr_date ;
/* .\H\dos.h 58 */ unsigned long size ;
/* .\H\dos.h 59 */
/* .\H\dos.h 60 */
/* .\H\dos.h 61 */
/* .\H\dos.h 62 */ char name [ 0xD ] ;
/* .\H\dos.h 63 */
/* .\H\dos.h 64 */ } ;
/* .\H\dos.h 65 */
/* .\H\dos.h 66 */
/* .\H\dos.h 67 */
/* .\H\dos.h 68 */
/* .\H\dos.h 69 */
/* .\H\dos.h 70 */
/* .\H\dos.h 71 */
/* .\H\dos.h 72 */
/* .\H\dos.h 73 */
/* .\H\dos.h 74 */
/* .\H\dos.h 75 */
/* .\H\dos.h 76 */
/* .\H\dos.h 77 */
/* .\H\dos.h 78 */
/* .\H\dos.h 79 */
/* .\H\dos.h 80 */
/* .\H\dos.h 81 */
/* .\H\dos.h 82 */
/* .\H\dos.h 83 */
/* .\H\dos.h 84 */
/* .\H\dos.h 85 */
/* .\H\dos.h 86 */ struct _diskfree_t {
/* .\H\dos.h 87 */ unsigned short total_clusters ;
/* .\H\dos.h 88 */ unsigned short avail_clusters ;
/* .\H\dos.h 89 */ unsigned short sectors_per_cluster ;
/* .\H\dos.h 90 */ unsigned short bytes_per_sector ;
/* .\H\dos.h 91 */ } ;
/* .\H\dos.h 92 */
/* .\H\dos.h 93 */
/* .\H\dos.h 94 */
/* .\H\dos.h 95 */ extern int bdos ( int __dosfn , unsigned int __dx , unsigned int __al ) ;
/* .\H\dos.h 96 */ extern void _chain_intr ( register void ( __interrupt __far * __handler ) ( ) ) ;
/* .\H\dos.h 97 */
/* .\H\dos.h 98 */
/* .\H\dos.h 99 */
/* .\H\dos.h 100 */ extern unsigned _dos_allocmem ( unsigned __size , unsigned short * __seg ) ;
/* .\H\dos.h 101 */
/* .\H\dos.h 102 */ extern unsigned _dos_close ( int __handle ) ;
/* .\H\dos.h 103 */ extern unsigned _dos_commit ( int __handle ) ;
/* .\H\dos.h 104 */ extern unsigned _dos_creat ( const char * __path , unsigned __attr , int * __handle ) ;
/* .\H\dos.h 105 */ extern unsigned _dos_creatnew ( const char * __path , unsigned __attr , int * __handle ) ;
/* .\H\dos.h 106 */ extern unsigned _dos_findfirst ( const char * __path , unsigned __attr , struct find_t * __buf ) ;
/* .\H\dos.h 107 */ extern unsigned _dos_findnext ( struct find_t * __buf ) ;
/* .\H\dos.h 108 */ extern unsigned _dos_findclose ( struct find_t * __buf ) ;
/* .\H\dos.h 109 */
/* .\H\dos.h 110 */
/* .\H\dos.h 111 */
/* .\H\dos.h 112 */ extern unsigned _dos_freemem ( unsigned short __seg ) ;
/* .\H\dos.h 113 */
/* .\H\dos.h 114 */ extern void _dos_getdate ( struct dosdate_t * __date ) ;
/* .\H\dos.h 115 */ extern unsigned _dos_getdiskfree ( unsigned __drive , struct _diskfree_t * __diskspace ) ;
/* .\H\dos.h 116 */ extern unsigned _getdiskfree ( unsigned __drive , struct _diskfree_t * __diskspace ) ;
/* .\H\dos.h 117 */ extern void _dos_getdrive ( unsigned * __drive ) ;
/* .\H\dos.h 118 */ extern unsigned _getdrive ( void ) ;
/* .\H\dos.h 119 */ extern unsigned _dos_getfileattr ( const char * __path , unsigned * __attr ) ;
/* .\H\dos.h 120 */ extern unsigned _dos_getftime ( int __handle , unsigned short * __date ,
/* .\H\dos.h 121 */ unsigned short * __time ) ;
/* .\H\dos.h 122 */ extern void _dos_gettime ( struct dostime_t * __time ) ;
/* .\H\dos.h 123 */ extern void ( __interrupt __far * _dos_getvect ( int __intnum ) ) ( ) ;
/* .\H\dos.h 124 */ extern void _dos_keep ( unsigned __retcode , unsigned __memsize ) ;
/* .\H\dos.h 125 */
/* .\H\dos.h 126 */ extern unsigned _dos_open ( const char * __path , unsigned __mode , int * __handle ) ;
/* .\H\dos.h 127 */ extern unsigned _dos_read ( int __handle , void __far * __buf , unsigned __count ,
/* .\H\dos.h 128 */ unsigned * __bytes ) ;
/* .\H\dos.h 129 */ extern unsigned _dos_setblock ( unsigned __size , unsigned short __seg ,
/* .\H\dos.h 130 */ unsigned * __maxsize ) ;
/* .\H\dos.h 131 */ extern unsigned _dos_setdate ( struct dosdate_t * __date ) ;
/* .\H\dos.h 132 */ extern void _dos_setdrive ( unsigned __drivenum , unsigned * __drives ) ;
/* .\H\dos.h 133 */ extern unsigned _dos_setfileattr ( const char * __path , unsigned __attr ) ;
/* .\H\dos.h 134 */ extern unsigned _dos_setftime ( int __handle , unsigned short __date , unsigned short __time ) ;
/* .\H\dos.h 135 */ extern unsigned _dos_settime ( struct dostime_t * __time ) ;
/* .\H\dos.h 136 */ extern void _dos_setvect ( int __intnum , void ( __interrupt __far * __handler ) ( ) ) ;
/* .\H\dos.h 137 */ extern unsigned _dos_write ( int __handle , void const __far * __buf , unsigned __count ,
/* .\H\dos.h 138 */ unsigned * __bytes ) ;
/* .\H\dos.h 139 */ extern int dosexterr ( struct _DOSERROR * ) ;
/* .\H\dos.h 140 */ extern void _harderr ( register int ( __far * __func ) ( unsigned __deverr ,
/* .\H\dos.h 141 */ unsigned __errcode , unsigned __far * __devhdr ) ) ;
/* .\H\dos.h 142 */ extern void _hardresume ( int __result ) ;
/* .\H\dos.h 143 */ extern void _hardretn ( int __error ) ;
/* .\H\dos.h 144 */ extern int intdos ( union REGS * , union REGS * ) ;
/* .\H\dos.h 145 */ extern int intdosx ( union REGS * , union REGS * , struct SREGS * ) ;
/* .\H\dos.h 146 */ extern void sleep ( unsigned __seconds ) ;
/* .\H\dos.h 147 */
/* .\H\dos.h 148 */
/* .\H\dos.h 149 */
/* .\H\dos.h 150 */
/* .\H\dos.h 151 */
/* .\H\dos.h 152 */
/* .\H\dos.h 153 */
/* .\H\dos.h 154 */ } ;
/* .\H\dos.h 155 */
/* .\H\dos.h 156 */
/* WATCOM100A.H 11 */
/* WATCOM100A.H 12 */
/* WATCOM100A.H 13 */
/* .\H\stdlib.h 1 */
/* .\H\stdlib.h 2 */
/* .\H\stdlib.h 3 */
/* .\H\stdlib.h 4 */
/* .\H\stdlib.h 5 */
/* .\H\stdlib.h 6 */
/* .\H\stdlib.h 7 */
/* .\H\stdlib.h 8 */
/* .\H\stdlib.h 9 */
/* .\H\stdlib.h 10 */
/* .\H\stdlib.h 11 */
/* .\H\stdlib.h 12 */
/* .\H\stdlib.h 13 */
/* .\H\stdlib.h 14 */
/* .\H\stdlib.h 15 */
/* .\H\stdlib.h 16 */
/* .\H\stdlib.h 17 */
/* .\H\stdlib.h 18 */
/* .\H\stdlib.h 19 */
/* .\H\stdlib.h 20 */
/* .\H\stdlib.h 21 */
/* .\H\stdlib.h 22 */
/* .\H\stdlib.h 23 */ typedef unsigned short wchar_t ;
/* .\H\stdlib.h 24 */
/* .\H\stdlib.h 25 */
/* .\H\stdlib.h 26 */
/* .\H\stdlib.h 27 */
/* .\H\stdlib.h 28 */
/* .\H\stdlib.h 29 */
/* .\H\stdlib.h 30 */
/* .\H\stdlib.h 31 */
/* .\H\stdlib.h 32 */
/* .\H\stdlib.h 33 */
/* .\H\stdlib.h 34 */
/* .\H\stdlib.h 35 */
/* .\H\stdlib.h 36 */
/* .\H\stdlib.h 37 */
/* .\H\stdlib.h 38 */
/* .\H\stdlib.h 39 */
/* .\H\stdlib.h 40 */
/* .\H\stdlib.h 41 */ typedef struct {
/* .\H\stdlib.h 42 */ int quot ;
/* .\H\stdlib.h 43 */ int rem ;
/* .\H\stdlib.h 44 */ } div_t ;
/* .\H\stdlib.h 45 */
/* .\H\stdlib.h 46 */ typedef struct {
/* .\H\stdlib.h 47 */ long quot ;
/* .\H\stdlib.h 48 */ long rem ;
/* .\H\stdlib.h 49 */ } ldiv_t ;
/* .\H\stdlib.h 50 */
/* .\H\stdlib.h 51 */ extern void abort ( void ) ;
/* .\H\stdlib.h 52 */ extern int abs ( int __j ) ;
/* .\H\stdlib.h 53 */ extern int atexit ( register void ( * __func ) ( void ) ) ;
/* .\H\stdlib.h 54 */ extern double atof ( const char * __nptr ) ;
/* .\H\stdlib.h 55 */ extern int atoi ( const char * __nptr ) ;
/* .\H\stdlib.h 56 */ extern long int atol ( const char * __nptr ) ;
/* .\H\stdlib.h 57 */ extern void * bsearch ( const void * __key , const void * __base ,
/* .\H\stdlib.h 58 */ @type size_t __nmemb , @type size_t __size ,
/* .\H\stdlib.h 59 */ int ( * __compar ) ( const void * __pkey , const void * __pbase ) ) ;
/* .\H\stdlib.h 60 */ extern void * calloc ( @type size_t __n , @type size_t __size ) ;
/* .\H\stdlib.h 61 */ extern @type div_t div ( int __numer , int __denom ) ;
/* .\H\stdlib.h 62 */ extern void exit ( int __status ) ;
/* .\H\stdlib.h 63 */ extern void free ( void * __ptr ) ;
/* .\H\stdlib.h 64 */ extern char * getenv ( const char * __name ) ;
/* .\H\stdlib.h 65 */ extern long int labs ( long int __j ) ;
/* .\H\stdlib.h 66 */ extern @type ldiv_t ldiv ( long int __numer , long int __denom ) ;
/* .\H\stdlib.h 67 */ extern void * malloc ( @type size_t __size ) ;
/* .\H\stdlib.h 68 */ extern int mblen ( const char * __s , @type size_t __n ) ;
/* .\H\stdlib.h 69 */ extern @type size_t mbstowcs ( @type wchar_t * __pwcs , const char * __s , @type size_t __n ) ;
/* .\H\stdlib.h 70 */ extern int mbtowc ( @type wchar_t * __pwc , const char * __s , @type size_t __n ) ;
/* .\H\stdlib.h 71 */ extern @type size_t wcstombs ( char * __s , const @type wchar_t * __pwcs , @type size_t __n ) ;
/* .\H\stdlib.h 72 */ extern int wctomb ( char * __s , @type wchar_t __wchar ) ;
/* .\H\stdlib.h 73 */ extern void qsort ( void * __base , @type size_t __nmemb , @type size_t __size ,
/* .\H\stdlib.h 74 */ int ( * __compar ) ( const void * , const void * ) ) ;
/* .\H\stdlib.h 75 */ extern int rand ( void ) ;
/* .\H\stdlib.h 76 */ extern void * realloc ( void * __ptr , @type size_t __size ) ;
/* .\H\stdlib.h 77 */ extern void srand ( unsigned int __seed ) ;
/* .\H\stdlib.h 78 */ extern double strtod ( const char * __nptr , char * * __endptr ) ;
/* .\H\stdlib.h 79 */ extern long int strtol ( const char * __nptr , char * * __endptr , int __base ) ;
/* .\H\stdlib.h 80 */ extern unsigned long strtoul ( const char * __nptr , char * * __endptr , int __base ) ;
/* .\H\stdlib.h 81 */ extern int system ( const char * __string ) ;
/* .\H\stdlib.h 82 */
/* .\H\stdlib.h 83 */
/* .\H\stdlib.h 84 */
/* .\H\stdlib.h 85 */
/* .\H\stdlib.h 86 */
/* .\H\stdlib.h 87 */
/* .\H\stdlib.h 88 */
/* .\H\stdlib.h 89 */
/* .\H\stdlib.h 90 */
/* .\H\stdlib.h 91 */
/* .\H\stdlib.h 92 */
/* .\H\stdlib.h 93 */
/* .\H\stdlib.h 94 */
/* .\H\stdlib.h 95 */
/* .\H\stdlib.h 96 */
/* .\H\stdlib.h 97 */ extern void _exit ( int __status ) ;
/* .\H\stdlib.h 98 */ extern char * ecvt ( double __val , int __ndig , int * __dec , int * __sign ) ;
/* .\H\stdlib.h 99 */ extern char * _ecvt ( double __val , int __ndig , int * __dec , int * __sign ) ;
/* .\H\stdlib.h 100 */ extern char * fcvt ( double __val , int __ndig , int * __dec , int * __sign ) ;
/* .\H\stdlib.h 101 */ extern char * _fcvt ( double __val , int __ndig , int * __dec , int * __sign ) ;
/* .\H\stdlib.h 102 */ extern char * _fullpath ( char * __buf , const char * __path , @type size_t __size ) ;
/* .\H\stdlib.h 103 */ extern char * gcvt ( double __val , int __ndig , char * __buf ) ;
/* .\H\stdlib.h 104 */ extern char * _gcvt ( double __val , int __ndig , char * __buf ) ;
/* .\H\stdlib.h 105 */ extern char * itoa ( int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 106 */ extern char * _itoa ( int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 107 */ extern unsigned long _lrotl ( unsigned long __value , unsigned int __shift ) ;
/* .\H\stdlib.h 108 */ extern unsigned long _lrotr ( unsigned long __value , unsigned int __shift ) ;
/* .\H\stdlib.h 109 */ extern char * ltoa ( long int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 110 */ extern char * _ltoa ( long int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 111 */ extern void _makepath ( char * __path , const char * __drive ,
/* .\H\stdlib.h 112 */ const char * __dir , const char * __fname ,
/* .\H\stdlib.h 113 */ const char * __ext ) ;
/* .\H\stdlib.h 114 */ extern unsigned int _rotl ( unsigned int __value , unsigned int __shift ) ;
/* .\H\stdlib.h 115 */ extern unsigned int _rotr ( unsigned int __value , unsigned int __shift ) ;
/* .\H\stdlib.h 116 */ extern int putenv ( const char * __string ) ;
/* .\H\stdlib.h 117 */ extern void _searchenv ( const char * __name , const char * __env_var ,
/* .\H\stdlib.h 118 */ char * __buf ) ;
/* .\H\stdlib.h 119 */ extern void _splitpath2 ( const char * __inp , char * __outp ,
/* .\H\stdlib.h 120 */ char * * __drive , char * * __dir , char * * __fn , char * * __ext ) ;
/* .\H\stdlib.h 121 */ extern void _splitpath ( const char * __path , char * __drive ,
/* .\H\stdlib.h 122 */ char * __dir , char * __fname , char * __ext ) ;
/* .\H\stdlib.h 123 */ extern void swab ( char * __src , char * __dest , int __num ) ;
/* .\H\stdlib.h 124 */ extern char * ultoa ( unsigned long int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 125 */ extern char * utoa ( unsigned int __value , char * __buf , int __radix ) ;
/* .\H\stdlib.h 126 */
/* .\H\stdlib.h 127 */
/* .\H\stdlib.h 128 */
/* .\H\stdlib.h 129 */
/* .\H\stdlib.h 130 */
/* .\H\stdlib.h 131 */
/* .\H\stdlib.h 132 */
/* .\H\stdlib.h 133 */
/* .\H\stdlib.h 134 */
/* .\H\stdlib.h 135 */
/* .\H\stdlib.h 136 */
/* .\H\stdlib.h 137 */
/* .\H\stdlib.h 138 */
/* .\H\stdlib.h 139 */
/* .\H\stdlib.h 140 */
/* .\H\stdlib.h 141 */
/* .\H\stdlib.h 142 */
/* .\H\stdlib.h 143 */
/* .\H\stdlib.h 144 */
/* .\H\stdlib.h 145 */
/* .\H\stdlib.h 146 */
/* .\H\stdlib.h 147 */
/* .\H\stdlib.h 148 */
/* .\H\stdlib.h 149 */
/* .\H\stdlib.h 150 */
/* .\H\stdlib.h 151 */
/* .\H\stdlib.h 152 */
/* .\H\stdlib.h 153 */
/* .\H\stdlib.h 154 */
/* .\H\stdlib.h 155 */
/* .\H\stdlib.h 156 */
/* .\H\stdlib.h 157 */
/* .\H\stdlib.h 158 */
/* .\H\stdlib.h 159 */
/* .\H\stdlib.h 160 */
/* .\H\stdlib.h 161 */
/* .\H\stdlib.h 162 */
/* .\H\stdlib.h 163 */
/* .\H\stdlib.h 164 */
/* .\H\stdlib.h 165 */
/* .\H\stdlib.h 166 */
/* .\H\stdlib.h 167 */
/* .\H\stdlib.h 168 */
/* .\H\stdlib.h 169 */ extern char * * __near environ ;
/* .\H\stdlib.h 170 */
/* .\H\stdlib.h 171 */
/* .\H\stdlib.h 172 */
/* .\H\stdlib.h 173 */
/* .\H\stdlib.h 174 */ extern volatile int ( * __get_errno_ptr ( ) ) ;
/* .\H\stdlib.h 175 */
/* .\H\stdlib.h 176 */ extern int ( * __get_doserrno_ptr ( ) ) ;
/* .\H\stdlib.h 177 */ extern unsigned __near _psp ;
/* .\H\stdlib.h 178 */
/* .\H\stdlib.h 179 */
/* .\H\stdlib.h 180 */ extern unsigned char __near _osmode ;
/* .\H\stdlib.h 181 */ extern int __near _fmode ;
/* .\H\stdlib.h 182 */ extern char * sys_errlist [ ] ;
/* .\H\stdlib.h 183 */ extern int __near sys_nerr ;
/* .\H\stdlib.h 184 */ extern unsigned __near __minreal ;
/* .\H\stdlib.h 185 */ extern unsigned long __near __win_alloc_flags ;
/* .\H\stdlib.h 186 */ extern unsigned long __near __win_realloc_flags ;
/* .\H\stdlib.h 187 */ extern unsigned char __near _osmajor ;
/* .\H\stdlib.h 188 */ extern unsigned char __near _osminor ;
/* .\H\stdlib.h 189 */ extern unsigned __near _amblksiz ;
/* .\H\stdlib.h 190 */
/* .\H\stdlib.h 191 */ extern void __near * __brk ( unsigned __new_brk_value ) ;
/* .\H\stdlib.h 192 */ extern void __near * sbrk ( int __increment ) ;
/* .\H\stdlib.h 193 */ typedef void ( * onexit_t ) ( ) ;
/* .\H\stdlib.h 194 */ extern @type onexit_t onexit ( @type onexit_t __func ) ;
/* .\H\stdlib.h 195 */
/* .\H\stdlib.h 196 */
/* .\H\stdlib.h 197 */
/* .\H\stdlib.h 198 */
/* .\H\stdlib.h 199 */
/* .\H\stdlib.h 200 */
/* .\H\stdlib.h 201 */
/* .\H\stdlib.h 202 */
/* WATCOM100A.H 14 */
/* .\H\stdio.h 1 */
/* .\H\stdio.h 2 */
/* .\H\stdio.h 3 */
/* .\H\stdio.h 4 */
/* .\H\stdio.h 5 */
/* .\H\stdio.h 6 */
/* .\H\stdio.h 7 */
/* .\H\stdio.h 8 */
/* .\H\stdio.h 9 */
/* .\H\stdio.h 10 */
/* .\H\stdio.h 11 */
/* .\H\stdio.h 12 */
/* .\H\stdio.h 13 */
/* .\H\stdio.h 14 */
/* .\H\stdio.h 15 */
/* .\H\stdio.h 16 */
/* .\H\stdio.h 17 */
/* .\H\stdio.h 18 */
/* .\H\stdio.h 19 */
/* .\H\stdio.h 20 */
/* .\H\stdio.h 21 */
/* .\H\stdio.h 22 */
/* .\H\stdio.h 23 */
/* .\H\stdio.h 24 */
/* .\H\stdio.h 25 */
/* .\H\stdio.h 26 */
/* .\H\stdio.h 27 */
/* .\H\stdio.h 28 */
/* .\H\stdio.h 29 */
/* .\H\stdio.h 30 */ typedef char * __va_list [ 0x1 ] ;
/* .\H\stdio.h 31 */
/* .\H\stdio.h 32 */
/* .\H\stdio.h 33 */
/* .\H\stdio.h 34 */
/* .\H\stdio.h 35 */
/* .\H\stdio.h 36 */
/* .\H\stdio.h 37 */
/* .\H\stdio.h 38 */
/* .\H\stdio.h 39 */
/* .\H\stdio.h 40 */
/* .\H\stdio.h 41 */
/* .\H\stdio.h 42 */
/* .\H\stdio.h 43 */ typedef struct __iobuf {
/* .\H\stdio.h 44 */ unsigned char * _ptr ;
/* .\H\stdio.h 45 */ int _cnt ;
/* .\H\stdio.h 46 */ unsigned char * _base ;
/* .\H\stdio.h 47 */ unsigned _flag ;
/* .\H\stdio.h 48 */ int _handle ;
/* .\H\stdio.h 49 */ unsigned _bufsize ;
/* .\H\stdio.h 50 */ unsigned char _ungotten ;
/* .\H\stdio.h 51 */ unsigned char _tmpfchar ;
/* .\H\stdio.h 52 */ } FILE ;
/* .\H\stdio.h 53 */
/* .\H\stdio.h 54 */ typedef long fpos_t ;
/* .\H\stdio.h 55 */
/* .\H\stdio.h 56 */
/* .\H\stdio.h 57 */
/* .\H\stdio.h 58 */
/* .\H\stdio.h 59 */
/* .\H\stdio.h 60 */
/* .\H\stdio.h 61 */
/* .\H\stdio.h 62 */
/* .\H\stdio.h 63 */
/* .\H\stdio.h 64 */
/* .\H\stdio.h 65 */
/* .\H\stdio.h 66 */
/* .\H\stdio.h 67 */
/* .\H\stdio.h 68 */
/* .\H\stdio.h 69 */
/* .\H\stdio.h 70 */
/* .\H\stdio.h 71 */ extern @type FILE __near __iob [ ] ;
/* .\H\stdio.h 72 */
/* .\H\stdio.h 73 */
/* .\H\stdio.h 74 */
/* .\H\stdio.h 75 */
/* .\H\stdio.h 76 */
/* .\H\stdio.h 77 */
/* .\H\stdio.h 78 */
/* .\H\stdio.h 79 */
/* .\H\stdio.h 80 */
/* .\H\stdio.h 81 */
/* .\H\stdio.h 82 */
/* .\H\stdio.h 83 */
/* .\H\stdio.h 84 */
/* .\H\stdio.h 85 */
/* .\H\stdio.h 86 */
/* .\H\stdio.h 87 */
/* .\H\stdio.h 88 */
/* .\H\stdio.h 89 */
/* .\H\stdio.h 90 */
/* .\H\stdio.h 91 */
/* .\H\stdio.h 92 */
/* .\H\stdio.h 93 */
/* .\H\stdio.h 94 */
/* .\H\stdio.h 95 */
/* .\H\stdio.h 96 */
/* .\H\stdio.h 97 */
/* .\H\stdio.h 98 */
/* .\H\stdio.h 99 */
/* .\H\stdio.h 100 */
/* .\H\stdio.h 101 */
/* .\H\stdio.h 102 */
/* .\H\stdio.h 103 */
/* .\H\stdio.h 104 */
/* .\H\stdio.h 105 */
/* .\H\stdio.h 106 */
/* .\H\stdio.h 107 */
/* .\H\stdio.h 108 */
/* .\H\stdio.h 109 */
/* .\H\stdio.h 110 */
/* .\H\stdio.h 111 */
/* .\H\stdio.h 112 */
/* .\H\stdio.h 113 */ extern void clearerr ( @type FILE * __fp ) ;
/* .\H\stdio.h 114 */ extern int fclose ( @type FILE * __fp ) ;
/* .\H\stdio.h 115 */ extern int feof ( @type FILE * __fp ) ;
/* .\H\stdio.h 116 */ extern int ferror ( @type FILE * __fp ) ;
/* .\H\stdio.h 117 */ extern int fflush ( @type FILE * __fp ) ;
/* .\H\stdio.h 118 */ extern int fgetc ( @type FILE * __fp ) ;
/* .\H\stdio.h 119 */ extern int fgetpos ( @type FILE * __fp , @type fpos_t * __pos ) ;
/* .\H\stdio.h 120 */ extern char * fgets ( char * __s , int __n , @type FILE * __fp ) ;
/* .\H\stdio.h 121 */ extern @type FILE * fopen ( const char * __filename , const char * __mode ) ;
/* .\H\stdio.h 122 */ extern int fprintf ( @type FILE * __fp , const char * __format , ... ) ;
/* .\H\stdio.h 123 */ extern int fputc ( int __c , @type FILE * __fp ) ;
/* .\H\stdio.h 124 */ extern int fputs ( const char * __s , @type FILE * __fp ) ;
/* .\H\stdio.h 125 */ extern @type size_t fread ( void * __ptr , @type size_t __size , @type size_t __n , @type FILE * __fp ) ;
/* .\H\stdio.h 126 */ extern @type FILE * freopen ( const char * __filename , const char * __mode , @type FILE * __fp ) ;
/* .\H\stdio.h 127 */ extern int fscanf ( @type FILE * __fp , const char * __format , ... ) ;
/* .\H\stdio.h 128 */ extern int fseek ( @type FILE * __fp , long int __offset , int __whence ) ;
/* .\H\stdio.h 129 */ extern int fsetpos ( @type FILE * __fp , const @type fpos_t * __pos ) ;
/* .\H\stdio.h 130 */ extern long int ftell ( @type FILE * __fp ) ;
/* .\H\stdio.h 131 */ extern @type size_t fwrite ( const void * __ptr , @type size_t __size , @type size_t __n , @type FILE * __fp ) ;
/* .\H\stdio.h 132 */ extern int getc ( @type FILE * __fp ) ;
/* .\H\stdio.h 133 */ extern int getchar ( void ) ;
/* .\H\stdio.h 134 */ extern char * gets ( char * __s ) ;
/* .\H\stdio.h 135 */ extern void perror ( const char * __s ) ;
/* .\H\stdio.h 136 */ extern int printf ( const char * __format , ... ) ;
/* .\H\stdio.h 137 */ extern int putc ( int __c , @type FILE * __fp ) ;
/* .\H\stdio.h 138 */ extern int putchar ( int __c ) ;
/* .\H\stdio.h 139 */ extern int puts ( const char * __s ) ;
/* .\H\stdio.h 140 */ extern int remove ( const char * __filename ) ;
/* .\H\stdio.h 141 */ extern int rename ( const char * __old , const char * __new ) ;
/* .\H\stdio.h 142 */ extern void rewind ( @type FILE * __fp ) ;
/* .\H\stdio.h 143 */ extern int scanf ( const char * __format , ... ) ;
/* .\H\stdio.h 144 */ extern void setbuf ( @type FILE * __fp , char * __buf ) ;
/* .\H\stdio.h 145 */ extern int setvbuf ( @type FILE * __fp , char * __buf , int __mode , @type size_t __size ) ;
/* .\H\stdio.h 146 */ extern int sprintf ( char * __s , const char * __format , ... ) ;
/* .\H\stdio.h 147 */ extern int sscanf ( const char * __s , const char * __format , ... ) ;
/* .\H\stdio.h 148 */ extern @type FILE * tmpfile ( void ) ;
/* .\H\stdio.h 149 */ extern char * tmpnam ( char * __s ) ;
/* .\H\stdio.h 150 */ extern int ungetc ( int __c , @type FILE * __fp ) ;
/* .\H\stdio.h 151 */ extern int vfprintf ( @type FILE * __fp , const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 152 */ extern int vprintf ( const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 153 */ extern int vsprintf ( char * __s , const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 154 */
/* .\H\stdio.h 155 */
/* .\H\stdio.h 156 */ extern int fcloseall ( void ) ;
/* .\H\stdio.h 157 */ extern @type FILE * fdopen ( int __handle , const char * __mode ) ;
/* .\H\stdio.h 158 */ extern int _grow_handles ( int __new_count ) ;
/* .\H\stdio.h 159 */ extern int fgetchar ( void ) ;
/* .\H\stdio.h 160 */ extern int fputchar ( int __c ) ;
/* .\H\stdio.h 161 */ extern @type FILE * _fsopen ( const char * __filename , const char * __mode , int __shflag ) ;
/* .\H\stdio.h 162 */ extern int flushall ( void ) ;
/* .\H\stdio.h 163 */ extern int vfscanf ( @type FILE * __fp , const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 164 */ extern int vscanf ( const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 165 */ extern int vsscanf ( const char * __s , const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 166 */ extern int _bprintf ( char * __buf , unsigned int __bufsize , const char * __fmt , ... ) ;
/* .\H\stdio.h 167 */ extern int _vbprintf ( char * __s , unsigned int __bufsize , const char * __format , @type __va_list __arg ) ;
/* .\H\stdio.h 168 */
/* .\H\stdio.h 169 */
/* .\H\stdio.h 170 */
/* .\H\stdio.h 171 */
/* .\H\stdio.h 172 */
/* .\H\stdio.h 173 */
/* .\H\stdio.h 174 */
/* .\H\stdio.h 175 */
/* .\H\stdio.h 176 */
/* .\H\stdio.h 177 */
/* .\H\stdio.h 178 */
/* .\H\stdio.h 179 */
/* .\H\stdio.h 180 */
/* .\H\stdio.h 187 */
/* .\H\stdio.h 194 */
/* .\H\stdio.h 195 */
/* .\H\stdio.h 196 */
/* .\H\stdio.h 197 */
/* .\H\stdio.h 198 */
/* .\H\stdio.h 199 */
/* .\H\stdio.h 200 */
/* .\H\stdio.h 201 */
/* .\H\stdio.h 202 */
/* .\H\stdio.h 203 */
/* WATCOM100A.H 15 */
/* .\H\conio.h 1 */
/* .\H\conio.h 2 */
/* .\H\conio.h 3 */
/* .\H\conio.h 4 */
/* .\H\conio.h 5 */
/* .\H\conio.h 6 */
/* .\H\conio.h 7 */
/* .\H\conio.h 8 */
/* .\H\conio.h 9 */
/* .\H\conio.h 10 */
/* .\H\conio.h 11 */
/* .\H\conio.h 12 */
/* .\H\conio.h 13 */
/* .\H\conio.h 14 */
/* .\H\conio.h 15 */
/* .\H\conio.h 16 */
/* .\H\conio.h 17 */
/* .\H\conio.h 18 */
/* .\H\conio.h 19 */
/* .\H\conio.h 20 */ extern char * cgets ( char * __buf ) ;
/* .\H\conio.h 21 */ extern int cputs ( const char * __buf ) ;
/* .\H\conio.h 22 */ extern int cprintf ( const char * __fmt , ... ) ;
/* .\H\conio.h 23 */ extern int cscanf ( const char * __fmt , ... ) ;
/* .\H\conio.h 24 */ extern int getch ( void ) ;
/* .\H\conio.h 25 */ extern int getche ( void ) ;
/* .\H\conio.h 26 */ extern int kbhit ( void ) ;
/* .\H\conio.h 27 */ extern unsigned inp ( unsigned __port ) ;
/* .\H\conio.h 28 */ extern unsigned inpw ( unsigned __port ) ;
/* .\H\conio.h 29 */ extern unsigned outp ( unsigned __port , unsigned __value ) ;
/* .\H\conio.h 30 */ extern unsigned outpw ( unsigned __port , unsigned __value ) ;
/* .\H\conio.h 31 */
/* .\H\conio.h 32 */ extern unsigned inpd ( unsigned __port ) ;
/* .\H\conio.h 33 */ extern unsigned outpd ( unsigned __port , unsigned __value ) ;
/* .\H\conio.h 34 */
/* .\H\conio.h 35 */ extern int putch ( int __c ) ;
/* .\H\conio.h 36 */ extern int ungetch ( int __c ) ;
/* .\H\conio.h 37 */ extern int vcprintf ( const char * __format , @type __va_list __arg ) ;
/* .\H\conio.h 38 */ extern int vcscanf ( const char * __format , @type __va_list __arg ) ;
/* .\H\conio.h 39 */
/* .\H\conio.h 40 */
/* .\H\conio.h 41 */
/* .\H\conio.h 42 */
/* .\H\conio.h 43 */
/* .\H\conio.h 44 */
/* .\H\conio.h 45 */
/* .\H\conio.h 46 */
/* .\H\conio.h 47 */
/* .\H\conio.h 48 */
/* .\H\conio.h 49 */
/* .\H\conio.h 50 */
/* .\H\conio.h 51 */
/* WATCOM100A.H 16 */
/* .\H\fcntl.h 1 */
/* .\H\fcntl.h 2 */
/* .\H\fcntl.h 3 */
/* .\H\fcntl.h 4 */
/* .\H\fcntl.h 5 */
/* .\H\fcntl.h 6 */
/* .\H\fcntl.h 7 */
/* .\H\fcntl.h 8 */
/* .\H\fcntl.h 9 */
/* .\H\fcntl.h 10 */
/* .\H\fcntl.h 11 */
/* .\H\fcntl.h 12 */
/* .\H\fcntl.h 13 */
/* .\H\fcntl.h 14 */
/* .\H\fcntl.h 15 */
/* .\H\fcntl.h 16 */
/* .\H\fcntl.h 17 */
/* .\H\fcntl.h 18 */
/* .\H\fcntl.h 19 */
/* .\H\fcntl.h 20 */
/* .\H\fcntl.h 21 */
/* .\H\fcntl.h 22 */
/* .\H\fcntl.h 23 */
/* .\H\fcntl.h 24 */
/* .\H\fcntl.h 25 */
/* .\H\fcntl.h 26 */
/* .\H\fcntl.h 27 */ extern int open ( const char * __path , int __oflag , ... ) ;
/* .\H\fcntl.h 28 */ extern int sopen ( const char * __path , int __oflag , int __share , ... ) ;
/* .\H\fcntl.h 29 */
/* .\H\fcntl.h 30 */
/* .\H\fcntl.h 31 */
/* .\H\fcntl.h 32 */
/* .\H\fcntl.h 33 */
/* .\H\fcntl.h 34 */
/* .\H\fcntl.h 35 */
/* WATCOM100A.H 17 */
/* WATCOM100A.H 18 */
/* .\H\io.h 1 */
/* .\H\io.h 2 */
/* .\H\io.h 3 */
/* .\H\io.h 4 */
/* .\H\io.h 5 */
/* .\H\io.h 6 */
/* .\H\io.h 7 */
/* .\H\io.h 8 */
/* .\H\io.h 9 */
/* .\H\io.h 10 */
/* .\H\io.h 11 */
/* .\H\io.h 12 */
/* .\H\io.h 13 */
/* .\H\io.h 14 */
/* .\H\io.h 15 */
/* .\H\io.h 16 */
/* .\H\io.h 17 */
/* .\H\io.h 18 */
/* .\H\io.h 19 */
/* .\H\io.h 20 */
/* .\H\io.h 21 */
/* .\H\io.h 22 */
/* .\H\io.h 23 */
/* .\H\io.h 24 */
/* .\H\io.h 25 */
/* .\H\io.h 26 */
/* .\H\io.h 27 */
/* .\H\io.h 28 */
/* .\H\io.h 29 */
/* .\H\io.h 30 */
/* .\H\io.h 31 */
/* .\H\io.h 32 */
/* .\H\io.h 33 */
/* .\H\io.h 34 */
/* .\H\io.h 35 */
/* .\H\io.h 36 */
/* .\H\io.h 37 */ extern int access ( const char * __path , int __mode ) ;
/* .\H\io.h 38 */ extern int _access ( const char * __path , int __mode ) ;
/* .\H\io.h 39 */ extern int chmod ( const char * __path , int __pmode ) ;
/* .\H\io.h 40 */ extern int chsize ( int __handle , long __size ) ;
/* .\H\io.h 41 */ extern int close ( int __handle ) ;
/* .\H\io.h 42 */ extern int creat ( const char * __path , int __pmode ) ;
/* .\H\io.h 43 */ extern int dup ( int __handle ) ;
/* .\H\io.h 44 */ extern int _dup ( int __handle ) ;
/* .\H\io.h 45 */ extern int dup2 ( int __handle1 , int __handle2 ) ;
/* .\H\io.h 46 */ extern int eof ( int __handle ) ;
/* .\H\io.h 47 */ extern long filelength ( int __handle ) ;
/* .\H\io.h 48 */ extern int _hdopen ( int __handle , int __mode ) ;
/* .\H\io.h 49 */ extern int isatty ( int __handle ) ;
/* .\H\io.h 50 */ extern int lock ( int __handle , unsigned long __offset , unsigned long __nbytes ) ;
/* .\H\io.h 51 */ extern long lseek ( int __handle , long __offset , int __origin ) ;
/* .\H\io.h 52 */ extern long _lseek ( int __handle , long __offset , int __origin ) ;
/* .\H\io.h 53 */ extern int open ( const char * __path , int __oflag , ... ) ;
/* .\H\io.h 54 */ extern int _os_handle ( int __handle ) ;
/* .\H\io.h 55 */ extern int read ( int __handle , void * __buf , unsigned int __len ) ;
/* .\H\io.h 56 */ extern int setmode ( int __handle , int __mode ) ;
/* .\H\io.h 57 */ extern int sopen ( const char * __path , int __oflag , int __shflag , ... ) ;
/* .\H\io.h 58 */ extern long tell ( int __handle ) ;
/* .\H\io.h 59 */ extern int umask ( int __permission ) ;
/* .\H\io.h 60 */ extern int unlink ( const char * __path ) ;
/* .\H\io.h 61 */ extern int unlock ( int __handle , unsigned long __offset , unsigned long __nbytes ) ;
/* .\H\io.h 62 */ extern int write ( int __handle , const void * __buf , unsigned int __len ) ;
/* .\H\io.h 63 */
/* .\H\io.h 64 */
/* .\H\sys/stat.h 1 */
/* .\H\sys/stat.h 2 */
/* .\H\sys/stat.h 3 */
/* .\H\sys/stat.h 4 */
/* .\H\sys/stat.h 5 */
/* .\H\sys/stat.h 6 */
/* .\H\sys/stat.h 7 */
/* .\H\sys/stat.h 8 */
/* .\H\sys/stat.h 9 */
/* .\H\sys/stat.h 10 */
/* .\H\sys/stat.h 11 */
/* .\H\sys/stat.h 12 */
/* .\H\sys/stat.h 13 */
/* .\H\sys/stat.h 14 */
/* .\H\sys/stat.h 15 */
/* .\H\sys/stat.h 16 */
/* .\H\sys/stat.h 17 */
/* .\H\sys/types.h 1 */
/* .\H\sys/types.h 2 */
/* .\H\sys/types.h 3 */
/* .\H\sys/types.h 4 */
/* .\H\sys/types.h 5 */
/* .\H\sys/types.h 6 */
/* .\H\sys/types.h 7 */
/* .\H\sys/types.h 8 */
/* .\H\sys/types.h 9 */
/* .\H\sys/types.h 10 */
/* .\H\sys/types.h 11 */
/* .\H\sys/types.h 12 */
/* .\H\sys/types.h 13 */ typedef unsigned long time_t ;
/* .\H\sys/types.h 14 */
/* .\H\sys/types.h 15 */
/* .\H\sys/types.h 16 */
/* .\H\sys/types.h 17 */
/* .\H\sys/types.h 18 */
/* .\H\sys/types.h 19 */
/* .\H\sys/types.h 20 */
/* .\H\sys/types.h 21 */ typedef unsigned int ino_t ;
/* .\H\sys/types.h 22 */ typedef int dev_t ;
/* .\H\sys/types.h 23 */ typedef long off_t ;
/* .\H\sys/types.h 24 */
/* .\H\sys/types.h 25 */
/* .\H\sys/types.h 26 */
/* .\H\sys/types.h 27 */
/* .\H\sys/types.h 28 */
/* .\H\sys/types.h 29 */
/* .\H\sys/stat.h 18 */
/* .\H\sys/stat.h 19 */
/* .\H\sys/stat.h 20 */
/* .\H\sys/stat.h 21 */
/* .\H\sys/stat.h 22 */ struct _stat {
/* .\H\sys/stat.h 23 */ @type dev_t st_dev ;
/* .\H\sys/stat.h 24 */ @type ino_t st_ino ;
/* .\H\sys/stat.h 25 */ unsigned short st_mode ;
/* .\H\sys/stat.h 26 */ short st_nlink ;
/* .\H\sys/stat.h 27 */ unsigned long st_uid ;
/* .\H\sys/stat.h 28 */ short st_gid ;
/* .\H\sys/stat.h 29 */ @type dev_t st_rdev ;
/* .\H\sys/stat.h 30 */
/* .\H\sys/stat.h 31 */ @type off_t st_size ;
/* .\H\sys/stat.h 32 */ @type time_t st_atime ;
/* .\H\sys/stat.h 33 */ @type time_t st_mtime ;
/* .\H\sys/stat.h 34 */ @type time_t st_ctime ;
/* .\H\sys/stat.h 35 */ @type time_t st_btime ;
/* .\H\sys/stat.h 36 */ unsigned long st_attr ;
/* .\H\sys/stat.h 37 */ unsigned long st_archivedID ;
/* .\H\sys/stat.h 38 */ unsigned long st_updatedID ;
/* .\H\sys/stat.h 39 */ unsigned short st_inheritedRightsMask ;
/* .\H\sys/stat.h 40 */ unsigned char st_originatingNameSpace ;
/* .\H\sys/stat.h 41 */ unsigned char st_name [ 0xD ] ;
/* .\H\sys/stat.h 42 */ } ;
/* .\H\sys/stat.h 43 */ struct stat {
/* .\H\sys/stat.h 44 */ @type dev_t st_dev ;
/* .\H\sys/stat.h 45 */ @type ino_t st_ino ;
/* .\H\sys/stat.h 46 */ unsigned short st_mode ;
/* .\H\sys/stat.h 47 */ short st_nlink ;
/* .\H\sys/stat.h 48 */ unsigned long st_uid ;
/* .\H\sys/stat.h 49 */ short st_gid ;
/* .\H\sys/stat.h 50 */ @type dev_t st_rdev ;
/* .\H\sys/stat.h 51 */
/* .\H\sys/stat.h 52 */ @type off_t st_size ;
/* .\H\sys/stat.h 53 */ @type time_t st_atime ;
/* .\H\sys/stat.h 54 */ @type time_t st_mtime ;
/* .\H\sys/stat.h 55 */ @type time_t st_ctime ;
/* .\H\sys/stat.h 56 */ @type time_t st_btime ;
/* .\H\sys/stat.h 57 */ unsigned long st_attr ;
/* .\H\sys/stat.h 58 */ unsigned long st_archivedID ;
/* .\H\sys/stat.h 59 */ unsigned long st_updatedID ;
/* .\H\sys/stat.h 60 */ unsigned short st_inheritedRightsMask ;
/* .\H\sys/stat.h 61 */ unsigned char st_originatingNameSpace ;
/* .\H\sys/stat.h 62 */ unsigned char st_name [ 0xD ] ;
/* .\H\sys/stat.h 63 */ } ;
/* .\H\sys/stat.h 64 */
/* .\H\sys/stat.h 65 */
/* .\H\sys/stat.h 66 */
/* .\H\sys/stat.h 67 */
/* .\H\sys/stat.h 68 */
/* .\H\sys/stat.h 69 */
/* .\H\sys/stat.h 70 */
/* .\H\sys/stat.h 71 */
/* .\H\sys/stat.h 72 */
/* .\H\sys/stat.h 73 */
/* .\H\sys/stat.h 74 */
/* .\H\sys/stat.h 75 */
/* .\H\sys/stat.h 76 */
/* .\H\sys/stat.h 77 */
/* .\H\sys/stat.h 78 */
/* .\H\sys/stat.h 79 */
/* .\H\sys/stat.h 80 */
/* .\H\sys/stat.h 81 */
/* .\H\sys/stat.h 82 */
/* .\H\sys/stat.h 83 */
/* .\H\sys/stat.h 84 */
/* .\H\sys/stat.h 85 */
/* .\H\sys/stat.h 86 */
/* .\H\sys/stat.h 87 */
/* .\H\sys/stat.h 88 */
/* .\H\sys/stat.h 89 */
/* .\H\sys/stat.h 90 */
/* .\H\sys/stat.h 91 */
/* .\H\sys/stat.h 92 */
/* .\H\sys/stat.h 93 */
/* .\H\sys/stat.h 94 */
/* .\H\sys/stat.h 95 */
/* .\H\sys/stat.h 96 */
/* .\H\sys/stat.h 97 */
/* .\H\sys/stat.h 98 */
/* .\H\sys/stat.h 99 */
/* .\H\sys/stat.h 100 */
/* .\H\sys/stat.h 101 */
/* .\H\sys/stat.h 102 */
/* .\H\sys/stat.h 103 */ extern int fstat ( int , struct stat * ) ;
/* .\H\sys/stat.h 104 */ extern int _fstat ( int , struct _stat * ) ;
/* .\H\sys/stat.h 105 */ extern int stat ( const char * , struct stat * ) ;
/* .\H\sys/stat.h 106 */ extern int _stat ( const char * , struct _stat * ) ;
/* .\H\sys/stat.h 107 */
/* .\H\sys/stat.h 108 */
/* .\H\sys/stat.h 109 */
/* .\H\sys/stat.h 110 */
/* .\H\sys/stat.h 111 */
/* .\H\sys/stat.h 112 */
/* .\H\sys/stat.h 113 */
/* .\H\io.h 65 */
/* .\H\io.h 66 */
/* .\H\io.h 67 */
/* .\H\io.h 68 */
/* .\H\io.h 69 */
/* .\H\io.h 70 */
/* .\H\io.h 71 */
/* WATCOM100A.H 19 */
/* .\H\mem.h 1 */
/* .\H\mem.h 2 */
/* .\H\mem.h 3 */
/* .\H\mem.h 4 */
/* .\H\mem.h 5 */
/* .\H\mem.h 6 */
/* .\H\mem.h 7 */
/* .\H\mem.h 8 */
/* .\H\mem.h 9 */
/* .\H\mem.h 10 */
/* .\H\mem.h 11 */ typedef int ptrdiff_t ;
/* .\H\mem.h 12 */
/* .\H\mem.h 13 */
/* .\H\mem.h 14 */
/* .\H\mem.h 15 */
/* .\H\string.h 1 */
/* .\H\string.h 2 */
/* .\H\string.h 3 */
/* .\H\string.h 4 */
/* .\H\string.h 5 */
/* .\H\string.h 6 */
/* .\H\string.h 7 */
/* .\H\string.h 8 */
/* .\H\string.h 9 */
/* .\H\string.h 10 */
/* .\H\string.h 11 */
/* .\H\string.h 12 */
/* .\H\string.h 13 */
/* .\H\string.h 14 */
/* .\H\string.h 15 */
/* .\H\string.h 16 */
/* .\H\string.h 17 */
/* .\H\string.h 18 */
/* .\H\string.h 19 */
/* .\H\string.h 20 */
/* .\H\string.h 21 */
/* .\H\string.h 22 */
/* .\H\string.h 23 */
/* .\H\string.h 24 */ extern void * memchr ( const void * __s , int __c , @type size_t __n ) ;
/* .\H\string.h 25 */ extern int memcmp ( const void * __s1 , const void * __s2 , @type size_t __n ) ;
/* .\H\string.h 26 */ extern void * memcpy ( void * __s1 , const void * __s2 , @type size_t __n ) ;
/* .\H\string.h 27 */ extern void * memmove ( void * __s1 , const void * __s2 , @type size_t __n ) ;
/* .\H\string.h 28 */ extern void * memset ( void * __s , int __c , @type size_t __n ) ;
/* .\H\string.h 29 */ extern char * strcat ( char * __s1 , const char * __s2 ) ;
/* .\H\string.h 30 */ extern char * strchr ( const char * __s , int __c ) ;
/* .\H\string.h 31 */ extern int strcmp ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 32 */ extern int strcoll ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 33 */ extern @type size_t strxfrm ( char * __s1 , const char * __s2 , @type size_t __n ) ;
/* .\H\string.h 34 */ extern char * strcpy ( char * __s1 , const char * __s2 ) ;
/* .\H\string.h 35 */ extern @type size_t strcspn ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 36 */ extern char * strerror ( int __errnum ) ;
/* .\H\string.h 37 */ extern @type size_t strlen ( const char * __s ) ;
/* .\H\string.h 38 */ extern char * strncat ( char * __s1 , const char * __s2 , @type size_t __n ) ;
/* .\H\string.h 39 */ extern int strncmp ( const char * __s1 , const char * __s2 , @type size_t __n ) ;
/* .\H\string.h 40 */ extern char * strncpy ( char * __s1 , const char * __s2 , @type size_t __n ) ;
/* .\H\string.h 41 */ extern char * strpbrk ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 42 */ extern char * strrchr ( const char * __s , int __c ) ;
/* .\H\string.h 43 */ extern @type size_t strspn ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 44 */ extern char * strstr ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 45 */ extern char * strtok ( char * __s1 , const char * __s2 ) ;
/* .\H\string.h 46 */
/* .\H\string.h 47 */
/* .\H\string.h 48 */
/* .\H\string.h 49 */
/* .\H\string.h 50 */
/* .\H\string.h 51 */ extern void __far * _fmemccpy ( void __far * __s1 , const void __far * __s2 , int __c , @type size_t __n ) ;
/* .\H\string.h 52 */ extern void __far * _fmemchr ( const void __far * __s , int __c , @type size_t __n ) ;
/* .\H\string.h 53 */ extern void __far * _fmemcpy ( void __far * __s1 , const void __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 54 */ extern void __far * _fmemmove ( void __far * __s1 , const void __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 55 */ extern void __far * _fmemset ( void __far * __s , int __c , @type size_t __n ) ;
/* .\H\string.h 56 */ extern int _fmemcmp ( const void __far * __s1 , const void __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 57 */ extern int _fmemicmp ( const void __far * __s1 , const void __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 58 */ extern char __far * _fstrcat ( char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 59 */ extern char __far * _fstrchr ( const char __far * __s , int __c ) ;
/* .\H\string.h 60 */ extern int _fstrcmp ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 61 */ extern char __far * _fstrcpy ( char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 62 */ extern @type size_t _fstrcspn ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 63 */ extern char __far * _fstrdup ( const char __far * __string ) ;
/* .\H\string.h 64 */ extern int _fstricmp ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 65 */ extern char __far * _fstrncat ( char __far * __s1 , const char __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 66 */ extern @type size_t _fstrlen ( const char __far * __s ) ;
/* .\H\string.h 67 */ extern char __far * _fstrlwr ( char __far * __string ) ;
/* .\H\string.h 68 */ extern int _fstrncmp ( const char __far * __s1 , const char __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 69 */ extern char __far * _fstrncpy ( char __far * __s1 , const char __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 70 */ extern int _fstrnicmp ( const char __far * __s1 , const char __far * __s2 , @type size_t __n ) ;
/* .\H\string.h 71 */ extern char __far * _fstrnset ( char __far * __string , int __c , @type size_t __len ) ;
/* .\H\string.h 72 */ extern char __far * _fstrpbrk ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 73 */ extern char __far * _fstrrchr ( const char __far * __s , int __c ) ;
/* .\H\string.h 74 */ extern char __far * _fstrrev ( char __far * __string ) ;
/* .\H\string.h 75 */ extern char __far * _fstrset ( char __far * __string , int __c ) ;
/* .\H\string.h 76 */ extern @type size_t _fstrspn ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 77 */ extern char __far * _fstrstr ( const char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 78 */ extern char __far * _fstrtok ( char __far * __s1 , const char __far * __s2 ) ;
/* .\H\string.h 79 */ extern char __far * _fstrupr ( char __far * __string ) ;
/* .\H\string.h 80 */ extern void movedata ( unsigned __srcseg , unsigned __srcoff ,
/* .\H\string.h 81 */ unsigned __tgtseg , unsigned __tgtoff , unsigned __len ) ;
/* .\H\string.h 82 */ extern void * memccpy ( void * __s1 , const void * __s2 , int __c , @type size_t __n ) ;
/* .\H\string.h 83 */ extern int memicmp ( const void * __s1 , const void * __s2 , @type size_t __n ) ;
/* .\H\string.h 84 */ extern int _memicmp ( const void * __s1 , const void * __s2 , @type size_t __n ) ;
/* .\H\string.h 85 */ extern int strcmpi ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 86 */ extern char * strdup ( const char * __string ) ;
/* .\H\string.h 87 */ extern char * _strdup ( const char * __string ) ;
/* .\H\string.h 88 */ extern int stricmp ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 89 */ extern int _stricmp ( const char * __s1 , const char * __s2 ) ;
/* .\H\string.h 90 */ extern char * strlwr ( char * __string ) ;
/* .\H\string.h 91 */ extern char * _strlwr ( char * __string ) ;
/* .\H\string.h 92 */ extern int strnicmp ( const char * __s1 , const char * __s2 , @type size_t __n ) ;
/* .\H\string.h 93 */ extern char * strnset ( char * __string , int __c , @type size_t __len ) ;
/* .\H\string.h 94 */ extern char * strrev ( char * __string ) ;
/* .\H\string.h 95 */ extern char * _strrev ( char * __string ) ;
/* .\H\string.h 96 */ extern char * strset ( char * __string , int __c ) ;
/* .\H\string.h 97 */ extern char * strupr ( char * __string ) ;
/* .\H\string.h 98 */ extern char * _strupr ( char * __string ) ;
/* .\H\string.h 99 */
/* .\H\string.h 100 */
/* .\H\string.h 101 */
/* .\H\string.h 102 */
/* .\H\string.h 103 */
/* .\H\string.h 104 */
/* .\H\string.h 105 */
/* .\H\string.h 106 */
/* .\H\string.h 107 */
/* .\H\string.h 108 */
/* .\H\string.h 109 */
/* .\H\string.h 110 */
/* .\H\string.h 111 */
/* .\H\string.h 112 */
/* .\H\string.h 113 */
/* .\H\string.h 114 */
/* .\H\string.h 115 */
/* .\H\string.h 116 */
/* .\H\string.h 117 */
/* WATCOM100A.H 20 */
/* .\H\math.h 1 */
/* .\H\math.h 2 */
/* .\H\math.h 3 */
/* .\H\math.h 4 */
/* .\H\math.h 5 */
/* .\H\math.h 6 */
/* .\H\math.h 7 */
/* .\H\math.h 8 */
/* .\H\math.h 9 */
/* .\H\math.h 10 */
/* .\H\math.h 11 */
/* .\H\math.h 12 */
/* .\H\math.h 13 */
/* .\H\math.h 14 */ extern const double __near _HugeValue ;
/* .\H\math.h 15 */
/* .\H\math.h 16 */
/* .\H\math.h 17 */
/* .\H\math.h 18 */ extern double acos ( double __x ) ;
/* .\H\math.h 19 */ extern double asin ( double __x ) ;
/* .\H\math.h 20 */ extern double atan ( double __x ) ;
/* .\H\math.h 21 */ extern double atan2 ( double __y , double __x ) ;
/* .\H\math.h 22 */ extern double ceil ( double __x ) ;
/* .\H\math.h 23 */ extern double cos ( double __x ) ;
/* .\H\math.h 24 */ extern double cosh ( double __x ) ;
/* .\H\math.h 25 */ extern double exp ( double __x ) ;
/* .\H\math.h 26 */ extern double fabs ( double __x ) ;
/* .\H\math.h 27 */ extern double floor ( double __x ) ;
/* .\H\math.h 28 */ extern double fmod ( double __x , double __y ) ;
/* .\H\math.h 29 */ extern double frexp ( double __value , int * __exp ) ;
/* .\H\math.h 30 */ extern double ldexp ( double __x , int __exp ) ;
/* .\H\math.h 31 */ extern double log ( double __x ) ;
/* .\H\math.h 32 */ extern double log10 ( double __x ) ;
/* .\H\math.h 33 */ extern double modf ( double __value , double * __iptr ) ;
/* .\H\math.h 34 */ extern double pow ( double __x , double __y ) ;
/* .\H\math.h 35 */ extern double sin ( double __x ) ;
/* .\H\math.h 36 */ extern double sinh ( double __x ) ;
/* .\H\math.h 37 */ extern double sqrt ( double __x ) ;
/* .\H\math.h 38 */ extern double tan ( double __x ) ;
/* .\H\math.h 39 */ extern double tanh ( double __x ) ;
/* .\H\math.h 40 */
/* .\H\math.h 41 */
/* .\H\math.h 42 */
/* .\H\math.h 43 */
/* .\H\math.h 44 */ struct _complex {
/* .\H\math.h 45 */ double x ;
/* .\H\math.h 46 */ double y ;
/* .\H\math.h 47 */ } ;
/* .\H\math.h 48 */
/* .\H\math.h 49 */ struct complex {
/* .\H\math.h 50 */ double x ;
/* .\H\math.h 51 */ double y ;
/* .\H\math.h 52 */ } ;
/* .\H\math.h 53 */
/* .\H\math.h 54 */
/* .\H\math.h 55 */ extern double acosh ( double __x ) ;
/* .\H\math.h 56 */ extern double asinh ( double __x ) ;
/* .\H\math.h 57 */ extern double atanh ( double __x ) ;
/* .\H\math.h 58 */ extern double cabs ( struct _complex ) ;
/* .\H\math.h 59 */ extern double hypot ( double __x , double __y ) ;
/* .\H\math.h 60 */ extern double j0 ( double __x ) ;
/* .\H\math.h 61 */ extern double j1 ( double __x ) ;
/* .\H\math.h 62 */ extern double jn ( int __n , double __x ) ;
/* .\H\math.h 63 */ extern double log2 ( double __x ) ;
/* .\H\math.h 64 */ extern double y0 ( double __x ) ;
/* .\H\math.h 65 */ extern double y1 ( double __x ) ;
/* .\H\math.h 66 */ extern double yn ( int __n , double __x ) ;
/* .\H\math.h 67 */
/* .\H\math.h 68 */
/* .\H\math.h 69 */
/* .\H\math.h 70 */
/* .\H\math.h 71 */
/* .\H\math.h 72 */ struct exception {
/* .\H\math.h 73 */ int type ;
/* .\H\math.h 74 */ char * name ;
/* .\H\math.h 75 */ double arg1 ;
/* .\H\math.h 76 */ double arg2 ;
/* .\H\math.h 77 */ double retval ;
/* .\H\math.h 78 */ } ;
/* .\H\math.h 79 */
/* .\H\math.h 80 */
/* .\H\math.h 81 */
/* .\H\math.h 82 */
/* .\H\math.h 83 */
/* .\H\math.h 84 */
/* .\H\math.h 85 */
/* .\H\math.h 86 */
/* .\H\math.h 87 */ extern int matherr ( struct exception * ) ;
/* .\H\math.h 88 */ extern double _matherr ( struct exception * ) ;
/* .\H\math.h 89 */
/* .\H\math.h 90 */
/* .\H\math.h 91 */
/* .\H\math.h 92 */
/* .\H\math.h 93 */
/* .\H\math.h 94 */
/* .\H\math.h 95 */
/* .\H\math.h 96 */
/* .\H\math.h 97 */
/* .\H\math.h 98 */
/* .\H\math.h 99 */
/* .\H\math.h 100 */
/* .\H\math.h 101 */
/* .\H\math.h 102 */
/* .\H\math.h 103 */
/* .\H\math.h 104 */
/* .\H\math.h 105 */
/* WATCOM100A.H 21 */
/* .\H\time.h 1 */
/* .\H\time.h 2 */
/* .\H\time.h 3 */
/* .\H\time.h 4 */
/* .\H\time.h 5 */
/* .\H\time.h 6 */
/* .\H\time.h 7 */
/* .\H\time.h 8 */
/* .\H\time.h 9 */
/* .\H\time.h 10 */
/* .\H\time.h 11 */
/* .\H\time.h 12 */
/* .\H\time.h 13 */
/* .\H\time.h 14 */
/* .\H\time.h 15 */
/* .\H\time.h 16 */
/* .\H\time.h 17 */
/* .\H\time.h 18 */
/* .\H\time.h 19 */
/* .\H\time.h 20 */
/* .\H\time.h 21 */
/* .\H\time.h 22 */
/* .\H\time.h 23 */
/* .\H\time.h 24 */
/* .\H\time.h 25 */
/* .\H\time.h 26 */
/* .\H\time.h 27 */
/* .\H\time.h 28 */
/* .\H\time.h 29 */
/* .\H\time.h 30 */
/* .\H\time.h 31 */
/* .\H\time.h 32 */
/* .\H\time.h 33 */
/* .\H\time.h 34 */
/* .\H\time.h 35 */
/* .\H\time.h 36 */ typedef unsigned long clock_t ;
/* .\H\time.h 37 */
/* .\H\time.h 38 */
/* .\H\time.h 39 */ struct tm {
/* .\H\time.h 40 */ int tm_sec ;
/* .\H\time.h 41 */ int tm_min ;
/* .\H\time.h 42 */ int tm_hour ;
/* .\H\time.h 43 */ int tm_mday ;
/* .\H\time.h 44 */ int tm_mon ;
/* .\H\time.h 45 */ int tm_year ;
/* .\H\time.h 46 */ int tm_wday ;
/* .\H\time.h 47 */ int tm_yday ;
/* .\H\time.h 48 */ int tm_isdst ;
/* .\H\time.h 49 */ } ;
/* .\H\time.h 50 */
/* .\H\time.h 51 */ extern char * asctime ( const struct tm * __timeptr ) ;
/* .\H\time.h 52 */ extern @type clock_t clock ( void ) ;
/* .\H\time.h 53 */ extern char * ctime ( const @type time_t * __timer ) ;
/* .\H\time.h 54 */ extern double difftime ( @type time_t __t1 , @type time_t __t0 ) ;
/* .\H\time.h 55 */ extern struct tm * gmtime ( const @type time_t * __timer ) ;
/* .\H\time.h 56 */ extern struct tm * localtime ( const @type time_t * __timer ) ;
/* .\H\time.h 57 */ extern @type time_t mktime ( struct tm * __timeptr ) ;
/* .\H\time.h 58 */ extern @type size_t strftime ( char * __s , @type size_t __maxsiz , const char * __fmt ,
/* .\H\time.h 59 */ const struct tm * __tp ) ;
/* .\H\time.h 60 */ extern @type time_t time ( @type time_t * __timer ) ;
/* .\H\time.h 61 */
/* .\H\time.h 62 */
/* .\H\time.h 63 */
/* .\H\time.h 64 */
/* .\H\time.h 65 */
/* .\H\time.h 66 */
/* .\H\time.h 67 */ extern char * _asctime ( const struct tm * __timeptr , char * __buf ) ;
/* .\H\time.h 68 */ extern char * _ctime ( const @type time_t * __timer , char * __buf ) ;
/* .\H\time.h 69 */ extern struct tm * _gmtime ( const @type time_t * __timer , struct tm * __tmbuf ) ;
/* .\H\time.h 70 */ extern struct tm * _localtime ( const @type time_t * __timer , struct tm * __tmbuf ) ;
/* .\H\time.h 71 */ extern char * _strdate ( char * __buf ) ;
/* .\H\time.h 72 */ extern char * _strtime ( char * __buf ) ;
/* .\H\time.h 73 */
/* .\H\time.h 74 */
/* .\H\time.h 75 */ extern void tzset ( void ) ;
/* .\H\time.h 76 */
/* .\H\time.h 77 */ extern char * tzname [ 0x2 ] ;
/* .\H\time.h 78 */ extern long timezone ;
/* .\H\time.h 79 */ extern int daylight ;
/* .\H\time.h 80 */
/* .\H\time.h 81 */
/* .\H\time.h 82 */
/* .\H\time.h 83 */
/* .\H\time.h 84 */
/* .\H\time.h 85 */
/* .\H\time.h 86 */
/* .\H\time.h 87 */
/* WATCOM100A.H 22 */
/* .\H\SYS\stat.h 1 */
/* .\H\SYS\stat.h 2 */
/* .\H\SYS\stat.h 3 */
/* .\H\SYS\stat.h 4 */
/* .\H\SYS\stat.h 5 */
/* .\H\SYS\stat.h 6 */
/* .\H\SYS\stat.h 7 */
/* .\H\SYS\stat.h 8 */
/* .\H\SYS\stat.h 9 */
/* .\H\SYS\stat.h 10 */
/* .\H\SYS\stat.h 11 */
/* .\H\SYS\stat.h 12 */
/* .\H\SYS\stat.h 13 */
/* .\H\SYS\stat.h 14 */
/* .\H\SYS\stat.h 15 */
/* .\H\SYS\stat.h 16 */
/* .\H\SYS\stat.h 17 */
/* .\H\SYS\stat.h 18 */
/* .\H\SYS\stat.h 19 */
/* .\H\SYS\stat.h 20 */
/* .\H\SYS\stat.h 21 */
/* .\H\SYS\stat.h 22 */
/* .\H\SYS\stat.h 23 */
/* .\H\SYS\stat.h 24 */
/* .\H\SYS\stat.h 25 */
/* .\H\SYS\stat.h 26 */
/* .\H\SYS\stat.h 27 */
/* .\H\SYS\stat.h 28 */
/* .\H\SYS\stat.h 29 */
/* .\H\SYS\stat.h 30 */
/* .\H\SYS\stat.h 31 */
/* .\H\SYS\stat.h 32 */
/* .\H\SYS\stat.h 33 */
/* .\H\SYS\stat.h 34 */
/* .\H\SYS\stat.h 35 */
/* .\H\SYS\stat.h 36 */
/* .\H\SYS\stat.h 37 */
/* .\H\SYS\stat.h 38 */
/* .\H\SYS\stat.h 39 */
/* .\H\SYS\stat.h 40 */
/* .\H\SYS\stat.h 41 */
/* .\H\SYS\stat.h 42 */
/* .\H\SYS\stat.h 43 */
/* .\H\SYS\stat.h 44 */
/* .\H\SYS\stat.h 45 */
/* .\H\SYS\stat.h 46 */
/* .\H\SYS\stat.h 47 */
/* .\H\SYS\stat.h 48 */
/* .\H\SYS\stat.h 49 */
/* .\H\SYS\stat.h 50 */
/* .\H\SYS\stat.h 51 */
/* .\H\SYS\stat.h 52 */
/* .\H\SYS\stat.h 53 */
/* .\H\SYS\stat.h 54 */
/* .\H\SYS\stat.h 55 */
/* .\H\SYS\stat.h 56 */
/* .\H\SYS\stat.h 57 */
/* .\H\SYS\stat.h 58 */
/* .\H\SYS\stat.h 59 */
/* .\H\SYS\stat.h 60 */
/* .\H\SYS\stat.h 61 */
/* .\H\SYS\stat.h 62 */
/* .\H\SYS\stat.h 63 */
/* .\H\SYS\stat.h 64 */
/* .\H\SYS\stat.h 65 */
/* .\H\SYS\stat.h 66 */
/* .\H\SYS\stat.h 67 */
/* .\H\SYS\stat.h 68 */
/* .\H\SYS\stat.h 69 */
/* .\H\SYS\stat.h 70 */
/* .\H\SYS\stat.h 71 */
/* .\H\SYS\stat.h 72 */
/* .\H\SYS\stat.h 73 */
/* .\H\SYS\stat.h 74 */
/* .\H\SYS\stat.h 75 */
/* .\H\SYS\stat.h 76 */
/* .\H\SYS\stat.h 77 */
/* .\H\SYS\stat.h 78 */
/* .\H\SYS\stat.h 79 */
/* .\H\SYS\stat.h 80 */
/* .\H\SYS\stat.h 81 */
/* .\H\SYS\stat.h 82 */
/* .\H\SYS\stat.h 83 */
/* .\H\SYS\stat.h 84 */
/* .\H\SYS\stat.h 85 */
/* .\H\SYS\stat.h 86 */
/* .\H\SYS\stat.h 87 */
/* .\H\SYS\stat.h 88 */
/* .\H\SYS\stat.h 89 */
/* .\H\SYS\stat.h 90 */
/* .\H\SYS\stat.h 91 */
/* .\H\SYS\stat.h 92 */
/* .\H\SYS\stat.h 93 */
/* .\H\SYS\stat.h 94 */
/* .\H\SYS\stat.h 95 */
/* .\H\SYS\stat.h 96 */
/* .\H\SYS\stat.h 97 */
/* .\H\SYS\stat.h 98 */
/* .\H\SYS\stat.h 99 */
/* .\H\SYS\stat.h 100 */
/* .\H\SYS\stat.h 101 */
/* .\H\SYS\stat.h 102 */
/* .\H\SYS\stat.h 103 */
/* .\H\SYS\stat.h 104 */
/* .\H\SYS\stat.h 105 */
/* .\H\SYS\stat.h 106 */
/* .\H\SYS\stat.h 107 */
/* .\H\SYS\stat.h 108 */
/* .\H\SYS\stat.h 109 */
/* .\H\SYS\stat.h 110 */
/* .\H\SYS\stat.h 111 */
/* .\H\SYS\stat.h 112 */
/* .\H\SYS\stat.h 113 */
/* WATCOM100A.H 23 */
/* .\H\SYS\types.h 1 */
/* .\H\SYS\types.h 2 */
/* .\H\SYS\types.h 3 */
/* .\H\SYS\types.h 4 */
/* .\H\SYS\types.h 5 */
/* .\H\SYS\types.h 6 */
/* .\H\SYS\types.h 7 */
/* .\H\SYS\types.h 8 */
/* .\H\SYS\types.h 9 */
/* .\H\SYS\types.h 10 */
/* .\H\SYS\types.h 11 */
/* .\H\SYS\types.h 12 */
/* .\H\SYS\types.h 13 */
/* .\H\SYS\types.h 14 */
/* .\H\SYS\types.h 15 */
/* .\H\SYS\types.h 16 */
/* .\H\SYS\types.h 17 */
/* .\H\SYS\types.h 18 */
/* .\H\SYS\types.h 19 */
/* .\H\SYS\types.h 20 */
/* .\H\SYS\types.h 21 */
/* .\H\SYS\types.h 22 */
/* .\H\SYS\types.h 23 */
/* .\H\SYS\types.h 24 */
/* .\H\SYS\types.h 25 */
/* .\H\SYS\types.h 26 */
/* .\H\SYS\types.h 27 */
/* .\H\SYS\types.h 28 */
/* .\H\SYS\types.h 29 */
/* WATCOM100A.H 24 */
/* .\H\assert.h 1 */
/* .\H\assert.h 2 */
/* .\H\assert.h 3 */
/* .\H\assert.h 4 */
/* .\H\assert.h 5 */
/* .\H\assert.h 6 */
/* .\H\assert.h 7 */
/* .\H\assert.h 8 */
/* .\H\assert.h 9 */
/* .\H\assert.h 10 */
/* .\H\assert.h 11 */
/* .\H\assert.h 12 */
/* .\H\assert.h 13 */
/* .\H\assert.h 14 */ extern void __assert ( int , char * , char * , int ) ;
/* .\H\assert.h 15 */
/* .\H\assert.h 16 */
/* .\H\assert.h 17 */
/* .\H\assert.h 18 */
/* .\H\assert.h 19 */
/* .\H\assert.h 20 */
/* .\H\assert.h 21 */
/* .\H\assert.h 22 */
/* .\H\assert.h 23 */
/* WATCOM100A.H 25 */ <END>
