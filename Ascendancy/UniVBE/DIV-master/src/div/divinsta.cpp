
//�����������������������������������������������������������������������������
//  M�dulo que contiene el c�digo del creador de instalaciones
//�����������������������������������������������������������������������������

#include "global.h"
#include "zlib.h"
#include <io.h>
#include <time.h>

//�����������������������������������������������������������������������������
//  Prototipos y variables del m�dulo
//�����������������������������������������������������������������������������

void Setup0();
void Setupm0();
void Setupe0();

char AppName[128];
char Copy_Right[128];
char PackName[128]="";
char Unid[128];
char DefDir[128];
char MsgExe[128];
char THelp1[128];
char THelp2[128];
char TDisk1[128];
char TDisk2[128];

char Ierr0[128];
char Ierr1[128];
char Ierr2[128];
char Ierr3[128];
char Ierr4[128];
char Ierr5[128];
char Ierr6[128];
char Ierr7[128];
char Ierr8[128];

char ifile1[256]="INSTALL\\INSTALL.FPG",ifile1name[16]="INSTALL.FPG";
char ifile2[256]="INSTALL\\INST_SMA.FNT",ifile2name[16]="INST_SMA.FNT";
char ifile3[256]="INSTALL\\INST_BIG.FNT",ifile3name[16]="INST_BIG.FNT";

//�����������������������������������������������������������������������������

int include_setup=0;
int create_dir=0;
int empaquetar=1;
int pentium=1;
int segundo_font=1;

//�����������������������������������������������������������������������������

typedef struct _HeaderSetup{
  char name[16];          // Nombre del archivo (en asciiz, sin path)
  unsigned int offset;    // Desplazamiento respecto al inicio del pack
  unsigned int len1;      // Longitud del archivo en el packfile (comprimido)
  unsigned int len2;      // Longitud del archivo real (descomprimido)
}HeaderSetup;

HeaderSetup *MiHeaderSetup;

int nfiles,is_disk=0;

char ExeGen[_MAX_PATH]; // PROGRAM.EXE

char *__ins,*_ins,*ins; // Punteros a EXEC.INS

extern char user1[];
extern char user2[];

//�����������������������������������������������������������������������������

struct {
  char pack[16];        // Nombre del propio packfile (no va en el archivo)
  char head[8];         // Cabecera inicial del packfile (dat<-\n00)
  int crc1,crc2,crc3;   // CRC's de hasta tres programas que lo utilicen
  int nfiles;           // N�mero de archivos contenidos
} dirhead;

struct tdir {
  char name[16];        // Nombre del archivo (en asciiz, sin path)
  unsigned int offset;  // Desplazamiento respecto al inicio del pack
  unsigned int len1;    // Longitud del archivo en el packfile (comprimido)
  unsigned int len2;    // Longitud del archivo real (descomprimido)
};

struct tdir * hdir;     // Directorio de ficheros

int memcrc[9];          // Para obtener el CRC de los programas

byte * imagen_install=NULL;

//�����������������������������������������������������������������������������
//  Ventana de Custom setup
//�����������������������������������������������������������������������������

void Setup1() {
  byte * ptr=v.ptr;
  int an=v.an/big2,al=v.al/big2;
  int x,y;

  if (segundo_font) {
    v.item[4].tipo=1;
  } else {
    v.item[4].tipo=-1;
    if (v.selected_item==4) {
      _select_new_item(v.selected_item+1);
    }
  }

  _show_items();

  wwrite(ptr,an,al,4,32,0,texto[521],c3);
  wwrite(ptr,an,al,4,32+19,0,texto[522],c3);
  wwrite(ptr,an,al,4,32+48,0,texto[523],c3);

  wbox(ptr,an,al,c12,4,40,100,8);
  wbox(ptr,an,al,c12,4,40+19,100,8);
  wbox(ptr,an,al,c12,4,40+48,100,8);

  wwrite(ptr,an,al,5,41,0,ifile1name,c3);
  wwrite(ptr,an,al,5,41+19,0,ifile2name,c3);
  wwrite(ptr,an,al,5,41+48,0,ifile3name,c3);

  if (!segundo_font) {
    for(y=(32+48)*big2;y<(32+48+19)*big2;y++) {
      for(x=4*big2;x<(120)*big2;x++) {
        ptr[y*v.an+x]=*(ghost+(int)c2*256+ptr[y*v.an+x]);
      }
    }
  }

  wbox(ptr,an,al,c0,2,29,an-4,1);
  wbox(ptr,an,al,c0,2,60+19*3,an-4,1);
  wbox(ptr,an,al,c0,2,al-20,an-4,1);

  wrectangulo(ptr,an,al,c0,140,29,144,89);

  if (imagen_install!=NULL) {
    for (y=0;y<87*big2;y++) for (x=0;x<142*big2;x++) {
      ptr[141*big2+x+(30*big2+y)*v.an]=imagen_install[x+y*142*big2];
    }
  } else {
    wbox(ptr,an,al,c1,141,30,142,87);
  }
}

void Setup2() {
  FILE * f;
  byte * ptrimg;
  char cwork[256];

  _process_items();

  switch(v.active_item) {
    case 0: v_aceptar=1; fin_dialogo=1; break;
    case 1: fin_dialogo=1; break;
    case 2:
      strcpy(cwork,tipo[4].path);
      strcpy(tipo[4].path,tipo[1].path);
      if (tipo[4].path[strlen(tipo[4].path)-1]!='\\') strcat(tipo[4].path,"\\");
      strcat(tipo[4].path,"INSTALL");
      v_modo=1; v_tipo=4;
      v_texto=texto[524];
      dialogo((int)browser0);

      strcpy(full,tipo[4].path);
      if (full[strlen(full)-1]!='\\') strcat(full,"\\");
      strcat(full,input);
      strcpy(tipo[4].path,cwork);

      if (v_terminado) if (v_existe) {
        if ((f=fopen(full,"rb"))!=NULL) {
          fread(cwork,1,8,f);
          fclose(f);
          if (strcmp(cwork,"fpg\x1a\x0d\x0a")) {
            v_texto=texto[46]; dialogo((int)err0);
          } else {
            ptrimg=imagen_install;
            crear_imagen_install(full,1);
            if (imagen_install!=NULL) {
              free(ptrimg);
              strcpy(ifile1,full);
              strcpy(ifile1name,input);
            } else imagen_install=ptrimg;
            call(v.paint_handler); v.volcar=1;
          }
        }
      }
      break;
    case 3:
      strcpy(cwork,tipo[5].path);
      strcpy(tipo[5].path,tipo[1].path);
      if (tipo[5].path[strlen(tipo[5].path)-1]!='\\') strcat(tipo[5].path,"\\");
      strcat(tipo[5].path,"INSTALL");
      v_modo=1; v_tipo=5;
      v_texto=texto[525];
      dialogo((int)browser0);

      strcpy(full,tipo[5].path);
      if (full[strlen(full)-1]!='\\') strcat(full,"\\");
      strcat(full,input);
      strcpy(tipo[5].path,cwork);

      if (v_terminado) if (v_existe) {
        if ((f=fopen(full,"rb"))!=NULL) {
          fread(cwork,1,8,f);
          fclose(f);
          if (strcmp(cwork,"fnt\x1a\x0d\x0a")) {
            v_texto=texto[46]; dialogo((int)err0);
          } else {
            strcpy(ifile2,full);
            strcpy(ifile2name,input);
            call(v.paint_handler); v.volcar=1;
          }
        }
      }
      break;
    case 4:
      strcpy(cwork,tipo[5].path);
      strcpy(tipo[5].path,tipo[1].path);
      if (tipo[5].path[strlen(tipo[5].path)-1]!='\\') strcat(tipo[5].path,"\\");
      strcat(tipo[5].path,"INSTALL");
      v_modo=1; v_tipo=5;
      v_texto=texto[525];
      dialogo((int)browser0);

      strcpy(full,tipo[v_tipo].path);
      if (full[strlen(full)-1]!='\\') strcat(full,"\\");
      strcat(full,input);
      strcpy(tipo[5].path,cwork);

      if (v_terminado) if (v_existe) {
        if ((f=fopen(full,"rb"))!=NULL) {
          fread(cwork,1,8,f);
          fclose(f);
          if (strcmp(cwork,"fnt\x1a\x0d\x0a")) {
            v_texto=texto[46]; dialogo((int)err0);
          } else {
            strcpy(ifile3,full);
            strcpy(ifile3name,input);
            call(v.paint_handler); v.volcar=1;
          }
        }
      }
      break;
    case 5:
      dialogo((int)Setupm0);
      break;
    case 6:
      dialogo((int)Setupe0);
      break;
    case 7:
      call(v.paint_handler);
      break;
  }
}

void Setup3() {
  FILE * f;

  if ((f=fopen("INSTALL\\INS_TEXT.ASC","wb"))!=NULL) {
    fwrite(MsgExe,1,128,f);
    fwrite(THelp1,1,128,f);
    fwrite(THelp2,1,128,f);
    fwrite(TDisk1,1,128,f);
    fwrite(TDisk2,1,128,f);
    fwrite(Ierr0,1,128,f);
    fwrite(Ierr1,1,128,f);
    fwrite(Ierr2,1,128,f);
    fwrite(Ierr3,1,128,f);
    fwrite(Ierr4,1,128,f);
    fwrite(Ierr5,1,128,f);
    fwrite(Ierr6,1,128,f);
    fwrite(Ierr7,1,128,f);
    fwrite(Ierr8,1,128,f);
    fclose(f);
  }
}

void Setup0() {
  char * chr;
  time_t t;
  char tbuf[26];
  FILE * f;
  int y;

  v_aceptar=0;
  v.tipo=1;
  v.an=310;
  v.al=125+16+19+20;
  v.titulo=texto[236];

  v.paint_handler=(int)Setup1;
  v.click_handler=(int)Setup2;
  v.close_handler=(int)Setup3;

  strcpy(ExeGen,ventana[v_ventana+1].titulo);
  if ((chr=strchr(ExeGen,'.'))!=NULL) *chr=0;
  strupr(ExeGen);

  if (strcmp(PackName,ExeGen)) {
    strcpy(PackName,ExeGen);
    strcpy(Copy_Right,texto[352]);
    t=time(NULL); _ctime(&t,tbuf); tbuf[24]=' ';
    strcat(Copy_Right,&tbuf[20]);
    if (strlen(user2)+strlen(Copy_Right)<=127) strcat(Copy_Right,user2);
    strcpy(Unid," :\\TMP");
    Unid[0]=toupper(tipo[1].path[0]);
    strcpy(DefDir,texto[353]);
    strcat(DefDir,ExeGen);
    strcpy(AppName,ExeGen);
    strcpy(dirhead.pack,ExeGen);
    strcat(dirhead.pack,".PAK");
  }

  strcat(ExeGen,".EXE");

  if ((f=fopen("INSTALL\\INS_TEXT.ASC","rb"))!=NULL) {
    fread(MsgExe,1,128,f);
    fread(THelp1,1,128,f);
    fread(THelp2,1,128,f);
    fread(TDisk1,1,128,f);
    fread(TDisk2,1,128,f);
    fread(Ierr0,1,128,f);
    fread(Ierr1,1,128,f);
    fread(Ierr2,1,128,f);
    fread(Ierr3,1,128,f);
    fread(Ierr4,1,128,f);
    fread(Ierr5,1,128,f);
    fread(Ierr6,1,128,f);
    fread(Ierr7,1,128,f);
    fread(Ierr8,1,128,f);
    fclose(f);
  } else {
    strcpy(MsgExe,texto[354]);
    strcpy(THelp1,texto[351]);
    strcpy(THelp2,texto[355]);
    strcpy(TDisk1,texto[515]);
    strcpy(TDisk2,texto[516]);
    strcpy(Ierr0,texto[528]);
    strcpy(Ierr1,texto[529]);
    strcpy(Ierr2,texto[530]);
    strcpy(Ierr3,texto[531]);
    strcpy(Ierr4,texto[532]);
    strcpy(Ierr5,texto[533]);
    strcpy(Ierr6,texto[534]);
    strcpy(Ierr7,texto[535]);
    strcpy(Ierr8,texto[536]);
  }

  y=64+19*3;

  _button(100,7,v.al-14,0);
  _button(101,v.an-8,v.al-14,2);

  _button(121,109,38,0);
  _button(121,109,38+19,0);
  _button(121,109,38+48,0);

  _button(527,7,48+19*3,0);
  _button(519,113,48+19*3,2);

  _flag(539,4,32+39,&segundo_font);

  _flag(517,4,12,&empaquetar);
  _flag(518,v.an/2,12,&pentium);
  _flag(239,4,20,&include_setup);
  _flag(240,v.an/2,20,&create_dir);

  _get(224,4,y+19*0,6*16,AppName,127,0,0);
  _get(226,6*16+8,y+19*0,(v.an-4)-(6*16+8),Copy_Right,127,0,0);

  _get(227,4,y+19*1,6*16,Unid,127,0,0);
  _get(228,6*16+8,y+19*1,(v.an-4)-(6*16+8),DefDir,127,0,0);

}

//�����������������������������������������������������������������������������
// Crea el thumbnail del instalador de 142x87 (*big2)
//�����������������������������������������������������������������������������

void crear_imagen_install(char * file, int errores) {
  FILE * es;
  byte * p, *fpg;
  int * ptr;
  int file_len;
  int lst[1000];
  byte pal[768];
  byte xlat[256];
  char cwork[256];

  float coefredy,coefredx,a,b;
  byte * temp2;
  int x,y,n,m,an,al;

  imagen_install=NULL;

  if ((es=fopen(file,"rb"))==NULL) return; else {
    fseek(es,0,SEEK_END); file_len=ftell(es);
    if ((fpg=p=(byte *)malloc(file_len))!=NULL) {

      fseek(es,0,SEEK_SET);
      fread(fpg,1,file_len,es);
      fclose(es);

      if (strcmp(fpg,"fpg\x1a\x0d\x0a")) {
        free(fpg); return;
      }

      memcpy(pal,fpg+8,768);

      p+=1352; // Longitud cabecera fpg
      memset(lst,0,1000*sizeof(int));

      while (p<fpg+file_len && *(int*)p<1000 && *(int*)p>0 ) {
        lst[*(int*)p]=(int)p;
        p+=*(int*)(p+4);
      }

      strcpy(cwork,"");

      if (!lst[1]) sprintf(cwork,texto[540],1);
      if (ptr=(int*)lst[2]) {
        if (ptr[13]!=640 || ptr[14]!=480) sprintf(cwork,texto[541],2);
      }
      if (!(ptr=(int*)lst[3])) sprintf(cwork,texto[540],3);
      if (ptr[13]!=640 || ptr[14]!=480) sprintf(cwork,texto[541],3);
      if (!is_point(ptr,1)) sprintf(cwork,texto[542],1,3);
      if (!lst[4] && !lst[5]) sprintf(cwork,texto[540],4);
      if (!lst[13]) sprintf(cwork,texto[540],13);
      if (!lst[14]) sprintf(cwork,texto[540],14);
      if (!lst[15]) sprintf(cwork,texto[540],15);
      if (!lst[16]) sprintf(cwork,texto[540],16);
      if (!lst[17]) sprintf(cwork,texto[540],17);

      if (strlen(cwork)) {
        if (errores) {
          v_texto=cwork;
          dialogo((int)err0);
        }
        return;
      }

      if (ptr=(int*)lst[3]) {
        if (ptr[13]==640 && ptr[14]==480) {
          p=(byte*)ptr+64+ptr[15]*4; // Inicio de la pantalla

          // Crea el thumbnail ...

          create_dac4();
          for (n=0;n<256;n++) xlat[n]=fast_find_color(pal[n*3],pal[n*3+1],pal[n*3+2]);

          an=142*2*big2; al=87*2*big2;

          coefredx=640/((float)an);
          coefredy=480/((float)al);

          if ((temp2=(char *)malloc(an*al))!=NULL) {

            memset(temp2,0,an*al);
            a=(float)0.0;
            for(y=0;y<al;y++) {
              b=(float)0.0;
              for(x=0;x<an;x++) {
                temp2[y*an+x]=p[((int)a)*640+(int)b];
                b+=coefredx;
              } a+=coefredy;
            }

            // Aplica la tabla xlat[] al thumbnail

            for (n=an*al-1;n>=0;n--) {
              temp2[n]=xlat[temp2[n]];
            }

            if ((imagen_install=(char *)malloc(an*al/4))!=NULL) {

              for (y=0;y<al;y+=2) {
                for (x=0;x<an;x+=2) {
                  n=*(ghost+temp2[x+y*an]*256+temp2[x+1+y*an]);
                  m=*(ghost+temp2[x+(y+1)*an]*256+temp2[x+1+(y+1)*an]);
                  imagen_install[x/2+(y/2)*(an/2)]=*(ghost+n*256+m);
                }
              }

            } free(temp2);
          }
        }
      }

      free(fpg);

    } else fclose(es);
  }
}

int px(int * ptr, int n) {
  return(*((word*)ptr+32+n*2));
}

int is_point(int * ptr, int n) {
  if (n<ptr[15]) {
    if (px(ptr,n)>=0 && px(ptr,n)<ptr[13]) return(1); else return(0);
  } else return(0);
}

//�����������������������������������������������������������������������������
//  Mensajes de informaci�n del instalador
//�����������������������������������������������������������������������������

void Setupm1() {
  byte * ptr=v.ptr;
  int an=v.an/big2,al=v.al/big2;
  _show_items();
  wwrite(ptr,an,al,v.an/2-16,12+11+19+9,0,"#",c3);
}

void Setupm2() {
  _process_items();
  switch(v.active_item) {
    case 0: fin_dialogo=1; break;
    case 6:
      strcpy(MsgExe,texto[354]);
      strcpy(THelp1,texto[351]);
      strcpy(THelp2,texto[355]);
      strcpy(TDisk1,texto[515]);
      strcpy(TDisk2,texto[516]);
      call(v.paint_handler);
      v.volcar=1;
      break;
  }
}

void Setupm0() {
  int y;

  v.tipo=1;
  v.an=310;
  v.al=12+9+19*4;
  v.titulo=texto[526];
  v.paint_handler=(int)Setupm1;
  v.click_handler=(int)Setupm2;

  y=12;
  _button(100,v.an-8,v.al-14,2);
  _get(225,4,y+19*0,v.an-8,THelp1,127,0,0); y+=11;
  _get(414,4,y+19*0,v.an-8,THelp2,127,0,0);
  _get(520,4,y+19*1,(v.an-16)/2-16,TDisk1,127,0,0);
  _get(414,v.an/2-8,y+19*1,v.an/2+4,TDisk2,127,0,0);
  _get(229,4,y+19*2,v.an-8,MsgExe,127,0,0);
  _button(538,7,v.al-14,0);
}

//�����������������������������������������������������������������������������
//  Mensajes de error del instalador
//�����������������������������������������������������������������������������

void Setupe1() {
  _show_items();
}

void Setupe2() {
  _process_items();
  switch(v.active_item) {
    case 0: fin_dialogo=1; break;
    case 10:
      strcpy(Ierr0,texto[528]);
      strcpy(Ierr1,texto[529]);
      strcpy(Ierr2,texto[530]);
      strcpy(Ierr3,texto[531]);
      strcpy(Ierr4,texto[532]);
      strcpy(Ierr5,texto[533]);
      strcpy(Ierr6,texto[534]);
      strcpy(Ierr7,texto[535]);
      strcpy(Ierr8,texto[536]);
      call(v.paint_handler);
      v.volcar=1;
      break;
  }
}

void Setupe0() {
  int y;

  v.tipo=1;
  v.an=310;
  v.al=12+9+99+8;
  v.titulo=texto[537];
  v.paint_handler=(int)Setupe1;
  v.click_handler=(int)Setupe2;

  y=4;
  _button(100,v.an-8,v.al-14,2);
  _get(414,4,y+11*0,v.an-8,Ierr0,127,0,0);
  _get(414,4,y+11*1,v.an-8,Ierr1,127,0,0);
  _get(414,4,y+11*2,v.an-8,Ierr2,127,0,0);
  _get(414,4,y+11*3,v.an-8,Ierr3,127,0,0);
  _get(414,4,y+11*4,v.an-8,Ierr4,127,0,0);
  _get(414,4,y+11*5,v.an-8,Ierr5,127,0,0);
  _get(414,4,y+11*6,v.an-8,Ierr6,127,0,0);
  _get(414,4,y+11*7,v.an-8,Ierr7,127,0,0);
  _get(414,4,y+11*8,v.an-8,Ierr8,127,0,0);
  _button(538,7,v.al-14,0);
}


//�����������������������������������������������������������������������������
//  Funcion invocada para crear una instalacion desde el men� programas
//�����������������������������������������������������������������������������

int GetFileLen(FILE *file) {
  int d;

  fseek(file,0,SEEK_END);
  d=ftell(file);
  fseek(file,0,SEEK_SET);
  return(d);
}

void crear_instalacion(void) {

  FILE *fin,*fout;
  int x,n,m,topack;
  char cWork[256];
  char dWork[256];
  unsigned _drive,my_drive;
  byte * chr;
  int TotLen=0,PackSize;
  int size[6];

  char full[_MAX_PATH+1];
  char drive[_MAX_DRIVE+1];
  char dir[_MAX_DIR+1];
  char fname[_MAX_FNAME+1];
  char ext[_MAX_EXT+1];

  if (imagen_install==NULL) {
    crear_imagen_install(ifile1,0);
  }

  dialogo((int)Setup0); if(!v_aceptar) return;

  // *** Tratamiento de la unidad de Disco destino (permite "a:","dir","\dir\new","d:\tmp",...)

  if (strlen(Unid)==1) { // Se supone una letra entre 'a' y 'z' como una unidad y no directorio
    strupr(Unid); if (Unid[0]>='A' && Unid[0]<='Z') strcat(Unid,":");
  }

  _fullpath(full,Unid,_MAX_PATH);
  _splitpath(full,drive,dir,fname,ext);

  if (strlen(dir)==0 || dir[strlen(dir)-1]!='\\') strcat(dir,"\\");
  if (strlen(fname)||strlen(ext)) { strcat(dir,fname); strcat(dir,ext); strcat(dir,"\\"); }

  strupr(drive);
  _dos_getdrive(&my_drive);
  _dos_setdrive((int)drive[0]-'A'+1,&_drive);
  _dos_getdrive(&_drive);
  if (_drive!=(word)drive[0]-'A'+1) {
    v_texto=texto[356]; dialogo((int)err0); return;
  }

  if (_drive<=2) { strcpy(dir,"\\"); is_disk=_drive; } // En un disquete no crear� directorios

  for(x=1;x<strlen(dir);x++) if(dir[x]=='\\') { // Crea directorios ...
    strcpy(cWork,drive);
    strcat(cWork,dir);
    cWork[x+2]=0;
    mkdir(cWork);
  }

  strcpy(full,drive); strcat(full,dir); // Destino: "full"*.*

  _dos_setdrive(my_drive,&_drive);

  // *** Directorio por defecto

  if (strlen(DefDir)==0) {
    strcpy(DefDir,ventana[v_ventana].titulo);
    if ((chr=strchr(DefDir,'.'))!=NULL) *chr=0;
  }

  strupr(DefDir);

  // *** Ficheros de la instalaci�n (los de exec y los de setup)

  fin=fopen("system\\EXEC.INS","rb"); fseek(fin,0,SEEK_END); n=ftell(fin); fclose(fin);

  fin=fopen("install\\setup.ins","rb"); fseek(fin,0,SEEK_END); x=ftell(fin);
  if (!include_setup) x=0;
  if ((__ins=_ins=ins=(byte *) malloc(n+x+32))==NULL) {
    v_texto=texto[357]; dialogo((int)err0);
    fclose(fin); return;
  } fseek(fin,0,SEEK_SET); x=fread(_ins,1,x,fin); fclose(fin);

  fin=fopen("system\\EXEC.INS","rb"); n=fread(_ins+x,1,n,fin)+x; fclose(fin);

  nfiles=2; if (include_setup) nfiles++;
  while (ins<_ins+n) { nfiles++; ins+=strlen(ins)+1; } ins=_ins;

  // *** Elimina ficheros duplicados

  if ((MiHeaderSetup=(HeaderSetup *)malloc(nfiles*sizeof(HeaderSetup)))==NULL) {
    v_texto=texto[357]; dialogo((int)err0);
    free(_ins); return; }

  dirhead.nfiles=0; // Archivos que van en el PACKFILE

  for(x=0;x<nfiles;x++) {
    if (x==0) strcpy(MiHeaderSetup[x].name,ExeGen);
    else if (x==1) strcpy(MiHeaderSetup[x].name,"DIV32RUN.DLL");
    else if (x==2 && include_setup) strcpy(MiHeaderSetup[x].name,"SETUP.EXE");
    else {
      chr=ins;
      if (*ins=='+') { // Cuando el archivo no puede incluirse en el PACKFILE
        ins++; topack=0;
      } else topack=1;
      _splitpath(ins,drive,dir,fname,ext);
      strcpy(MiHeaderSetup[x].name,fname);
      strcat(MiHeaderSetup[x].name,ext);
      strupr(MiHeaderSetup[x].name);
      for (n=0;n<x;n++) {
        if (!strcmp(MiHeaderSetup[n].name,MiHeaderSetup[x].name)) break;
      }
      if (n<x || !strcmp(MiHeaderSetup[n].name,"SOUND.CFG")) {

        // Si el fichero llevaba '+', pone un '+' a su aparici�n anterior

        ins+=strlen(ins)+1;

        if (n<x && topack==0) {
          chr=_ins;

          if (include_setup) n-=3; else n-=2;

          while (n) { chr+=strlen(chr)+1; n--; }
          if (*chr!='+') {
            memmove(chr+1,chr,__ins-chr);
            __ins++;
            *chr='+';
            dirhead.nfiles--;
          }
        }

        x--; nfiles--;

        continue;
      } else {
        ins+=strlen(ins)+1;
        strcpy(__ins,chr);
        strupr(__ins);
        __ins+=strlen(__ins)+1;
        if (topack) dirhead.nfiles++;
      }
    }
  }

  free(MiHeaderSetup); ins=_ins;

  if (!empaquetar) dirhead.nfiles=0; // Cuando no deba generarse el PACKFILE

//�����������������������������������������������������������������������������

  // Aqu� se crear� el "PACKFILE.DAT" con los archivos pertinentes
  // *** OJO *** Cuando el usuario seleccione la opci�n "Instalaci�n protegida"
  // nfiles es el n�mero de ficheros totales (EXE + OVL [+ SETUP] + char * ins)
  // Crea el directorio en hdir[].name/offset/len1/len2
  // y su cabecera en dirhead.packname/head/crc1/crc2/crc3/nfiles

  if (dirhead.nfiles) {

    // 0� Define los valores b�sicos de la cabecera del packfile

    strcpy(cWork,texto[498]);
    strcat(cWork,dirhead.pack);

    memcpy(dirhead.head,"dat\x1a\x0d\x0a\x00\x00",8);

    // dirhead.nfiles ya est� precalculado antes

    // 1� Obtiene los CRC del system\exec.exe y install\setup.ovl (si include_setup)

    dirhead.crc1=0;
    dirhead.crc2=0;
    dirhead.crc3=0;

    if ((fin=fopen("system\\exec.exe","rb"))!=NULL) {
      fseek(fin,602,SEEK_SET);
      fread(memcrc,4,9,fin);
      memcrc[0]=(memcrc[0]&1);
      for (n=0;n<9;n++) { dirhead.crc1<<=1; dirhead.crc1^=memcrc[n]; }
      fclose(fin);
    }

    if ((fin=fopen("install\\setup.ovl","rb"))!=NULL) {
      fseek(fin,602,SEEK_SET);
      fread(memcrc,4,9,fin);
      memcrc[0]=(memcrc[0]&1);
      for (n=0;n<9;n++) { dirhead.crc2<<=1; dirhead.crc2^=memcrc[n]; }
      fclose(fin);
    }

    // 2� Abre el fichero ("INSTALL\\PACKFILE.DAT","wb")

    if ((fout=fopen("INSTALL\\PACKFILE.DAT","wb"))==NULL) {
      v_texto=texto[358]; dialogo((int)err0);
      free(_ins); return;
    }

    // 3� Graba la cabecera (&dirhead.head)

    fwrite(&dirhead.head,1,8+3*4+4,fout);

    // 4� Pide memoria para el directorio (hdir[])

    if ((hdir=(struct tdir *)malloc(dirhead.nfiles*sizeof(struct tdir)))==NULL) {
      v_texto=texto[357]; dialogo((int)err0);
      fclose(fout); free(_ins); return;
    }

    // 5� Graba el directorio (con basura, inicialmente)

    fwrite(hdir,sizeof(struct tdir),dirhead.nfiles,fout);

    // 6� Graba todos los archivos a continuacion (rellenando hdir[])

    ins=__ins=_ins;

    for(n=0;n<dirhead.nfiles;n++) {

      Progress(cWork,n,dirhead.nfiles);

      while (*ins=='+') {
        chr=ins; ins+=strlen(ins)+1;
        strcpy(__ins,chr); __ins+=strlen(__ins)+1;
      }

      if ((fin=fopen(ins,"rb"))==NULL) {
        v_texto=texto[231]; dialogo((int)err0);
        free(hdir); fclose(fout); free(_ins); return;
      }

      _splitpath(ins,drive,dir,fname,ext);
      strcpy(hdir[n].name,fname);
      strcat(hdir[n].name,ext);
      strupr(hdir[n].name);
      hdir[n].offset=ftell(fout);

      fseek(fin,0,SEEK_END);
      hdir[n].len2=ftell(fin);
      fseek(fin,0,SEEK_SET);

      // Carga fin, lo comprime, y lo graba en fout (-1 si error)

      hdir[n].len1=comprimir_fichero(fin,fout,(unsigned long)hdir[n].len2);

      fclose(fin);

      if (hdir[n].len1==-1) {
        Progress(cWork,dirhead.nfiles,dirhead.nfiles);
        v_texto=texto[357]; dialogo((int)err0);
        free(hdir); fclose(fout); free(_ins); return;
      }

      ins+=strlen(ins)+1;
    }

    // 7� Actualiza la lista de ficheros a incluir (_ins), con el PACKFILE

    nfiles=nfiles-dirhead.nfiles+1;

    while (*ins=='+') {
      chr=ins; ins+=strlen(ins)+1;
      strcpy(__ins,chr); __ins+=strlen(__ins)+1;
    }

    strcpy(__ins,"INSTALL\\PACKFILE.DAT"); // a�ade el PACKFILE como el �ltimo fichero

    // 8� Reescribe el hdir[] y cierra el fichero

    fseek(fout,8+3*4+4,SEEK_SET);
    fwrite(hdir,sizeof(struct tdir),dirhead.nfiles,fout);
    fseek(fout,0,SEEK_END);
    fclose(fout);

    free(hdir);

    Progress(cWork,dirhead.nfiles,dirhead.nfiles);

  }

//�����������������������������������������������������������������������������

   // Crea el INSTALL\DIV32RUN.DLL a partir de (INSTALL\DIV32RUN.INS/386 + SYSTEM\LENGUAJE.INT)

  if ((fout=fopen("INSTALL\\DIV32RUN.DLL","wb"))==NULL) {
    v_texto=texto[358]; dialogo((int)err0);
    free(_ins); return;
  }

  if (pentium) fin=fopen("install\\div32run.ins","rb");
  else         fin=fopen("install\\div32run.386","rb");

  if (fin==NULL) {
    v_texto=texto[231]; dialogo((int)err0);
    fclose(fout); free(_ins); return;
  }

  fseek(fin,0,SEEK_END);
  x=ftell(fin);
  fseek(fin,0,SEEK_SET);

  if (copiar_fichero(fin,fout,(unsigned long)x,0)==-1) {
    v_texto=texto[358]; dialogo((int)err0);
    fclose(fout); fclose(fin); free(_ins); return;
  }

  fclose(fin);

  if ((fin=fopen("system\\lenguaje.int","rb"))==NULL) {
    v_texto=texto[231]; dialogo((int)err0);
    fclose(fout); free(_ins); return;
  }

  fseek(fin,0,SEEK_END);
  x=ftell(fin);
  fseek(fin,0,SEEK_SET);

  if (copiar_fichero(fin,fout,(unsigned long)x,0)==-1) {
    v_texto=texto[358]; dialogo((int)err0);
    fclose(fout); fclose(fin); free(_ins); return;
  }

  fclose(fin);

  if (fwrite(&x,4,1,fout)!=1) {
    v_texto=texto[358]; dialogo((int)err0);
    fclose(fout); free(_ins); return;
  }

  fclose(fout);

//�����������������������������������������������������������������������������

  // *** Crea install.div (fichero empaquetado original)

  if ((fout=fopen("INSTALL\\INSTALL.DIV","wb"))==NULL) {
    v_texto=texto[358]; dialogo((int)err0);
    free(_ins); return;
  }

  fwrite(&nfiles,sizeof(int),1,fout);

  if ((MiHeaderSetup=(HeaderSetup *)malloc(nfiles*sizeof(HeaderSetup)))==NULL) {
    v_texto=texto[357]; dialogo((int)err0);
    fclose(fout); free(_ins); return;
  } fwrite(MiHeaderSetup,sizeof(HeaderSetup),nfiles,fout);

  // Copia al INSTALL.DIV todos los ficheros de la instalaci�n

  ins=_ins;

  for(x=0;x<nfiles;x++) {
    Progress(texto[219],x*100,nfiles*100);
    if (x==0) {
      fin=fopen("system\\EXEC.EXE","rb");
      strcpy(MiHeaderSetup[x].name,ExeGen);
      topack=0;
    } else if (x==1) {

      fin=fopen("install\\div32run.dll","rb");

//    if (pentium) fin=fopen("install\\div32run.ins","rb");
//    else         fin=fopen("install\\div32run.386","rb");

      strcpy(MiHeaderSetup[x].name,"DIV32RUN.DLL");
      topack=0;
    } else if (x==2 && include_setup) {
      fin=fopen("install\\setup.ovl","rb");
      strcpy(MiHeaderSetup[x].name,"SETUP.EXE");
      topack=0;
    } else {
      if (*ins=='+') ins++;
      if (!strcmp(ins,"INSTALL\\PACKFILE.DAT")) topack=0; else topack=1;
      fin=fopen(ins,"rb");
      _splitpath(ins,drive,dir,fname,ext);
      strcpy(MiHeaderSetup[x].name,fname);
      strcat(MiHeaderSetup[x].name,ext);
      if (!topack) strcpy(MiHeaderSetup[x].name,dirhead.pack);
      ins+=strlen(ins)+1;
    }

    if (fin==NULL) {
      Progress(texto[219],nfiles*100,nfiles*100);
      v_texto=texto[231]; dialogo((int)err0);
      fclose(fout); free(_ins); free(MiHeaderSetup);
      return;
    }

    MiHeaderSetup[x].offset=ftell(fout);

    MiHeaderSetup[x].len2=GetFileLen(fin);

    if (topack) {
      MiHeaderSetup[x].len1=comprimir_fichero(fin,fout,(unsigned long)MiHeaderSetup[x].len2);
    } else {
      MiHeaderSetup[x].len1=copiar_fichero(fin,fout,(unsigned long)MiHeaderSetup[x].len2,((!x)&&(!pentium)));
    }

    if (MiHeaderSetup[x].len1==-1) {
      Progress(texto[219],nfiles*100,nfiles*100);
      v_texto=texto[357]; dialogo((int)err0);
      fclose(fin); fclose(fout); free(_ins); free(MiHeaderSetup);
      return;
    }

    TotLen+=((GetFileLen(fin)/32768)+1)*32768;
    fclose(fin);
  }

  free(_ins);
  fseek(fout,sizeof(int),SEEK_SET);
  fwrite(MiHeaderSetup,sizeof(HeaderSetup),nfiles,fout);
  PackSize=((GetFileLen(fout)/32768)+1)*32768;
  TotLen+=PackSize;
  fseek(fout,0,SEEK_END);
  fclose(fout);
  free(MiHeaderSetup);

  Progress(texto[219],nfiles*100,nfiles*100); // INSTALL.DIV ya creado

  strcpy(cWork,tipo[1].path); // Borra el PACKFILE.DAT
  strcat(cWork,"\\");
  strcat(cWork,"INSTALL\\PACKFILE.DAT");
  DaniDel(cWork);

  // *** Graba INSTALL.EXE con la coletilla informativa

  strcpy(cWork,tipo[1].path);
  strcat(cWork,"\\");
  strcat(cWork,"install\\install.ovl");

  strcpy(dWork,full);
  strcat(dWork,"INSTALL.EXE");

  if(!FileCopyICE(cWork,dWork,0,237)) { v_texto=texto[231]; dialogo((int)err0); return; }

  Progress(texto[543],0,100);

  if((fout=fopen(dWork,"ab"))==NULL) {
    Progress(texto[543],100,100); v_texto=texto[231]; dialogo((int)err0); return;
  }

  fwrite(AppName,1,strlen(AppName)+1,fout); n=strlen(AppName)+1;
  fwrite(Copy_Right,1,strlen(Copy_Right)+1,fout); n+=strlen(Copy_Right)+1;
  fwrite(PackName,1,strlen(PackName)+1,fout); n+=strlen(PackName)+1;
  fwrite(DefDir,1,strlen(DefDir)+1,fout); n+=strlen(DefDir)+1;
  fwrite(MsgExe,1,strlen(MsgExe)+1,fout); n+=strlen(MsgExe)+1;
  sprintf(cWork,"%s %s",THelp1,THelp2);
  fwrite(cWork,1,strlen(cWork)+1,fout); n+=strlen(cWork)+1;
  fwrite(TDisk1,1,strlen(TDisk1)+1,fout); n+=strlen(TDisk1)+1;
  fwrite(TDisk2,1,strlen(TDisk2)+1,fout); n+=strlen(TDisk2)+1;
  fwrite(Ierr0,1,strlen(Ierr0)+1,fout); n+=strlen(Ierr0)+1;
  fwrite(Ierr1,1,strlen(Ierr1)+1,fout); n+=strlen(Ierr1)+1;
  fwrite(Ierr2,1,strlen(Ierr2)+1,fout); n+=strlen(Ierr2)+1;
  fwrite(Ierr3,1,strlen(Ierr3)+1,fout); n+=strlen(Ierr3)+1;
  fwrite(Ierr4,1,strlen(Ierr4)+1,fout); n+=strlen(Ierr4)+1;
  fwrite(Ierr5,1,strlen(Ierr5)+1,fout); n+=strlen(Ierr5)+1;
  fwrite(Ierr6,1,strlen(Ierr6)+1,fout); n+=strlen(Ierr6)+1;
  fwrite(Ierr7,1,strlen(Ierr7)+1,fout); n+=strlen(Ierr7)+1;
  fwrite(Ierr8,1,strlen(Ierr8)+1,fout); n+=strlen(Ierr8)+1;

  fwrite(&TotLen,1,4,fout); n+=4;
  fwrite(&PackSize,1,4,fout); n+=4;
  fwrite(&create_dir,1,4,fout); n+=4;
  fwrite(&include_setup,1,4,fout); n+=4;
  fwrite(&segundo_font,1,4,fout); n+=4;

  Progress(texto[543],25,100);

  if ((fin=fopen(ifile1,"rb"))==NULL) {
    fclose(fout);
    Progress(texto[543],100,100);
    v_texto=texto[231]; dialogo((int)err0); return;
  }

  fseek(fin,0,SEEK_END); x=ftell(fin); fseek(fin,0,SEEK_SET);
  m=comprimir_fichero(fin,fout,(unsigned long)x);
  fclose(fin);

  if (m==-1) {
    fclose(fout);
    Progress(texto[543],100,100);
    v_texto=texto[231]; dialogo((int)err0); return;
  } else n+=m;

  size[0]=m; size[1]=x;
  Progress(texto[543],75,100);

  if ((fin=fopen(ifile2,"rb"))==NULL) {
    fclose(fout);
    Progress(texto[543],100,100);
    v_texto=texto[231]; dialogo((int)err0); return;
  }

  fseek(fin,0,SEEK_END); x=ftell(fin); fseek(fin,0,SEEK_SET);
  m=comprimir_fichero(fin,fout,(unsigned long)x);
  fclose(fin);

  if (m==-1) {
    fclose(fout);
    Progress(texto[543],100,100);
    v_texto=texto[231]; dialogo((int)err0); return;
  } else n+=m;

  size[2]=m; size[3]=x;
  Progress(texto[543],85,100);

  if (segundo_font) {
    if ((fin=fopen(ifile3,"rb"))==NULL) {
      fclose(fout);
      Progress(texto[543],100,100);
      v_texto=texto[231]; dialogo((int)err0); return;
    }

    fseek(fin,0,SEEK_END); x=ftell(fin); fseek(fin,0,SEEK_SET);
    m=comprimir_fichero(fin,fout,(unsigned long)x);
    fclose(fin);

    if (m==-1) {
      fclose(fout);
      Progress(texto[543],100,100);
      v_texto=texto[231]; dialogo((int)err0); return;
    } else n+=m;

    size[4]=m; size[5]=x;

  } else {

    size[4]=0; size[5]=0;

  }

  fwrite(size,6,4,fout); n+=6*4;

  n+=4; fwrite(&n,1,4,fout);
  fclose(fout);

  Progress(texto[543],100,100);

  // *** Graba PackName.001, 002, ... a partir de INSTALL.DIV

  strcpy(cWork,tipo[1].path);
  strcat(cWork,"\\");
  strcat(cWork,"INSTALL\\INSTALL.DIV");

  strcpy(dWork,full);
  strcat(dWork,PackName);

  if(!FileCopyICE(cWork,dWork,1,234)) { v_texto=texto[231]; dialogo((int)err0); return; }

  DaniDel(cWork);              // Borra el INSTALL.DIV

  v_titulo=texto[359];        // Di�logo indicando el final de la instalaci�n
  strcpy(cWork,texto[360]);
  strupr(full);
  strcat(cWork,full);
  cWork[strlen(cWork)-1]=0;
  strcat(cWork,texto[361]);
  v_texto=cWork;
  dialogo((int)info0);

}

//�����������������������������������������������������������������������������
//  Comprime de un fichero a otro, utilizando zlib (devuelve -1 si error)
//�����������������������������������������������������������������������������

int comprimir_fichero(FILE * fin, FILE * fout, unsigned long len) {
  unsigned char * pin, * pout;
  unsigned long final_len;

  final_len=len+1024;

  if ((pin=(unsigned char*)malloc(len))==NULL) return(-1);
  if ((pout=(unsigned char*)malloc(final_len))==NULL) { free(pin); return(-1); }

  if (fread(pin,1,len,fin)!=len) { free(pout); free(pin); return(-1); }

  if (compress(pout,&final_len,pin,len)) {
    free(pout); free(pin); return(-1);
  }

  if (fwrite(pout,1,final_len,fout)!=final_len) { free(pout); free(pin); return(-1); }

  free(pout); free(pin);

  return(final_len);
}

int copiar_fichero(FILE * fin, FILE * fout, unsigned long len, int patch) {
  unsigned char * pin;

  if ((pin=(unsigned char*)malloc(len))==NULL) return(-1);
  if (fread(pin,1,len,fin)!=len) { free(pin); return(-1); }

  if (patch) { // version para 386+ (parchea el div_stub)
    pin[0x4F]=0x03; // Comparar CPU con 80386 o mayor
    pin[0x51]=0x16; // Si no, emitir mensaje de Intel386 not found
  }

  if (fwrite(pin,1,len,fout)!=len) { free(pin); return(-1); }
  free(pin);
  return(len);
}

//�����������������������������������������������������������������������������
//  Copia al disco destino la instalaci�n
//�����������������������������������������������������������������������������

unsigned int GetFreeUnid(char unidad) {
  union REGS regs;

  memset(&regs,0,sizeof(regs));
  regs.h.ah=0x36;
  regs.h.dl=unidad;
  intdos(&regs,&regs);
  if(regs.w.ax==0xFFFF) return 0;
  return(regs.w.ax*regs.w.bx*regs.w.cx);
}

int FileCopyICE(char *org,char *dest,int vols,int _texto) { // Devuelve 0-Error, 1-Exito
  FILE  *fin,*fout;
  unsigned int tlen,len,NewVolume=1,curvol=0,retval=1;
  unsigned int totfree;
  char *buffer;
  char cWork[256];

  buffer=(char *)malloc(16384);
  if(buffer==NULL) return 0;

  fin=fopen(org,"rb");
  if(fin==NULL) { free(buffer); return 0; }

  fseek(fin,0,SEEK_END);
  tlen=len=ftell(fin);
  fseek(fin,0,SEEK_SET);

  while(len) {
    Progress(texto[_texto],tlen-len,tlen);

    if (NewVolume) {

      if(curvol!=0 && NewVolume<2) {
        if (!is_disk) { retval=0; break; }
        v_titulo=texto[233]; // Disk full.
        v_texto=texto[232];  // Please, insert a new disk.
        dialogo((int)aceptar0);
        if (!v_aceptar) { retval=0; break; }
      }

      NewVolume=0;

      totfree=GetFreeUnid((dest[0]-'A')+1);

      if(totfree<=1024) { // Disco lleno.
        if (vols) {
          v_titulo=texto[362];
          v_texto=texto[232];
          dialogo((int)aceptar0);
          if (v_aceptar) { NewVolume=2; continue; }
        } retval=0; break;
      }

      if(vols){
        sprintf(cWork,"%s.%03d",dest,curvol+1);
        fout=fopen(cWork,"wb");
      } else fout=fopen(dest,"wb");

      if(fout==NULL) { // Disquete protegido
        v_titulo=texto[363];
        v_texto=texto[364];
        dialogo((int)aceptar0);
        if (v_aceptar) { NewVolume=2; continue; }
        retval=0; break;
      }

      if(vols) {
        if(fwrite("stp\x1a\x0d\x0a\x00",1,8,fout)!=8) { // Alg�n otro error
          retval=0; break;
        } totfree-=8; curvol++;
      }
    }

    if(totfree>16384) { // hay espacio en el dico para grabar
      if(len>16384) { // Se puede grabar un paquete completo
        fread(buffer,1,16384,fin);
        if (fwrite(buffer,1,16384,fout)!=16384) { retval=0; break; }
        len-=16384;
        totfree-=16384;
      } else {
        fread(buffer,1,len,fin);
        if (fwrite(buffer,1,len,fout)!=len) { retval=0; break; }
        totfree-=len;
        len=0;
      }

    } else { // Digo yo que ser� esto ...
      if (len<=totfree) { // Da igual, coge de todas formas
        fread(buffer,1,len,fin);
        if (fwrite(buffer,1,len,fout)!=len) { retval=0; break; }
        totfree-=len;
        len=0;
      } else { // No coge (queda solo totfree espacio)

        if (!vols) { retval=0; break; }

        fread(buffer,1,totfree,fin);
        if (fwrite(buffer,1,totfree,fout)!=totfree) { retval=0; break; }
        len-=totfree;
        totfree=0;
        fseek(fout,7,SEEK_SET);
        fwrite("\x01",1,1,fout);
        fclose(fout);
        NewVolume=1;
      }
    }

  }
  fclose(fin);
  fclose(fout);
  Progress(texto[_texto],tlen,tlen);
  free(buffer);
  return(retval);
}

