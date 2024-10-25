
//�����������������������������������������������������������������������������
//      M�dulo de acceso al rat�n
//�����������������������������������������������������������������������������

#include "global.h"

extern int help_paint_active;
int m_b;

float m_x=0.0,m_y=0.0;

//�����������������������������������������������������������������������������
//      Comprueba si el rat�n est� en una caja
//�����������������������������������������������������������������������������

int mouse_in(int x, int y, int x2, int y2) {
  return(mouse_x>=x && mouse_x<=x2 && mouse_y>=y && mouse_y<=y2);
}

int wmouse_in(int x, int y, int an, int al) {
  return(wmouse_x>=x && wmouse_x<=x+an-1 &&
         wmouse_y>=y && wmouse_y<=y+al-1);
}

//�����������������������������������������������������������������������������
//      Coloca el rat�n en la posici�n indicada
//�����������������������������������������������������������������������������

void set_mouse(word x, word y) {
  m_x=(float)x;
  m_y=(float)y;
}

//�����������������������������������������������������������������������������
//      Lee la posici�n y botones del rat�n
//�����������������������������������������������������������������������������

void read_mouse(void) {
  int n=0;
  int s,shift=0;

  old_mouse_b=mouse_b;

  read_mouse2();

  if (modo<100 && hotkey && !help_paint_active) tecla();

  real_mouse_x=(int)m_x; real_mouse_y=(int)m_y;

  if (mouse_x!=(int)m_x || mouse_y!=(int)m_y || mouse_b!=m_b) {

    mouse_x=(int)m_x;
    mouse_y=(int)m_y;
    mouse_b=m_b;
    shift=1;

    if (modo<100 && hotkey && !help_paint_active) {
      if (key(_SPC)) {
        if (mouse_b!=0xfffd) {
          mouse_b=0xfffd;
        }
      } else if (mouse_b==0xfffd) mouse_b=0;
    }

  } else if (modo<100 && hotkey && !help_paint_active) { // Las teclas est�n solo activas en edici�n

    if (!(shift_status&4)) {

      mouse_x=mouse_shift_x;
      mouse_y=mouse_shift_y;

      if ((shift_status&3) || key(_L_SHIFT) || key(_R_SHIFT)) s=8; else s=1;

      if (key(_C_RIGHT) || key(_RIGHT) || key(_P)) {
        kbdFLAGS[_C_RIGHT]=0; kbdFLAGS[_RIGHT]=0; kbdFLAGS[_P]=0;
        mouse_x+=(1<<zoom)*s; shift=1;
      }

      if (key(_C_LEFT) || key(_LEFT) || key(_O)) {
        kbdFLAGS[_C_LEFT]=0; kbdFLAGS[_LEFT]=0; kbdFLAGS[_O]=0;
        mouse_x-=(1<<zoom)*s; shift=1;
      }

      if (key(_C_DOWN) || key(_DOWN) || key(_A)) {
        kbdFLAGS[_C_DOWN]=0; kbdFLAGS[_DOWN]=0; kbdFLAGS[_A]=0;
        mouse_y+=(1<<zoom)*s; shift=1;
      }

      if (key(_C_UP) || key(_UP) || key(_Q)) {
        kbdFLAGS[_C_UP]=0; kbdFLAGS[_UP]=0; kbdFLAGS[_Q]=0;
        mouse_y-=(1<<zoom)*s; shift=1;
      }

      if (key(_SPC)) {
        if (mouse_b!=0xfffd) {
          mouse_b=0xfffd;
        }
      } else if (mouse_b==0xfffd) mouse_b=0;

      if (shift) {
        real_mouse_x=mouse_x; real_mouse_y=mouse_y;
        set_mouse(mouse_x,mouse_y);
      } else mouse_shift=0;
    }
  }

  if (shift) {

    if (mouse_x<0) { mouse_x=0; n++; }
    else if (mouse_x>=vga_an) { mouse_x=vga_an-1; n++; }
    if (mouse_y<0) { mouse_y=0; n++; }
    else if (mouse_y>=vga_al) { mouse_y=vga_al-1; n++; }

    if (n) set_mouse(mouse_x,mouse_y);
  }

  if (shift) {
    mouse_shift=0;
    mouse_shift_x=mouse_x;
    mouse_shift_y=mouse_y;
  }

  coord_x=zoom_x+(mouse_shift_x-zx)/(1<<zoom);
  coord_y=zoom_y+(mouse_shift_y-zy)/(1<<zoom);
  if(free_drag) switch(arrastrar) {
    case 0:
      if ((mouse_b&1) && !(old_mouse_b&1)) {
        arrastrar=1; arrastrar_x=mouse_x; arrastrar_y=mouse_y;
      } break;
    case 1:
      arrastrar=0;
      break;
    case 2:
      if (mouse_b&1) {
        if (abs(mouse_x-arrastrar_x)>1 || abs(mouse_y-arrastrar_y)>1)
        {
          arrastrar=3;
          wmouse_x=-1;
          wmouse_y=-1;
          mouse_b=0;
          call(v.click_handler);
          quien_arrastra=v.orden;
          mouse_b=1;
          mouse_graf=arrastrar_graf;
        }
      } else {
        arrastrar=0;
      } break;
    case 3:
      if (!(mouse_b&1)) {
        arrastrar=4;
      } break;
    case 4:
    case 5:
      libera_drag();
      break;
  }
}

void libera_drag(void) {
 int n;
  arrastrar=0;
  for (n=0;n<max_windows;n++)
    if (ventana[n].tipo && ventana[n].orden==quien_arrastra) break;
  if (n<max_windows && ventana[n].tipo==101 && ventana[n].mapa!=NULL) {
    free(ventana[n].mapa->map);
    free(ventana[n].mapa);
    ventana[n].mapa=NULL;

    if (n) {
      wup(n);
    }

    wmouse_x=-1; wmouse_y=-1; call(v.paint_handler);

    if (n) {
      wdown(n);
    }

    if(modo>=100) vuelca_ventana(n); ventana[n].volcar=0;
  }
}

//�����������������������������������������������������������������������������
//  Rutinas de rat�n nuevas (sin interrupci�n)
//�����������������������������������������������������������������������������

void read_mouse2(void) {
  union REGS regs;
  short ix,iy;

  memset(&regs,0,sizeof(regs));
  regs.w.ax=3;
  int386(0x33,&regs,&regs);

  m_b=regs.w.bx;

  memset(&regs,0,sizeof(regs));
  regs.w.ax=0xb;
  int386(0x33,&regs,&regs);

  ix=regs.w.cx;
  iy=regs.w.dx;

  m_x+=(float)ix/(1.0+((float)Setupfile.mouse_ratio/3.0));
  m_y+=(float)iy/(1.0+((float)Setupfile.mouse_ratio/3.0));
}
