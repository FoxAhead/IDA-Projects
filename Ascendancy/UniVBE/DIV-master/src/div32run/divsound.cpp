#include "inter.h"
#include "divsound.h"
#include "divmixer.hpp"

tSonido  sonido[128];
tCancion cancion[128];

int SongType=0;
int MusicChannels=0;
int NextChannel=0;
int *NewSound;
int ChannelCon=0;

int SongInst[128];

int Freq_original[CHANNELS];

int SoundActive=1;

void InitSound(void)
{
  FILE *File_Cfg;
  int con;
  int master=10,sound_fx=10,cd_audio=10;
  char Device[8]={DEV_NOSOUND,DEV_SB,DEV_SB,DEV_SBPRO,DEV_SB16,DEV_SB16,DEV_GUS,DEV_GUS};
  unsigned short Puertos[6]={0x210,0x220,0x230,0x240,0x250,0x260};
  unsigned short IRQS[10]  ={2,3,5,7,10,11,12,13,14,15};
  unsigned short DMAS[10]  ={0,1,2,3,4,5,6,7,8,9};
  unsigned short DMAS2[10] ={0,1,2,3,4,5,6,7,8,9};

//int mixer         = QUALITYMIXER;
  int mixer         = FASTMIXER;
  int mixrate       = 44100;
  int mixmode       = SIXTEENBIT | STEREO;
//int mixmode       = EIGHTBIT | MONO;
  int interpolation = 1;
  int cfg_dev, cfg_port, cfg_irq, cfg_dma1, cfg_dma2;

  atexit(judas_uninit);
  atexit(timer_uninit);

  NewSound=mem+end_struct+32;
  if(SoundActive) {

    if(!(mem[0]&1))
    {
      File_Cfg=fopen("sound.cfg","rb");
      if(File_Cfg!=NULL) {
        fread(&cfg_dev,  1, 4, File_Cfg);
        fread(&cfg_port, 1, 4, File_Cfg);
        fread(&cfg_irq,  1, 4, File_Cfg);
        fread(&cfg_dma1, 1, 4, File_Cfg);
        fread(&cfg_dma2, 1, 4, File_Cfg);
        fread(&master,   1, 4, File_Cfg);
        fread(&sound_fx, 1, 4, File_Cfg);
        fread(&cd_audio, 1, 4, File_Cfg);

        // Nuevos valores del sound.cfg

        if (fread(&mixer, 1, 4, File_Cfg)==4) {
          fread(&mixrate, 1, 4, File_Cfg);
          fread(&mixmode, 1, 4, File_Cfg);
          if (mixer<1 || mixer>2) mixer=FASTMIXER;
          if (mixrate<11025) mixrate=11025;
          if (mixrate>44100) mixrate=44100;
          if (mixmode==16) mixmode=SIXTEENBIT | STEREO;
          else mixmode=EIGHTBIT | STEREO;
        }

        fclose(File_Cfg);
      }
    }
    File_Cfg=fopen("system\\exec.bin","rb");
    if(File_Cfg!=NULL) {
      fread(&sound_fx,1,1,File_Cfg);
      fread(&cd_audio,1,1,File_Cfg);
      fread(&master,1,1,File_Cfg);
      fclose(File_Cfg);
    }

    judas_config();

    if(!(mem[0]&1)) {
      File_Cfg=fopen("sound.cfg","rb");
      if(File_Cfg!=NULL) {
        fclose(File_Cfg);
        judascfg_device = Device[cfg_dev];
        judascfg_port   = Puertos[cfg_port];
        judascfg_irq    = IRQS[cfg_irq];
        judascfg_dma1   = DMAS[cfg_dma1];
        judascfg_dma2   = DMAS2[cfg_dma2];
      }
    }

    setup->master   = master;
    setup->sound_fx = sound_fx;
    setup->cd_audio = cd_audio;
    setup->mixer    = mixer;
    setup->mixrate  = mixrate;
    if (mixmode==(SIXTEENBIT | STEREO)) setup->mixmode  = 16;
    else                                setup->mixmode  =  8;
    setup->card=setup->port=setup->irq=setup->dma=setup->dma2=0;

    switch(judascfg_device) {
      case DEV_NOSOUND: setup->card=0; break;
      case DEV_SB:      setup->card=1; break;
      case DEV_SBPRO:   setup->card=3; break;
      case DEV_SB16:    setup->card=4; break;
      case DEV_GUS:     setup->card=6; break;
      default: setup->card=0; break;
    }
    switch(judascfg_port) {
      case 0x210: setup->port=0; break;
      case 0x220: setup->port=1; break;
      case 0x230: setup->port=2; break;
      case 0x240: setup->port=3; break;
      case 0x250: setup->port=4; break;
      case 0x260: setup->port=5; break;
      default: setup->port=1; break;
    }
    switch(judascfg_irq) {
      case  2: setup->irq=0; break;
      case  3: setup->irq=1; break;
      case  5: setup->irq=2; break;
      case  7: setup->irq=3; break;
      case 10: setup->irq=4; break;
      case 11: setup->irq=5; break;
      case 12: setup->irq=6; break;
      case 13: setup->irq=7; break;
      case 14: setup->irq=8; break;
      case 15: setup->irq=9; break;
      default: setup->irq=7; break;
    }
    setup->dma  = judascfg_dma1;
    setup->dma2 = judascfg_dma2;

    if (setup->dma<0) setup->dma=0;
    if (setup->dma2<0) setup->dma2=0;
  }
  else {
    judascfg_device = DEV_NOSOUND;
  }

  timer_init(1193180 / 100, judas_update);
  if(!judas_init(mixrate, mixer, mixmode, interpolation)) {
    judascfg_device = DEV_NOSOUND;
    judas_init(mixrate, mixer, mixmode, interpolation);
  } else {
    judas_setmusicmastervolume(CHANNELS, 50);
    set_mixer();
  }

  for(con=0; con<128; con++) {
    UnloadSound(con);
    UnloadSong(con);
  }
  for(con=16; con<32; con++) judas_channel[con].smp=NULL;
  for(con= 0; con<32; con++) channel(con)=0;
  MusicChannels=0;
}

void ResetSound(void)
{
  int con;
  char Device[8]={DEV_NOSOUND,DEV_SB,DEV_SB,DEV_SBPRO,DEV_SB16,DEV_SB16,DEV_GUS,DEV_GUS};
  unsigned short Puertos[6]={0x210,0x220,0x230,0x240,0x250,0x260};
  unsigned short IRQS[10]  ={2,3,5,7,10,11,12,13,14,15};
  unsigned short DMAS[10]  ={0,1,2,3,4,5,6,7,8,9};
  unsigned short DMAS2[10] ={0,1,2,3,4,5,6,7,8,9};

//int mixer         = QUALITYMIXER;
  int mixer         = FASTMIXER;
  int mixrate       = 44100;
  int mixmode       = SIXTEENBIT | STEREO;
//int mixmode       = EIGHTBIT | MONO;
  int interpolation = 1;

  StopSong();
  for(con=0; con<32; con++) StopSound(con);

  judascfg_device = Device[setup->card];
  judascfg_port   = Puertos[setup->port];
  judascfg_irq    = IRQS[setup->irq];
  judascfg_dma1   = DMAS[setup->dma];
  judascfg_dma2   = DMAS2[setup->dma2];

  if (setup->mixer<1 || setup->mixer>2) setup->mixer=FASTMIXER;
  if (setup->mixrate<11025) setup->mixrate=11025;
  if (setup->mixrate>44100) setup->mixrate=44100;
  if (setup->mixmode==16) setup->mixmode=16;
  else                    setup->mixmode=8;

  mixer  =setup->mixer;
  mixrate=setup->mixrate;
  if (setup->mixmode==16) mixmode=SIXTEENBIT | STEREO;
  else mixmode=EIGHTBIT | STEREO;

  if(!judas_init(mixrate, mixer, mixmode, interpolation))
  {
    judascfg_device = DEV_NOSOUND;
    judas_init(mixrate, mixer, mixmode, interpolation);
  } else {
    judas_setmusicmastervolume(CHANNELS, 50);
    set_mixer();
  }

  for(con=16; con<32; con++) judas_channel[con].smp=NULL;
  for(con= 0; con<32; con++) channel(con)=0;
  MusicChannels=0;
}

int LoadSound(char *ptr, long Len, int Loop)
{
  SoundInfo *SI=NULL;
  int con=0;

  while(con<128 && sonido[con].smp!=NULL) con++;
  if(con==128) return(-1);

  SI = judas_loadwav_mem(ptr);
  if(judas_error != JUDAS_OK && judas_error == JUDAS_WRONG_FORMAT)
  {
    if(SI != NULL) free(SI);
    SI = judas_loadrawsample_mem(ptr, Len, 0, 0, 0);
  }
  if(judas_error != JUDAS_OK)
  {
    if(SI != NULL) free(SI);
    return(-1);
  }

  if(Loop) (SI->sample)->voicemode |= VM_LOOP;
  sonido[con].smp  = SI->sample;
  sonido[con].freq = SI->SoundFreq;

  free(SI);

  return(con);
}

int UnloadSound(int NumSonido)
{
  if(sonido[NumSonido].smp)
  {
    judas_freesample(sonido[NumSonido].smp);
    sonido[NumSonido].smp=NULL;
  }

  return(1);
}

int PlaySound(int NumSonido, int Volumen, int Frec) // Vol y Frec (0..256)
{
  int con, InitChannel=16;

  if(MusicChannels>InitChannel) InitChannel=MusicChannels;
  if(InitChannel>=32) return(-1);
  if(!sonido[NumSonido].smp) return(-1);

  con=InitChannel;
  while(con<32 && IsPlayingSound(con)) con++;
  if(con==32) {
    con=InitChannel+NextChannel;
    NextChannel++;
    if(InitChannel+NextChannel>=32) NextChannel=0;
    if(con>=32) con=InitChannel;
  }

  StopSound(con);
  judas_playsample(sonido[NumSonido].smp, con, (sonido[NumSonido].freq*Frec)/256, 32*Volumen, MIDDLE);

  Freq_original[con]=sonido[NumSonido].freq;

  channel(con)=1;

  return(con);
}

int StopSound(int NumChannel)
{
  if(NumChannel >= CHANNELS) return(-1);

  judas_stopsample(NumChannel);

  return(1);
}

int ChangeSound(int NumChannel,int Volumen,int Frec)
{
  CHANNEL *chptr;

  if(NumChannel >= CHANNELS || NumChannel < MusicChannels) return(-1);

  chptr = &judas_channel[NumChannel];

  chptr->vol       = 32*Volumen;
  chptr->freq      = (Freq_original[NumChannel]*Frec)/256;

  return(1);
}

int ChangeChannel(int NumChannel,int Volumen,int Panning)
{
  CHANNEL *chptr;

  if(NumChannel >= CHANNELS || NumChannel < MusicChannels) return(-1);

  chptr = &judas_channel[NumChannel];

  chptr->mastervol = Volumen/2;
  chptr->panning   = Panning;

  return(1);
}

int IsPlayingSound(int NumChannel)
{
  SAMPLE *smp = judas_channel[NumChannel].smp;
  char *pos   = judas_channel[NumChannel].pos;

  if( (NumChannel >= CHANNELS) ||
      ((judas_channel[NumChannel].voicemode & VM_ON) == VM_OFF) ||
      (!judas_channel[NumChannel].smp) ) return(0);

//if(NumChannel >= CHANNELS) return(0);

  if (pos >= smp->end || pos < smp->start) return(0);

//printf("%d - %d\n", chptr->pos, chptr->end);

  return(1);
}

int LoadSong(char *ptr, int Len, int Loop)
{
  int con=0;

  while(con<128 && cancion[con].ptr!=NULL) con++;
  if(con==128) return(-1);

  judas_loadxm_mem(ptr);
  if(judas_error == JUDAS_OK)
  {
    cancion[con].SongType=XM;
    judas_freexm();
  }
  else if(judas_error == JUDAS_WRONG_FORMAT)
  {
    judas_loads3m_mem(ptr);
    if(judas_error == JUDAS_OK)
    {
      cancion[con].SongType=S3M;
      judas_frees3m();
    }
    else if(judas_error == JUDAS_WRONG_FORMAT)
    {
      judas_loadmod_mem(ptr);
      if(judas_error == JUDAS_OK)
      {
        cancion[con].SongType=MOD;
        judas_freemod();
      }
    }
  }

  if(judas_error != JUDAS_OK) return(-1);
  if((cancion[con].ptr=malloc(Len))==NULL) return(-1);

  memcpy(cancion[con].ptr, ptr, Len);
  cancion[con].loop=Loop;

  return(con);
}

int PlaySong(int NumSong)
{
  if(NumSong>127 || !cancion[NumSong].ptr) return(-1);

  StopSong();

  switch(cancion[NumSong].SongType)
  {
    case XM:
      judas_loadxm_mem(cancion[NumSong].ptr);
      if(cancion[NumSong].loop) judas_playxm(1000000000);
      else                      judas_playxm(1);
      MusicChannels = judas_getxmchannels();
      break;
    case S3M:
      judas_loads3m_mem(cancion[NumSong].ptr);
      if(cancion[NumSong].loop) judas_plays3m(1000000000);
      else                      judas_plays3m(1);
      MusicChannels = judas_gets3mchannels();
      break;
    case MOD:
      judas_loadmod_mem(cancion[NumSong].ptr);
      if(cancion[NumSong].loop) judas_playmod(1000000000);
      else                      judas_playmod(1);
      MusicChannels = judas_getmodchannels();
      break;
  }

  SongType = cancion[NumSong].SongType;

  return(1);
}

void StopSong(void)
{
  if(!judas_songisplaying()) return;

  switch(SongType)
  {
    case XM:  judas_freexm();  break;
    case S3M: judas_frees3m(); break;
    case MOD: judas_freemod(); break;
  }

  MusicChannels=0;
}

void UnloadSong(int NumSong)
{
  if(NumSong>127 || !cancion[NumSong].ptr) return;

  free(cancion[NumSong].ptr);
  cancion[NumSong].ptr=NULL;
}

void SetSongPos(int SongPat)
{
  if(!judas_songisplaying()) return;

  switch(SongType)
  {
    case XM:  judas_set_xm_pos(SongPat);  break;
    case S3M: judas_set_s3m_pos(SongPat); break;
    case MOD: judas_set_mod_pos(SongPat); break;
  }
}

int GetSongPos(void)
{
  int pos;

  if(!judas_songisplaying()) return(-1);

  switch(SongType)
  {
    case XM:  pos=judas_getxmpos();  break;
    case S3M: pos=judas_gets3mpos(); break;
    case MOD: pos=judas_getmodpos(); break;
  }

  return(pos);
}

int GetSongLine(void)
{
  int pos;

  if(!judas_songisplaying()) return(-1);

  switch(SongType)
  {
    case XM:  pos=judas_getxmline();  break;
    case S3M: pos=judas_gets3mline(); break;
    case MOD: pos=judas_getmodline(); break;
  }

  return(pos);
}

int IsPlayingSong(void)
{
  if(judas_songisplaying()) return(1);

  return(0);
}

void EndSound(void)
{
  judas_uninit();
  timer_uninit();
}

