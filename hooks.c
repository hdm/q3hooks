
// hooks.c - quake3 libc interception toolkit
    
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>

#define LIB "/lib/libc.so.6"
#define LOGFD stdout

/* define these function psudeo-prototypes */
typedef char * (*cp2cpcp)(char *, char *);
typedef char * (*cp2cpcpi)(char *, char *, int);
typedef int (*i2cpcp)(char *, char *);
typedef void (*v2cpis)(char *, int, size_t);
typedef int (*i2tvtz)(struct timeval *, struct timezone *);
typedef int (*i2cpim)(char *, int, mode_t);
typedef int (*i2cpccp) (char *, const char *, ...);
typedef char * (*cp2cpccps) (char *, const char *, size_t n);


/* some flags used for interception/modification */
int ok_to_strcat = 0;
int time_hack = 0;

/* globals */
int init = 0;
void *lib_handle;
const char *lib_err;

/* this defines the function pointers to the real libc */
cp2cpcp     loaded_func1;
i2cpcp      loaded_func2;
i2cpcp      loaded_func3;
cp2cpcp     loaded_func4;
cp2cpcp     loaded_func5;
cp2cpcpi    loaded_func6;
v2cpis      loaded_func7; // memset
i2tvtz      loaded_func8; // gettimeofday
cp2cpccps   loaded_func9; // strncpy


/* this is called only once by the first intercept */
void init_hooks (void)
{
   srand(1235124516606 + getpid());
   lib_handle = dlopen(LIB, RTLD_LAZY);
   if (lib_handle == NULL)
   {
        fprintf(LOGFD, "could not open '%s' : %s\n", LIB, dlerror());
        return;   
   } 
   
   /* strcopy */
   loaded_func1 = dlsym(lib_handle, "strcpy");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }
   
   /* strcmp */
   loaded_func2 = dlsym(lib_handle, "strcmp");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }
   
   /* strcasecmp */
   loaded_func3 = dlsym(lib_handle, "strcasecmp");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }
    /* strstr */
   loaded_func4 = dlsym(lib_handle, "strstr");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }
   
    /* strcpy */
   loaded_func5 = dlsym(lib_handle, "strcat");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }     
    /* strncat */
   loaded_func6 = dlsym(lib_handle, "strncat");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }    
   
   /* memset */
   loaded_func7 = dlsym(lib_handle, "memset");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }  
   
    
   // gettimeofday
   loaded_func8 = dlsym(lib_handle, "gettimeofday");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   }           
   
    
   // strncpy
   loaded_func9 = dlsym(lib_handle, "strncpy");
   lib_err = dlerror();
   if (lib_err)
   {
        fprintf(LOGFD, "count not find symbol: %s\n",lib_err);
        dlclose(lib_handle);
        return;
   } 
               
   init++;
   return;
}

char *strcpy (char *dst, const char *src)
{
    char *ret;
            
    if (!init)
        init_hooks();
    
    fprintf(LOGFD, "strcpy: 0x%.8x => '%s'\n", (int) dst, src);
        
    ret = (*loaded_func1)(dst, src);
    return ret;
}

int strcmp (char *hay, const char *needle)
{
    int ret;
    
    if (!init)
        init_hooks();
    
    fprintf(LOGFD, "strcmp: '%s' in '%s'\n", needle, hay);
    ret = (*loaded_func2)(hay, needle);
    return ret;
}

int strcasecmp (char *hay, char *needle)
{
    int ret;
    
    if (!init)
        init_hooks();
    
    fprintf(LOGFD, "strcasecmp: '%s' in '%s'\n", needle, hay);
    ret = (*loaded_func3)(hay, needle);
    return ret;
}

char *strstr (char *hay, char *needle)
{
    char * ret;
    
    if (!init)
        init_hooks();
    
    if (strlen(hay) < 100)
    {
        fprintf(LOGFD, "strstr: '%s' in '%s' ", needle, hay);
    } else {
        fprintf(LOGFD, "strstr: '%s' in '<BIG TEXT>' ", needle);
    }
    
    ret = (*loaded_func4)(hay, needle);
    fprintf(LOGFD, "(0x%.8x)\n", (int) ret);
    
    return ret;
}

char *strcat (char *dst, char *src)
{
    char * ret;
    char *timehack_on =  "timehack_on";
    char *timehack_off = "timehack_off";
    char *rep = "\x0a\x0d";

       
    if (!init)
        init_hooks();
    
    if (ok_to_strcat)
    {
        fprintf(LOGFD, "strcat: '%s' to '%s'\n", src, dst);
    }
    
    
    if ((*loaded_func4)(src, timehack_on) != NULL)
    {
        fprintf(LOGFD, "MOD: setting timehack on.");
        time_hack++;
        src = rep;
          
    }
    if ((*loaded_func4)(src, timehack_off) != NULL)
    {
        fprintf(LOGFD, "MOD: setting timehack off.\n");
        time_hack = 0;
        src = rep;
    }
    
    ret = (*loaded_func5)(dst, src);
    
    return ret;
}

char *strncat (char *dst, char *src, int size)
{
    char * ret;
    if (!init)
        init_hooks();
    fprintf(LOGFD, "strncat: (%d bytes) '%s' to '%s'\n ", size, src, dst);
    ret = (*loaded_func6)(dst, src, size);
    return ret;
}

void *memset (char *dst, int chr, size_t size)
{
    char * ret;
    if (!init)
        init_hooks();
    
    //fprintf(LOGFD, "memset: setting %d bytes to %d at 0x%.8x\n ", size, chr, dst);
    (*loaded_func7)(dst, chr, size);
    return ret;
}


int gettimeofday (struct timeval *tv, struct timezone *tz)
{
    int ret; 
    
    if (!init)
        init_hooks();     
    
    ret = (*loaded_func8)(tv, tz); 
    
    if (time_hack > 0)
    { 
        tv->tv_usec += 2500;
        tv->tv_usec -= (int) (5000 * rand()/(RAND_MAX+1.0));  
    }
    
    return ret;
}


char *strncpy (char *dst, char *src, size_t size)
{
    char *ret;
    int rnd;
    
    if (!init)
        init_hooks();
/*
    if ((*loaded_func4)(src, "tc ") != NULL)
    {
        if (strlen(src) > 6 && src[4] == 0x20)
        {
            rnd = (int)(100.0*rand()/(RAND_MAX+1.0));

            fprintf(LOGFD, "MOD: changing number in '%s'.\n", src);
            src[3]++;
            fprintf(LOGFD, "MOD: changed number in '%s'.\n", src);

        }
    }
*/
    /* use this to modify your 'say' commands before they get sent out! */
    if ((*loaded_func4)(src, "say hello!") != NULL)
    {
        src = "say HELLO INTERCEPTED!";
    } 

           
                
    fprintf(LOGFD, "strncpy: (%d bytes) '%s' to '%s'\n ", size, src, dst);
    ret = (*loaded_func9)(dst, src, size);
    return ret;
}


int sprintf(char *dest, const char *format, ...)
{
    int ret;
    va_list ap;
    
    va_start(ap, format);
   
    ret = vsprintf(dest, format, ap); 
    fprintf(LOGFD, "sprintf: ret = %d\tformat = '%s'\tresult = '%s'\n ", ret, format, dest);
    
    va_end(ap);
    return ret;
}
