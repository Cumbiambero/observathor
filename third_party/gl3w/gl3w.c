#include "gl3w.h"
#ifndef APIENTRY
# ifdef _WIN32
#  define APIENTRY __stdcall
# else
#  define APIENTRY
# endif
#endif
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
static void* gl3wLoad(const char* name){ return (void*)wglGetProcAddress(name); }
#elif defined(__APPLE__)
#include <dlfcn.h>
static void* gl3wLoad(const char* name){ static void* lib=0; if(!lib) lib=dlopen("/System/Library/Frameworks/OpenGL.framework/Versions/Current/OpenGL", RTLD_LAZY); return lib? dlsym(lib,name):0; }
#else
#include <dlfcn.h>
static void* gl3wLoad(const char* name){ static void* lib=0; if(!lib) lib=dlopen("libGL.so.1", RTLD_LAZY|RTLD_LOCAL); return lib? dlsym(lib,name):0; }
#endif

// function pointers (trimmed minimal set actually used during backend init + rendering)
void (APIENTRY *glViewport)(int,int,int,int); 
void (APIENTRY *glScissor)(int,int,int,int); 
unsigned int (APIENTRY *glCreateShader)(unsigned int); 
void (APIENTRY *glShaderSource)(unsigned int,int,const char *const*,const int*); 
void (APIENTRY *glCompileShader)(unsigned int); 
unsigned int (APIENTRY *glCreateProgram)(void); 
void (APIENTRY *glAttachShader)(unsigned int,unsigned int); 
void (APIENTRY *glLinkProgram)(unsigned int); 
void (APIENTRY *glDeleteShader)(unsigned int);
void (APIENTRY *glClearColor)(float,float,float,float);
void (APIENTRY *glClear)(unsigned int);

static int load_basic(){
#define GL3W_GET(x) ((x = (void*)gl3wGetProcAddress(#x)) != 0)
    int ok=1;
    ok &= GL3W_GET(glViewport);
    ok &= GL3W_GET(glScissor);
    ok &= GL3W_GET(glCreateShader);
    ok &= GL3W_GET(glShaderSource);
    ok &= GL3W_GET(glCompileShader);
    ok &= GL3W_GET(glCreateProgram);
    ok &= GL3W_GET(glAttachShader);
    ok &= GL3W_GET(glLinkProgram);
    ok &= GL3W_GET(glDeleteShader);
    ok &= GL3W_GET(glClearColor);
    ok &= GL3W_GET(glClear);
    return ok?0:-1;
#undef GL3W_GET
}

void *gl3wGetProcAddress(const char *proc){ return gl3wLoad(proc); }
int gl3wInit(void){ return load_basic(); }
int gl3wIsSupported(int major,int minor){ (void)major; (void)minor; return 1; }
