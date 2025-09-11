#pragma once
// Minimal gl3w header subset for core loading used by ImGui (OpenGL 3.0+)
#include <stddef.h>
#ifndef APIENTRY
# ifdef _WIN32
#  define APIENTRY __stdcall
# else
#  define APIENTRY
# endif
#endif
#ifdef __cplusplus
extern "C" {
#endif
int gl3wInit(void);
int gl3wIsSupported(int major, int minor);
void *gl3wGetProcAddress(const char *proc);
// Declare a few core function pointers demanded by ImGui backend; the full loader populates them.
extern void (APIENTRY *glViewport)(int x,int y,int w,int h);
extern void (APIENTRY *glScissor)(int x,int y,int w,int h);
extern unsigned int (APIENTRY *glCreateShader)(unsigned int type);
extern void (APIENTRY *glShaderSource)(unsigned int shader, int count, const char *const* string, const int * length);
extern void (APIENTRY *glCompileShader)(unsigned int shader);
extern unsigned int (APIENTRY *glCreateProgram)(void);
extern void (APIENTRY *glAttachShader)(unsigned int program, unsigned int shader);
extern void (APIENTRY *glLinkProgram)(unsigned int program);
extern void (APIENTRY *glDeleteShader)(unsigned int shader);
extern void (APIENTRY *glClearColor)(float r,float g,float b,float a);
extern void (APIENTRY *glClear)(unsigned int mask);
#ifdef __cplusplus
}
#endif
