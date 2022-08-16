#pragma once
#ifndef INJECT_INJECT_H
#define INJECT_INJECT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

int inject_remote_process(pid_t pid, char * LibPath, char * FunctionName, char * FlagSELinux);

void handle_parameter(int argc, char * argv[]);

int init_inject(int argc, char * argv[]);
#endif //INJECT_INJECT_H