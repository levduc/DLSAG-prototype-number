//
// Created by dduck on 2/10/20.
//
#include <cstdio>
#include <string>
#include <stdexcept>

#ifndef DLSAG_HELPER_H
#define DLSAG_HELPER_H
void hex2bin(const char *src, unsigned  char *target);
std::string hexStr(unsigned char *data, int len);
void hexdump(unsigned char *a, int len);
#endif //DLSAG_HELPER_H
