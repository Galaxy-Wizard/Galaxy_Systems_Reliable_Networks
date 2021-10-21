#pragma once

namespace encrypt
{

char *encrypt_xor(char* source_message, size_t source_message_length, char xor_code);

wchar_t* encrypt_xor(wchar_t* source_message, size_t source_message_length, wchar_t xor_code);

void* encrypt_xor(void* source_message, size_t source_message_length, size_t atom_data_size, unsigned long long xor_code);

void* encrypt_xor(void* source_message, size_t source_message_length, size_t atom_data_size, unsigned char* xor_code);

}