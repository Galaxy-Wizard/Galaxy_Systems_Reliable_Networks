#include "pch.h"

#include "encrypt_xor.h"

#include <limits>

namespace encrypt
{

	char* encrypt_xor(char* source_message, size_t source_message_length, char xor_code)
	{
		char* local_result = source_message;

		for (size_t local_counter = 0; local_counter < source_message_length; local_counter++)
		{
			local_result[local_counter] ^= xor_code;
		}

		return local_result;
	}

	wchar_t* encrypt_xor(wchar_t* source_message, size_t source_message_length, wchar_t xor_code)
	{
		wchar_t* local_result = source_message;

		for (size_t local_counter = 0; local_counter < source_message_length; local_counter++)
		{
			local_result[local_counter] ^= xor_code;
		}

		return local_result;
	}

	void* encrypt_xor(void* source_message, size_t source_message_length, size_t atom_data_size, unsigned long long xor_code)
	{
		unsigned char* local_result = (unsigned char*)source_message;

		for (size_t local_counter = 0; local_counter < source_message_length; local_counter++)
		{
			for (size_t local_atom_counter = 0; local_atom_counter < atom_data_size && atom_data_size * local_counter + local_atom_counter < source_message_length; local_atom_counter++)
			{
				local_result[atom_data_size * local_counter + local_atom_counter] ^= unsigned char(xor_code >> (local_atom_counter * std::numeric_limits<unsigned char>::digits));
			}
		}

		return local_result;
	}

	void* encrypt_xor(void* source_message, size_t source_message_length, size_t atom_data_size, unsigned char* xor_code)
	{
		unsigned char* local_result = (unsigned char*)source_message;

		for (size_t local_counter = 0; local_counter < source_message_length; local_counter++)
		{
			for (size_t local_atom_counter = 0; local_atom_counter < atom_data_size && atom_data_size * local_counter + local_atom_counter < source_message_length; local_atom_counter++)
			{
				local_result[atom_data_size * local_counter + local_atom_counter] ^= xor_code[local_atom_counter];
			}
		}

		return local_result;
	}

}
