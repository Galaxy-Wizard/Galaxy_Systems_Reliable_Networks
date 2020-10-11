#include "pch.h"

#include "encrypt_xor.h"

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

}
