#pragma once

/* Copyright (c) 2017, Dustin J Sparks
*
* PUBLIC DOMAIN MARK
*
* While this work is free from any patent or intellectual property claims, the algorithm, pseudo-code, and test vectors were derived from
* RFC 7914 "The scrypt Password-Based Key Derivation Function" (C. Percival, August 2016, ISSN: 2070-1721)
*
* From the RFC:
* Copyright (c) 2016 IETF Trust and the persons identified as the
* document authors. All rights reserved.
* This document is subject to BCP 78 and the IETF Trust’s Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info)
* in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions
* with respect to this document. Code Components extracted from this document must include Simplified BSD License text as described in Section 4.e of
* the Trust Legal Provisions and are provided without warranty as described in the Simplified BSD License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "ScryptManaged.h"
#include "PBKDF2HMACSHA.cpp"

using namespace System;
using namespace System::Text;

namespace ScryptManaged
{
	String^ Scrypt::Encode(String^ Password, const int Iterations, const short BlockSize, const short Parallelism)
	{
		return Encode((array<const Byte>^)Encoding::UTF8->GetBytes(Password), nullptr, Iterations, BlockSize, Parallelism, 32);
	}

	String^ Scrypt::Encode(array<const Byte>^ Password, const int Iterations, const short BlockSize, const short Parallelism)
	{
		return Encode(Password, nullptr, Iterations, BlockSize, Parallelism, 32);
	}

	String^ Scrypt::Encode(String^ Password, array<const Byte>^ Salt, const int Iterations, const short BlockSize, const short Parallelism)
	{
		return Encode((array<const Byte>^)Encoding::UTF8->GetBytes(Password), Salt, Iterations, BlockSize, Parallelism, 32);
	}

	String^ Scrypt::Encode(array<const Byte>^ Password, array<const Byte>^ Salt, const int Iterations, const short BlockSize, const short Parallelism)
	{
		return Encode(Password, Salt, Iterations, BlockSize, Parallelism, 32);
	}

	String^ Scrypt::Encode(String^ Password, array<const Byte>^ Salt,
		const int Iterations, const short BlockSize, const short Parallelism, const int OutputByteLength)
	{
		return Encode((array<const Byte>^)Encoding::UTF8->GetBytes(Password), Salt, Iterations, BlockSize, Parallelism, OutputByteLength);
	}

	String^ Scrypt::Encode(String^ Password, const int Iterations, const short BlockSize, const short Parallelism, const int OutputByteLength) 
	{
		return Encode((array<const Byte>^)Encoding::UTF8->GetBytes(Password), nullptr, Iterations, BlockSize, Parallelism, OutputByteLength);
	}

	String^ Scrypt::Encode(array<const Byte>^ Password, const int Iterations, const short BlockSize, const short Parallelism, const int OutputByteLength) 
	{
		return Encode(Password, nullptr, Iterations, BlockSize, Parallelism, OutputByteLength);
	}

	String^ Scrypt::Encode(array<const Byte>^ Password, array<const Byte>^ Salt,
		const int Iterations, const short BlockSize, const short Parallelism, const int OutputByteLength)
	{
		array<const Byte>^ salt;
		if (Salt == nullptr) // if they didn't provide one, we will
		{
			array<Byte>^ _salt = gcnew array<Byte>(32);
			(gcnew System::Security::Cryptography::RNGCryptoServiceProvider())->GetBytes(_salt);
			salt = (array<const Byte>^)_salt;
		}
		else
			salt = Salt;
		array<Byte>^ stuff = ComputeDerivedHash(Password, salt, Iterations, BlockSize, Parallelism, OutputByteLength);
		Header^ h = gcnew Header(2, Salt, Iterations, BlockSize, Parallelism, stuff);
		return h->ToString();
	}
	
	bool Scrypt::Compare(const String^ encodedHash, const String^ password)
	{
		String^ pass = password == nullptr ? "" : const_cast<String^>(password);
		return Scrypt::Compare(encodedHash, (array<const Byte>^)(gcnew Text::UTF8Encoding())->GetBytes(pass));
	}

	bool Scrypt::Compare(const String^ encodedHash, array<const Byte>^ password)
	{
		if (String::IsNullOrWhiteSpace(const_cast<String^>(encodedHash)))
			throw gcnew ArgumentNullException("encodedHash");
		if (password == nullptr || password->Length == 0)
			throw gcnew ArgumentNullException("password");
		Scrypt::Header^ h = Scrypt::Header::FromString(encodedHash); // exceptions will be raised from here as necessary
		array<Byte>^ stuff;
		if (h->v >= 2)
		{
			stuff = Scrypt::ComputeDerivedHash(password, (array<const Byte>^)h->s, h->cc, h->b, h->p, h->olen);
		}
		else if (h->v == 1)
		{
			stuff = Scrypt::ComputeDerivedHash(password, (array<const Byte>^)h->s, h->cc, h->b, h->p, h->olen);
		}
		else
			stuff = Scrypt::ComputeDerivedHash(password, (array<const Byte>^)h->s, h->cc, h->b, h->p, h->olen);

		return Scrypt::SafeEquals(stuff, h->Hash);
	}

	array<Byte>^ Scrypt::ComputeDerivedHash(
		array<const Byte>^ Password, array<const Byte>^ Salt,
		const int Iterations, const short BlockSize, const short Parallelism)
	{
		return ComputeDerivedHash(Password, Salt, Iterations, BlockSize, Parallelism, 32);
	}

	array<Byte>^ Scrypt::ComputeDerivedHash(
		array<const Byte>^ Password, array<const Byte>^ Salt,
		const int Iterations, const short BlockSize, const short Parallelism,
		const int OutputByteLength)
	{
		if (Salt == nullptr || Salt->Length == 0)
			throw gcnew ArgumentOutOfRangeException("Salt", "Salt cannot be null or zero length.");
		array<Byte>^ P = (array<Byte>^)Password;
		if (P == nullptr) { P = gcnew array<Byte>(0); };
		if (Iterations < 2 || (Iterations & 1L) == 1 || (Iterations & (Iterations - 1)) != 0L)
			throw gcnew ArgumentOutOfRangeException("Iterations", "Iterations must be a power of 2, and greater than 1.");
		if ((UInt64)BlockSize*(UInt64)Parallelism > 1 << 30 ||
			BlockSize > 0x7fffffff / 128 / Parallelism ||
			BlockSize > 0x7fffffff / 256 ||
			Iterations > 0x7fffffff / 128 / BlockSize)
			throw gcnew ArgumentOutOfRangeException("*", "Combined Parameter Values are too large.");
		if (OutputByteLength == 0 || OutputByteLength % 32 != 0)
			throw gcnew ArgumentOutOfRangeException("OutputByteLength", "OutputByteLength must be a multiple of 32, and greater than 0.");
		int r128 = BlockSize * 128; // precompute for speed
		
		array<Byte>^ B = PBKDF2::HMACSHA256((array<const Byte>^)P, Salt, 1, Parallelism * r128);

		// these are defined here rather than in the ROMix loop to prevent a lot of memory allocation and disposal operations
		array<UInt32>^ seqMem = gcnew array<UInt32>(Iterations * r128 / 4); 
		array<UInt32>^ X = gcnew array<UInt32>(r128 / 4);
		array<UInt32>^ T = gcnew array<UInt32>(r128 / 4);
		// should be 64 bytes, 16*4 for blockMix, defined here to prevent a lot of memory allocation and disposal operations
		array<UInt32>^ scratch = gcnew array<UInt32>(16); 
	
		for (Int32 p = 0; p < Parallelism; p++)
		{
			//ROmix
			
			Buffer::BlockCopy(B, p * r128, X, 0, r128); // X = B[p]
			//TODO:  This operation could be made as a worker process or thread so long as each thread is given the X
			//       value and returns the updated X value to be written to the main array in it's representative slot. 
			// The main array B is expanded to include a slot for each thread's output (implied per the spec).

			for (int i = 0; i < Iterations; i += 2) // data independant iterations
			{
				// the Sequential Memory array is defined here, after this loop it does not change and is isolated between parallel operations (thread safe)
				//NOTE: blockMix overwrites the output in a different pattern than it reads the input.  
				//The input and output arrays MUST be different, hence the X <-> T mixing
				Buffer::BlockCopy(X, 0, seqMem, i * r128, r128); // Vi = X
				blockMix((array<const UInt32>^)X, T, BlockSize, scratch);
				Buffer::BlockCopy(T, 0, seqMem, (i + 1) * r128, r128); // Vi = X
				blockMix((array<const UInt32>^)T, X, BlockSize, scratch);
			}

			for (int i = 0; i < Iterations; i++) // data dependant iterations, blocks called out by the J value will get an extra mix
			{
				UInt64 J = 
					integerify(X, BlockSize) & 
					(Iterations - 1);
				Buffer::BlockCopy(seqMem, (int)J * r128, T, 0, r128); // why is J UInt64 when it is only used as Int here?!  (this is from the original spec)
				for (int x = 0; x < T->Length; x++) 
				{ T[x] ^= X[x]; } // T = X xor V[j]
				blockMix((array<const UInt32>^)T, X, BlockSize, scratch); // X = Salsa T
			}
			// end of thread

			Buffer::BlockCopy(X, 0, B, p * r128, r128); // B[p] = X
		}
		Array::Clear(seqMem, 0, seqMem->Length); // secure memory (or at least try)
		Array::Clear(X, 0, X->Length);
		Array::Clear(T, 0, T->Length);
		array<Byte>^ output = PBKDF2::HMACSHA256((array<const Byte>^)P, (array<const Byte>^)B, 1, OutputByteLength);
		Array::Clear(B, 0, B->Length);
		B[0] ^= seqMem[0] ^ X[0] ^ output[0]; // should all be zero, but these calls keep the Clears from being optimized out (ideally) 
		output[0] ^= T[0] + seqMem[0];
		seqMem = nullptr;
		X = nullptr;
		T = nullptr;
		scratch = nullptr;
		B = nullptr;
		return output;
	}
}
