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

using namespace System;

namespace ScryptManaged {

	public ref class PBKDF2
	{
	internal:
		// The interal F method used by PBKFD2
		static array<Byte>^ _F(System::Security::Cryptography::HMAC^ hmac, array<const Byte>^ P, array<Byte>^ S, UInt32 TT, UInt32 I);
		// Checks if two strings are equal. Compares every char to prevent timing attacks. Returns True if both strings are equal
		static __inline bool SafeEquals(String^ a, String^ b)
		{
			if (a->Length != b->Length)
				return false;
			UInt32 diff = 0; // each char is actually wchar_t which can be as wide as 32 bits, so use max width for highest portability

			for (int i = 0; i < a->Length; i++)
				diff |= (UInt32)a[i] ^ (UInt32)b[i];
			
			return diff == 0;
		}

	public:
		// RFC 2898 Password Based Key Derivation Function # 2, using SHA1 in an HMAC configuration.  
		// This is functionally equivalent to MS .NET System::Security::Cryptography::Rfc2898DeriveBytes
		static array<Byte>^ HMACSHA1(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount);
		// RFC 2898 Password Based Key Derivation Function # 2, using SHA256 in an HMAC configuration. SCRYPT Uses this operation internally
		static array<Byte>^ HMACSHA256(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount);
		// RFC 2898 Password Based Key Derivation Function # 2, using SHA512 in an HMAC configuration.
		static array<Byte>^ HMACSHA512(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount);
	};

	public ref class Scrypt
	{
	internal:
#define R32(a,b) (((UInt32)(a) << (b)) | ((a) >> (32 - (b))))
		ref struct Header
		{
		internal:
			Byte v;
			array<Byte>^ s;
			int cc;
			short b;
			short p;
			int olen;
			Header() {};
		public:
			array<Byte>^ Hash;
			Header(const int version, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength)
				:v(version), s((array<Byte>^)salt->Clone()), cc(CPUCost), b(BlockSize), p(Parallelism), olen(OutputByteLength), Hash(nullptr) {}
			Header(const int version, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism, array<Byte>^ Hash)
				: v(version), s((array<Byte>^)salt->Clone()), cc(CPUCost), b(BlockSize), p(Parallelism), olen(Hash->Length), Hash(Hash) {}

			String^ ToString() override
			{
				Text::StringBuilder^ sb = gcnew Text::StringBuilder("$s");
				if (v >= 2)
				{
					// $s$cc$b$p$<salt>$<result>
					sb->Append("2$");
					sb->Append(cc.ToString())->Append("$");
					sb->Append(b.ToString())->Append("$");
					sb->Append(p.ToString())->Append("$");
					sb->Append(Convert::ToBase64String((array<Byte>^)s))->Append("$");
					sb->Append(Convert::ToBase64String((array<Byte>^)Hash));
				}
				else // DEPRECATED!!!!
				{
					// $s<1 or 0>$0x0b0p$<salt>$<result>
					if (cc > 256 || b > 256 || p > 256) throw gcnew System::ArithmeticException("Parameter Overflow on Deprecated ToString() method call");
					if (v == 1) sb->Append("1$"); else sb->Append("0$");
					String^ config = Convert::ToString((Byte)cc << 16 | (Byte)b << 8 | (Byte)p, 16);
					sb->Append(config)->Append("$");
					sb->Append(Convert::ToBase64String((array<Byte>^)s))->Append("$");
					sb->Append(Convert::ToBase64String((array<Byte>^)Hash));
				}
				return sb->ToString();
			}

			static Header^ FromString(const String^ value)
			{
				if (String::IsNullOrWhiteSpace(const_cast<String^>(value)))
					return nullptr;
				array<String^>^ splitit = gcnew array<String^>(1); splitit[0] = "$";
				array<String^>^ pieces = const_cast<String^>(value)->Split(splitit, StringSplitOptions::RemoveEmptyEntries);
				Header^ result = gcnew Header();
				result->v = int::Parse(pieces[0]->Replace("s",""));
				if (result->v == 2)
				{   //  0     1  2 3 4      5
					// $s<2+>$cc$b$p$<salt>$<result>
					result->cc = Convert::ToInt32(pieces[1]);
					result->b = Convert::ToUInt16(pieces[2]);
					result->p = Convert::ToUInt16(pieces[3]);
					result->s = Convert::FromBase64String(pieces[4]);
					result->Hash = Convert::FromBase64String(pieces[5]);
					result->olen = result->Hash->Length;
				}
				else
				{
					//  0         1 hex    2      3
					// $s<1 or 0>$000c0b0p$<salt>$<result>
					UInt64 config = Convert::ToUInt64(pieces[1], 16);
					result->cc = (config >> 16) & 0xffff;
					result->b = (config >> 8) & 0xff;
					result->p = (config & 0xff);
					result->s = Convert::FromBase64String(pieces[2]);
					result->Hash = Convert::FromBase64String(pieces[3]);
					result->olen = result->Hash->Length;
				}
				return result;
			}		
		};

		static __inline void salsa20_8(array<UInt32>^ data)
		{
			// from Dan Bernstein, adapted direct from the RFC document
			UInt32 x0 = data[0], x1 = data[1], x2 = data[2], x3 = data[3], x4 = data[4], x5 = data[5], x6 = data[6], x7 = data[7],
				x8 = data[8], x9 = data[9], xA = data[10], xB = data[11], xC = data[12], xD = data[13], xE = data[14], xF = data[15];
			for (Byte i = 8; 0 < i && i < 16; i -= 2) { // the in-between nomenclature is for underflow protection
				x4 ^= R32(x0 + xC, 7); x8 ^= R32(x4 + x0, 9);
				xC ^= R32(x8 + x4, 13); x0 ^= R32(xC + x8, 18);
				x9 ^= R32(x5 + x1, 7); xD ^= R32(x9 + x5, 9);
				x1 ^= R32(xD + x9, 13); x5 ^= R32(x1 + xD, 18);
				xE ^= R32(xA + x6, 7); x2 ^= R32(xE + xA, 9);
				x6 ^= R32(x2 + xE, 13); xA ^= R32(x6 + x2, 18);
				x3 ^= R32(xF + xB, 7); x7 ^= R32(x3 + xF, 9);
				xB ^= R32(x7 + x3, 13); xF ^= R32(xB + x7, 18);
				x1 ^= R32(x0 + x3, 7); x2 ^= R32(x1 + x0, 9);
				x3 ^= R32(x2 + x1, 13); x0 ^= R32(x3 + x2, 18);
				x6 ^= R32(x5 + x4, 7); x7 ^= R32(x6 + x5, 9);
				x4 ^= R32(x7 + x6, 13); x5 ^= R32(x4 + x7, 18);
				xB ^= R32(xA + x9, 7); x8 ^= R32(xB + xA, 9);
				x9 ^= R32(x8 + xB, 13); xA ^= R32(x9 + x8, 18);
				xC ^= R32(xF + xE, 7); xD ^= R32(xC + xF, 9);
				xE ^= R32(xD + xC, 13); xF ^= R32(xE + xD, 18);
			}
			data[0] += x0; data[1] += x1; data[2] += x2; data[3] += x3; data[4] += x4; data[5] += x5; data[6] += x6; data[7] += x7;
			data[8] += x8; data[9] += x9; data[10] += xA; data[11] += xB; data[12] += xC; data[13] += xD; data[14] += xE; data[15] += xF;
		}

		static __inline void blockMix(array<const UInt32>^ data, array<UInt32>^ dataOut, int blocksize, array<UInt32>^ scratch)
		{
			Buffer::BlockCopy(data, (2 * blocksize - 1) * 64, scratch, 0, 64); // 1. X = B
			array<UInt32>^ buffer = gcnew array<UInt32>(16);
			for (Int32 i = 0; i < (2 * blocksize); i += 2)
			{
				// NOTE that the output is written as:
				// B'={Y[0],Y[2],...Y[2*r-2],Y[1],Y[3]...Y[2*r-1]}
				// The first Salsa operation is written starting from the "front" of B',
				//   while the second Salsa operation is written starting from the "middle". 
				// This is per the spec, and the reason for separate input and output arrays.
				// This is also why the specification REQUIRES 'N' to be an even number!
				Buffer::BlockCopy(data, i * 64, buffer, 0, 64);
				for (int x = 0; x < buffer->Length; x++) { scratch[x] ^= buffer[x]; } // 2.  T= X xor B[i]
				salsa20_8(scratch); // X = Salsa T
				Buffer::BlockCopy(scratch, 0, dataOut, i * 32, 64); // Y[i] = X for all even I

				Buffer::BlockCopy(data, i * 64 + 64, buffer, 0, 64);
				for (int x = 0; x < buffer->Length; x++) { scratch[x] ^= buffer[x]; } // 2.  T= X xor B[i]
				salsa20_8(scratch); // X = Salsa T
				Buffer::BlockCopy(scratch, 0, dataOut, (i * 32) + (blocksize * 64), 64); // Y[i] = X for all odd I
			}
			buffer = nullptr;
		}

		static __inline UInt64 integerify(array<UInt32>^ data, int blocksize)
		{
			UInt32 j = ((2 * blocksize) - 1) * 16;
			return ((UInt64)(data[j + 1]) << 32) | data[j];
		}

		// Checks if two arrays are equal. Compares every byte to prevent timing attacks. Returns True if both arrays are equal
		static __inline bool SafeEquals(array<Byte>^ a, array<Byte>^ b)
		{
			if (a->Length != b->Length)
				return false;
			Byte diff = 0; 
			for (int i = 0; i < a->Length; i++)
				diff |= (UInt32)a[i] ^ (UInt32)b[i];
			return diff == 0;
		}

	public:
		// RFC 7914 The scrypt Password-Based Key Derivation Function
		// Password=Byte Array of password('P'), Salt=Byte Array of salt ('S', cannot be null or empty), CPUCost=Iterations('N'), 
		// BlockSize=Blocks used Internally('r', memory cost), Parallelism=Number of threads used ('p', also a memory cost [not currently implemented as actual threads!])
		static array<Byte>^ ComputeDerivedHash(array<const Byte>^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism);
		static array<Byte>^ ComputeDerivedHash(array<const Byte>^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength);
		// RFC 7914 The scrypt Password-Based Key Derivation Function
		// Password=Byte Array of password('P'), Salt=Byte Array of salt ('S', cannot be null or empty), CPUCost=Iterations('N'), 
		// BlockSize=Blocks used Internally('r', memory cost), Parallelism=Number of threads used ('p', also a memory cost [not currently implemented as actual threads!])
		// Outputs encoded string with result and all variables included
		static String^ Encode(String^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength);
		static String^ Encode(array<const Byte>^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength);
		static String^ Encode(String^ password, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength);
		static String^ Encode(array<const Byte>^ password, const int CPUCost, const short BlockSize, const short Parallelism, const int OutputByteLength);
		static String^ Encode(String^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism);
		static String^ Encode(array<const Byte>^ password, array<const Byte>^ salt, const int CPUCost, const short BlockSize, const short Parallelism);
		static String^ Encode(String^ password, const int CPUCost, const short BlockSize, const short Parallelism);
		static String^ Encode(array<const Byte>^ password, const int CPUCost, const short BlockSize, const short Parallelism);
		// RFC 7914 The scrypt Password-Based Key Derivation Function
		// Password=Byte Array of password('P'), Salt=Byte Array of salt ('S', cannot be null or empty), CPUCost=Iterations('N'), 
		// BlockSize=Blocks used Internally('r', memory cost), Parallelism=Number of threads used ('p', also a memory cost [not currently implemented as actual threads!])
		// Decodes hashed and encoded string and compares against supplied password (FALSE if no match)
		static bool Compare(const String^ hash, const String^ password);
		static bool Compare(const String^ hash, array<const Byte>^ password);
	};
}
