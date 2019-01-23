#pragma once

using namespace System;

namespace ScryptManaged
{
#define SHA1BLOCKSIZE		20
#define SHA256BLOCKSIZE		32
#define SHA512BLOCKSIZE		64

	static array<Byte>^ IntToBytes(UInt32 i)
	{
		array<Byte>^ bytes = BitConverter::GetBytes(i);
		if (!BitConverter::IsLittleEndian)
		{
			return bytes;
		}
		else
		{
			Array::Reverse(bytes);
			return bytes;
		}
	}

	// the core function of the PBKDF which does all the iterations
	// per the spec section 5.2 step 3
	array<Byte>^ ScryptManaged::PBKDF2::_F(System::Security::Cryptography::HMAC^ hmac, array<const Byte>^ P, array<Byte>^ S, UInt32 TT, UInt32 I)
	{
		//NOTE: SPEC IS MISLEADING!!!
		//THE HMAC FUNCTIONS ARE KEYED BY THE PASSWORD! NEVER THE SALT!
		array<Byte>^ bufferU = nullptr;
		array<Byte>^ bufferOut = nullptr;
		array<Byte>^ _int = IntToBytes(TT);
		hmac->Initialize();
		hmac->Key = (array<Byte>^)P; // KEY BY THE PASSWORD!!!
		hmac->TransformBlock(S, 0, S->Length, S, 0);
		hmac->TransformFinalBlock(_int, 0, _int->Length);
		bufferU = hmac->Hash;
		bufferOut = (array<Byte>^)bufferU->Clone();
		for (UInt32 c = 1; c < I; c++)
		{
			hmac->Initialize();
			hmac->Key = (array<Byte>^)P;  // KEY BY THE PASSWORD!
			bufferU = hmac->ComputeHash(bufferU);
			//Xor step
			for (int i = 0; i < bufferOut->Length; i++)
				bufferOut[i] ^= bufferU[i];
		}
		return bufferOut;
	}

	array<Byte>^ ScryptManaged::PBKDF2::HMACSHA1(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount)
	{
		if (Salt == nullptr || Password == nullptr)
			throw gcnew InvalidOperationException("Object not Initialized!");
		if (Iterations < 1)
			throw gcnew ArgumentOutOfRangeException("Iterations");
		if (OutputByteCount < 1)// || OutputByteCount > uint.MaxValue * blockSize)
			throw gcnew ArgumentOutOfRangeException("OutputByteCount");

		int totalBlocks = (int)Math::Ceiling((Decimal)OutputByteCount / SHA1BLOCKSIZE);
		int partialBlock = (int)(OutputByteCount % SHA1BLOCKSIZE);
		array<Byte>^ result = gcnew array<Byte>(OutputByteCount);
		array<Byte>^ buffer = nullptr;
		array<Byte>^ _s = (array<Byte>^)Salt;
		System::Security::Cryptography::HMAC^ h = gcnew System::Security::Cryptography::HMACSHA1();
		for (int T = 1; T <= totalBlocks; T++)
		{
			// run the F function with the _C number of iterations for block number TT
			buffer = _F(h, Password, _s, (UInt32)T, Iterations);
			//IF we're not at the last block requested
			//OR the last block requested is whole (not partial)
			//  then take everything from the result of F for this block number TT
			//ELSE only take the needed bytes from F
			if (T != totalBlocks || (T == totalBlocks && partialBlock == 0))
				Buffer::BlockCopy(buffer, 0, result, SHA512BLOCKSIZE * (T - 1), SHA512BLOCKSIZE);
			else
				Buffer::BlockCopy(buffer, 0, result, SHA512BLOCKSIZE * (T - 1), partialBlock);
		}
		return result;
	}

	array<Byte>^ ScryptManaged::PBKDF2::HMACSHA256(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount)
	{
		if (Salt == nullptr || Password == nullptr)
			throw gcnew InvalidOperationException("Object not Initialized!");
		if (Iterations < 1)
			throw gcnew ArgumentOutOfRangeException("Iterations");
		if (OutputByteCount < 1)// || OutputByteCount > uint.MaxValue * blockSize)
			throw gcnew ArgumentOutOfRangeException("OutputByteCount");

		int totalBlocks = (int)Math::Ceiling((Decimal)OutputByteCount / SHA256BLOCKSIZE);
		int partialBlock = (int)(OutputByteCount % SHA256BLOCKSIZE);
		array<Byte>^ result = gcnew array<Byte>(OutputByteCount);
		array<Byte>^ buffer = nullptr;
		array<Byte>^ _s = (array<Byte>^)Salt;
		System::Security::Cryptography::HMAC^ h = gcnew System::Security::Cryptography::HMACSHA256();
		for (int T = 1; T <= totalBlocks; T++)
		{
			// run the F function with the _C number of iterations for block number TT
			buffer = _F(h, Password, _s, T, Iterations);
			//IF we're not at the last block requested
			//OR the last block requested is whole (not partial)
			//  then take everything from the result of F for this block number TT
			//ELSE only take the needed bytes from F
			if (T != totalBlocks || (T == totalBlocks && partialBlock == 0))
				Buffer::BlockCopy(buffer, 0, result, SHA256BLOCKSIZE * (T - 1), SHA256BLOCKSIZE);
			else
				Buffer::BlockCopy(buffer, 0, result, SHA256BLOCKSIZE * (T - 1), partialBlock);
		}
		return result;
	}

	array<Byte>^ ScryptManaged::PBKDF2::HMACSHA512(array<const Byte>^ Password, array<const Byte>^ Salt, int Iterations, int OutputByteCount)
	{
		if (Salt == nullptr || Password == nullptr)
			throw gcnew InvalidOperationException("Object not Initialized!");
		if (Iterations < 1)
			throw gcnew ArgumentOutOfRangeException("Iterations");
		if (OutputByteCount < 1)// || OutputByteCount > uint.MaxValue * blockSize)
			throw gcnew ArgumentOutOfRangeException("OutputByteCount");

		int totalBlocks = (int)Math::Ceiling((Decimal)OutputByteCount / SHA512BLOCKSIZE);
		int partialBlock = (int)(OutputByteCount % SHA512BLOCKSIZE);
		array<Byte>^ result = gcnew array<Byte>(OutputByteCount);
		array<Byte>^ buffer = nullptr;
		array<Byte>^ _s = (array<Byte>^)Salt;
		System::Security::Cryptography::HMAC^ h = gcnew System::Security::Cryptography::HMACSHA512();
		for (int T = 1; T <= totalBlocks; T++)
		{
			// run the F function with the _C number of iterations for block number TT
			buffer = _F(h, Password, _s, (UInt32)T, Iterations);
			//IF we're not at the last block requested
			//OR the last block requested is whole (not partial)
			//  then take everything from the result of F for this block number TT
			//ELSE only take the needed bytes from F
			if (T != totalBlocks || (T == totalBlocks && partialBlock == 0))
				Buffer::BlockCopy(buffer, 0, result, SHA512BLOCKSIZE * (T - 1), SHA512BLOCKSIZE);
			else
				Buffer::BlockCopy(buffer, 0, result, SHA512BLOCKSIZE * (T - 1), partialBlock);
		}
		return result;
	}

	

	
}