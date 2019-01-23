#pragma once

using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

//
// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
//
[assembly:AssemblyTitleAttribute(L"ScryptManaged")];
[assembly:AssemblyDescriptionAttribute(L"A managed C++/CLR implementation of Scrypt (RFC7914) and PBKDF2HMAC512 (RFC2829)")];
[assembly:AssemblyConfigurationAttribute(L"")];
[assembly:AssemblyCompanyAttribute(L"")];
[assembly:AssemblyProductAttribute(L"ScryptManaged")];
[assembly:AssemblyCopyrightAttribute(L"Copyright (c) Dustin J Sparks 2017")];
[assembly:AssemblyTrademarkAttribute(L"Originally developed by Colin Percival and Simon Josefsson, uses Salsa20 Core from Dan Bernstein")];
[assembly:AssemblyCultureAttribute(L"")];

//
// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version
//      Build Number
//      Revision
//
// You can specify all the value or you can default the Revision and Build Numbers
// by using the '*' as shown below:

[assembly:AssemblyVersionAttribute("1.0.*")];

[assembly:ComVisible(false)];

[assembly:CLSCompliantAttribute(true)];