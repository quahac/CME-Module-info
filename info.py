import glob,sqlite3

class CMEModule:
    
    '''
    Module checks LOG files (on IP + Hostname) when connected to the system and prints login information from logs.
    --------------------------------------------------------------------------

    crackmapexec smb 10.10.10.10 -M info
        [+] (Pwnd3!): TEST-PC\administrator:password -id 12 (Prints pwnd accounts with credential ID to login faster)
    
    crackmapexec smb 10.10.10.10 -id 12
        [+] TEST-PC\administrator:password (Pwn3d!)

    crackmapexec smb 10.10.10.10 -M info --ntds      (Prints Administrator and krbtgt hashes)
        [+] NTDS: location: /root/.cme/logs/TEST-PC_192.168.56.113_2022-05-31_081331.ntds
        [+] NTDS: Administrator:500:111f37ed915c5716aad3b435b51404ee:eb37f9cd74303274cb923442a7348ef4:::    
        [+] NTDS: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f031bf1f16bba6f9de84dffcc164e0f8::: 
        [+] NTDS: LM Crack: [hashcat -m 3000 -a 3 /location] or [john --format=lm /location] detected 18x (Prints when available)
        [+] NTDS: NT Crack: [hashcat -m 1000 -a 3 /location] or [john --format=nt /location]   
   
    crackmapexec smb 10.10.10.10 -M info --sam       (Prints SAM file only local Administrator with valid password)
        [+] SAM: Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c::: 
    
    crackmapexec smb 10.10.10.10 -M info --lsa
        [+] LSA: dpapi_machinekey:0x4e467fabe4afb57..ce3730
        [+] LSA: dpapi_userkey:0x0797f33ba6c6043ff7..1558bc
        [+] LSA: NL$KM:c53c6dcd9cff1a4cf8355c4f3c40..32d1be

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

    '''

    name = 'info'
    description = 'Module checks LOG files (on IP + Hostname) when connected to the system and prints login information from logs'
    supported_protocols = ['smb']
    opsec_safe= True 
    multiple_hosts = True 

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):

        if context.sam == True and context.only_files == False:
            files=[]
            for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.sam'):
                with open(name, 'r') as f:
                    files.append(f.read())
            file ='\n'.join(map(str, list(set(files))))
            splits = file.splitlines()
            for split in splits:
                if '500' in split.split(':')[1]:
                    if '31d6cfe0d16ae931b73c59d7e0c089c0' not in split.split(':')[3]:
                        context.log.success('SAM: '+split)  
                
        if context.lsa == True and context.only_files == False:
            files=[]
            for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.secrets'):
                with open(name, 'r') as f:
                    files.append(f.read())
            file ='\n'.join(map(str, list(set(files))))
            splits = file.splitlines()
            for split in splits:
                context.log.success('LSA: ' + split)
     
        if context.ntds is not None and context.only_files == False:
            files=[]
            for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.ntds'):
                with open(name, 'r') as f:
                    files.append(f.read())
                file ='\n'.join(map(str, list(set(files))))
                splits = file.splitlines()
                context.log.success('NTDS: location: '+name) 
                for split in splits:
                    if '500' in split.split(':')[1]:
                        context.log.success('NTDS: '+split)   
                    if '502' in split.split(':')[1]:
                        context.log.success('NTDS: '+split)   
                LMcount = 0
                for split in splits:
                    if 'aad3b435b51404eeaad3b435b51404ee' not in split.split(':')[2]:
                        LMcount += 1
                if LMcount > 0: 
                    context.log.success('NTDS: LM Crack: [hashcat -m 3000 -a 3 /location] or [john --format=lm /location]' + ' detected '+str(LMcount)+'x')
                context.log.success('NTDS: NT Crack: [hashcat -m 1000 -a 3 /location] or [john --format=nt /location]')            
        

        if context.only_files == True:
            if context.ntds is not None:
                for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.ntds'):
                    context.log.success('NTDS: location: ' + name)
            if context.sam == True:
                for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.sam'):
                    context.log.success('SAM: location: ' + name)
            if context.lsa == True:
                for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*.secrets'):
                    context.log.success('LSA: location: ' + name)
            if context.sam == False and context.lsa == False and context.ntds is None:
                for name in glob.glob('/root/.cme/logs/*'+connection.hostname+'_'+connection.host+'*'):
                    context.log.success('LOG: location: ' + name)


        if context.sam == False and context.lsa == False and context.only_files == False and context.ntds is None:
            for name in glob.glob('/root/.cme/workspaces/*'):
                con = sqlite3.connect(name + '/smb.db')
                cur = con.cursor()
                cur.execute("select DISTINCT computers.ip,computers.hostname, computers.domain, users.username, users.password, users.id from users CROSS JOIN admin_relations on users.id = admin_relations.userid CROSS JOIN computers on computers.id = admin_relations.computerid where computers.ip = ? and computers.hostname = ? order by users.id desc", (connection.host,connection.hostname,))
                rows = cur.fetchall()
                for row in rows:
                    context.log.success( '\033[1;33;40m' + '(Pwnd3!) ' + '\x1b[0m' + row[2] + '\\' + row[3]+":"+row[4] + ' -id=' + str(row[5]))
                con.close()
        pass

