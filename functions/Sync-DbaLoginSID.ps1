function Sync-DbaLoginSID {
    <#
        .SYNOPSIS
            Updates the SQL Login SID on the destination SQL Servers. Supports SQL Server versions 2000 and newer.

        .DESCRIPTION
            SQL Server 2000: Migrates logins with SIDs, passwords, server roles and database roles.

            SQL Server 2005 & newer: Migrates logins with SIDs, passwords, defaultdb, server roles & securables, database permissions & securables, login attributes (enforce password policy, expiration, etc.)

            The login hash algorithm changed in SQL Server 2012, and is not backwards compatible with previous SQL Server versions. This means that while SQL Server 2000 logins can be migrated to SQL Server 2012, logins created in SQL Server 2012 can only be migrated to SQL Server 2012 and above.

        .PARAMETER Source
            Source SQL Server. You must have sysadmin access and server version must be SQL Server version 2000 or higher.

        .PARAMETER SourceSqlCredential
            Allows you to login to servers using SQL Logins instead of Windows Authentication (AKA Integrated or Trusted). To use:

            $scred = Get-Credential, then pass $scred object to the -SourceSqlCredential parameter.

            Windows Authentication will be used if SourceSqlCredential is not specified. SQL Server does not accept Windows credentials being passed as credentials.

            To connect as a different Windows user, run PowerShell as that user.

        .PARAMETER Destination
            Destination SQL Server. You must have sysadmin access and the server must be SQL Server 2000 or higher.

        .PARAMETER DestinationSqlCredential
            Allows you to login to servers using SQL Logins instead of Windows Authentication (AKA Integrated or Trusted). To use:

            $dcred = Get-Credential, then pass this $dcred to the -DestinationSqlCredential parameter.

            Windows Authentication will be used if DestinationSqlCredential is not specified. SQL Server does not accept Windows credentials being passed as credentials.

            To connect as a different Windows user, run PowerShell as that user.

        .PARAMETER Login
            The login(s) to process. Options for this list are auto-populated from the server. If unspecified, all logins will be processed.

        .PARAMETER ExcludeLogin
            The login(s) to exclude. Options for this list are auto-populated from the server.

        .PARAMETER OutFile
            Calls Export-SqlLogin and exports all logins to a T-SQL formatted file. This does not perform a copy, so no destination is required.

        .PARAMETER KillActiveConnection
            If this switch and -Force are enabled, all active connections and sessions on Destination will be killed.

            A login cannot be dropped when it has active connections on the instance.

        .PARAMETER WhatIf
            If this switch is enabled, no actions are performed but informational messages will be displayed that explain what would happen if the command were to run.

        .PARAMETER Confirm
            If this switch is enabled, you will be prompted for confirmation before executing any operations that change state.

        .PARAMETER EnableException
            By default, when something goes wrong we try to catch it, interpret it and give you a friendly warning message.
            This avoids overwhelming you with "sea of red" exceptions, but is inconvenient because it basically disables advanced scripting.
            Using this switch turns this "nice by default" feature off and enables you to catch exceptions with your own try/catch.

        .NOTES
            Tags: Migration, Login
            Author: Tony Wilhelm (@tonywsql)
            Requires: sysadmin access on SQL Servers

            Website: https://dbatools.io
            Copyright: (C) Chrissy LeMaire, clemaire@gmail.com
            License: GNU GPL v3 https://opensource.org/licenses/GPL-3.0

        .LINK
            https://dbatools.io/Sync-DbaLoginSID

        .EXAMPLE
            Sync-DbaLoginSID -Source sqlserver2014a -Destination sqlserver2014b -login 'TonyW' -Force

            Drops and recreates the login 'TonyW' on the desitnation server with the SID from the source server. The login wil retain the password, 
            ownerships and permissions that it had previously on the destination server.

            If active connections are found for a login, the copy of that Login will fail as it cannot be dropped.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $true)]
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [DbaInstanceParameter]$Source,
        [PSCredential]
        $SourceSqlCredential,
        [parameter(ParameterSetName = "Destination", Mandatory = $true)]
        [DbaInstanceParameter]$Destination,
        [PSCredential]
        $DestinationSqlCredential,
        [object[]]$Login,
        [object[]]$ExcludeLogin,
        [parameter(ParameterSetName = "File", Mandatory = $true)]
        [string]$OutFile,
        [switch]$KillActiveConnection,
        [switch][Alias('Silent')]$EnableException
    )

    begin {

        function Sync-LoginSID{            
            foreach ($sourceLogin in $SourceServer.Logins) {
                $userName = $sourceLogin.name    
                
                $SwitchLoginStatus = [pscustomobject]@{
                    SourceServer      = $SourceServer.Name
                    DestinationServer = $destServer.Name
                    Type              = "Login - $($sourceLogin.LoginType)"
                    Name              = $userName
                    DestinationLogin  = $userName
                    DestinationSID    = $null
                    SourceLogin       = $userName
                    SourceSID         = $null
                    Status            = $null
                    Notes             = $null
                    DateTime          = [DbaDateTime](Get-Date)
                }                                

                if ($Login -and $Login -notcontains $userName -or $ExcludeLogin -contains $userName) { continue }

                if ($sourceLogin.id -eq 1) { continue }

                if ($userName.StartsWith("##") -or $userName -eq 'sa') {
                    Write-Message -Level Verbose -Message "Skipping $userName."
                    continue
                }

                $currentLogin = $Source.ConnectionContext.truelogin

                if ($currentLogin -eq $userName) {
                    if ($Pscmdlet.ShouldProcess("console", "Stating $userName is skipped because it is performing the migration.")) {
                        Write-Message -Level Verbose -Message "Cannot drop login performing the migration. Skipping."
                    }

                    $SwitchLoginStatus.Status = "Skipped"
                    $SwitchLoginStatus.Notes = "Current login"
                    $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                    continue
                }                

                if (($destServer.LoginMode -ne [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed) -and ($sourceLogin.LoginType -eq [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin)) {
                    Write-Message -Level Verbose -Message "$Destination does not have Mixed Mode enabled. [$userName] is an SQL Login. Enable mixed mode authentication after the migration completes to use this type of login."
                }

                if ($sourceLogin.LoginType -ne [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin) {
                    Write-Message -Level  Verbose -Message "Skipping $userName, function only valid for SQL logins."
                    continue
                }

                if ($sourceLogin.name -notin ($destServer.logins).name) {
                    Write-Message -Level Verbose -Message "Skipping $userName, It's not on $($destServer.name) Use Copy-DbaLogin instead"
                    continue
                }

                if ($userName -eq $destServer.ServiceAccount) {
                    Write-Message -Level Verbose -Message "Skipping $userName, it's the destination service account on $($destServer.name)."

                    $SwitchLoginStatus.Status = "Skipped"
                    $SwitchLoginStatus.Notes = "Destination service account"
                    $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                    continue
                }                

                $destServer.logins | 
                    Where-Object name -eq $userName |
                    ForEach-Object {
                        $login = [pscustomobject]@{
                            id                          = $PSItem.id
                            sid                         = $psitem.Get_Sid()
                            DefaultDatabase             = $PSItem.DefaultDatabase
                            Language                    = $PSItem.Language
                            PasswordPolicyEnforced      = "ON"
                            PasswordExpirationEnabled   = "ON"
                        } 
                        if ($PSItem.PasswordPolicyEnforced -eq $false) { $login.PasswordPolicyEnforced = "OFF" }
                        if (!$PSItem.PasswordExpirationEnabled) { $login.PasswordExpirationEnabled = "OFF" }
                    }
                    
                Write-Message -Level Verbose -Message "Getting the databases owned by $userName on $($destServer.name)"                
                $ownedDbs = $destServer.Databases | Where-Object Owner -eq $userName

                Write-Message -Level Verbose -Message "Getting the SQLAgent jobs owned by $userName on $($destServer.name)"                
                $ownedJobs = $destServer.JobServer.Jobs | Where-Object OwnerLoginName -eq $userName    

                Write-Message -Level Verbose -Message "Getting the server group membership of $userName on $($destServer.name)"                
                $oldRoles = @()
                try {
                    $oldroles = $destServer.roles | Where-Object {$PSItem.EnumMemberNames() -contains $username} 
                }
                catch {
                    $oldroles = $destServer.roles | Where-Object {$PSItem.EnumServerRoleMembers() -contains $username} 
                }                                    
                
                if ($DestServer.VersionMajor -ge 9) {
                    <#
                        These operations are only supported by SQL Server 2005 and above.
                        Securables: Connect SQL, View any database, Administer Bulk Operations, etc.
                    #>
                    $perms = $DestServer.EnumServerPermissions($userName)
                }

                # get the hashed password                
                switch ($destServer.versionMajor) {
                    0 { $sql = "SELECT CONVERT(VARBINARY(256),password) as hashedpass FROM master.dbo.syslogins WHERE loginname='$userName'" }
                    8 { $sql = "SELECT CONVERT(VARBINARY(256),password) as hashedpass FROM dbo.syslogins WHERE name='$userName'" }
                    9 { $sql = "SELECT CONVERT(VARBINARY(256),password_hash) as hashedpass FROM sys.sql_logins where name='$userName'" }
                    default {
                        $sql = "SELECT CAST(CONVERT(VARCHAR(256), CAST(LOGINPROPERTY(name,'PasswordHash')
                AS VARBINARY(256)), 1) AS NVARCHAR(max)) AS hashedpass FROM sys.server_principals
                WHERE principal_id = $($login.id)"
                    }
                }
                try {
                    $hashedPass = $destServer.ConnectionContext.ExecuteScalar($sql)
                }
                catch {
                    $hashedPassDt = $destServer.Databases['master'].ExecuteWithResults($sql)
                    $hashedPass = $hashedPassDt.Tables[0].Rows[0].Item(0)
                }

                if ($hashedPass.GetType().Name -ne "String") {
                    $passString = "0x"; 
                    $hashedPass | ForEach-Object { $passString += ("{0:X}" -f $_).PadLeft(2, "0") }
                    $hashedPass = $passString
                }                

                # Drop the old login
                if ($Pscmdlet.ShouldProcess($destination, "Dropping $userName")) {
                    Write-Message -Level Verbose -Message "Attempting to drop $userName on $destination."
                    try {
                        foreach ($ownedDb in $ownedDbs) {
                            Write-Message -Level Verbose -Message "Changing database owner for $($ownedDb.name) from $userName to sa."
                            $ownedDb.SetOwner('sa')
                            $ownedDb.Alter()
                        }

                        foreach ($ownedJob in $ownedJobs) {
                            Write-Message -Level Verbose -Message "Changing job owner for $($ownedJob.name) from $userName to sa."
                            $ownedJob.Set_OwnerLoginName('sa')
                            $ownedJob.Alter()
                        }

                        $activeConnections = $destServer.EnumProcesses() | Where-Object Login -eq $userName

                        if ($activeConnections -and $KillActiveConnection) {
                            if (!$destServer.Logins.Item($userName).IsDisabled) {
                                $disabled = $true
                                $destServer.Logins.Item($userName).Disable()
                            }

                            $activeConnections | ForEach-Object { $destServer.KillProcess($_.Spid)}
                            Write-Message -Level Verbose -Message "-KillActiveConnection was provided. There are $($activeConnections.Count) active connections killed."
                            # just in case the kill didn't work, it'll leave behind a disabled account
                            if ($disabled) { $destServer.Logins.Item($userName).Enable() }
                        }
                        elseif ($activeConnections) {
                            Write-Message -Level Verbose -Message "There are $($activeConnections.Count) active connections found for the login $userName. Utilize -KillActiveConnection with -Force to kill the connections."
                        }
                        $destServer.Logins.Item($userName).Drop()

                        Write-Message -Level Verbose -Message "Successfully dropped $userName on $destination."
                    }
                    catch {
                        $SwitchLoginStatus.Status = "Failed"
                        $SwitchLoginStatus.Notes = $_.Exception.Message
                        $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject

                        Stop-Function -Message "Could not drop $userName." -Category InvalidOperation -ErrorRecord $_ -Target $destServer -Continue 3>$null
                    }                    
                }

                $login | Format-List *
                
                #FIXME: remove the following line
                #$userName += "_test" #HACK
                $SwitchLoginStatus.DestinationLogin = $username
                if ($Pscmdlet.ShouldProcess($destination, "Adding SQL login $userName")) {
                    Write-Message -Level Verbose -Message "Attempting to add $userName to $destination."
                    $destLogin = New-Object Microsoft.SqlServer.Management.Smo.Login($destServer, $userName)

                    Write-Message -Level Verbose -Message "Setting $userName SID to source username SID."
                    $destLogin.Set_Sid($sourceLogin.Get_Sid())
                    $SwitchLoginStatus.SourceSID = ($sourceLogin.Get_Sid() | ForEach-Object { ("{0:X}" -f $_).PadLeft(2, "0") }) -join ""
                    $SwitchLoginStatus.DestinationSID = ($Login.SID | ForEach-Object { ("{0:X}" -f $_).PadLeft(2, "0") }) -join ""

                    Write-Message -Level Verbose -Message "Set $userName defaultdb to $defaultDb."
                    $destLogin.DefaultDatabase = $Login.DefaultDatabase

                    Write-Message -Level Verbose -Message "Setting login language to $($sourceLogin.Language)."
                    $destLogin.Language = $login.Language
                    
                    $destLogin.PasswordPolicyEnforced       = $login.PasswordPolicyEnforced
                    $destLogin.PasswordExpirationEnabled    = $login.PasswordExpirationEnabled

                    #TODO: Create the login
                    
                    try {
                        $destLogin.Create($hashedPass, [Microsoft.SqlServer.Management.Smo.LoginCreateOptions]::IsHashed)
                        $destLogin.Refresh()
                        Write-Message -Level Verbose -Message "Successfully re-added $userName to $destination."

                        $SwitchLoginStatus.Status = "Successful"
                        $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject

                    }
                    catch {
                        try {
                            $sid = "0x"; $sourceLogin.sid | ForEach-Object { $sid += ("{0:X}" -f $_).PadLeft(2, "0") }
                            $sql = "CREATE LOGIN [$userName] WITH PASSWORD = $hashedPass HASHED, SID = $sid,
                                            DEFAULT_DATABASE = [$($Login.DefaultDatabase)], CHECK_POLICY = $($Login.PasswordPolicyEnforced),
                                            CHECK_EXPIRATION = $($Login.PasswordExpirationEnabled), DEFAULT_LANGUAGE = [$($Login.Language)]"
                            $sql
                            $null = Invoke-DbaSqlCmd -SqlInstance $destServer -Database 'Master' -query $sql

                            $destLogin = $destServer.logins[$userName]
                            Write-Message -Level Verbose -Message "Successfully added $userName to $destination."

                            $SwitchLoginStatus.Status = "Successful"
                            $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject
                        }
                        catch {
                            $SwitchLoginStatus.Status = "Failed"
                            $SwitchLoginStatus.Notes = $_.Exception.Message
                            $SwitchLoginStatus | Select-DefaultView -Property DateTime, SourceServer, DestinationServer, Name, Type, Status, Notes -TypeName MigrationObject

                            Stop-Function -Message "Failed to add $userName to $destination." -Category InvalidOperation -ErrorRecord $_ -Target $destServer -Continue 3>$null
                        }
                    }                    

                    # Reassign the ownership of the databases
                    foreach ($owneddb in $ownedDbs){
                        if ($Pscmdlet.ShouldProcess($destination, "Changing of datrabase owner to $userName for $($owneddb.Name).")) {
                            try {                                
                                Write-Message -Level Verbose -Message "Changing database owner for $($ownedDb.name) to $userName."
                                $ownedDb.SetOwner($userName)
                                $ownedDb.Alter()                                
                            }
                            catch{
                                Stop-Function -Message "Failed to change database owner for $($owneddb.Name) on $destination." -Target $owneddb -ErrorRecord $_
                            }                            
                        }
                    }

                    # Reassign the ownership of the jobs 
                    foreach ($ownedJob in $ownedJobs) {
                        if ($Pscmdlet.ShouldProcess($destination, "Changing of job owner to $userName for $($ownedJob.Name).")) {
                            try {
                                $destOwnedJob = $DestServer.JobServer.Jobs | Where-Object { $_.Name -eq $ownedJobs.Name }
                                $destOwnedJob.Set_OwnerLoginName($userName)
                                $destOwnedJob.Alter()
                                Write-Message -Level Verbose -Message "Changing job owner to $userName for $($ownedJob.Name) on $destination successfully performed."
                            }
                            catch {
                                Stop-Function -Message "Failed to change job owner for $($ownedJob.Name) on $destination." -Target $ownedJob -ErrorRecord $_
                            }
                        }
                    }

                    # Add back the group memberships
                    foreach ($role in $oldRoles){
                        if ($Pscmdlet.ShouldProcess($destination, "Reassigning $userName to $($role.Name).")) {
                            try {
                                $role.AddMember($userName)
                                Write-Message -Level Verbose -Message "Adding $userName to $($role.name) server role on $destination successfully performed."
                            }
                            catch {
                                Stop-Function -Message "Failed to add $userName to $($role.name) server role on $destination." -Target $role -ErrorRecord $_
                            }
                        }
                    }

                    # Add the other server permissions
                    if ($DestServer.VersionMajor -ge 9) {
                        <#
                            These operations are only supported by SQL Server 2005 and above.
                            Securables: Connect SQL, View any database, Administer Bulk Operations, etc.
                        #>
                        foreach ($perm in $perms){
                            $permState = $perm.PermissionState
                            if ($permState -eq "GrantWithGrant") {
                                $grantWithGrant = $true;
                                $permState = "grant"
                            }
                            else {
                                $grantWithGrant = $false
                            }
                            $permSet = New-Object Microsoft.SqlServer.Management.Smo.ServerPermissionSet($perm.PermissionType)
                            if ($Pscmdlet.ShouldProcess($destination, "$permState on $($perm.PermissionType) for $userName.")) {
                                try {
                                    $DestServer.PSObject.Methods[$permState].Invoke($permSet, $userName, $grantWithGrant)
                                    Write-Message -Level Verbose -Message "$permState $($perm.PermissionType) to $userName on $destination successfully performed."
                                }
                                catch {
                                    Stop-Function -Message "Failed to $permState $($perm.PermissionType) to $userName on $destination." -Target $perm -ErrorRecord $_
                                }
                            }                
                        }
                    }
                }

                $SwitchLoginStatus                

            }
        } #end function Sync-LoginSID

        Write-Message -Level Verbose -Message "Attempting to connect to SQL Servers."
        $SourceServer = Connect-SqlInstance -RegularUser -SqlInstance $Source -SqlCredential $SourceSqlCredential
        $source = $Source.DomainInstanceName

        if ($Destination) {
            $destServer = Connect-SqlInstance -RegularUser -SqlInstance $Destination -SqlCredential $DestinationSqlCredential
            $Destination = $destServer.DomainInstanceName

            $sourceVersionMajor = $SourceServer.VersionMajor
            $destVersionMajor = $destServer.VersionMajor
            if ($sourceVersionMajor -gt 10 -and $destVersionMajor -lt 11) {
                Stop-Function -Message "Login migration from version $sourceVersionMajor to $destVersionMajor is not supported." -Category InvalidOperation -ErrorRecord $_ -Target $Source
            }

            if ($sourceVersionMajor -lt 8 -or $destVersionMajor -lt 8) {
                Stop-Function -Message "SQL Server 7 and below are not supported." -Category InvalidOperation -InnerErrorRecord $_ -Target $Source
            }
        }

        if ($Source -eq $Destination){
            Stop-Function -Message "Source ($Source) and Destination ($Destination) servers must be different." -Category InvalidOperation -ErrorRecord $_ -Target $Source
        }

        return $serverParms
    }

    process {
        if ($Pscmdlet.ShouldProcess("console", "Showing migration attempt message")) {
            Write-Message -Level Verbose -Message "Attempting Login Migration."
        }

        Sync-LoginSID -sourceserver $Source -destserver $destServer -Login $Login -Exclude $ExcludeLogin
    }
    end {
        
    }
}
