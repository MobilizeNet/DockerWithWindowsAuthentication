# escape=`
FROM mcr.microsoft.com/windows/servercore/iis:latest
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'Continue'; $verbosePreference='Continue';"]

# Enable Windows Authentication
RUN Install-WindowsFeature Web-Windows-Auth

# Install .NET Core
ENV DOTNET_VERSION 3.1.4
ENV DOTNET_DOWNLOAD_URL https://download.visualstudio.microsoft.com/download/pr/5bed16f2-fd1a-4027-bee3-3d6a1b5844cc/dd22ca2820fadb57fd5378e1763d27cd/dotnet-hosting-$DOTNET_VERSION-win.exe

ENV DOTNET_DOWNLOAD_SHA c4efac485e527240dc0e5b806eb1d06bf70d22193d68090a17f68d09806275214bf23450385fb71e725a2eed8b09c3e91cb582979678186f66a6cb563e5688c0
RUN Invoke-WebRequest $Env:DOTNET_DOWNLOAD_URL -OutFile WindowsHosting.exe; `
    if ((Get-FileHash WindowsHosting.exe -Algorithm sha512).Hash -ne $Env:DOTNET_DOWNLOAD_SHA) { `
        Write-Host 'CHECKSUM VERIFICATION FAILED!'; `
        exit 1; `
    }; `
    `
    dir c:\Windows\Installer; `
    Start-Process "./WindowsHosting.exe" '/install /quiet /norestart' -Wait; `
    Remove-Item -Force -Recurse 'C:\ProgramData\Package Cache\*'; `
    Remove-Item -Force -Recurse C:\Windows\Installer\*; `
    Remove-Item -Force WindowsHosting.exe

RUN setx /M PATH $($Env:PATH + ';' + $Env:ProgramFiles + '\dotnet')
# Enable detection of running in a container
ENV DOTNET_RUNNING_IN_CONTAINER=true

## Create Web Site and Web Application and unlock sections
 
 RUN Remove-Website -Name 'Default Web Site'; `
    New-WebAppPool -Name 'webapp'; `
    Set-ItemProperty IIS:\AppPools\webapp -Name managedRuntimeVersion -Value ''; `
    Set-ItemProperty IIS:\AppPools\webapp -Name enable32BitAppOnWin64 -Value 0; `
    Set-ItemProperty IIS:\AppPools\webapp -Name processModel -value @{identitytype='ApplicationPoolIdentity'}; `
    New-Website -Name 'webapp' `
                -Port 80 -PhysicalPath 'C:\webapp' `
                -ApplicationPool 'webapp' -force;  `
    & $env:windir\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/windowsAuthentication;  `
    & $env:windir\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/anonymousAuthentication

# Create a directory for the webapp and copy it
RUN mkdir c:\webapp
COPY .\published\ C:\webapp