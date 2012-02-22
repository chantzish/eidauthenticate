How to debug

http://blogs.msdn.com/alejacma/archive/2007/11/13/how-to-debug-lsass-exe-process.aspx

Run Virtual PC -> not working : use vmware
http://www.microsoft.com/downloads/details.aspx?FamilyId=28C97D22-6EB8-4A09-A7F7-F6C7A1F000B5

Enable kernel debugging on the virtual machine
Vista :
bcdedit /debug yes
Xp :
......

Run kernel debugger
1) don't forget to set symbol path (path to .dll & .pdb) and source path,
else you will find only asm, not cpp code.
2) Run "ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF" to see Debugging with debug release (OutputDebug)
(needed only for Vista & later)

Set a breakpoint in a function called by lsass
================================================
!process 0 0 lsass.exe
.process -i 12345678    (obtained in !process with lsass.exe)
g         (to swithc context)
.reload  /user           (to enable pdb loading)
bp eidauthenticationpackage!lsaaplogonuserex2   (to set a breakpoint to lsaaplogonuserex2)

to enable tracing in kernel debugger, issue the following command in windbg : 
ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF


