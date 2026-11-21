# LocalSystem-only worker. Public paths in argv; password crosses only LogonUserW.
function Get-WorkerIdentity { return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
function Initialize-UserNative {
    if ('S6WorkerNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Security;
using System.Runtime.InteropServices;
public static class S6WorkerNative {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 public struct Profile { public int size,flags; public string user,path,defaultPath,server,policy; public IntPtr handle; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 public struct Startup { public int size; public string reserved,desktop,title; public int x,y,cx,cy,charsX,charsY,fill,flags; public short show,reserved2; public IntPtr reservedPtr,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] public struct ProcessInfo { public IntPtr Process,Thread; public int pid,tid; }
 [StructLayout(LayoutKind.Sequential)] public struct Limits { public long processTime,jobTime; public uint flags; public UIntPtr minWorking,maxWorking; public uint active; public UIntPtr affinity; public uint priority,scheduling; }
 [StructLayout(LayoutKind.Sequential)] public struct Accounting { public long user,kernel,periodUser,periodKernel; public uint faults,total,active,terminated; }
 [StructLayout(LayoutKind.Sequential)] public struct IO { public ulong r,w,o,rb,wb,ob; }
 [StructLayout(LayoutKind.Sequential)] public struct Extended { public Limits limits; public IO io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
 [StructLayout(LayoutKind.Sequential)] public struct Luid { public uint low; public int high; }
 [StructLayout(LayoutKind.Sequential)] public struct Privilege { public uint count; public Luid luid; public uint attributes; }
 public sealed class Privileges { public IntPtr token; public Privilege[] previous = new Privilege[4]; public int count; }
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool LogonUserW(string user,string domain,IntPtr password,int type,int provider,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValueW(string system,string name,out Luid luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege state,int length,out Privilege old,out int required);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("userenv.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool LoadUserProfileW(IntPtr token,ref Profile profile);
 [DllImport("userenv.dll",SetLastError=true)] public static extern bool UnloadUserProfile(IntPtr token,IntPtr profile);
 [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr environment,IntPtr token,bool inherit);
 [DllImport("userenv.dll",SetLastError=true)] public static extern bool DestroyEnvironmentBlock(IntPtr environment);
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcessAsUserW(IntPtr token,string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo process);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int info,ref Extended limits,int length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int info,out Accounting accounting,int length,IntPtr returned);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
 static void Check(bool ok) { if(!ok) throw new InvalidOperationException("S6 native worker failed (values suppressed)"); }
 public static Privileges EnablePrivileges() {
  var p=new Privileges(); Check(OpenProcessToken(GetCurrentProcess(),0x28,out p.token));
  try {
   foreach(var name in new[]{"SeBackupPrivilege","SeRestorePrivilege","SeAssignPrimaryTokenPrivilege","SeIncreaseQuotaPrivilege"}) {
    var next=new Privilege();next.count=1;next.attributes=2;Check(LookupPrivilegeValueW(null,name,out next.luid));
    int required;Privilege old;Check(AdjustTokenPrivileges(p.token,false,ref next,Marshal.SizeOf(typeof(Privilege)),out old,out required));
    Check(Marshal.GetLastWin32Error()==0);p.previous[p.count++]=old;
   }
   return p;
  } catch { RestorePrivileges(p);throw; }
 }
 public static void RestorePrivileges(Privileges p) {
  bool ok=true;
  try { for(int i=p.count-1;i>=0;i--){int n;Privilege ignored;var old=p.previous[i];ok=AdjustTokenPrivileges(p.token,false,ref old,Marshal.SizeOf(typeof(Privilege)),out ignored,out n)&&ok;} }
  finally {ok=CloseHandle(p.token)&&ok;}
  Check(ok);
 }
 public static IntPtr Logon(string user,SecureString password) {
  IntPtr ptr=Marshal.SecureStringToGlobalAllocUnicode(password),token;
  try { Check(LogonUserW(user,null,ptr,2,0,out token));return token; }
  finally {Marshal.ZeroFreeGlobalAllocUnicode(ptr);}
 }
 public static IntPtr LoadProfile(IntPtr token,string user) {
  var p=new Profile();p.size=Marshal.SizeOf(typeof(Profile));p.flags=1;p.user=user.Split('@')[0];
  Check(LoadUserProfileW(token,ref p));return p.handle;
 }
 public static IntPtr Environment(IntPtr token) {IntPtr env;Check(CreateEnvironmentBlock(out env,token,false));return env;}
 public static IntPtr Job() {
  IntPtr job=CreateJobObjectW(IntPtr.Zero,null);Check(job!=IntPtr.Zero);
  var limits=new Extended();limits.limits.flags=0x2000;
  if(!SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(Extended)))){CloseHandle(job);Check(false);}return job;
 }
 public static ProcessInfo Create(IntPtr token,IntPtr environment,string script,string input) {
  string exe=System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe");
  var command=new StringBuilder("\""+exe+"\" -NoLogo -NoProfile -NonInteractive -File \""+script+"\" -InputFile \""+input+"\"");
  var startup=new Startup();startup.size=Marshal.SizeOf(typeof(Startup));ProcessInfo process;
  Check(CreateProcessAsUserW(token,exe,command,IntPtr.Zero,IntPtr.Zero,false,0x08000404,environment,System.IO.Path.GetDirectoryName(script),ref startup,out process));
  return process;
 }
 public static void DrainJob(IntPtr job) {
  Check(TerminateJobObject(job,2));var clock=System.Diagnostics.Stopwatch.StartNew();
  do {Accounting a;Check(QueryInformationJobObject(job,1,out a,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero));
      if(a.active==0)return;System.Threading.Thread.Sleep(20);
  } while(clock.ElapsedMilliseconds<5000);
  Check(false);
 }
 public static uint ExitCode(IntPtr process) {uint code;Check(GetExitCodeProcess(process,out code));return code;}
}
'@
}
function Invoke-UserNative($Operation,$State) {
    switch ($Operation) {
        'privileges' { return [S6WorkerNative]::EnablePrivileges() }
        'restore-privileges' { [S6WorkerNative]::RestorePrivileges($State.privileges) }
        'logon' { return [S6WorkerNative]::Logon($State.credential.UserName,$State.credential.Password) }
        'profile' { return [S6WorkerNative]::LoadProfile($State.token,$State.credential.UserName) }
        'environment' { return [S6WorkerNative]::Environment($State.token) }
        'job' { return [S6WorkerNative]::Job() }
        'create' { return [S6WorkerNative]::Create($State.token,$State.environment,$State.script,$State.input) }
        'assign' { Assert-S6 ([S6WorkerNative]::AssignProcessToJobObject($State.job,$State.process.Process)) }
        'resume' { Assert-S6 ([S6WorkerNative]::ResumeThread($State.process.Thread) -ne [uint32]::MaxValue) }
        'wait' { $code=[S6WorkerNative]::WaitForSingleObject($State.process.Process,$State.timeout);Assert-S6 ($code -in @(0,258));return $code -eq 0 }
        'exit' { return [S6WorkerNative]::ExitCode($State.process.Process) }
        'terminate' {
            # Job contains all descendants once assigned. Before assignment the
            # new process is suspended and can have no children.
            if($State.assigned){Assert-S6 ([S6WorkerNative]::TerminateJobObject($State.job,2))}
            else{Assert-S6 ([S6WorkerNative]::TerminateProcess($State.process.Process,2))}
            Assert-S6 ([S6WorkerNative]::WaitForSingleObject($State.process.Process,5000) -eq 0)
        }
        'close-thread' { Assert-S6 ([S6WorkerNative]::CloseHandle($State.process.Thread)) }
        'close-process' { Assert-S6 ([S6WorkerNative]::CloseHandle($State.process.Process)) }
        'close-job' { try{[S6WorkerNative]::DrainJob($State.job)}finally{Assert-S6 ([S6WorkerNative]::CloseHandle($State.job))} }
        'destroy-environment' { Assert-S6 ([S6WorkerNative]::DestroyEnvironmentBlock($State.environment)) }
        'unload-profile' { Assert-S6 ([S6WorkerNative]::UnloadUserProfile($State.token,$State.profile)) }
        'close-token' { Assert-S6 ([S6WorkerNative]::CloseHandle($State.token)) }
        default { throw 'S6 unknown worker operation' }
    }
}
function Invoke-UserWorker($Credential,[string]$ScriptFile,[string]$InputFile) {
    Assert-S6 ((Get-WorkerIdentity) -ceq 'S-1-5-18')
    foreach($path in @($ScriptFile,$InputFile)){Assert-S6 ($path -cmatch '^[A-Z]:\\[A-Za-z0-9_ .\\-]+$' -and $path -notmatch '\.\.')}
    Initialize-UserNative
    $state=@{credential=$Credential;script=$ScriptFile;input=$InputFile;timeout=180000;assigned=$false}
    $finished=$false;$failure=$false
    try {
        $state.privileges=Invoke-UserNative 'privileges' $state
        $state.token=Invoke-UserNative 'logon' $state
        $state.profile=Invoke-UserNative 'profile' $state
        $state.environment=Invoke-UserNative 'environment' $state
        $state.job=Invoke-UserNative 'job' $state
        $state.process=Invoke-UserNative 'create' $state
        Invoke-UserNative 'assign' $state;$state.assigned=$true
        Invoke-UserNative 'resume' $state
        $finished=Invoke-UserNative 'wait' $state;Assert-S6 $finished
        Assert-S6 ((Invoke-UserNative 'exit' $state) -eq 0)
    } catch {$failure=$true}
    finally {
        $cleanup=@()
        if($state.ContainsKey('process')){
            if(-not $finished){$cleanup+='terminate'}
            $cleanup+=@('close-thread','close-process')
        }
        if($state.ContainsKey('job')){$cleanup+='close-job'}
        if($state.ContainsKey('environment')){$cleanup+='destroy-environment'}
        if($state.ContainsKey('profile')){$cleanup+='unload-profile'}
        if($state.ContainsKey('token')){$cleanup+='close-token'}
        if($state.ContainsKey('privileges')){$cleanup+='restore-privileges'}
        foreach($operation in $cleanup){try{Invoke-UserNative $operation $state}catch{$failure=$true}}
        $state.Clear()
    }
    Assert-S6 (-not $failure)
}
