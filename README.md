<div align="center">
  <a href="https://www.youtube.com/watch?v=jihTFIG116k">
    <img src="https://img.youtube.com/vi/jihTFIG116k/0.jpg" alt="POC SOPHOS XDR BYPASS" width="80%">
  </a>
  
  <h1>Hollow Purple</h1>

  <p>
    <b>A stealthy BYOVD tool to neutralize PPL processes and bypass HVCI.</b>
  </p>
</div>

---

## 🚩 About

Hollow Purple leverages a vulnerable driver (`cormem.sys`) to achieve arbitrary physical memory read/write. 

This application-layer wipe triggers a Ring 3 `STATUS_ACCESS_VIOLATION` instead of a Ring 0 BSOD, safely neutralizing heavily protected processes (like EDRs or PPLs) without triggering hypervisor faults on modern Windows 11 systems.

## 🚀 Usage

Initialize the driver first:

```cmd
sc create poc type= kernel binPath= "C:\Path\To\Cormem.sys"
sc start poc
```
Run the executable as Administrator. The tool supports targeting processes by their executable name.
Note: After wiping a process, you can use RAMMap (Empty Standby List) or simply restart your PC to restore the process functionality.

📖 Technical Deep Dive
Read the full article:

