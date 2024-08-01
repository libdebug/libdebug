# libdebug VS GDB Benchmarks
The benchmarks were run on libdebug 0.5.4 and GDB 15.1

## System Information
```
$ uname -a
Linux 6.9.9-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 12 Jul 2024 00:06:53 +0000 x86_64 GNU/Linux
```

<pre>
                   <span style="color: cyan;">-`</span>                    Neofetch Results
                  <span style="color: cyan;">.o+`</span>                   ---------------------------
                 <span style="color: cyan;">`ooo/</span>                   <span style="color: cyan;">OS</span>: Arch Linux x86_64
                <span style="color: cyan;">`+oooo:</span>                  <span style="color: cyan;">Host</span>: XPS 14 9440
               <span style="color: cyan;">`+oooooo:</span>                 <span style="color: cyan;">Kernel</span>: 6.9.9-arch1-1
               <span style="color: cyan;">-+oooooo+:</span>                <span style="color: cyan;">Uptime</span>: 15 mins
             <span style="color: cyan;">`/:-:++oooo+:</span>               <span style="color: cyan;">Packages</span>: 1038 (pacman), 6 (flatpak)
            <span style="color: cyan;">`/++++/+++++++:</span>              <span style="color: cyan;">Shell</span>: zsh 5.9
           <span style="color: cyan;">`/++++++++++++++:</span>             <span style="color: cyan;">Resolution</span>: 1920x1200
          <span style="color: cyan;">`/+++ooooooooooooo/`</span>           <span style="color: cyan;">DE</span>: GNOME 46.3.1
         <span style="color: cyan;">./ooosssso++osssssso+`</span>          <span style="color: cyan;">WM</span>: Mutter
        <span style="color: cyan;">.oossssso-````/ossssss+</span>          <span style="color: cyan;">WM Theme</span>: Adwaita
       <span style="color: cyan;">-osssssso.      :ssssssso.</span>        <span style="color: cyan;">Theme</span>: Adwaita [GTK2/3]
      <span style="color: cyan;">:osssssss/        osssso+++.</span>       <span style="color: cyan;">Icons</span>: Adwaita [GTK2/3]
     <span style="color: cyan;">/ossssssss/        +ssssooo/-</span>       <span style="color: cyan;">Terminal</span>: alacritty
   <span style="color: cyan;">`/ossssso+/:-        -:/+osssso+-</span>     <span style="color: cyan;">CPU</span>: Intel Ultra 7 155H (22) @ 4.500GHz
  <span style="color: cyan;">`+sso+:-`                 `.-/+oso:</span>    <span style="color: cyan;">GPU</span>: Intel Arc Graphics
 <span style="color: cyan;">`++:.                           `-/+/</span>   <span style="color: cyan;">GPU</span>: NVIDIA GeForce RTX 4050 Max-Q / Mobile
 <span style="color: cyan;">.`                                 `/</span>   <span style="color: cyan;">Memory</span>: 3809MiB / 63749MiB
</pre>

## Folder structure
In this folder, you will find all python scripts to run experiments on both libdebug and GDB. The available benchmarks are on breakpoint hits and syscall handling.

The *results* folder contains Python pickles of the lists of time required for each run as well as the extracted boxplots for the distributions.

## Replicating the benchmarks

### GDB Scripts
GDB is not designed to be scriptable. However, it is possible to implement some custom commands to be run once GDB is loaded. Because of this, the benchmark will include user logs and other overhead. To run a GDB test you need to open GDB with the test script loaded and then run the associated command. E.g.,
```bash
gdb -q -x breakpoint_gdb.py
(gdb) breakpoint_gdb
```

### libdebug scripts
Once you have the exact same version of libdebug installed, run the script like any other Python script. E.g.,
```bash
python breakpoint_libdebug.py
```