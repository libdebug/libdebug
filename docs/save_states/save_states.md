---
icon: material/database
search:
    boost: 4
---
# :material-database: Save States
Save states are a powerful feature in **libdebug** to save the current state of the process.

The state of a process in an operating system, is _not just its memory and register contents_. The process interacts with _shared external resources_, such as files, sockets, and other processes. These resources cannot be restored in a reliable way. Still, there are many interesting use cases for saving and restoring all that can be saved.

**libdebug** currently supports only one type of save state: [snapshots](../snapshots).