# Procfs

A library for reading values from /proc.

Note: reading and parsing /proc is inherently slow, and processes may disappear while
traversing the /proc tree. When this happens, values are either returned as [None] (where
the type permits) or the process is omitted from the result entirely.
