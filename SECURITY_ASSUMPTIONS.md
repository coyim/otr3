# Security Assumptions

We have the following assumptions about the Golang VM

1. Zeroing `byte` slices wipes the value it previously had from the memory.
2. Assigning 0 to a `big.Int` wipes the value it previously had from the memory.

