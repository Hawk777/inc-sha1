## Overview

`inc-sha1` is a library for incrementally calculating an SHA-1 hash value. It
uses the `sha` crate but encapsulates handling of partial blocks and final
padding so that the application can simply write any number of blocks of bytes
of any length and ask for a final hash value.
