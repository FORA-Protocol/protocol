package core

import "time"

// DefaultWindow exposes, to this package's tests only, the window a transport built
// without WithWindow signs with, over a clock the test supplies. The transport's own
// default reads time.Now, which no test can move; the signing-window corpus emits its
// "default" rows through this function, and TestSigningWindow_DefaultIsDefaultWindow
// pins that a transport built without WithWindow signs with it.
func DefaultWindow(now func() time.Time) Window { return defaultWindow(now) }
