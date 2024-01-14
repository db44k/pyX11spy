# pyX11spy

## Overview
`pyX11spy` is a Python-based re-implementation of the `xspy` tool, which captures
keystrokes sent to an open X Display System. Like its source of inspiration,
`pyX11spy` uses the X11 `XQueryKeymap` method to periodically sample the state of
a keyboard attached to a remote display. The differences between the current
state and the previously queried state are then compared to determine which
keys have been pressed and which keys have been released. This has the
potential to create a large amount of network traffic (the default sample rate
is 100,000 queries per second, meaning at least 100,000 packets per second)
but this can be tuned on the command line by specifying a new sample rate to
the `-s` or `--sample_delay` option.

Too high of a sample rate and too much network traffic is created; too low of
a sample rate and keystrokes may be missed.

Characters that don't have an ASCII-printable representation, such as the
escape key, are represented inside single brackets: i.e., `[Escape]`. To
eliminate any potential for confusion, if the actual open- or close-bracket key
is struck, it is repeated: i.e., `[[` or `]]`. Since special key symbols only
appear wrapped with one bracket and the keystroke itself appears with two,
there should be no confusion as to the series of keystrokes actually used. In a
similar manner, if `-p` or `--print_up` is specified, `pyX11spy` will print when
keys are released (in the event they are held down). In this case, the release
will be indicated by the key surrounded by parens, i.e. `(w)` to indicate that
`w` was released. To eliminate any potential for confusion here, if the open- or
close-parens key (exists and) is struck then the output is repeated, i.e. `((` or
`))`.

`pyX11spy` also comes with the nifty option to monitor window focus as well. If
this option (`-w` or `--window_focus`) then `pyX11spy` will also report changes in
window focus by window ID and window name, allowing the caller to see what
window keystrokes are being delivered to.

## Usage

```sh
python3 pyX11spy.py -h
usage: pyX11spy.py [-h] [-t TARGET] [-d DISPLAY] [-f FLUSH_DELAY]
                   [-s SAMPLE_DELAY] [-p] [-w] [-v]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target URL or IP address to capture from (default =
                        localhost)
  -d DISPLAY, --display DISPLAY
                        display number to capture from (default = 0)
  -f FLUSH_DELAY, --flush_delay FLUSH_DELAY
                        seconds between flushes of stdout to screen (default =
                        2.0s)
  -s SAMPLE_DELAY, --sample_delay SAMPLE_DELAY
                        seconds between polls of remote keyboard (default =
                        0.00001s)
  -p, --print_up        print when keys are released (indicated by parens)
  -w, --window_focus    display changes in remote display's window focus
  -v, --verbose         increase output verbosity (currently not implemented)
```

## Example

Begin logging keystrokes in a remote X11 display while printing changes in window focus:
```sh
python3 pyX11spy.py -t <TARGET_IP> -d <DIPLAY_NO> -f 1.0 s 0.00001 -w
```

## Requirements

Just Python3 and  `python-xlib`. (`pip3 install Xlib`)

## References

See the following for more information:
 - Source code to the original `spy` tool - <https://github.com/mnp/xspy/blob/master/xspy.c>
 - Scorpion Labs Blog - <https://www.klogixsecurity.com/scorpion-labs-blog/>
