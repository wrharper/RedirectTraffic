# RedirectTraffic

This depends on https://github.com/wrharper/WindivertWrapper and is the main event to make it possible to handle traffic.

The .Sys file is digitally signed thanks to https://github.com/basil00/WinDivert, but still be very careful.

If you don't know what you are doing, you can be stuck in a windows boot loop. Disable driver signature enforcement as a startup option if this happens to recover.

Program.cs should give enough examples to show how to use this properly.

Once you properly start the driver you can use command line in admin mode: sc start WinDivert64

Run the program in admin mode because this is a kernel level driver.

I am not responsable for your actions if you use this program.
