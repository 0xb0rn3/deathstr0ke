# duress end-to-end test

Proves the full chain as one flow: a duress code entered through the **real PAM stack** triggers
`pam_ds`, which fires the **real `ds-erase`**, which crypto-erases the configured LUKS device. A normal
password logs in and leaves it intact.

Run as root inside a machine marked disposable (`/etc/arxos/deathstroke/DISPOSABLE_MACHINE_OK_TO_DESTROY`).
The erase target is a `/tmp` loopback, never the real root, so the machine survives to report.

Deploy `ds-erase`, `dsctl`, `libpam_ds.so` to `/tmp` first, then `sudo bash run.sh`. Expect
`E2E-DURESS: ALL PASS`.
