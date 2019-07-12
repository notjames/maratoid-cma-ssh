# For the MaaS Controller
Do the following:

  1. Place the `curtin_userdata_custom` on the maas controller in
     `/etc/maas/preseeds/`.

Now you just need to edit `curtin_userdata_custom` and
add the *crypted* password in the REDACTED sectios. That can be
found in 1password or regenerated if so required. Note! The password
that belongs in the password section IS NOT the plaintext password BUT
the encrypted password (raw) that goes in the `/etc/shadow` file on the
Linux systems.

This section will likely be moved when SBrain is on its own project.
