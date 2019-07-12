# For the MaaS Controller
Do the following:

  1. Place the `curtin_userdata` on the maas controller in
     `/etc/maas/preseeds/`.

Now you just need to edit `curtin_userdata_custom` and
add the *crypted* password in the REDACTED sectios. Note! Any password
that belongs in the `password` section IS NOT the plaintext password BUT
the encrypted password (raw) that goes in the `/etc/shadow` file on the
Linux systems.
