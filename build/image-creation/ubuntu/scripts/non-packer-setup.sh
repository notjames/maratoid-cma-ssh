#!/bin/bash

set -e
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_root=$(mktemp -d /mnt/XXXXXXX_system)
iso_home="$__dir/../iso"
# shellcheck disable=SC2153
system_name="${SYSTEM_NAME:-"unnamed"}"
sqfs_image="$(echo "$PWD" | awk -F'/' '{fs = NF - 1; os = $fs; ver = NF; print os"-"$ver}')"
image_name=""

trap 'mount_cleanup; cleanup_tmpdir' EXIT

sqfs["0"]="16.04:xenial"
sqfs["1"]="18.04:bionic"

mount_cleanup()
{
  umount "$build_root"/dev >/dev/null 2>&1 || true
  umount "$build_root"/sys >/dev/null 2>&1 || true
  umount "$build_root"/proc >/dev/null 2>&1 || true
}

cleanup_tmpdir()
{
  echo >&2 "Cleaned up system mounts..."
  rm -rf "$build_root"
  echo >&2 "Cleaned up temp build directory..."
}

check_shas()
{
  cd "$iso_home"

  wget -O SHA256SUMS -p --quiet https://cloud-images.ubuntu.com/xenial/current/SHA256SUMS
  chksum=$(sha256sum --quiet --ignore-missing -c SHA256SUMS >/dev/null 2>&1; echo $?)
  cd - >/dev/null

  return "$chksum"
}

download()
{
  wget -O "$iso_home/$image_name" \
    https://cloud-images.ubuntu.com/"$distro_name"/current/"$image_name"
}

get_image()
{
  local ver _ build_type match

  distro_name=""
  match=0
  c=0

  if ! [[ "$sqfs_image" =~ ^(ubuntu|centos)-[0-9]+ ]]; then
    echo >&2 "Must run from distribution/version directory. You're in: $PWD"
    exit 1
  fi
  IFS='-' read -r distro ver <<< "$sqfs_image"

  for sq in "${sqfs[@]}"; do
    IFS=':' read -r v distro_name <<< "$sq"
    IFS='-' read -r ver build_type <<< "$ver"

    if [[ $v == "$ver" ]]; then
      match=1
      break
    fi
  done

  if [[ "$match" == 0 ]] || [[ "$distro_name" == "" ]]; then
    echo >&2 "cannot determine distribution name."
    exit 1
  fi

  image_name="$distro_name"-server-cloudimg-amd64.squashfs
  system_name="$distro-$ver-${build_type:-standard}".tar.gz

  mkdir -p "$iso_home"

  if [[ ! -d "$iso_home" ]]; then
    echo >&2 "Unable to create '$iso_home'"
    return 1
  fi

  if [[ ! -f "$iso_home/$image_name" ]]; then
    download
  fi

  while ! check_shas && [[ $c -le 0 ]]; do
    download
    (( c++ ))
  done
}

apt_minify_image()
{
  echo 'Updating /etc/apt/apt.conf.9/*build-system'

  cat <<E > "$build_root"/etc/apt/apt.conf.d/99build-system
DPkg::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };
APT::Update::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };

Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache;
E

}

init_global_install()
{
  local packages
  packages=(nfs-common)

  cat <<E > "$global_script_fullpath"
export DEBIAN_FRONTEND=noninteractive
apt install -y ${packages[@]}
apt autoremove
apt clean
E

  chown root "$global_script_fullpath"
  chmod 755 "$global_script_fullpath"
}

fix_useradd()
{
  # maas's preseed curtin_userdata cloud-init uses useradd
  # to add users so set the default shell to /bin/bash instead
  # the default of borne.
  echo "Updating /etc/default/useradd"
  sed -i.bak 's#SHELL=/bin/sh#SHELL=/bin/bash#' "$build_root"/etc/default/useradd
}

fix_resolvconf()
{
  echo "Updating /etc/resolv.conf"
  mv "$build_root"/etc/resolv.conf.bak "$build_root"/etc/resolv.conf || true
}

fix_modulesconf()
{
  # adds bonding for NIC bonding
  if ! grep -qP '^bonding$' "$build_root"/etc/modules; then
    echo 'Updating /etc/modules'
    echo 'bonding' >> "$build_root"/etc/modules
  fi
}

main()
{
  [[ -z "$build_root" ]]     && return 1
  [[ "$build_root" == '/' ]] && return 1
  [[ $USER != "root" ]]      && \
    {
      echo >&2 "Must be root"
      return 1
    }

  global_script="/tmp/global_install.sh"
  global_script_fullpath="$build_root$global_script"

  # prep work area
  rm -rf "$build_root" > /dev/null 2>&1
  mkdir -p "$build_root"/{tmp,etc}/

  # get image
  get_image

  cp docker-install.sh "$build_root"/tmp/docker-install.sh
  chown root "$build_root"/tmp/docker-install.sh && \
    chgrp root "$build_root"/tmp/docker-install.sh
  chmod +x "$build_root"/tmp/docker-install.sh

  cp kubernetes-install.sh "$build_root"/tmp/kubernetes-install.sh
  chown root "$build_root"/tmp/kubernetes-install.sh && \
    chgrp root "$build_root"/tmp/kubernetes-install.sh
  chmod +x "$build_root"/tmp/kubernetes-install.sh

  unsquashfs -f -d "$build_root" "$iso_home/$image_name"
  mount -t proc proc "$build_root"/proc/
  mount -t sysfs sys "$build_root"/sys/
  mount -o bind /dev "$build_root"/dev

  cp /etc/hosts "$build_root"/etc/hosts
  # resolv.conf is a symlink to systemd runtime
  mv "$build_root"/etc/resolv.conf "$build_root"/etc/resolv.conf.bak || true
  echo 'nameserver 8.8.8.8' > "$build_root"/etc/resolv.conf

  chroot "$build_root"/ /tmp/docker-install.sh
  chroot "$build_root"/ /tmp/kubernetes-install.sh

  apt_minify_image

  # add package names for installation in all ubuntu distros
  # to this function
  init_global_install
  chroot "$build_root"/ "$global_script"

  # global image changes
  # these are things that need to be done to all images the
  # steps of which are the same across distributions.
  fix_useradd
  fix_resolvconf
  fix_modulesconf

  # finish up
  mount_cleanup
  tar cpzf /var/tmp/"$system_name" -C "$build_root" .
}


if ! main "$@"; then
  exit 1
fi

echo "...done."
