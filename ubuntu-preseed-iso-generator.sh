#!/bin/bash

set -Eeuo pipefail

function cleanup() {
        trap - SIGINT SIGTERM ERR EXIT
        if [ -n "${tmpdir+x}" ]; then
                rm -rf -- "$tmpdir"
                log "Deleted temporary working directory $tmpdir"
        fi
}

trap cleanup SIGINT SIGTERM ERR EXIT
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
[[ ! -x "$(command -v date)" ]] && echo "date command not found." && exit 1
today=$(date +"%Y-%m-%d")

function log() {
        echo >&2 -e "[$(date +"%Y-%m-%d %H:%M:%S")] ${1-}"
}

function die() {
        local msg=$1
        local code=${2-1} # Bash parameter expansion - default exit status 1. See https://wiki.bash-hackers.org/syntax/pe#use_a_default_value
        log "$msg"
        exit "$code"
}

usage() {
        cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-k] [-v] [-p preseed-configuration-file] [-s source-iso-file] [-d destination-iso-file]

This script will create fully-automated Ubuntu Desktop installation media.

Available options:

-h, --help          Print this help and exit
-v, --verbose       Print script debug info
-p, --preseed       Path to preseed configuration file.
-k, --no-verify     Disable GPG verification of the source ISO file. By default SHA256SUMS-$today and
                    SHA256SUMS-$today.gpg in ${script_dir} will be used to verify the authenticity and integrity
                    of the source ISO file. If they are not present the latest daily SHA256SUMS will be
                    downloaded and saved in ${script_dir}. The Ubuntu signing key will be downloaded and
                    saved in a new keyring in ${script_dir}
-s, --source        Source ISO file. By default the latest daily ISO for Ubuntu 20.04 will be downloaded
                    and saved as ${script_dir}/ubuntu-original-<release name>-$today.iso
                    That file will be used by default if it already exists.
-d, --destination   Destination ISO file. By default ${script_dir}/ubuntu-preseed-$today.iso will be
                    created, overwriting any existing file.
EOF
        exit
}

function parse_params() {
        # default values of variables set from params
        preseed_file=""
        source_iso="${script_dir}/ubuntu-original-${ubuntu_rel_name}-$today.iso"
        destination_iso="${script_dir}/ubuntu-preseed-$today.iso"
        gpg_verify=1

        while :; do
                case "${1-}" in
                -h | --help) usage ;;
                -v | --verbose) set -x ;;
                -k | --no-verify) gpg_verify=0 ;;
                -p | --preseed)
                        preseed_file="${2-}"
                        shift
                        ;;
                -s | --source)
                        source_iso="${2-}"
                        shift
                        ;;
                -d | --destination)
                        destination_iso="${2-}"
                        shift
                        ;;
                -?*) die "Unknown option: $1" ;;
                *) break ;;
                esac
                shift
        done

        log "Starting up..."

        # check required params and arguments
        [[ -z "${preseed_file}" ]] && die "preseed file was not specified."
        [[ ! -f "$preseed_file" ]] && die "preseed file could not be found."

        if [ "${source_iso}" != "${script_dir}/ubuntu-original-${ubuntu_rel_name}-$today.iso" ]; then
                [[ ! -f "${source_iso}" ]] && die "Source ISO file could not be found."
        fi

        destination_iso=$(realpath "${destination_iso}")
        source_iso=$(realpath "${source_iso}")

        return 0
}


# 20.04
#ubuntu_rel_name="focal"

# 22.04
ubuntu_rel_name="jammy"

ubuntu_gpg_key_id="843938DF228D22F7B3742BC0D94AA3F0EFE21092"
ubuntu_iso_name="${ubuntu_rel_name}-desktop-amd64.iso"
ubuntu_url_mirror="https://cdimage.ubuntu.com/${ubuntu_rel_name}/daily-live/current"
ubuntu_key_server="hkp://keyserver.ubuntu.com:80"

parse_params "$@"

tmpdir=$(mktemp -d)


log "building ${ubuntu_rel_name}"

if [[ ! "$tmpdir" || ! -d "$tmpdir" ]]; then
        die "Could not create temporary working directory."
else
        log "Created temporary working directory $tmpdir"
fi

log "Checking for required utilities..."
[[ ! -x "$(command -v xorriso)" ]] && die "xorriso is not installed."
[[ ! -x "$(command -v sed)" ]] && die "sed is not installed."
[[ ! -x "$(command -v curl)" ]] && die "curl is not installed."
[[ ! -x "$(command -v gpg)" ]] && die "gpg is not installed."
[[ ! -f "/usr/lib/ISOLINUX/isohdpfx.bin" ]] && die "isolinux is not installed."
log "All required utilities are installed."


if [ ! -f "${source_iso}" ]; then
        log "Downloading current daily ISO image ${ubuntu_iso_name}"
        log "Download mirror: ${ubuntu_url_mirror}"
        curl -NsSL "${ubuntu_url_mirror}/${ubuntu_iso_name}" -o "${source_iso}"
        log "Downloaded and saved to ${source_iso}"
else
        log "Using existing ${source_iso} file."
        if [ ${gpg_verify} -eq 1 ]; then
                if [ "${source_iso}" != "${script_dir}/ubuntu-original-${ubuntu_rel_name}-$today.iso" ]; then
                        log "Automatic GPG verification is enabled. If the source ISO file is not the latest daily image, verification will fail!"
                fi
        fi
fi

if [ ${gpg_verify} -eq 1 ]; then
        if [ ! -f "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}" ]; then
                log "Downloading SHA256SUMS file..."
                curl -NsSL "${ubuntu_url_mirror}/SHA256SUMS" -o "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}"
                log "Downloading SHA256SUMS.gpg file..."
                curl -NsSL "${ubuntu_url_mirror}/SHA256SUMS.gpg" -o "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}.gpg"
        else
                log "Using existing ${ubuntu_rel_name}-SHA256SUMS-${today} & ${ubuntu_rel_name}-SHA256SUMS-${today}.gpg files."
        fi

        if [ ! -f "${script_dir}/${ubuntu_gpg_key_id}.keyring" ]; then
                log "Downloading and saving Ubuntu signing key..."
                gpg -q --no-default-keyring --keyring "${script_dir}/${ubuntu_gpg_key_id}.keyring" --keyserver "${ubuntu_key_server}" --recv-keys "${ubuntu_gpg_key_id}"
                log "Downloaded and saved to ${script_dir}/${ubuntu_gpg_key_id}.keyring"
        else
                log "Using existing Ubuntu signing key saved in ${script_dir}/${ubuntu_gpg_key_id}.keyring"
        fi

        log "Verifying ${source_iso} integrity and authenticity..."
        gpg -q --keyring "${script_dir}/${ubuntu_gpg_key_id}.keyring" --verify "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}.gpg" "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}" 2>/dev/null
        if [ $? -ne 0 ]; then
                rm -fv "${script_dir}/${ubuntu_gpg_key_id}.keyring~"
                die "Verification of SHA256SUMS signature failed."
        fi

        rm -f "${script_dir}/${ubuntu_gpg_key_id}.keyring~"
        digest=$(sha256sum "${source_iso}" | cut -f1 -d ' ')
        set +e
        grep -Fq "$digest" "${script_dir}/${ubuntu_rel_name}-SHA256SUMS-${today}"
        if [ $? -eq 0 ]; then
                log "Verification succeeded."
                set -e
        else
                die "Verification of ISO digest failed."
        fi
else
        log "Skipping verification of source ISO."
fi

log "Extracting ISO image..."
xorriso -osirrox on -indev "${source_iso}" -extract / "$tmpdir" &>/dev/null
chmod -R u+w "$tmpdir"
rm -rf -- "$tmpdir/"'[BOOT]'
log "Extracted to $tmpdir showing files below"
echo "----------------"
ls -lah -- $tmpdir
echo "----------------"

log "Adding preseed parameters to kernel command line..."

# These are for UEFI mode
sed -i -e 's,file=/cdrom/preseed/ubuntu.seed maybe-ubiquity quiet splash,file=/cdrom/preseed/custom.seed auto=true priority=critical boot=casper automatic-ubiquity quiet splash noprompt noshell,g' "$tmpdir/boot/grub/grub.cfg"
sed -i -e 's,file=/cdrom/preseed/ubuntu.seed maybe-ubiquity iso-scan/filename=${iso_path} quiet splash,file=/cdrom/preseed/custom.seed auto=true priority=critical boot=casper automatic-ubiquity quiet splash noprompt noshell,g' "$tmpdir/boot/grub/loopback.cfg"

# This one is used for BIOS mode
    mkdir -p "$tmpdir/isolinux/"
cat <<EOF > "$tmpdir/isolinux/txt.cfg"
default live-install
label live-install
  menu label ^Install Ubuntu
  kernel /casper/vmlinuz
  append  file=/cdrom/preseed/custom.seed auto=true priority=critical boot=casper automatic-ubiquity initrd=/casper/initrd quiet splash noprompt noshell ---
EOF

log "Added parameters to UEFI and BIOS kernel command lines."

log "Adding preseed configuration file..."
cp -v "$preseed_file" "$tmpdir/preseed/custom.seed"
log "Added preseed file"

log "Updating $tmpdir/md5sum.txt with hashes of modified files..."
# Using the full list of hashes causes long delays at boot.
# For now, just include a couple of the files we changed.
md5=$(md5sum "$tmpdir/boot/grub/grub.cfg" | cut -f1 -d ' ')
echo "$md5  ./boot/grub/grub.cfg" > "$tmpdir/md5sum.txt"
md5=$(md5sum "$tmpdir/boot/grub/loopback.cfg" | cut -f1 -d ' ')
echo "$md5  ./boot/grub/loopback.cfg" >> "$tmpdir/md5sum.txt"
log "Updated hashes."

log "Repackaging extracted files into an ISO image..."
cd "$tmpdir"
log "Changed to $tmpdir"
#xorriso -as mkisofs -r -V "ubuntu-preseed-$today" -J -b isolinux/isolinux.bin -c isolinux/boot.cat \
#        -no-emul-boot -boot-load-size 4 -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin -boot-info-table \
#        -input-charset utf-8 -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat \
#        -o "${destination_iso}" .

log "### Extract mbr and efi sectors from ${source_iso}... "
mbr="mbr"
efi="efi"
dest=.....

dd if="$source_iso" bs=1 count=446 of="$mbr"

skip=$(/sbin/fdisk -l "$source_iso" | fgrep '.iso2 ' | awk '{print $2}')
size=$(/sbin/fdisk -l "$source_iso" | fgrep '.iso2 ' | awk '{print $4}')
dd if="$source_iso" bs=512 skip="$skip" count="$size" of="$efi"

xorriso -as mkisofs -r -V "ubuntu-preseed" -J -joliet-long -l -iso-level 3 -partition_offset 16 --grub2-mbr "$mbr" --mbr-force-bootable -append_partition 2 0xEF "$efi" -appended_part_as_gpt -c boot.catalog -b boot/grub/i386-pc/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info -eltorito-alt-boot -e '--interval:appended_partition_2:all::' -no-emul-boot -o "${destination_iso}" .

cd "$OLDPWD"
log "Changed to $OLDPWD"
log "Repackaged into ${destination_iso}"

die "Completed." 0
